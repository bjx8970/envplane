"""Event-synchronised regressions for local UoW/heartbeat coordination.

Only disposable PostgreSQL and genuine least-privilege runtime credentials are
used. Events hold transactions at known boundaries, never timing guesses about
whether a worker has acquired the durable lease-row lock.
"""
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from threading import Event, Lock, get_ident
import time
import unittest
from unittest.mock import patch

from sqlalchemy import event, text

from control_plane.config import COORDINATOR_LOCK_KEY, RuntimeSettings
from control_plane.coordination import CoordinatorLease, LeaseLost
from control_plane.persistence import admit_job, write_storage
from control_plane.runtime import ControlPlaneRuntime, LeadershipLost
from tests_control_plane.p1_harness import runtime_database
from tests_control_plane.pg_harness import engine_for
from tests_control_plane.test_p1_schema import insert, job_arguments


class ObservedGate:
    """A real lock with deterministic notification before a contended wait."""

    def __init__(self):
        self.lock = Lock()
        self.waiters = Queue()

    def acquire(self, blocking=True, timeout=-1):
        if blocking and self.lock.locked():
            self.waiters.put(get_ident())
        return self.lock.acquire(blocking, timeout)

    def release(self):
        self.lock.release()


class AbortWrite(BaseException):
    pass


class HeartbeatUnitOfWorkTests(unittest.TestCase):
    def setUp(self):
        admin_url, runtime_url = self.enterContext(runtime_database())
        self.admin = engine_for(admin_url)
        self.addCleanup(self.admin.dispose)
        self.runtime = ControlPlaneRuntime(RuntimeSettings.from_env({
            "CONTROL_PLANE_DATABASE_URL": runtime_url,
        }))
        self.runtime.start()
        self.addCleanup(self.runtime.stop)
        self.lease = self.runtime._lease

    def expiry(self):
        with self.admin.connect() as connection:
            return connection.scalar(text(
                "SELECT expires_at FROM control_plane.coordinator_leases WHERE id=1"
            ))

    def test_slow_low_privilege_uow_survives_concurrent_polls_and_commits(self):
        staged, finish = Event(), Event()

        def writer():
            with self.runtime.fenced_transaction() as unit:
                plugin = insert(unit, "plugin_instances", plugin_key="heartbeat-regression")
                write_storage(unit, plugin, "hosts", {"committed": True})
                job, replay = admit_job(unit, **job_arguments(unit))
                self.assertFalse(replay)
                staged.set()
                self.assertTrue(finish.wait(8), "test did not release the writer")
            return job

        with ThreadPoolExecutor(max_workers=2) as pool:
            writing = pool.submit(writer)
            try:
                self.assertTrue(staged.wait(5), "writer did not acquire lease row")
                before = self.expiry()
                started = time.monotonic()
                # Three real polls during a >2s legitimate transaction. A busy
                # local gate may validate, but must not update expires_at.
                for _ in range(3):
                    pool.submit(self.runtime.poll).result(timeout=3)
                    self.assertEqual(self.expiry(), before)
                    Event().wait(0.75)
                self.assertGreaterEqual(time.monotonic() - started, 2.2)
            finally:
                finish.set()
            job = writing.result(timeout=5)
        self.runtime.poll()
        self.assertGreater(self.expiry(), before)
        # Visibility is checked on an independent administrative connection,
        # not via another transaction on the runtime's pool/session.
        with self.admin.connect() as connection:
            self.assertEqual(connection.scalar(text("SELECT count(*) FROM control_plane.jobs WHERE id=:id"), {"id": job}), 1)
            self.assertEqual(connection.scalar(text("SELECT count(*) FROM control_plane.plugin_storage_versions")), 1)
            self.assertEqual(connection.scalar(text("SELECT count(*) FROM control_plane.plugin_storage_heads")), 1)

    def test_expiry_while_local_writer_is_busy_fails_poll_and_rolls_back(self):
        with self.admin.begin() as connection:
            connection.execute(text("UPDATE control_plane.coordinator_leases SET expires_at=clock_timestamp()+interval '0.6 seconds' WHERE id=1"))
        staged, finish = Event(), Event()

        def writer():
            with self.runtime.fenced_transaction() as unit:
                unit.execute(text("INSERT INTO control_plane.audit_events(action,result) VALUES ('expired','must rollback')"))
                staged.set()
                self.assertTrue(finish.wait(5))

        with ThreadPoolExecutor(max_workers=1) as pool:
            writing = pool.submit(writer)
            try:
                self.assertTrue(staged.wait(3))
                before = self.expiry()
                self.runtime.poll()
                self.assertEqual(self.expiry(), before)
                with self.admin.connect() as connection:
                    connection.execute(text("SELECT pg_sleep(GREATEST(0,EXTRACT(EPOCH FROM expires_at-clock_timestamp()))+0.05) FROM control_plane.coordinator_leases WHERE id=1"))
                with self.assertRaises(LeadershipLost):
                    self.runtime.poll()
            finally:
                finish.set()
            with self.assertRaises(LeaseLost):
                writing.result(timeout=3)
        with self.admin.connect() as connection:
            self.assertEqual(connection.scalar(text("SELECT count(*) FROM control_plane.audit_events")), 0)
            self.assertEqual(connection.scalar(text("SELECT expires_at FROM control_plane.coordinator_leases WHERE id=1")), before)

    def test_baseexception_rollback_cleans_gate_for_poll_and_next_writer(self):
        with self.assertRaises(AbortWrite):
            with self.runtime.fenced_transaction() as unit:
                unit.execute(text("INSERT INTO control_plane.audit_events(action,result) VALUES ('aborted','must rollback')"))
                raise AbortWrite()
        self.runtime.poll()
        with self.runtime.fenced_transaction() as unit:
            unit.execute(text("INSERT INTO control_plane.audit_events(action,result) VALUES ('next','committed')"))
        with self.admin.connect() as connection:
            self.assertEqual(connection.execute(text("SELECT action FROM control_plane.audit_events")).all(), [("next",)])

    def test_busy_polls_request_boundary_renewal_between_short_writers(self):
        # Direct lease construction permits a short test TTL without changing
        # runtime settings validation. Keep the genuine low-privilege engine.
        self.lease.release()
        self.lease = CoordinatorLease(self.runtime._engine, COORDINATOR_LOCK_KEY, 1)
        self.runtime._lease = self.lease
        self.assertTrue(self.lease.acquire())
        initial = self.expiry()
        started = time.monotonic()
        last = None
        for index in range(5):
            with self.runtime.fenced_transaction() as unit:
                unit.execute(text("INSERT INTO control_plane.audit_events(action,result) VALUES (:action,'committed')"), {"action": f"writer-{index}"})
                current = self.expiry()
                if last is not None:
                    self.assertGreater(current, last)
                self.runtime.poll()
                self.assertEqual(self.expiry(), current)
                # Event.wait has a finite duration; synchronisation with the
                # writer is exact because this thread owns its transaction.
                Event().wait(0.28)
                last = current
        self.assertGreater(time.monotonic() - started, 1)
        self.assertGreater(last, initial)
        with self.admin.connect() as connection:
            self.assertEqual(connection.scalar(text("SELECT count(*) FROM control_plane.audit_events")), 5)

    def _assert_gate_covers_database_exit(self, abort):
        gate = ObservedGate()
        self.lease._write_gate = gate
        exiting, finish, next_entered = Event(), Event(), Event()
        event_name = "rollback" if abort else "commit"

        def at_exit(connection):
            if not exiting.is_set():
                exiting.set()
                self.assertTrue(finish.wait(8), "database exit was not released")

        def writer():
            with self.runtime.fenced_transaction() as unit:
                unit.execute(text("INSERT INTO control_plane.audit_events(action,result) VALUES ('first','staged')"))
                if abort:
                    raise AbortWrite()

        def next_writer():
            with self.runtime.fenced_transaction() as unit:
                next_entered.set()
                unit.execute(text("INSERT INTO control_plane.audit_events(action,result) VALUES ('next','committed')"))

        event.listen(self.runtime._engine, event_name, at_exit)
        try:
            with ThreadPoolExecutor(max_workers=3) as pool:
                first = pool.submit(writer)
                try:
                    # SQLAlchemy fires this event BEFORE the actual DBAPI
                    # commit/rollback. The transaction still owns its row lock.
                    self.assertTrue(exiting.wait(5))
                    before = self.expiry()
                    pool.submit(self.runtime.poll).result(timeout=3)
                    self.assertEqual(self.expiry(), before)
                    following = pool.submit(next_writer)
                    gate.waiters.get(timeout=3)
                    self.assertFalse(next_entered.is_set())
                finally:
                    finish.set()
                if abort:
                    with self.assertRaises(AbortWrite):
                        first.result(timeout=4)
                else:
                    first.result(timeout=4)
                following.result(timeout=4)
        finally:
            finish.set()
            event.remove(self.runtime._engine, event_name, at_exit)
        with self.admin.connect() as connection:
            self.assertEqual(connection.scalar(text("SELECT count(*) FROM control_plane.audit_events")), 1 if abort else 2)
        self.assertGreater(self.expiry(), before)

    def test_writer_gate_covers_actual_commit_and_queued_writer(self):
        self._assert_gate_covers_database_exit(abort=False)

    def test_writer_gate_covers_exception_rollback_and_queued_writer(self):
        self._assert_gate_covers_database_exit(abort=True)

    def test_queued_writer_cannot_borrow_reacquired_generation(self):
        gate = ObservedGate()
        self.lease._write_gate = gate
        self.assertTrue(gate.acquire())
        entered = Event()

        def queued_writer():
            with self.lease.fenced_transaction():
                entered.set()

        with ThreadPoolExecutor(max_workers=1) as pool:
            waiting = pool.submit(queued_writer)
            try:
                gate.waiters.get(timeout=3)  # identity captured before waiting
                previous = self.lease.revision
                self.lease.release()
                self.assertTrue(self.lease.acquire())
                self.assertEqual(self.lease.revision, previous + 1)
            finally:
                gate.release()
            with self.assertRaises(LeaseLost):
                waiting.result(timeout=3)
        self.assertFalse(entered.is_set())
        with self.runtime.fenced_transaction() as unit:
            self.assertEqual(unit.scalar(text("SELECT 1")), 1)

    def test_nested_uow_is_rejected_without_wait_or_outer_poisoning(self):
        with self.runtime.fenced_transaction() as unit:
            started = time.monotonic()
            with self.assertRaises(LeaseLost):
                with self.runtime.fenced_transaction():
                    self.fail("nested writer was admitted")
            self.assertLess(time.monotonic() - started, 0.5)
            unit.execute(text("INSERT INTO control_plane.audit_events(action,result) VALUES ('outer','committed')"))
        self.runtime.poll()

    def test_busy_poll_checks_actual_advisory_lock_and_writer_rolls_back(self):
        with self.assertRaises(LeaseLost):
            with self.runtime.fenced_transaction() as unit:
                unit.execute(text("INSERT INTO control_plane.audit_events(action,result) VALUES ('unlocked','must rollback')"))
                # Fault injection, serialised just like all production access to
                # the dedicated connection. Durable owner/expiry remain valid.
                self.assertTrue(self.lease._session_gate.acquire(timeout=1))
                try:
                    self.assertTrue(self.lease._connection.scalar(text("SELECT pg_advisory_unlock(:key)"), {"key": COORDINATOR_LOCK_KEY}))
                finally:
                    self.lease._session_gate.release()
                with self.assertRaises(LeadershipLost):
                    self.runtime.poll()
        with self.admin.connect() as connection:
            self.assertEqual(connection.scalar(text("SELECT count(*) FROM control_plane.audit_events")), 0)

    def test_stopped_renewal_cannot_publish_old_generation_counters(self):
        # Create a real pending request, then pause after the database renewal
        # COMMIT but before local bookkeeping; stop must win that race.
        with self.runtime.fenced_transaction():
            self.runtime.poll()
        self.assertGreater(self.lease._renew_requested, 0)
        renewed, finish = Event(), Event()
        mark = self.lease._mark_renewed

        def after_database_commit(identity, requested):
            renewed.set()
            self.assertTrue(finish.wait(5))
            return mark(identity, requested)

        with patch.object(self.lease, "_mark_renewed", side_effect=after_database_commit):
            with ThreadPoolExecutor(max_workers=1) as pool:
                verifying = pool.submit(self.lease.verify)
                try:
                    self.assertTrue(renewed.wait(3))
                    started = time.monotonic()
                    self.lease.release()  # Does not wait indefinitely for poll.
                    self.assertLess(time.monotonic() - started, 2.5)
                finally:
                    finish.set()
                self.assertFalse(verifying.result(timeout=3))
        self.assertEqual((self.lease._renew_requested, self.lease._renew_served), (0, 0))
        # The interrupted release conservatively retained its durable deadline;
        # only explicit expiry permits this same object to acquire a new owner
        # revision. Old local counters must not suppress its first renewal.
        with self.admin.begin() as connection:
            connection.execute(text("UPDATE control_plane.coordinator_leases SET expires_at=clock_timestamp()-interval '1 second' WHERE id=1"))
        self.assertTrue(self.lease.acquire())
        self.assertEqual((self.lease._renew_requested, self.lease._renew_served), (0, 0))
        with self.runtime.fenced_transaction():
            self.runtime.poll()
            before = self.expiry()
        with self.runtime.fenced_transaction():
            self.assertGreater(self.expiry(), before)

    def test_concurrent_busy_polls_serialize_the_dedicated_connection(self):
        gate = ObservedGate()
        self.lease._session_gate = gate
        querying, resume = Event(), Event()

        def before_query(connection, cursor, statement, parameters, context, many):
            if (connection is self.lease._connection and not querying.is_set()
                    and "SELECT id FROM control_plane.coordinator_leases" in statement):
                querying.set()
                self.assertTrue(resume.wait(3))

        event.listen(self.runtime._engine, "before_cursor_execute", before_query)
        try:
            with self.runtime.fenced_transaction():
                before = self.expiry()
                with ThreadPoolExecutor(max_workers=2) as pool:
                    first = pool.submit(self.runtime.poll)
                    try:
                        self.assertTrue(querying.wait(3))
                        second = pool.submit(self.runtime.poll)
                        gate.waiters.get(timeout=0.8)
                    finally:
                        resume.set()
                    first.result(timeout=3)
                    second.result(timeout=3)
                self.assertEqual(self.expiry(), before)
        finally:
            resume.set()
            event.remove(self.runtime._engine, "before_cursor_execute", before_query)


if __name__ == "__main__":
    unittest.main()
