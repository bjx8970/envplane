"""Regression coverage for PR #30 heartbeat, Unit-of-Work and role boundaries."""
from concurrent.futures import ThreadPoolExecutor
import time
import unittest

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from control_plane.config import COORDINATOR_LOCK_KEY, RuntimeSettings
from control_plane.coordination import CoordinatorLease, LeaseLost
from control_plane.migrations import BASELINE_REVISION, SchemaMismatch, run_migrations
from control_plane.permissions import RuntimePermissionError
from control_plane.persistence import admit_job, write_storage
from control_plane.runtime import ControlPlaneRuntime
from tests_control_plane.p1_harness import fresh_database, migrated_database, runtime_database
from tests_control_plane.pg_harness import CliProcess, engine_for, run_cli_once, try_advisory_lock
from tests_control_plane.test_p1_runtime import database_command
from tests_control_plane.test_p1_schema import insert, job_arguments


def wait_for_lock(engine, pid, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with engine.connect() as monitor:
            if monitor.scalar(text("SELECT wait_event_type='Lock' FROM pg_stat_activity WHERE pid=:pid"), {"pid": pid}):
                return
        time.sleep(0.01)
    raise AssertionError("coordinator did not reach row-lock wait")


class HeartbeatBudgetTests(unittest.TestCase):
    def test_held_row_cannot_stall_verify_and_does_not_renew(self):
        with migrated_database() as url:
            engine = engine_for(url)
            lease = CoordinatorLease(engine, COORDINATOR_LOCK_KEY)
            try:
                self.assertTrue(lease.acquire())
                pid = lease.backend_pid
                with engine.begin() as gate:
                    before = gate.scalar(text("SELECT expires_at FROM control_plane.coordinator_leases WHERE id=1 FOR UPDATE"))
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        started = time.monotonic()
                        result = pool.submit(lease.verify)
                        wait_for_lock(engine, pid)
                        # Keep the lock until verify has returned, not just until expiry.
                        self.assertFalse(result.result(timeout=3))
                        self.assertLess(time.monotonic() - started, 3)
                    self.assertEqual(gate.scalar(text("SELECT expires_at FROM control_plane.coordinator_leases WHERE id=1")), before)
                    self.assertTrue(try_advisory_lock(url, COORDINATOR_LOCK_KEY))
                with self.assertRaises(LeaseLost):
                    with lease.fenced_transaction():
                        self.fail("timed-out owner retained write qualification")
            finally:
                lease.release()
                engine.dispose()

    def test_sigterm_during_held_heartbeat_lock_exits_bounded(self):
        with runtime_database() as (admin_url, runtime_url):
            process = CliProcess(runtime_url, lock_poll_seconds=0.1)
            self.addCleanup(process.kill)
            payload = process.read_event("ready")
            engine = engine_for(admin_url)
            try:
                with engine.begin() as gate:
                    gate.execute(text("SELECT id FROM control_plane.coordinator_leases WHERE id=1 FOR UPDATE"))
                    wait_for_lock(engine, int(payload["lock_backend_pid"]))
                    started = time.monotonic()
                    process.send_stop()
                    code, out, err = process.wait_for_exit(timeout=4)
                    self.assertEqual(code, 4, out + err)
                    self.assertIn("leadership_lost", err)
                    self.assertLess(time.monotonic() - started, 3)
                    self.assertTrue(try_advisory_lock(admin_url, COORDINATOR_LOCK_KEY))
            finally:
                engine.dispose()

    def test_release_is_bounded_while_lease_row_is_held(self):
        with migrated_database() as url:
            engine = engine_for(url)
            lease = CoordinatorLease(engine, COORDINATOR_LOCK_KEY)
            try:
                self.assertTrue(lease.acquire())
                with engine.begin() as gate:
                    gate.execute(text("SELECT id FROM control_plane.coordinator_leases WHERE id=1 FOR UPDATE"))
                    started = time.monotonic()
                    lease.release()
                    self.assertLess(time.monotonic() - started, 3)
                    self.assertTrue(try_advisory_lock(url, COORDINATOR_LOCK_KEY))
            finally:
                lease.release()
                engine.dispose()


class FencedPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.url = self.enterContext(migrated_database())
        self.engine = engine_for(self.url)
        self.addCleanup(self.engine.dispose)
        self.lease = CoordinatorLease(self.engine, COORDINATOR_LOCK_KEY)
        self.addCleanup(self.lease.release)
        self.assertTrue(self.lease.acquire())
        with self.engine.begin() as conn:
            self.instance = insert(conn, "plugin_instances", plugin_key="fake")
            self.args = job_arguments(conn)

    def reject_both(self, connection):
        with self.assertRaises(LeaseLost):
            write_storage(connection, self.instance, "hosts", {})
        with self.assertRaises(LeaseLost):
            admit_job(connection, **self.args)

    def test_live_owner_cannot_pass_an_ordinary_transaction(self):
        with self.engine.begin() as conn:
            self.reject_both(conn)

    def test_lost_owner_direct_api_and_new_owner_takeover(self):
        old = self.lease
        old._close()
        with self.engine.begin() as conn:
            conn.execute(text("UPDATE control_plane.coordinator_leases SET expires_at=clock_timestamp()-interval '1 second' WHERE id=1"))
            self.reject_both(conn)
        with self.assertRaises(LeaseLost):
            with old.fenced_transaction():
                self.fail("lost owner opened a new Unit of Work")
        replacement = CoordinatorLease(self.engine, COORDINATOR_LOCK_KEY)
        self.addCleanup(replacement.release)
        self.assertTrue(replacement.acquire())
        with replacement.fenced_transaction() as conn:
            write_storage(conn, self.instance, "hosts", {"valid": True})
            job, replay = admit_job(conn, **self.args)
            self.assertFalse(replay)
        with self.engine.connect() as conn:
            self.assertIsNotNone(job)
            self.assertEqual(conn.scalar(text("SELECT count(*) FROM control_plane.plugin_storage_versions")), 1)

    def test_expired_scope_is_rejected_before_api_write(self):
        with self.assertRaises(LeaseLost):
            with self.lease.fenced_transaction() as conn:
                conn.execute(text("UPDATE control_plane.coordinator_leases SET expires_at=clock_timestamp()-interval '1 second' WHERE id=1"))
                self.reject_both(conn)
        with self.engine.connect() as conn:
            self.assertEqual(conn.scalar(text("SELECT count(*) FROM control_plane.jobs")), 0)
            self.assertEqual(conn.scalar(text("SELECT count(*) FROM control_plane.plugin_storage_versions")), 0)

    def test_scope_cannot_be_reused_after_exit_or_from_another_thread(self):
        with self.lease.fenced_transaction() as conn:
            with ThreadPoolExecutor(max_workers=1) as pool:
                pool.submit(self.reject_both, conn).result(timeout=3)
            version = write_storage(conn, self.instance, "hosts", {})
        self.reject_both(conn)
        with self.lease.fenced_transaction() as next_scope:
            self.reject_both(conn)
            write_storage(next_scope, self.instance, "hosts", {"next": True}, expected_version=version.id)

    def test_uow_hides_early_commit_handles_and_rejects_transaction_control(self):
        from control_plane.coordination import FencedConnection
        with self.engine.begin() as raw:
            with self.assertRaises(LeaseLost):
                FencedConnection(raw, self.lease)
        with self.lease.fenced_transaction() as conn:
            result = conn.execute(text("SELECT 1"))
            self.assertFalse(hasattr(result, "connection"))
            self.assertFalse(hasattr(result, "cursor"))
            self.assertEqual(result.scalar_one(), 1)
            iterator = iter(conn.execute(text("SELECT 2")))
            self.assertFalse(hasattr(iterator, "connection"))
            self.assertEqual(next(iterator)[0], 2)
            with conn.begin_nested() as nested:
                self.assertIsNone(nested)
            for sql in ("COMMIT", "END", "ROLLBACK", "PREPARE TRANSACTION 'escape'",
                        "SELECT 1; COMMIT", "-- comment\nCOMMIT", "DO $$BEGIN COMMIT; END$$"):
                with self.subTest(sql=sql), self.assertRaises(LeaseLost):
                    conn.execute(text(sql))
            write_storage(conn, self.instance, "hosts", {})

    def test_lease_loss_after_both_writes_rolls_back_everything(self):
        with self.assertRaises(LeaseLost):
            with self.lease.fenced_transaction() as conn:
                write_storage(conn, self.instance, "hosts", {})
                admit_job(conn, **self.args)
                self.lease._connection.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": COORDINATOR_LOCK_KEY})
        with self.engine.connect() as conn:
            self.assertEqual(conn.scalar(text("SELECT count(*) FROM control_plane.jobs")), 0)
            self.assertEqual(conn.scalar(text("SELECT count(*) FROM control_plane.plugin_storage_versions")), 0)


class ReviewDeploymentTests(unittest.TestCase):
    def test_migration_account_cannot_start_runtime(self):
        with migrated_database() as url:
            runtime = ControlPlaneRuntime(RuntimeSettings.from_env({"CONTROL_PLANE_DATABASE_URL": url}))
            with self.assertRaises(RuntimePermissionError):
                runtime.start()
            runtime.stop()
            code, out, err = run_cli_once(url)
            self.assertEqual(code, 4, out + err)
            self.assertIn("least-privilege", err)
            self.assertNotIn(url, err)
            self.assertTrue(try_advisory_lock(url, COORDINATOR_LOCK_KEY))

    def test_low_privilege_runtime_can_commit_both_persistence_apis(self):
        with runtime_database() as (_, runtime_url):
            runtime = ControlPlaneRuntime(RuntimeSettings.from_env({"CONTROL_PLANE_DATABASE_URL": runtime_url}))
            try:
                runtime.start()
                with runtime.fenced_transaction() as conn:
                    plugin = insert(conn, "plugin_instances", plugin_key="fake")
                    write_storage(conn, plugin, "hosts", {"authorized": True})
                    job, replay = admit_job(conn, **job_arguments(conn))
                    self.assertFalse(replay)
                    conn.execute(text("INSERT INTO control_plane.audit_events(action,result) VALUES ('test','committed')"))
                runtime.poll()
                with runtime.fenced_transaction() as conn:
                    self.assertIsNotNone(conn.scalar(text("SELECT id FROM control_plane.jobs WHERE id=:id"), {"id": job}))
            finally:
                runtime.stop()

    def test_high_privilege_login_cannot_hide_behind_set_role(self):
        from sqlalchemy.engine import make_url
        from unittest.mock import patch
        with runtime_database() as (admin_url, runtime_url):
            role = make_url(runtime_url).username
            admin_engine = engine_for(admin_url)
            # Simulate a pool configured with a low current role but privileged
            # session login. Startup must reject RESET ROLE escalation.
            with admin_engine.connect() as conn:
                conn.execute(text(f'SET ROLE "{role}"'))
                conn.commit()
            runtime = ControlPlaneRuntime(RuntimeSettings.from_env({"CONTROL_PLANE_DATABASE_URL": admin_url}))
            with patch("control_plane.runtime.create_database_engine", return_value=admin_engine):
                with self.assertRaises(RuntimePermissionError):
                    runtime.start()
            runtime.stop()

    def test_0001_requires_explicit_upgrade_and_0002_downgrades_cleanly(self):
        with fresh_database() as url:
            settings = RuntimeSettings.from_env({"CONTROL_PLANE_DATABASE_URL": url})
            run_migrations(settings, BASELINE_REVISION)
            engine = engine_for(url)
            try:
                lease = CoordinatorLease(engine, COORDINATOR_LOCK_KEY)
                with self.assertRaises(SchemaMismatch):
                    lease.acquire()
                run_migrations(settings)
                with engine.begin() as conn:
                    for table in ("audit_events", "operation_evidence", "job_logs"):
                        with self.assertRaises(DBAPIError) as raised:
                            with conn.begin_nested():
                                conn.execute(text(f"TRUNCATE control_plane.{table}"))
                        self.assertEqual(raised.exception.orig.args[0]["C"], "23514")
                run_migrations(settings, "base", upgrade=False)
                with engine.connect() as conn:
                    self.assertIsNone(conn.scalar(text("SELECT to_regnamespace('control_plane')")))
            finally:
                engine.dispose()

    def test_cli_grant_runtime_is_explicit_idempotent_and_not_migration(self):
        from sqlalchemy.engine import make_url
        with runtime_database() as (admin_url, runtime_url):
            role = make_url(runtime_url).username
            result = database_command(admin_url, "grant-runtime", role)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("runtime_permissions_granted", result.stdout)
            result = database_command(runtime_url, "upgrade")
            self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
            self.assertNotIn(runtime_url, result.stdout + result.stderr)
