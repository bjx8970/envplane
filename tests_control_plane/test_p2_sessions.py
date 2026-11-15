from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import replace
import threading
import time
from types import SimpleNamespace
import unittest
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from control_plane.config import COORDINATOR_LOCK_KEY
from control_plane.coordination import CoordinatorLease
from control_plane.persistence import admit_job
from control_plane.plugins.sdk import AuthorizationDenied, Deadline, PluginError, PreparedCall, SessionOpenResult
from control_plane.plugins.sessions import (OpeningNotEstablished, OpeningPlan, RepositoryOpeningAdapter, SessionConflict,
    SessionService, SessionStore, validate_client_frame, validate_server_frame)
from control_plane.plugins.capacity import CapacitySettings, CapacitySupervisor
from control_plane.plugins.context import RuntimeContext
from control_plane.execution.repository import Repository
from control_plane.execution.adapters import Projection
from tests_control_plane.p1_harness import migrated_database
from tests_control_plane.pg_harness import engine_for
from tests_control_plane.test_p1_schema import insert, job_arguments, operation_arguments


class DeferredCapacity:
    """No worker until tests explicitly drive the bounded receive loop."""
    def __init__(self):
        self.calls = []
    def submit(self, instance_id, fn, **kwargs):
        future = Future()
        self.calls.append((instance_id, fn, kwargs, future))
        return future


class FakeTransport:
    def __init__(self):
        self.sent, self.sizes, self.closed = [], [], []
        self.events = []
        self.confirm_close = True
        self.receiving = threading.Event()
    def send(self, handle, frame, *, deadline):
        deadline.check()
        self.sent.append(dict(frame))
    def resize(self, handle, size, *, deadline):
        deadline.check()
        self.sizes.append(size)
    def receive(self, handle, *, deadline):
        self.receiving.set()
        if self.events:
            return self.events.pop(0)
        time.sleep(min(.005, deadline.check()))
        return None
    def close_session(self, handle, reason, *, deadline):
        deadline.check()
        self.closed.append(reason)
        return {"channel_closed": self.confirm_close}


class MemoryStore:
    def __init__(self):
        self.rows, self.audits = {}, []
        self.touches = 0
        self.lock = threading.RLock()
    def get(self, session_id):
        with self.lock:
            return dict(self.rows[str(session_id)])
    def create(self, session_id, plan):
        self.rows[session_id] = {"id": session_id, "environment_id": plan.environment_id,
            "resource_id": plan.resource_id, "job_id": plan.job_id, "open_operation_id": plan.operation_id,
            "actor_id": plan.actor_id, "plugin_instance_id": plan.plugin_instance_id,
            "template_entry": plan.template_entry, "state": "opening", "controller_id": plan.actor_id,
            "controller_revision": 0, "session_type": plan.session_type}
    def transition(self, session_id, previous, state, reason=None, actor_id=None):
        with self.lock:
            row = self.rows[str(session_id)]
            if row["state"] != previous:
                raise SessionConflict()
            row["state"] = state
            row["reason"] = reason
            return dict(row)
    def controller(self, session_id, actor_id, expected_revision, controller_id, action):
        with self.lock:
            row = self.rows[str(session_id)]
            if row["state"] != "active" or row["controller_revision"] != expected_revision or row["controller_id"] == controller_id:
                raise SessionConflict()
            row["controller_id"], row["controller_revision"] = controller_id, expected_revision + 1
            self.audits.append((actor_id, action))
            return dict(row)
    def audit(self, row, actor_id, action):
        self.audits.append((actor_id, action))
    def touch(self, session_id):
        self.touches += 1
    def disconnect_on_restart(self, *, limit=100, deadline=None, before=None):
        result = []
        for row in list(self.rows.values()):
            if row["state"] in ("opening", "active", "closing"):
                result.append(dict(row))
                self.transition(row["id"], row["state"], "disconnected", "process_restart")
        return result


class FakeOpening:
    def __init__(self, plan):
        self.plan, self.unknowns = plan, []
        self.error = None
    def prepare(self, request):
        return self.plan
    def dispatch(self, plan):
        if self.error:
            raise self.error
        return SessionOpenResult(object())
    def unknown(self, operation_id, reason):
        self.unknowns.append((operation_id, reason))


class SessionProtocolTests(unittest.TestCase):
    def make(self, **limits):
        self.transport, self.store, self.capacity = FakeTransport(), MemoryStore(), DeferredCapacity()
        self.denied, self.checks = set(), []
        def authorize(actor_id, environment_id, action, **context):
            self.checks.append((actor_id, action))
            return (actor_id, action) not in self.denied
        self.authorize = authorize
        plan = OpeningPlan("operation", "job", "environment", "student", "instance", "secret-v1", "terminal-entry",
                           PreparedCall("terminal"), self.transport, SimpleNamespace(deadline=Deadline.after(10)))
        self.opening = FakeOpening(plan)
        self.service = SessionService(None, None, self.capacity, store=self.store,
                                      authorizer=authorize, opening_adapter=self.opening, **limits)
        self.service.start()
        self.row = self.service.open({})
        self.sid = self.row["id"]
        self.live = self.service._live[self.sid]
        return self.service

    def test_explicit_lifecycle_independent_receiver_and_memory_only_handle(self):
        self.make()
        self.assertEqual(self.row["state"], "active")
        self.assertNotIn("handle", self.row)
        self.assertEqual(self.capacity.calls[0][2]["lane"], "session")
        self.assertLess(self.capacity.calls[0][2]["deadline_at"].timestamp() - time.time(), 86401)
        self.service.stop(grace=0)
        self.assertEqual(self.store.get(self.sid)["state"], "disconnected")
        self.assertFalse(self.capacity.calls[0][3].done(), "stopping must not fake receiver exit")
        with self.assertRaises(PluginError):
            self.service.open({})

    def test_missing_authorization_adapter_fails_closed_for_every_boundary(self):
        self.make()
        client = self.service.observe("student", self.sid)
        self.service.authorizer = None
        for invoke in (lambda: self.service.frame("student", self.sid, {"type": "input", "data": "x", "epoch": 0}),
                       lambda: self.service.frame("student", self.sid, {"type": "resize", "cols": 80, "rows": 24, "epoch": 0}),
                       lambda: self.service.poll_output("student", self.sid, client),
                       lambda: self.service.observe("student", self.sid, reconnect=True),
                       lambda: self.service.takeover("teacher", self.sid, 0),
                       lambda: self.service.close("student", self.sid)):
            with self.assertRaises(AuthorizationDenied):
                invoke()

    def test_observer_readonly_takeover_cas_epoch_drops_pending_old_input(self):
        self.make()
        self.service.observe("teacher", self.sid)
        self.service.frame("student", self.sid, {"type": "input", "data": "old-pending", "epoch": 0})
        with self.assertRaises(SessionConflict):
            self.service.frame("teacher", self.sid, {"type": "input", "data": "observer", "epoch": 0})
        row = self.service.takeover("teacher", self.sid, 0)
        self.assertEqual(row["controller_revision"], 1)
        self.service._drain_one(self.sid, self.live)
        self.assertEqual(self.transport.sent, [])
        with self.assertRaises(SessionConflict):
            self.service.frame("student", self.sid, {"type": "input", "data": "stale", "epoch": 0})
        with self.assertRaises(SessionConflict):
            self.service.takeover("other-teacher", self.sid, 0)
        self.service.frame("teacher", self.sid, {"type": "input", "data": "new", "epoch": 1})
        self.service._drain_one(self.sid, self.live)
        self.assertEqual([frame["data"] for frame in self.transport.sent], ["new"])
        row = self.service.release("teacher", self.sid, 1)
        self.assertEqual((row["controller_id"], row["controller_revision"]), ("student", 2))
        self.assertIn(("teacher", "takeover"), self.store.audits)
        self.assertIn(("teacher", "release"), self.store.audits)

    def test_takeover_serializes_actual_send_not_just_enqueue(self):
        self.make()
        sending, allow_send, takeover_done = threading.Event(), threading.Event(), threading.Event()
        def slow_send(handle, frame, *, deadline):
            sending.set()
            self.assertTrue(allow_send.wait(1))
            self.transport.sent.append(frame)
        self.transport.send = slow_send
        self.service.frame("student", self.sid, {"type": "input", "data": "in-flight", "epoch": 0})
        def takeover():
            row = self.service.takeover("teacher", self.sid, 0)
            takeover_done.set()
            return row
        with ThreadPoolExecutor(max_workers=2) as pool:
            old = pool.submit(self.service._drain_one, self.sid, self.live)
            self.assertTrue(sending.wait(1))
            new = pool.submit(takeover)
            self.assertFalse(takeover_done.wait(.02))
            allow_send.set()
            old.result(1)
            self.assertEqual(new.result(1)["controller_revision"], 1)
        self.assertEqual(len(self.transport.sent), 1)

    def test_queued_input_reauthorizes_before_forwarding(self):
        self.make()
        self.service.frame("student", self.sid, {"type": "input", "data": "queued", "epoch": 0})
        self.denied.add(("student", "session.input"))
        with self.assertRaises(AuthorizationDenied):
            self.service._drain_one(self.sid, self.live)
        self.assertEqual(self.transport.sent, [])

    def test_output_replay_reconnect_reauthorize_and_never_resend_input(self):
        self.make()
        client = self.service.observe("student", self.sid)
        self.service._publish(self.sid, self.live, {"type": "output", "data": "first"})
        frames = self.service.poll_output("student", self.sid, client)
        self.assertEqual(frames[0]["seq"], 1)
        reconnected = self.service.observe("student", self.sid, reconnect=True, after_seq=0)
        self.assertEqual(self.service.poll_output("student", self.sid, reconnected), frames)
        self.assertEqual(self.transport.sent, [])
        self.denied.add(("student", "session.replay"))
        with self.assertRaises(AuthorizationDenied):
            self.service.observe("student", self.sid, reconnect=True, after_seq=0)
        self.denied.add(("student", "session.output"))
        self.service._publish(self.sid, self.live, {"type": "output", "data": "revoked"})
        self.assertTrue(self.live.clients[client].disconnected)
        self.assertEqual(self.live.clients[client].bytes, 0)
        with self.assertRaises(AuthorizationDenied):
            self.service.poll_output("student", self.sid, client)

    def test_bounded_input_output_replay_and_slow_consumer_disconnect(self):
        self.make(input_bytes=100, output_bytes=100, replay_bytes=100)
        client = self.service.observe("student", self.sid)
        self.service.frame("student", self.sid, {"type": "input", "data": "a" * 30, "epoch": 0})
        with self.assertRaises(PluginError):
            self.service.frame("student", self.sid, {"type": "input", "data": "b" * 30, "epoch": 0})
        for _ in range(10):
            self.service._publish(self.sid, self.live, {"type": "output", "data": "x" * 30})
        self.assertLessEqual(self.live.replay_bytes, 100)
        self.assertTrue(self.live.clients[client].disconnected)
        self.assertEqual(self.live.clients[client].bytes, 0)
        with self.assertRaises(SessionConflict):
            self.service.poll_output("student", self.sid, client)
        with self.assertRaises(PluginError):
            self.service.observe("teacher", self.sid, after_seq=0)

    def test_strict_frame_schema_size_sequence_and_dimensions(self):
        for frame in ({"type": "unknown"}, {"type": "input", "data": "x", "epoch": True},
                      {"type": "input", "data": "x", "epoch": 0, "extra": 1},
                      {"type": "resize", "cols": 0, "rows": 24, "epoch": 0},
                      {"type": "close", "reason": 42}):
            with self.assertRaises((PluginError, ValueError)):
                validate_client_frame(frame)
        with self.assertRaises(ValueError):
            validate_client_frame({"type": "input", "data": "x" * 20000, "epoch": 0})
        with self.assertRaises(PluginError):
            validate_server_frame({"type": "output", "seq": 0, "data": "x"})
        self.make(max_frame_bytes=256)
        with self.assertRaises(ValueError):
            self.service._publish(self.sid, self.live, {"type": "output", "data": "x" * 300})

    def test_close_confirms_only_channel_and_idle_has_finite_policy(self):
        for confirmed in (True, False):
            with self.subTest(confirmed=confirmed):
                self.make(idle_seconds=.01)
                self.transport.confirm_close = confirmed
                self.live.last_activity -= 1
                self.service._receive_loop(self.sid, self.live)
                self.assertEqual(self.store.get(self.sid)["state"], "closed" if confirmed else "disconnected")
                self.assertEqual(len(self.transport.closed), 1)
        self.make()
        self.service.close("student", self.sid)
        self.assertEqual(self.store.get(self.sid)["state"], "closing")
        self.service._receive_loop(self.sid, self.live)
        self.assertEqual(self.store.get(self.sid)["state"], "closed")

    def test_restart_disconnects_and_opening_unknown_is_not_failed(self):
        self.make()
        opening_id = str(uuid4())
        self.store.create(opening_id, self.opening.plan)
        self.service.stop(grace=0)
        # Simulate a process that died before shutdown touched its opening row.
        self.store.rows[opening_id]["state"] = "opening"
        service = SessionService(None, None, self.capacity, store=self.store,
                                 authorizer=self.authorize, opening_adapter=self.opening)
        service.start()
        self.assertEqual(self.store.get(opening_id)["state"], "disconnected")
        self.assertIn(("operation", "process_restart"), self.opening.unknowns)
        self.assertEqual(service._live, {})

    def test_open_error_unknown_unless_adapter_proves_not_established(self):
        for error, expected in ((RuntimeError("transport failure"), "disconnected"),
                                (OpeningNotEstablished("not_established"), "failed")):
            with self.subTest(expected=expected):
                self.make()
                self.opening.error = error
                with self.assertRaises(type(error)):
                    self.service.open({})
                states = [row["state"] for row in self.store.rows.values()]
                self.assertIn(expected, states)

    def test_noisy_remote_output_does_not_extend_client_idle(self):
        self.make(idle_seconds=.02, receive_wait=.01)
        original = self.live.last_activity
        def noisy(handle, *, deadline):
            time.sleep(.002)
            return {"type": "output", "data": "still running"}
        self.transport.receive = noisy
        start = time.monotonic()
        self.service._receive_loop(self.sid, self.live)
        self.assertLess(time.monotonic() - start, .5)
        self.assertGreater(self.live.seq, 0)
        self.assertEqual(self.live.last_activity, original)
        self.assertEqual(self.store.touches, 0)
        self.assertEqual(self.store.get(self.sid)["state"], "closed")

    def test_client_input_and_resize_refresh_idle_only_after_authorization(self):
        self.make(idle_seconds=.01)
        self.live.last_activity -= 1
        before = self.live.last_activity
        self.service.frame("student", self.sid, {"type": "resize", "cols": 90, "rows": 25, "epoch": 0})
        self.assertGreater(self.live.last_activity, before)
        self.service._drain_one(self.sid, self.live)
        self.assertEqual(self.transport.sizes, [{"cols": 90, "rows": 25}])
        self.assertEqual(self.store.touches, 1)
        before = self.live.last_activity
        self.denied.add(("student", "session.input"))
        with self.assertRaises(AuthorizationDenied):
            self.service.frame("student", self.sid, {"type": "input", "data": "denied", "epoch": 0})
        self.assertEqual(self.live.last_activity, before)

    def test_quiesce_stops_forwarding_before_metadata_write_or_receiver_exit(self):
        self.make()
        client = self.service.observe("student", self.sid)
        def lost(*args, **kwargs):
            raise RuntimeError("coordinator lost")
        self.store.transition = lost
        self.service.quiesce()
        self.assertTrue(self.live.stop.is_set())
        self.assertFalse(self.live.receiver.done())
        self.service.stop(grace=0)
        with self.assertRaises(PluginError):
            self.service.poll_output("student", self.sid, client)
        with self.assertRaises(PluginError):
            self.service.frame("student", self.sid, {"type": "input", "data": "late", "epoch": 0})
        before = self.live.seq
        self.service._publish(self.sid, self.live, {"type": "output", "data": "late"})
        self.assertEqual(self.live.seq, before)

    def test_stop_during_opening_cannot_attach_late_handle_or_restart_receive(self):
        self.make()
        entered, proceed = threading.Event(), threading.Event()
        def slow_open(plan):
            entered.set()
            self.assertTrue(proceed.wait(1))
            return SessionOpenResult(object())
        self.opening.dispatch = slow_open
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.service.open, {})
            self.assertTrue(entered.wait(1))
            self.service.stop(grace=0)
            proceed.set()
            with self.assertRaises(PluginError):
                future.result(1)
        self.assertTrue(all(row["state"] == "disconnected" for row in self.store.rows.values()))
        self.assertEqual(self.service._pending, {})

    def test_excessive_or_nonfinite_session_limits_are_rejected(self):
        for name, value in (("close_seconds", 1e300), ("receive_wait", 31), ("idle_seconds", 86401),
                            ("lifetime_seconds", 86401), ("max_clients", 129), ("max_sessions", 1025),
                            ("input_bytes", 4194305), ("recovery_batch", 101), ("recovery_batch", 1.5),
                            ("startup_seconds", float("inf")), ("recovery_seconds", 6)):
            with self.subTest(name=name), self.assertRaises(ValueError):
                SessionService(None, None, DeferredCapacity(), store=MemoryStore(), **{name: value})

    def test_instance_session_and_observer_capacity_are_finite(self):
        self.make(max_sessions=1, max_clients=1)
        with self.assertRaises(PluginError):
            self.service.open({})
        self.service.observe("student", self.sid)
        with self.assertRaises(PluginError):
            self.service.observe("teacher", self.sid)


class SessionPostgreSQLTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.url = cls.enterClassContext(migrated_database())
        cls.engine = engine_for(cls.url)
        cls.addClassCleanup(cls.engine.dispose)

    def setUp(self):
        self.lease = CoordinatorLease(self.engine, COORDINATOR_LOCK_KEY)
        self.assertTrue(self.lease.acquire())
        self.addCleanup(self.lease.release)
        with self.lease.fenced_transaction() as connection:
            arguments = job_arguments(connection)
            job_id, _ = admit_job(connection, **arguments)
            step = insert(connection, "job_steps", job_id=job_id, step_path="access.terminal", item_key="")
            operation = operation_arguments(connection, job_id, step)
            operation_id = insert(connection, "operations", **operation)
            secret = insert(connection, "secrets", purpose="environment", environment_id=arguments["environment_id"])
            secret_version = insert(connection, "secret_versions", secret_id=secret, version=1,
                                    ciphertext=b"test-only-ciphertext", encryption_key_id="test-only-key")
            connection.execute(text("INSERT INTO control_plane.job_secret_refs(job_id,plugin_instance_id,secret_version_id) VALUES (:job,:instance,:version)"),
                               {"job": job_id, "instance": operation["plugin_instance_id"], "version": secret_version})
            self.teacher = insert(connection, "users", username=uuid4().hex, role="teacher", password_hash="test")
            self.other_teacher = insert(connection, "users", username=uuid4().hex, role="teacher", password_hash="test")
        self.actor = arguments["actor_id"]
        self.plan = OpeningPlan(str(operation_id), str(job_id), str(arguments["environment_id"]), str(self.actor),
            str(operation["plugin_instance_id"]), str(secret_version), "published-terminal-entry",
            PreparedCall("terminal", target_ref={"opaque": "fixed"}), FakeTransport(), SimpleNamespace(deadline=Deadline.after(10)))
        self.store = SessionStore(self.engine, self.lease)
        self.sid = str(uuid4())
        self.store.create(self.sid, self.plan)

    def test_metadata_default_schema_fixed_identity_and_no_handle(self):
        row = self.store.get(self.sid)
        self.assertEqual(row["session_type"], "terminal")
        self.assertEqual(row["controller_revision"], 0)
        self.assertIsNotNone(row["last_activity_at"].tzinfo)
        self.assertEqual(row["target_ref"], {"opaque": "fixed"})
        self.assertNotIn("session_handle", row)
        with self.assertRaises(DBAPIError):
            with self.lease.fenced_transaction() as connection:
                connection.execute(text("UPDATE control_plane.interactive_sessions SET target_ref='{}'::jsonb WHERE id=:id"), {"id": self.sid})

    def test_concurrent_controller_cas_has_one_winner_and_transactional_audit(self):
        self.store.transition(self.sid, "opening", "active")
        def takeover(actor):
            try:
                return self.store.controller(self.sid, actor, 0, actor, "takeover")["controller_revision"]
            except SessionConflict:
                return "conflict"
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(takeover, (self.teacher, self.other_teacher)))
        self.assertEqual(sorted(map(str, results)), ["1", "conflict"])
        row = self.store.get(self.sid)
        self.assertEqual(row["controller_revision"], 1)
        with self.engine.connect() as connection:
            count = connection.scalar(text("SELECT count(*) FROM control_plane.audit_events WHERE operation_id=:operation AND action='session.takeover'"), {"operation": self.plan.operation_id})
        self.assertEqual(count, 1)

    def test_failed_cas_and_rollback_do_not_mutate_control_or_audit(self):
        self.store.transition(self.sid, "opening", "active")
        with self.assertRaises(SessionConflict):
            self.store.controller(self.sid, self.teacher, 8, self.teacher, "takeover")
        row = self.store.get(self.sid)
        self.assertEqual(row["controller_revision"], 0)
        self.assertEqual(str(row["controller_id"]), str(self.actor))
        with self.assertRaises(DBAPIError):
            # Invalid controller FK causes the entire update+audit transaction to fail.
            self.store.controller(self.sid, self.teacher, 0, uuid4(), "takeover")
        self.assertEqual(self.store.get(self.sid)["controller_revision"], 0)
        with self.engine.connect() as connection:
            self.assertEqual(connection.scalar(text("SELECT count(*) FROM control_plane.audit_events WHERE operation_id=:op AND action='session.takeover'"), {"op": self.plan.operation_id}), 0)

    def test_database_prevents_epoch_bypass_and_illegal_terminal_revival(self):
        self.store.transition(self.sid, "opening", "active")
        with self.assertRaises(DBAPIError):
            with self.lease.fenced_transaction() as connection:
                connection.execute(text("UPDATE control_plane.interactive_sessions SET controller_id=:actor WHERE id=:id"), {"id": self.sid, "actor": self.teacher})
        self.store.transition(self.sid, "active", "closing")
        self.store.transition(self.sid, "closing", "closed", "channel_confirmed")
        with self.assertRaises(DBAPIError):
            with self.lease.fenced_transaction() as connection:
                connection.execute(text("UPDATE control_plane.interactive_sessions SET state='active' WHERE id=:id"), {"id": self.sid})

    def test_service_fake_transport_pg_metadata_and_revoked_queued_input(self):
        self.store.transition(self.sid, "opening", "disconnected", "fixture_unused")
        capacity, denied = DeferredCapacity(), set()
        authorizer = lambda actor, env, action, **kw: (actor, action) not in denied
        opening = FakeOpening(self.plan)
        service = SessionService(self.engine, self.lease, capacity, authorizer=authorizer,
                                 opening_adapter=opening, receive_wait=.01)
        service.start()
        row = service.open({})
        sid = str(row["id"])
        live = service._live[sid]
        service.frame(self.actor, sid, {"type": "input", "data": "queued-not-persisted", "epoch": 0})
        service.takeover(self.teacher, sid, 0)
        service._drain_one(sid, live)
        self.assertEqual(self.plan.plugin.sent, [])
        observer = service.observe(self.teacher, sid)
        service._publish(sid, live, {"type": "output", "data": "opaque output"})
        self.assertEqual(service.poll_output(self.teacher, sid, observer)[0]["type"], "output")
        denied.add((str(self.teacher), "session.output"))
        with self.assertRaises(AuthorizationDenied):
            service.poll_output(self.teacher, sid, observer)
        service.stop(grace=0)
        self.assertEqual(self.store.get(sid)["state"], "disconnected")

    def _repository_service(self, *, fail_application=False, fail_open=None):
        runtime = SimpleNamespace(fenced_transaction=self.lease.fenced_transaction,
            coordinator_identity=(str(self.lease.owner_id), self.lease.revision))
        # Explicit trusted Fake reference/source policies; no production implicit
        # allow is installed by RepositoryOpeningAdapter.
        repository = Repository(runtime, reference_validator=lambda *a, **k: None,
                                source_publisher=lambda *a, **k: None, safe_json=lambda value: value)
        job_lease = repository.claim("session-opening-test", instance_ids=[self.plan.plugin_instance_id])
        self.assertEqual(str(job_lease.job_id), self.plan.job_id)
        with self.lease.fenced_transaction() as connection:
            step = insert(connection, "job_steps", job_id=job_lease.job_id, step_path="access.real_open", item_key="")
        repository.start_prepare(job_lease, step, 10)
        operation = repository.commit_prepared(job_lease, step, self.plan.prepared_call, self.plan.plugin_instance_id)
        context = RuntimeContext(self.plan.plugin_instance_id, self.plan.environment_id, self.plan.job_id,
            str(step), str(operation["id"]), operation["invocation_key"], str(job_lease.token),
            Deadline.after(5), {}, None, None, None, None, None, None, None)
        plan = replace(self.plan, operation_id=str(operation["id"]), context=context)
        observations = []
        def open_session(prepared, ctx):
            ctx.deadline.check()
            with self.engine.connect() as connection:
                op = connection.execute(text("SELECT state,dispatch_intent_at FROM control_plane.operations WHERE id=:id"), {"id": plan.operation_id}).one()
                row = connection.execute(text("SELECT state FROM control_plane.interactive_sessions WHERE open_operation_id=:id"), {"id": plan.operation_id}).one()
                observations.append((op.state, op.dispatch_intent_at is not None, row.state))
            if fail_open is not None:
                raise fail_open
            return SessionOpenResult(object(), {"opaque": "external-session"})
        plan.plugin.open_session = open_session
        class Projector:
            def project(self, operation, result):
                return Projection()
        class Applicator:
            def apply(self, uow, operation, projection):
                if fail_application:
                    raise RuntimeError("injected local application failure")
        capacity = CapacitySupervisor(CapacitySettings(ordinary_workers=1, control_workers=1,
            session_workers=1, queue_limit=2, instance_limit=1, shutdown_grace_seconds=.2))
        capacity.start()
        self.addCleanup(capacity.stop, .2)
        adapter = RepositoryOpeningAdapter(repository, capacity, prepare_plan=lambda request: (plan, job_lease),
                                            projector=Projector(), applicator=Applicator())
        service = SessionService(self.engine, self.lease, capacity, authorizer=lambda *a, **k: True,
                                 opening_adapter=adapter, receive_wait=.01, close_seconds=.2)
        service.start()
        self.addCleanup(service.stop, .2)
        return service, plan, repository, job_lease, observations

    def test_opening_repository_commits_intent_and_success_with_active_atomically(self):
        service, plan, repository, job_lease, observations = self._repository_service()
        row = service.open({})
        self.assertEqual(row["state"], "active")
        self.assertEqual(observations, [("running", True, "opening")])
        with self.engine.connect() as connection:
            operation = connection.execute(text("SELECT state,output FROM control_plane.operations WHERE id=:id"), {"id": plan.operation_id}).one()
            evidence = list(connection.scalars(text("SELECT data FROM control_plane.operation_evidence WHERE operation_id=:id"), {"id": plan.operation_id}))
        self.assertEqual((operation.state, operation.output), ("succeeded", {}))
        self.assertTrue(evidence)
        self.assertNotIn("session_handle", str(evidence))
        self.assertNotIn("object at", str(evidence))
        self.assertEqual(service.store.get(row["id"])["state"], "active")

    def test_opening_local_application_rollback_keeps_unknown_not_false_success(self):
        service, plan, repository, job_lease, observations = self._repository_service(fail_application=True)
        with self.assertRaises(RuntimeError):
            service.open({})
        with self.engine.connect() as connection:
            row = connection.execute(text("SELECT o.state AS operation_state,s.state AS session_state FROM control_plane.operations o JOIN control_plane.interactive_sessions s ON s.open_operation_id=o.id WHERE o.id=:id"), {"id": plan.operation_id}).one()
        self.assertEqual((row.operation_state, row.session_state), ("unknown", "disconnected"))
        self.assertTrue(plan.plugin.closed, "obtained but unattached handle must be closed cooperatively")

    def test_opening_transport_proven_failure_and_uncertain_failure_are_distinct(self):
        service, plan, repository, job_lease, observations = self._repository_service(
            fail_open=OpeningNotEstablished("not_established"))
        with self.assertRaises(OpeningNotEstablished):
            service.open({})
        with self.engine.connect() as connection:
            row = connection.execute(text("SELECT o.state AS operation_state,s.state AS session_state FROM control_plane.operations o JOIN control_plane.interactive_sessions s ON s.open_operation_id=o.id WHERE o.id=:id"), {"id": plan.operation_id}).one()
        self.assertEqual((row.operation_state, row.session_state), ("failed", "failed"))

    def test_new_coordinator_marks_unattached_dispatched_opening_unknown(self):
        service, plan, repository, job_lease, observations = self._repository_service()
        interrupted = str(uuid4())
        service.store.create(interrupted, plan)
        repository.begin_call(job_lease, plan.operation_id, "execute", 5)
        self.assertFalse(repository.recover_opening_unknown(plan.operation_id),
                         "same-generation live opener cannot be stolen")
        self.lease.release()
        new_lease = CoordinatorLease(self.engine, COORDINATOR_LOCK_KEY)
        self.assertTrue(new_lease.acquire())
        self.addCleanup(new_lease.release)
        runtime = SimpleNamespace(fenced_transaction=new_lease.fenced_transaction,
            coordinator_identity=(str(new_lease.owner_id), new_lease.revision))
        recovered_repository = Repository(runtime)
        adapter = SimpleNamespace(unknown=recovered_repository.recover_opening_unknown)
        restarted = SessionService(self.engine, new_lease, DeferredCapacity(), authorizer=lambda *a, **k: True,
                                   opening_adapter=adapter)
        restarted.start()
        self.addCleanup(restarted.stop, 0)
        with self.engine.connect() as connection:
            row = connection.execute(text("SELECT o.state AS operation_state,s.state AS session_state,j.state AS job_state FROM control_plane.operations o JOIN control_plane.interactive_sessions s ON s.open_operation_id=o.id JOIN control_plane.jobs j ON j.id=o.job_id WHERE s.id=:id"), {"id": interrupted}).one()
        self.assertEqual((row.operation_state, row.session_state, row.job_state), ("unknown", "disconnected", "blocked"))
        self.assertEqual(observations, [], "recovery must not call open_session again")

    def test_restart_recovery_pages_are_bounded_and_never_disconnect_new_sessions(self):
        for _ in range(2):
            self.store.create(str(uuid4()), self.plan)
        service = SessionService(self.engine, self.lease, DeferredCapacity(), authorizer=lambda *a, **k: True,
                                 opening_adapter=FakeOpening(self.plan), recovery_batch=1)
        service.start()
        self.addCleanup(service.stop, 0)
        with self.engine.connect() as connection:
            remaining = connection.scalar(text("SELECT count(*) FROM control_plane.interactive_sessions WHERE open_operation_id=:op AND state='opening'"), {"op": self.plan.operation_id})
        self.assertEqual(remaining, 2)
        new_session = str(uuid4())
        self.store.create(new_session, self.plan)
        self.store.transition(new_session, "opening", "active")
        service.poll()
        service.poll()
        self.assertEqual(self.store.get(self.sid)["state"], "disconnected")
        self.assertEqual(self.store.get(new_session)["state"], "active")
        self.assertEqual(len(list(self.store.disconnect_on_restart(limit=1))), 1)
        with self.assertRaises(ValueError):
            list(self.store.disconnect_on_restart(limit=101))

    def test_restart_disconnect_persists_reason_but_not_remote_stopped(self):
        rows = list(self.store.disconnect_on_restart())
        original = next(row for row in rows if str(row["id"]) == self.sid)
        self.assertEqual(original["state"], "opening")
        row = self.store.get(self.sid)
        self.assertEqual(row["state"], "disconnected")
        self.assertEqual(row["reason"], {"code": "process_restart"})
        self.assertIsNotNone(row["closed_at"])


if __name__ == "__main__":
    unittest.main()
