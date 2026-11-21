"""Real low-privilege PostgreSQL + registry/context/capacity/driver integration.

Only Fake P3 business policy lives here. All waits and tick counts are finite;
these tests never connect to vendors or create a test dependency environment.
"""
import copy
from threading import Event
from uuid import uuid4
import unittest

from sqlalchemy import text

from control_plane.config import RuntimeSettings
from control_plane.execution import (Repository, ExecutionDriver, DriverSettings,
    JobLeaseLost, Projection, LocalOutcomeApplicator, admit_request)
from control_plane.persistence import admit_job, RequestConflict
from control_plane.plugins.capacity import CapacitySupervisor, CapacitySettings
from control_plane.plugins.configuration import ConfigurationService
from control_plane.plugins.context import ContextBuilder
from control_plane.plugins.registry import PluginRegistry
from control_plane.plugins.sdk import (PreparedCall, ExecutionResult, ExecutionPolicy,
    SecretRef, Deadline)
from control_plane.plugins.secrets import SecretService
from control_plane.plugins.storage import StorageService
from control_plane.runtime import ControlPlaneRuntime
from tests_control_plane.p1_harness import runtime_database
from tests_control_plane.pg_harness import engine_for
from tests_control_plane.test_p1_schema import graph, insert
from tests_control_plane.test_p2_execution import FakeLifecycle, FakeQuota


MANIFEST = {
    "manifest_version": 1, "api_version": "1", "plugin_key": "driver-fake",
    "plugin_version": "1.0.0", "display_name": "Test only", "entrypoint": "test:DriverFake",
    "actions": {"run": {"display_name": "Run", "input_schema": {"type": "object"},
        "output_schema": {"type": "object", "additionalProperties": False,
            "properties": {"phase": {"type": "string"}, "host": {"type": "string"},
                "config": {"type": "string"}, "secret_version": {"type": "string"}},
            "required": ["phase", "host", "config", "secret_version"]},
        "execution": {"effect": "mutating", "idempotency": "unsupported",
            "recovery": "unsupported", "cancellation": "unsupported"}}},
}


class DriverFake:
    def __init__(self):
        self.outcome = "succeeded"
        self.invalid_output = False
        self.execute_count = 0
        self.reads = []
        self.passwords = []
        self.b_entered = Event()
        self.b_release = Event()

    def describe(self):
        return copy.deepcopy(MANIFEST)

    def prepare(self, action_key, input, context):
        if input["phase"] == "B":
            self.b_entered.set()
            if not self.b_release.wait(5):
                raise TimeoutError("finite test synchronization budget exhausted")
        host = context.storage.get("hosts/main")
        ref = context.secrets.resolve(SecretRef(input["secret_id"]))
        resolved = {"phase": input["phase"], "host": host.value["address"],
                    "config": context.configuration["marker"], "secret_version": ref.version_id}
        self.reads.append(resolved)
        return PreparedCall(action_key, resolved_input=resolved,
            target_ref={"host": host.value["address"]}, storage_refs=(host.ref,), secret_refs=(ref,))

    def execute(self, prepared_call, context):
        self.execute_count += 1
        with context.secrets.get(prepared_call.secret_refs[0]) as handle:
            self.passwords.append(handle.reveal())
        if self.outcome == "unknown":
            return ExecutionResult("unknown")
        return ExecutionResult("succeeded", {"bad": "schema"} if self.invalid_output else dict(prepared_call.resolved_input))


class FakePlanner:
    def __init__(self, instance, secret, phases):
        self.instance, self.secret, self.phases = instance, secret, phases

    def plan(self, snapshot, confirmed_outputs):
        return [{"step_path": phase, "input": {"plugin_instance_id": str(self.instance),
            "action_key": "run", "input": {"phase": phase, "secret_id": self.secret},
            "depends_on": [] if phase == "A" else ["A"]}} for phase in self.phases]


class FakeProjection:
    def __init__(self, last_phase):
        self.last_phase = last_phase

    def project(self, operation, result):
        phase = result.output["phase"]
        complete = phase == self.last_phase
        return Projection(create_results={phase: result.output},
            resources=({"resource_slot": phase, "name": phase, "type_label": "test",
                        "data": result.output, "target_ref": operation["prepared_call"]["target_ref"]},),
            job_complete=complete, release_conflicts=complete, lifecycle="ready" if complete else None)


class FakeAdmission:
    """Test-only P3 adapter demonstrates atomic fixed admission, not real auth."""
    def __init__(self, case):
        self.case = case
        self.calls = 0
        self.fail_after_bind = False

    def authorize_and_reserve(self, uow, fixed_request):
        self.calls += 1
        case = self.case
        capture = case.configuration.capture_in(uow, case.instance, case.secrets, case.environment)
        execution_snapshot = {"plugins": {str(case.instance): capture}, "workflow": "test-fixed"}
        job, replay = admit_job(uow, actor_id=case.actor, request_key=fixed_request["request_key"],
            request_digest=fixed_request["request_digest"], environment_id=case.environment,
            execution_group_id=case.group, logical_invocation_id=uuid4(), kind="create", input={},
            execution_snapshot=execution_snapshot)
        if replay:
            raise AssertionError("outer request lock must dedupe before policy")
        case.configuration.bind_capture_in(uow, job, case.instance, capture, case.secrets)
        if self.fail_after_bind:
            uow.scalar(text("SELECT 1/0"))
        # The real P3 adapter must perform business authorization and teacher
        # limit arithmetic before this INSERT; this fixture has only one request.
        uow.execute(text("SELECT teacher_id FROM control_plane.teacher_quotas WHERE teacher_id=:actor FOR UPDATE"), {"actor": case.actor})
        uow.execute(text("INSERT INTO control_plane.quota_reservations(job_id,environment_id,teacher_id,environments,vms,vcpu,memory_mb) VALUES (:job,:env,:actor,1,0,0,0)"),
                    {"job": job, "env": case.environment, "actor": case.actor})
        uow.execute(text("INSERT INTO control_plane.conflict_protections(scope_key,execution_group_id) VALUES (:scope,:group)"),
                    {"scope": "environment:" + str(case.environment), "group": case.group})
        return job


class DriverIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin_url, cls.runtime_url = cls.enterClassContext(runtime_database())
        cls.admin_engine, cls.engine = engine_for(cls.admin_url), engine_for(cls.runtime_url)
        cls.addClassCleanup(cls.admin_engine.dispose)
        cls.addClassCleanup(cls.engine.dispose)

    def setUp(self):
        self.runtime = ControlPlaneRuntime(RuntimeSettings.from_env({"CONTROL_PLANE_DATABASE_URL": self.runtime_url}))
        self.runtime.start()
        self.addCleanup(self.runtime.stop)
        self.fake = DriverFake()
        self.addCleanup(self.fake.b_release.set)
        self.registry = PluginRegistry()
        self.registry.register(self.fake, MANIFEST, code_digest="driver-fake-v1")
        self.secrets = SecretService(self.engine, self.runtime, {"test": b"k" * 32}, "test")
        self.configuration = ConfigurationService(self.engine, self.runtime, self.registry, safe_json=self.secrets.safe_json)
        self.storage = StorageService(self.engine, self.runtime, safe_json=self.secrets.safe_json)
        with self.admin_engine.begin() as c:
            self.actor, _, _, self.environment, self.group = graph(c)
            self.instance = insert(c, "plugin_instances", plugin_key="driver-fake")
            c.execute(text("INSERT INTO control_plane.teacher_quotas(teacher_id,environments,vms,vcpu,memory_mb) VALUES (:actor,10,10,10,10240)"), {"actor": self.actor})
        self.secret = self.secrets.create(b"driver-original-password")
        self.configuration.put(self.instance, {"data": {"marker": "original"},
            "allowed_secret_refs": [{"secret_id": self.secret.secret_id}]}, expected_revision=0)
        self.admin_storage = self.storage.bind(self.instance)
        self.host = self.admin_storage.put("hosts/main", {"address": "original-host"})
        self.context = ContextBuilder(self.engine, self.runtime, self.registry, self.secrets)
        self.repo = Repository(self.runtime)
        self.capacity = CapacitySupervisor(CapacitySettings(ordinary_workers=2, control_workers=1,
            session_workers=1, queue_limit=2, instance_limit=1, shutdown_grace_seconds=1))
        self.capacity.start()
        self.addCleanup(self.capacity.stop)
        self.policy = FakeAdmission(self)
        self.job = None
        self.driver = None

    def admit(self, key=None):
        with self.runtime.fenced_transaction() as uow:
            self.job, replay = admit_request(uow, {"actor_id": self.actor,
                "request_key": key or uuid4().hex, "request_digest": "fixed-digest"}, admission=self.policy)
        return self.job, replay

    def start_driver(self, phases=("A",)):
        self.driver = ExecutionDriver(self.repo, self.capacity, self.registry, self.context,
            planner=FakePlanner(self.instance, self.secret.secret_id, phases),
            projector=FakeProjection(phases[-1]), applicator=LocalOutcomeApplicator(FakeLifecycle(), FakeQuota()),
            settings=DriverSettings(scan_limit=8, max_jobs=4))
        self.driver.start()
        self.addCleanup(self.driver.stop)

    def state(self):
        with self.engine.connect() as c:
            return c.scalar(text("SELECT state FROM control_plane.jobs WHERE id=:job"), {"job": self.job})

    def ticks_until(self, predicate, *, count=80):
        for _ in range(count):
            self.driver.tick()
            if predicate():
                return
            # Waiting on actual finite handles advances workers without sleeps,
            # unbounded busy polling, or assumptions about CPU scheduling.
            for call in list(self.driver._calls.values()):
                try:
                    call["handle"].result(timeout=0.1)
                except TimeoutError:
                    pass
                except Exception:
                    pass  # The next tick persists the bounded safe failure.
        self.fail("bounded driver ticks did not reach the expected durable state")

    def test_two_steps_use_original_config_storage_secret_snapshot_after_rotation(self):
        self.admit()
        self.start_driver(("A", "B"))
        self.ticks_until(self.fake.b_entered.is_set)
        self.admin_storage.put("hosts/main", {"address": "new-host"}, self.host)
        self.admin_storage.put("hosts/new", {"address": "unrelated"})
        self.configuration.put(self.instance, {"data": {"marker": "new-config"},
            "allowed_secret_refs": [{"secret_id": self.secret.secret_id}]}, expected_revision=1)
        replacement = self.secrets.rotate(self.secret.secret_id, b"driver-new-password")
        self.fake.b_release.set()
        self.ticks_until(lambda: self.state() == "succeeded")
        self.assertEqual(self.fake.execute_count, 2)
        self.assertEqual([v["host"] for v in self.fake.reads], ["original-host", "original-host"])
        self.assertEqual([v["config"] for v in self.fake.reads], ["original", "original"])
        self.assertEqual([v["secret_version"] for v in self.fake.reads], [self.secret.version_id] * 2)
        self.assertNotEqual(replacement.version_id, self.secret.version_id)
        self.assertEqual(self.fake.passwords, [b"driver-original-password"] * 2)
        with self.engine.connect() as c:
            steps = c.execute(text("SELECT state,output FROM control_plane.job_steps WHERE job_id=:job ORDER BY step_path"), {"job": self.job}).all()
            self.assertEqual([r.state for r in steps], ["succeeded", "succeeded"])
            self.assertEqual(c.scalar(text("SELECT lifecycle FROM control_plane.environments WHERE id=:env"), {"env": self.environment}), "ready")
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.experiment_resources WHERE environment_id=:env"), {"env": self.environment}), 2)
            capture = c.scalar(text("SELECT execution_snapshot FROM control_plane.jobs WHERE id=:job"), {"job": self.job})["plugins"][str(self.instance)]
            pin = c.execute(text("SELECT * FROM control_plane.job_plugin_snapshots WHERE job_id=:job"), {"job": self.job}).one()
            self.assertEqual(capture["configuration_revision"], pin.configuration_revision)
            self.assertEqual(str(capture["storage_snapshot_id"]), str(pin.storage_snapshot_id))
            self.assertEqual(str(c.scalar(text("SELECT secret_version_id FROM control_plane.job_secret_refs WHERE job_id=:job AND NOT derived"), {"job": self.job})), str(self.secret.version_id))

    def test_plugin_events_keep_call_provenance_and_reject_secrets_and_stale_writes(self):
        original = self.fake.execute
        contexts = []

        def execute(prepared, context):
            result = original(prepared, context)
            contexts.append(context)
            context.logger.info("checked host", attempts=1)
            context.progress({"percent": 50})
            with self.assertRaises(ValueError):
                context.logger.info("driver-original-password")
            return result

        self.fake.execute = execute
        self.admit()
        self.start_driver()
        self.ticks_until(lambda: self.state() == "succeeded")
        with self.assertRaises(JobLeaseLost):
            contexts[0].logger.info("late")
        with self.engine.connect() as connection:
            events = connection.execute(text("""
                SELECT data FROM control_plane.job_logs WHERE job_id=:job
                  AND data->>'code' LIKE 'plugin_%' ORDER BY sequence
            """), {"job": self.job}).scalars().all()
        provenance = {"step_id": contexts[0].step_instance_id, "operation_id": contexts[0].operation_id}
        self.assertEqual(events, [
            {**provenance, "code": "plugin_log",
             "details": {"level": "info", "message": "checked host", "details": {"attempts": 1}}},
            {**provenance, "code": "plugin_progress", "details": {"percent": 50}},
        ])

    def test_unknown_result_never_executes_twice_after_more_ticks(self):
        self.fake.outcome = "unknown"
        self.admit()
        self.start_driver()
        self.ticks_until(lambda: self.state() == "blocked")
        for _ in range(8):
            self.driver.tick()
        self.assertEqual(self.fake.execute_count, 1)
        with self.engine.connect() as c:
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.operation_call_attempts a JOIN control_plane.operations o ON o.id=a.operation_id WHERE o.job_id=:job AND a.method='execute'"), {"job": self.job}), 1)
            self.assertEqual(c.scalar(text("SELECT state FROM control_plane.quota_reservations WHERE job_id=:job"), {"job": self.job}), "quarantined")

    def test_schema_error_preserves_original_safe_output_without_second_execute(self):
        self.fake.invalid_output = True
        self.admit()
        self.start_driver()
        self.ticks_until(lambda: self.state() == "blocked")
        for _ in range(8):
            self.driver.tick()
        self.assertEqual(self.fake.execute_count, 1)
        with self.engine.connect() as c:
            op = c.execute(text("SELECT id,output,protocol_error FROM control_plane.operations WHERE job_id=:job"), {"job": self.job}).one()
            self.assertIsNone(op.output)
            self.assertEqual(op.protocol_error["code"], "protocol_error")
            self.assertEqual(c.scalar(text("SELECT data->'output' FROM control_plane.operation_evidence WHERE operation_id=:op AND kind='late_result'"), {"op": op.id}), {"bad": "schema"})

    def test_saturated_instance_job_remains_queued_with_no_job_lease(self):
        entered, release = Event(), Event()
        def blocked():
            entered.set()
            if not release.wait(5):
                raise TimeoutError("bounded test gate")
        handle = self.capacity.submit(str(self.instance), blocked, deadline_at=Deadline.after(10).expires_at)
        self.addCleanup(release.set)
        self.assertTrue(entered.wait(2))
        self.admit()
        self.start_driver()
        for _ in range(4):
            self.driver.tick()
        self.assertEqual(self.state(), "queued")
        with self.engine.connect() as c:
            self.assertIsNone(c.scalar(text("SELECT lease_token FROM control_plane.jobs WHERE id=:job"), {"job": self.job}))
        self.assertEqual(self.fake.execute_count, 0)
        release.set()
        handle.result(timeout=2)
        self.ticks_until(lambda: self.state() == "succeeded")

    def test_atomic_admission_dedupe_does_not_capture_or_reserve_twice(self):
        key = uuid4().hex
        first, replay = self.admit(key)
        self.assertFalse(replay)
        second, replay = self.admit(key)
        self.assertEqual(first, second)
        self.assertTrue(replay)
        self.assertEqual(self.policy.calls, 1)
        with self.runtime.fenced_transaction() as uow:
            with self.assertRaises(RequestConflict):
                admit_request(uow, {"actor_id": self.actor, "request_key": key, "request_digest": "different"}, admission=self.policy)
        with self.engine.connect() as c:
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.quota_reservations WHERE job_id=:job"), {"job": first}), 1)
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.job_plugin_snapshots WHERE job_id=:job"), {"job": first}), 1)
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.conflict_protections WHERE execution_group_id=:group"), {"group": self.group}), 1)

    def test_admission_fault_rolls_back_job_snapshot_grants_quota_and_conflicts(self):
        self.policy.fail_after_bind = True
        key = uuid4().hex
        from sqlalchemy.exc import DBAPIError
        with self.assertRaises(DBAPIError):
            self.admit(key)
        with self.engine.connect() as c:
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.jobs WHERE actor_id=:actor AND request_key=:key"), {"actor": self.actor, "key": key}), 0)
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.quota_reservations WHERE environment_id=:env"), {"env": self.environment}), 0)
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.conflict_protections WHERE execution_group_id=:group"), {"group": self.group}), 0)
