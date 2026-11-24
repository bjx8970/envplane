"""Deterministic PostgreSQL execution faults; no vendor or test-only prod adapters."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from threading import Barrier, Event
import unittest
from unittest import mock
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from control_plane.config import RuntimeSettings
from control_plane.coordination import LeaseLost
from control_plane.execution import (
    Repository, JobLeaseLost, ExecutionConflict, InvalidTransition, Projection,
    LocalOutcomeApplicator, AdapterUnavailable, admit_request,
)
from control_plane.persistence import admit_job, RequestConflict
from control_plane.plugins.sdk import PreparedCall, ExecutionPolicy, ExecutionResult, CancelResult
from control_plane.runtime import ControlPlaneRuntime
from tests_control_plane.p1_harness import runtime_database
from tests_control_plane.pg_harness import engine_for
from tests_control_plane.test_p1_schema import insert, graph


class FakeProjector:
    def project(self, operation, result):
        return Projection(create_results={"result": result.output}, resources=({
            "resource_slot": "report", "name": "report", "type_label": "opaque",
            "data": {"value": result.output}, "target_ref": {"opaque": "original"},
        },), lifecycle="ready", job_complete=True, release_conflicts=True)


class FakeLifecycle:
    def apply(self, uow, operation, projection):
        if projection.lifecycle:
            uow.execute(text("UPDATE control_plane.environments SET lifecycle=:state WHERE id=:env"),
                        {"state": projection.lifecycle, "env": operation["environment_id"]})


class FakeQuota:
    def apply(self, uow, operation, facts):
        uow.execute(text("UPDATE control_plane.quota_reservations SET state='allocated' WHERE environment_id=:env AND state IN ('reserved','quarantined')"), {"env": operation["environment_id"]})


class P2DatabaseCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin_url, cls.runtime_url = cls.enterClassContext(runtime_database())
        cls.engine = engine_for(cls.admin_url)
        cls.addClassCleanup(cls.engine.dispose)

    def setUp(self):
        self.runtime = ControlPlaneRuntime(RuntimeSettings.from_env({"CONTROL_PLANE_DATABASE_URL": self.runtime_url}))
        self.runtime.start()
        self.addCleanup(self.runtime.stop)
        self.repo = Repository(self.runtime, reference_validator=lambda *args, **kwargs: None)
        self.projector = FakeProjector()
        self.applicator = LocalOutcomeApplicator(FakeLifecycle(), FakeQuota())
        with self.engine.begin() as c:
            self.actor, self.course, self.version, self.env, self.group = graph(c)
            self.job = insert(c, "jobs", actor_id=self.actor, environment_id=self.env,
                              execution_group_id=self.group, request_key=uuid4().hex,
                              request_digest="digest", kind="create", input={}, execution_snapshot={"workflow": {"kind": "create", "steps": []}})
            self.instance = insert(c, "plugin_instances", plugin_key="fake")
            insert(c, "plugin_instance_versions", instance_id=self.instance, revision=1,
                   configuration={}, plugin_version="1", code_digest="e" * 64)
            snapshot = insert(c, "plugin_storage_snapshots", instance_id=self.instance, namespace_revision=0)
            c.execute(text("""INSERT INTO control_plane.job_plugin_snapshots
                (job_id,instance_id,configuration_revision,storage_snapshot_id,plugin_version,code_digest)
                VALUES (:job,:instance,1,:snapshot,'1',:digest)"""),
                {"job": self.job, "instance": self.instance, "snapshot": snapshot, "digest": "e" * 64})
            self.step = insert(c, "job_steps", job_id=self.job, step_path="create", input={
                "plugin_instance_id": str(self.instance), "action_key": "create", "input": {}})
            c.execute(text("INSERT INTO control_plane.teacher_quotas(teacher_id,environments,vms,vcpu,memory_mb) VALUES (:teacher,10,10,10,10240)"), {"teacher": self.actor})
            self.reservation = insert(c, "quota_reservations", job_id=self.job,
                environment_id=self.env, teacher_id=self.actor, environments=1, vms=1, vcpu=1, memory_mb=1024)
        self.lease = None

    def claim(self):
        self.lease = self.repo.claim("worker", 30, instance_ids=[self.instance])
        self.assertIsNotNone(self.lease)
        self.assertEqual(self.lease.job_id, self.job)
        return self.lease

    def prepared(self, policy=None):
        if self.lease is None:
            self.claim()
        self.repo.start_prepare(self.lease, self.step, 30)
        prepared = PreparedCall("create", {"value": 1}, {"opaque": "original"},
                                execution_policy=policy or ExecutionPolicy())
        op = self.repo.commit_prepared(self.lease, self.step, prepared, self.instance)
        return op

    def dispatched(self, policy=None):
        op = self.prepared(policy)
        call = self.repo.begin_call(self.lease, op["id"], "execute", 30)
        return op, call

    def row(self, table, id):
        with self.engine.connect() as c:
            return dict(c.execute(text(f'SELECT * FROM control_plane."{table}" WHERE id=:id'), {"id": id}).one()._mapping)

    def expire(self, job=None):
        with self.engine.begin() as c:
            c.execute(text("UPDATE control_plane.jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=:job"), {"job": job or self.job})

    def complete(self, call, result=None):
        return self.repo.record_result(self.lease, call.id, result or ExecutionResult("succeeded", {"ok": True}),
                                       projector=self.projector, applicator=self.applicator)


class ExecutionRepositoryTests(P2DatabaseCase):
    def test_claim_commits_job_token_group_revision_and_bounded_attempt(self):
        lease = self.claim()
        job, group = self.row("jobs", self.job), self.row("execution_groups", self.group)
        self.assertEqual(job["state"], "running")
        self.assertEqual(job["attempts"], 1)
        self.assertEqual(str(job["lease_token"]), str(lease.token))
        self.assertEqual(group["revision"], lease.group_revision)
        self.assertEqual(group["current_job_id"], self.job)
        self.assertIsNone(self.repo.claim("another", instance_ids=[self.instance]))

    def test_claim_skip_locked_does_not_wait_or_mark_locked_job_running(self):
        with self.engine.connect() as blocker:
            transaction = blocker.begin()
            blocker.execute(text("SELECT id FROM control_plane.jobs WHERE id=:id FOR UPDATE"), {"id": self.job})
            try:
                self.assertIsNone(self.repo.claim("worker", instance_ids=[self.instance]))
                self.assertEqual(self.row("jobs", self.job)["state"], "queued")
            finally:
                transaction.rollback()
        self.claim()

    def test_parallel_claim_same_job_has_one_winner(self):
        barrier = Barrier(2)
        def claim(owner):
            barrier.wait(timeout=5)
            return self.repo.claim(owner, instance_ids=[self.instance])
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(claim, ("a", "b")))
        self.assertEqual(sum(r is not None for r in results), 1)
        self.assertEqual(self.row("jobs", self.job)["attempts"], 1)

    def test_prepare_budget_fixed_once(self):
        self.claim()
        first = self.repo.start_prepare(self.lease, self.step, 30)
        second = self.repo.start_prepare(self.lease, self.step, 300)
        self.assertEqual(first, second)
        self.assertEqual(self.row("job_steps", self.step)["state"], "pending")
        with self.engine.connect() as c:
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.operations WHERE job_id=:job"), {"job": self.job}), 0)

    def test_step_running_and_prepared_operation_are_atomic_on_write_failure(self):
        self.claim()
        self.repo.start_prepare(self.lease, self.step, 30)
        # A real DB fault after the Operation INSERT must roll that INSERT back.
        from control_plane.coordination import FencedConnection
        original = FencedConnection.execute
        def fault(uow, statement, parameters=None):
            if "UPDATE control_plane.job_steps SET state='running'" in str(statement):
                uow.scalar(text("SELECT 1/0"))
            return original(uow, statement, parameters)
        with mock.patch.object(FencedConnection, "execute", fault):
            with self.assertRaises(DBAPIError):
                self.repo.commit_prepared(self.lease, self.step, PreparedCall("create"), self.instance)
        self.assertEqual(self.row("job_steps", self.step)["state"], "pending")
        with self.engine.connect() as c:
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.operations WHERE job_id=:job"), {"job": self.job}), 0)

    def test_duplicate_preparation_reuses_operation_and_cannot_change_target(self):
        op = self.prepared()
        prepared = PreparedCall.from_dict(op["prepared_call"])
        same = self.repo.commit_prepared(self.lease, self.step, prepared, self.instance)
        self.assertEqual(same["id"], op["id"])
        with self.assertRaises(ExecutionConflict):
            self.repo.commit_prepared(self.lease, self.step, replace(prepared, target_ref={"opaque": "different"}), self.instance)

    def test_intent_and_call_provenance_commit_before_any_external_execution(self):
        op, call = self.dispatched()
        stored = self.row("operations", op["id"])
        attempt = self.row("operation_call_attempts", call.id)
        self.assertEqual(stored["state"], "running")
        self.assertIsNotNone(stored["dispatch_intent_at"])
        self.assertEqual(str(attempt["job_lease_token"]), str(self.lease.token))
        self.assertEqual(str(attempt["coordinator_owner"]), self.lease.coordinator_owner)
        self.assertEqual(attempt["coordinator_revision"], self.lease.coordinator_revision)
        self.assertGreater(attempt["deadline_at"], attempt["created_at"])

    def test_call_insert_fault_rolls_dispatch_intent_back(self):
        op = self.prepared()
        from control_plane.coordination import FencedConnection
        original = FencedConnection.scalar
        def fault(uow, statement, parameters=None):
            if "INSERT INTO control_plane.operation_call_attempts" in str(statement):
                return original(uow, text("SELECT 1/0"))
            return original(uow, statement, parameters)
        with mock.patch.object(FencedConnection, "scalar", fault):
            with self.assertRaises(DBAPIError):
                self.repo.begin_call(self.lease, op["id"], "execute", 30)
        stored = self.row("operations", op["id"])
        self.assertEqual(stored["state"], "prepared")
        self.assertIsNone(stored["dispatch_intent_at"])

    def test_expired_job_token_rejected_even_current_coordinator_uow(self):
        op, call = self.dispatched()
        self.expire()
        with self.assertRaises(JobLeaseLost):
            self.repo.heartbeat(self.lease)
        self.assertEqual(self.complete(call), "late_evidence")
        self.assertEqual(self.row("operations", op["id"])["state"], "running")
        self.assertEqual(self.row("quota_reservations", self.reservation)["state"], "reserved")
        self.assertEqual(self.row("execution_groups", self.group)["state"], "active")

    def test_wrong_group_revision_cannot_heartbeat_or_finish(self):
        op, call = self.dispatched()
        self.lease = replace(self.lease, group_revision=self.lease.group_revision + 1)
        with self.assertRaises(JobLeaseLost):
            self.repo.heartbeat(self.lease)
        self.assertEqual(self.complete(call), "late_evidence")
        self.assertEqual(self.row("operations", op["id"])["state"], "running")

    def test_sync_report_dedupes_and_preserves_changed_same_key_history(self):
        _, call = self.dispatched()
        first = self.repo.report(self.lease, call.id, "external_ref", "remote", {"id": "opaque-1"})
        same = self.repo.report(self.lease, call.id, "external_ref", "remote", {"id": "opaque-1"})
        second = self.repo.report(self.lease, call.id, "external_ref", "remote", {"id": "opaque-2"})
        self.assertEqual(first, same)
        self.assertNotEqual(first, second)
        with self.engine.connect() as c:
            rows = c.execute(text("SELECT revision,data,call_attempt_id FROM control_plane.operation_evidence WHERE operation_id=:op AND kind='external_ref' ORDER BY revision"), {"op": call.operation_id}).all()
        self.assertEqual([r.revision for r in rows], [1, 2])
        self.assertEqual([r.data["id"] for r in rows], ["opaque-1", "opaque-2"])
        self.assertTrue(all(r.call_attempt_id == call.id for r in rows))

    def test_event_identity_conflict_does_not_replace_first_evidence(self):
        _, call = self.dispatched()
        self.repo.report(self.lease, call.id, "checkpoint", "stage", {"n": 1}, event_id="event-1")
        with self.assertRaises(ExecutionConflict):
            self.repo.report(self.lease, call.id, "checkpoint", "stage", {"n": 2}, event_id="event-1")
        with self.engine.connect() as c:
            self.assertEqual(c.scalar(text("SELECT data FROM control_plane.operation_evidence WHERE operation_id=:op AND event_id='event-1'"), {"op": call.operation_id}), {"n": 1})

    def test_success_output_step_resources_lifecycle_quota_commit_together(self):
        op, call = self.dispatched()
        self.assertEqual(self.complete(call), "applied")
        self.assertEqual(self.row("operations", op["id"])["output"], {"ok": True})
        self.assertEqual(self.row("job_steps", self.step)["state"], "succeeded")
        self.assertEqual(self.row("jobs", self.job)["state"], "succeeded")
        self.assertEqual(self.row("environments", self.env)["lifecycle"], "ready")
        self.assertEqual(self.row("environments", self.env)["create_results"], {"result": {"ok": True}})
        self.assertEqual(self.row("quota_reservations", self.reservation)["state"], "allocated")
        with self.engine.connect() as c:
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.experiment_resources WHERE environment_id=:env"), {"env": self.env}), 1)
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.conflict_protections WHERE execution_group_id=:group AND released_at IS NULL"), {"group": self.group}), 0)

    def test_local_projection_db_fault_preserves_raw_result_and_rolls_products_back(self):
        op, call = self.dispatched()
        class Broken(FakeLifecycle):
            def apply(self, uow, operation, projection):
                super().apply(uow, operation, projection)
                uow.scalar(text("SELECT 1/0"))
        self.applicator = LocalOutcomeApplicator(Broken(), FakeQuota())
        with self.assertRaises(DBAPIError):
            self.complete(call)
        self.assertEqual(self.row("operations", op["id"])["state"], "unknown")
        self.assertIsNone(self.row("operations", op["id"])["output"])
        self.assertEqual(self.row("job_steps", self.step)["state"], "blocked")
        self.assertEqual(self.row("environments", self.env)["create_results"], {})
        self.assertEqual(self.row("environments", self.env)["lifecycle"], "blocked")
        with self.engine.connect() as c:
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.experiment_resources WHERE environment_id=:env"), {"env": self.env}), 0)
            self.assertEqual(c.scalar(text("SELECT data->'output' FROM control_plane.operation_evidence WHERE operation_id=:op AND event_id=:event"), {"op": op["id"], "event": "result:" + str(call.id)}), {"ok": True})

    def test_output_protocol_error_blocks_without_exposing_output_or_resending(self):
        op, call = self.dispatched()
        result = ExecutionResult("succeeded", {"bad": "schema"}, external_refs=({"ref_key": "partial", "id": "remote"},),
                                 protocol_error={"code": "protocol_error"})
        self.complete(call, result)
        self.assertEqual(self.row("operations", op["id"])["state"], "unknown")
        self.assertEqual(self.row("operations", op["id"])["protocol_error"], {"code": "protocol_error"})
        self.assertIsNone(self.row("job_steps", self.step)["output"])
        with self.assertRaises(JobLeaseLost):
            self.repo.begin_call(self.lease, op["id"], "execute", 30)
        self.assertEqual(self.row("quota_reservations", self.reservation)["state"], "quarantined")
        with self.engine.connect() as c:
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.operation_call_attempts WHERE operation_id=:op"), {"op": op["id"]}), 1)
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.operation_evidence WHERE operation_id=:op AND kind='external_ref'"), {"op": op["id"]}), 1)

    def test_pending_external_poll_intent_has_independent_deadline_no_reexecute(self):
        op, call = self.dispatched(ExecutionPolicy(recovery="queryable"))
        self.complete(call, ExecutionResult("pending_external", external_execution_ref={"task": "opaque"}))
        before = self.row("operations", op["id"])["deadline_at"]
        poll = self.repo.begin_call(self.lease, op["id"], "poll", 5)
        self.assertLess(poll.deadline_at, before)
        self.assertEqual(self.row("operations", op["id"])["deadline_at"], before)
        with self.assertRaises(InvalidTransition):
            self.repo.begin_call(self.lease, op["id"], "execute", 30)

    def test_cancel_requested_then_real_success_remains_success(self):
        op, call = self.dispatched(ExecutionPolicy(cancellation="requestable"))
        self.repo.request_cancel(self.job)
        cancel = self.repo.begin_call(self.lease, op["id"], "cancel", 5)
        self.repo.record_cancel(self.lease, cancel.id, CancelResult("too_late"))
        self.complete(call)
        self.assertEqual(self.row("jobs", self.job)["state"], "succeeded")
        self.assertEqual(self.row("operations", op["id"])["cancellation_result"], "too_late")

    def test_cancel_requested_is_not_confirmation_and_preserves_protection(self):
        op, _ = self.dispatched(ExecutionPolicy(cancellation="requestable"))
        self.repo.request_cancel(self.job)
        cancel = self.repo.begin_call(self.lease, op["id"], "cancel", 5)
        self.repo.record_cancel(self.lease, cancel.id, CancelResult("requested"))
        self.assertEqual(self.row("jobs", self.job)["state"], "cancel_requested")
        self.assertEqual(self.row("operations", op["id"])["state"], "running")
        self.assertEqual(self.row("quota_reservations", self.reservation)["state"], "reserved")

    def test_no_p3_adapters_fail_closed_after_safe_raw_result(self):
        op, call = self.dispatched()
        with self.assertRaises(AdapterUnavailable):
            self.repo.record_result(self.lease, call.id, ExecutionResult("succeeded", {}))
        self.assertEqual(self.row("jobs", self.job)["state"], "blocked")
        self.assertEqual(self.row("operations", op["id"])["state"], "unknown")

    def test_admission_dedupe_happens_before_snapshot_or_quota_adapter(self):
        args = {"actor_id": self.actor, "request_key": self.row("jobs", self.job)["request_key"], "request_digest": "digest"}
        class ForbiddenPolicy:
            def authorize_and_reserve(self, *args):
                raise AssertionError("duplicate invoked business policy")
        with self.runtime.fenced_transaction() as uow:
            value, replay = admit_request(uow, args, admission=ForbiddenPolicy())
        self.assertEqual(value, self.job)
        self.assertTrue(replay)
        with self.assertRaises(RequestConflict):
            with self.runtime.fenced_transaction() as uow:
                admit_request(uow, {**args, "request_digest": "different"}, admission=ForbiddenPolicy())

    def test_authority_and_secret_publisher_rechecked_after_callback(self):
        op, call = self.dispatched()
        called = []
        self.repo.source_publisher = lambda *args: called.append(True)
        self.expire()
        with self.assertRaises(JobLeaseLost):
            self.repo.report(self.lease, call.id, "checkpoint", "late", {"safe": True})
        self.assertEqual(called, [])
        with self.engine.connect() as c:
            evidence = c.execute(text("SELECT call_attempt_id,data,trusted_for_derivation FROM control_plane.operation_evidence WHERE operation_id=:op AND ref_key='late'"), {"op": op["id"]}).one()
        self.assertEqual(evidence.call_attempt_id, call.id)
        self.assertFalse(evidence.trusted_for_derivation)
        self.assertEqual(self.row("quota_reservations", self.reservation)["state"], "reserved")

    def test_result_checkpoint_raw_copy_does_not_grant_until_current_call_acceptance(self):
        op, call = self.dispatched(ExecutionPolicy(recovery="queryable"))
        self.complete(call, ExecutionResult("pending_external", checkpoints=({"checkpoint_key": "phase", "data": {"n": 1}},)))
        with self.engine.connect() as c:
            rows = c.execute(text("SELECT trusted_for_derivation,event_id FROM control_plane.operation_evidence WHERE operation_id=:op AND kind='checkpoint' ORDER BY revision"), {"op": op["id"]}).all()
        self.assertEqual([r.trusted_for_derivation for r in rows], [False, True])
        self.assertTrue(rows[1].event_id.startswith("accepted-result:"))

    def test_result_safety_guard_runs_before_plaintext_is_persisted(self):
        op, call = self.dispatched()
        def guard(value):
            if "sentinel-secret" in str(value):
                raise ValueError("secret leak rejected")
            return value
        self.repo.safe_json = guard
        with self.assertRaises(ValueError):
            self.complete(call, ExecutionResult("succeeded", {"password": "sentinel-secret"}))
        with self.engine.connect() as c:
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.operation_evidence WHERE operation_id=:op"), {"op": op["id"]}), 0)
