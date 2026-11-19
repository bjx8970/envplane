"""Persistent expansion, partial products, lifecycle and worker reauthorization."""
import unittest
from uuid import uuid4

from sqlalchemy import text

from control_plane.config import RuntimeSettings
from control_plane.execution.repository import Repository
from control_plane.plugins.sdk import AuthorizationDenied, ExecutionResult, PreparedCall
from control_plane.runtime import ControlPlaneRuntime
from control_plane.workflows import TemplateWorkflow
from tests_control_plane.p1_harness import runtime_database
from tests_control_plane.pg_harness import engine_for
from tests_control_plane.test_p1_schema import graph, insert


def action(name, **overrides):
    return {"id": name, "plugin_instance": "demo", "action": "inspect",
            "input": {}, "timeout_seconds": 20, **overrides}


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.admin_url, url = self.enterContext(runtime_database())
        self.engine = engine_for(self.admin_url)
        self.addCleanup(self.engine.dispose)
        self.runtime = ControlPlaneRuntime(RuntimeSettings.from_env({"CONTROL_PLANE_DATABASE_URL": url}))
        self.runtime.start()
        self.addCleanup(self.runtime.stop)
        self.workflow = TemplateWorkflow()
        self.allowed = True
        self.repo = Repository(self.runtime, reference_validator=lambda *a, **kw: None,
                               authorize_job=lambda tx, job: self.allowed)
        with self.engine.begin() as c:
            self.actor, _, _, self.env, self.group = graph(c)
            self.instance = insert(c, "plugin_instances", plugin_key="demo")

    def start(self, steps, resources=(), readiness=None):
        workflow = {"kind": "create", "instances": {"demo": str(self.instance)}, "params": {"items": ["a", "b"]},
                    "environment": {"id": str(self.env)}, "steps": steps, "resources": list(resources),
                    "readiness": {"require_steps": []} if readiness is None else readiness}
        with self.engine.begin() as c:
            self.job = insert(c, "jobs", actor_id=self.actor, environment_id=self.env,
                              execution_group_id=self.group, request_key=uuid4().hex, request_digest="digest",
                              kind="create", input={}, execution_snapshot={"workflow": workflow})
            insert(c, "plugin_instance_versions", instance_id=self.instance, revision=1,
                   configuration={}, plugin_version="1", code_digest="e" * 64)
            snap = insert(c, "plugin_storage_snapshots", instance_id=self.instance, namespace_revision=0)
            c.execute(text("""INSERT INTO control_plane.job_plugin_snapshots(job_id,instance_id,
                configuration_revision,storage_snapshot_id,plugin_version,code_digest)
                VALUES (:job,:instance,1,:snap,'1',:digest)"""),
                      {"job": self.job, "instance": self.instance, "snap": snap, "digest": "e" * 64})
            c.execute(text("""INSERT INTO control_plane.teacher_quotas
                (teacher_id,environments,vms,vcpu,memory_mb) VALUES (:actor,1,0,0,0)"""), {"actor": self.actor})
            insert(c, "quota_reservations", environment_id=self.env, teacher_id=self.actor,
                   job_id=self.job, environments=1, vms=0, vcpu=0, memory_mb=0)
        self.lease = self.repo.claim("worker", 30)

    def expand(self):
        job, steps, _ = self.repo.view(self.lease)
        self.repo.add_steps(self.lease, self.workflow.plan_steps(job["execution_snapshot"], steps))
        return self.repo.view(self.lease)[1]

    def prepare(self, step):
        self.repo.start_prepare(self.lease, step["id"], 20)
        return self.repo.commit_prepared(self.lease, step["id"],
                                         PreparedCall("inspect", resolved_input=step["input"]["input"]),
                                         self.instance)

    def succeed(self, step, output):
        operation = self.prepare(step)
        call = self.repo.begin_call(self.lease, operation["id"], "execute", 20)
        self.repo.record_result(self.lease, call.id, ExecutionResult("succeeded", output),
                                projector=self.workflow, applicator=self.workflow)
        return operation["id"]

    def test_deferred_resource_completes_with_original_provenance_and_durable_items(self):
        loop = {"items": {"$ref": "params.items"}, "max_items": 2, "item_key": {"$ref": "item"}}
        self.start([
            action("collect", for_each=loop, input={"name": {"$ref": "item"}}),
            action("finish", depends_on=["collect"]),
        ], [{"key": "report", "name": "report", "type_label": "generic", "data": {
            "names": {"$ref": "steps.collect.output"}, "summary": {"$ref": "steps.finish.output"}}}],
           {"require_steps": ["collect", "finish"], "require_resources": ["report"]})
        first, second = self.expand()
        first_source = self.succeed(first, "A")
        self.assertEqual([row["id"] for row in self.expand()], [first["id"], second["id"]])
        self.succeed(second, "B")
        with self.engine.connect() as c:
            self.assertEqual(c.scalar(text("SELECT state FROM control_plane.local_resource_items")), "pending")
        finish = next(step for step in self.expand() if step["step_path"] == "finish")
        self.succeed(finish, "done")
        with self.engine.connect() as c:
            row = c.execute(text("SELECT data,source_operation_id FROM control_plane.experiment_resources")).one()
            self.assertEqual(row.data, {"names": {"a": "A", "b": "B"}, "summary": "done"})
            self.assertEqual(row.source_operation_id, first_source)
            self.assertEqual(c.scalar(text("SELECT state FROM control_plane.quota_reservations")), "allocated")
            self.assertEqual(c.scalar(text("SELECT lifecycle FROM control_plane.environments")), "ready")

    def test_skipped_tail_can_complete_a_pending_resource_without_another_call(self):
        self.start([
            action("inspect"),
            action("tail", depends_on=["inspect"], for_each={
                "items": [], "item_key": {"$ref": "item"}, "max_items": 1}),
        ], [{"key": "report", "name": "report", "type_label": "result", "data": {
            "observed": {"$ref": "steps.inspect.output"}, "tail": {"$ref": "steps.tail.output"}}}],
            {"require_steps": ["inspect", "tail"], "require_resources": ["report"]})
        source = self.succeed(self.expand()[0], {"name": "confirmed"})
        with self.engine.connect() as c:
            pending = c.execute(text("SELECT id,state FROM control_plane.local_resource_items")).one()
            self.assertEqual(pending.state, "pending")
        tail = next(step for step in self.expand() if step["step_path"] == "tail")
        self.assertEqual(tail["state"], "skipped")
        self.repo.finish_workflow(self.lease, self.workflow)
        with self.engine.connect() as c:
            resource = c.execute(text("""SELECT data,local_resource_item_id,source_operation_id
                                          FROM control_plane.experiment_resources""")).one()
            self.assertEqual(resource.data, {"observed": {"name": "confirmed"}, "tail": {}})
            self.assertEqual((resource.local_resource_item_id, resource.source_operation_id), (pending.id, source))
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.operation_call_attempts")), 1)
            self.assertEqual(c.scalar(text("SELECT state FROM control_plane.jobs")), "succeeded")
            self.assertEqual(c.scalar(text("SELECT lifecycle FROM control_plane.environments")), "ready")
            self.assertEqual(c.scalar(text("SELECT state FROM control_plane.quota_reservations")), "allocated")

    def test_empty_workflow_with_unsatisfied_readiness_is_persisted_without_releasing_quota(self):
        self.start([], readiness={"require_steps": [], "conditions": [False]})
        self.repo.finish_workflow(self.lease, self.workflow)
        with self.engine.connect() as c:
            self.assertEqual(c.scalar(text("SELECT state FROM control_plane.jobs")), "failed")
            self.assertEqual(c.scalar(text("SELECT lifecycle FROM control_plane.environments")), "create_failed")
            self.assertEqual(c.scalar(text("SELECT state FROM control_plane.quota_reservations")), "quarantined")

    def test_revocation_after_prepare_prevents_dispatch_and_undispatched_cancel_releases_quota(self):
        self.start([action("first")])
        op = self.prepare(self.expand()[0])
        self.allowed = False
        with self.assertRaises(AuthorizationDenied):
            self.repo.begin_call(self.lease, op["id"], "execute", 10)
        self.repo.cancel_undispatched(self.lease)
        with self.engine.connect() as c:
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.operation_call_attempts")), 0)
            self.assertEqual(c.scalar(text("SELECT state FROM control_plane.quota_reservations")), "released")

    def test_creation_blocked_before_dispatch_releases_its_reservation_and_scope(self):
        self.start([action("first")])
        op = self.prepare(self.expand()[0])
        self.allowed = False
        with self.assertRaises(AuthorizationDenied):
            self.repo.begin_call(self.lease, op["id"], "execute", 10)
        self.repo.block_job(self.lease, "dispatch_denied")
        with self.engine.connect() as c:
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.operation_call_attempts")), 0)
            self.assertEqual(c.scalar(text("SELECT state FROM control_plane.operations")), "cancelled")
            self.assertEqual(c.scalar(text("SELECT state FROM control_plane.jobs")), "blocked")
            self.assertEqual(c.scalar(text("SELECT state FROM control_plane.quota_reservations")), "released")
            self.assertEqual(c.scalar(text("SELECT state FROM control_plane.execution_groups")), "released")

    def test_replayed_creation_success_restores_quarantined_reservation(self):
        self.start([action("first")])
        op = self.prepare(self.expand()[0])
        call = self.repo.begin_call(self.lease, op["id"], "execute", 20)
        self.repo.record_result(self.lease, call.id, ExecutionResult("unknown"),
                                projector=self.workflow, applicator=self.workflow)
        evidence = self.repo.append_evidence(call.id, "late_result", "confirmed", {
            "outcome": "succeeded", "output": {"confirmed": True}})
        with self.engine.begin() as c:
            self.assertEqual(c.scalar(text("SELECT state FROM control_plane.quota_reservations")), "quarantined")
            c.execute(text("UPDATE control_plane.jobs SET lease_expires_at=clock_timestamp()-interval '1 second'"))
        lease = self.repo.takeover_blocked(self.job, "recovery", expected_revision=self.lease.group_revision,
                                          evidence_id=evidence, actor_id=self.actor, reason="verified success")
        self.assertEqual(self.repo.replay_result(lease, evidence, projector=self.workflow, applicator=self.workflow),
                         "applied")
        with self.engine.connect() as c:
            self.assertEqual(c.scalar(text("SELECT lifecycle FROM control_plane.environments")), "ready")
            self.assertEqual(c.scalar(text("SELECT state FROM control_plane.quota_reservations")), "allocated")
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.operation_call_attempts")), 1)

    def test_resource_tied_only_to_later_step_identifies_that_operation(self):
        self.start([action("a"), action("b", depends_on=["a"])], [{
            "key": "report", "name": "report", "type_label": "result",
            "data": {"value": {"$ref": "steps.b.output"}},
        }])
        self.succeed(self.expand()[0], {"irrelevant": True})
        with self.engine.connect() as c:
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.local_resource_items")), 0)
        op = self.succeed(next(row for row in self.expand() if row["step_path"] == "b"), "ok")
        with self.engine.connect() as c:
            facts = c.execute(text("""SELECT r.source_operation_id,l.data FROM control_plane.experiment_resources r
                JOIN control_plane.local_resource_items l ON l.id=r.local_resource_item_id""")).one()
            self.assertEqual(facts.source_operation_id, op)
            self.assertEqual(facts.data["input_operations"], [str(op)])

    def test_unmatched_expansion_key_cannot_substitute_whole_producer_output(self):
        source_loop = {"items": ["a"], "item_key": {"$ref": "item"}, "max_items": 2}
        dest_loop = {**source_loop, "items": ["b"]}
        self.start([action("first", for_each=source_loop), action("second", for_each=dest_loop,
                         input={"target": {"$ref": "steps.first.output"}})])
        self.succeed(self.expand()[0], {"target": "a"})
        with self.assertRaises(ValueError):
            self.expand()
        with self.engine.connect() as c:
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.job_steps")), 1)

    def test_observation_expires_using_database_clock(self):
        from control_plane.workflows import resource_state
        self.start([action("setup")], [{"key": "one", "name": "item", "type_label": "item", "data": {}}])
        self.succeed(self.expand()[0], {})
        with self.engine.begin() as c:
            resource = c.scalar(text("SELECT id FROM control_plane.experiment_resources"))
            c.execute(text("""
                INSERT INTO control_plane.audit_events(environment_id,resource_id,action,result,data,created_at)
                VALUES (:env,:resource,'resource.state_observed','observed',
                        jsonb_build_object('state','running','ttl_seconds',5),clock_timestamp()-interval '10 seconds')
            """), {"env": self.env, "resource": resource})
        with self.runtime.fenced_transaction() as tx:
            status = resource_state(tx, resource)
        self.assertEqual(status["state"], "unknown")
        self.assertIsNotNone(status["observed_at"])

    def start_action(self, steps):
        """Submit another group against the same ready environment and confirmed occupancy."""
        from control_plane.business import _group
        from control_plane.persistence import admit_job
        previous = self.job
        with self.runtime.fenced_transaction() as uow:
            self.group, _ = _group(uow, self.env, "environment_action")
            self.job, _ = admit_job(
                uow, actor_id=self.actor, request_key=uuid4().hex, request_digest="digest",
                environment_id=self.env, execution_group_id=self.group, logical_invocation_id=uuid4(),
                kind="environment_action", input={}, execution_snapshot={"workflow": {
                    "kind": "action", "steps": steps, "instances": {"demo": str(self.instance)}}})
            uow.execute(text("""
                INSERT INTO control_plane.job_plugin_snapshots(job_id,instance_id,configuration_revision,
                                                              storage_snapshot_id,plugin_version,code_digest)
                SELECT :job,instance_id,configuration_revision,storage_snapshot_id,plugin_version,code_digest
                FROM control_plane.job_plugin_snapshots WHERE job_id=:previous
            """), {"previous": previous, "job": self.job})
        self.lease = self.repo.claim("worker", 30)
        self.assertEqual(self.lease.job_id, self.job)

    def action_disposition(self):
        with self.engine.connect() as c:
            return c.execute(text("""
                SELECT j.state,g.state,r.state,EXISTS(
                    SELECT 1 FROM control_plane.conflict_protections p
                    WHERE p.execution_group_id=g.id AND p.released_at IS NULL
                ) FROM control_plane.jobs j JOIN control_plane.execution_groups g ON g.id=j.execution_group_id
                JOIN control_plane.quota_reservations r ON r.environment_id=j.environment_id WHERE j.id=:job
            """), {"job": self.job}).one()

    def test_undispatched_actions_preserve_occupancy_and_allow_a_new_request(self):
        self.start([action("create")])
        self.succeed(self.expand()[0], {})
        for interruption in ("failed", "cancelled", "blocked"):
            with self.subTest(interruption=interruption):
                self.start_action([action("update")])
                step = self.expand()[0]
                if interruption == "failed":
                    self.repo.start_prepare(self.lease, step["id"], 20)
                    self.repo.prepare_failed(self.lease, step["id"])
                else:
                    self.prepare(step)
                    if interruption == "cancelled":
                        self.repo.request_cancel(self.job)
                        self.repo.cancel_undispatched(self.lease)
                    else:
                        self.repo.block_job(self.lease)
                self.assertEqual(self.action_disposition(), (interruption, "released", "allocated", False))
        self.start_action([action("update")])
        self.succeed(self.expand()[0], {})
        self.assertEqual(self.action_disposition(), ("succeeded", "released", "allocated", False))

    def test_later_prepare_failure_retains_previous_action_effect_and_conflict(self):
        from control_plane.execution.repository import ExecutionConflict
        self.start([action("create")])
        self.succeed(self.expand()[0], {})
        self.start_action([action("first"), action("second", depends_on=["first"])])
        self.succeed(self.expand()[0], {})
        step = next(r for r in self.expand() if r["state"] == "pending")
        self.repo.start_prepare(self.lease, step["id"], 20)
        self.repo.prepare_failed(self.lease, step["id"])
        self.assertEqual(self.action_disposition(), ("failed", "blocked", "allocated", True))
        with self.assertRaises(ExecutionConflict):
            self.start_action([action("update")])

    def test_uncertain_dispatched_mutating_action_retains_conflict_and_quarantines_occupancy(self):
        self.start([action("create")])
        self.succeed(self.expand()[0], {})
        self.start_action([action("update")])
        op = self.prepare(self.expand()[0])
        call = self.repo.begin_call(self.lease, op["id"], "execute", 20)
        self.repo.record_result(self.lease, call.id, ExecutionResult("unknown"),
                                projector=self.workflow, applicator=self.workflow)
        self.assertEqual(self.action_disposition(), ("blocked", "blocked", "quarantined", True))
