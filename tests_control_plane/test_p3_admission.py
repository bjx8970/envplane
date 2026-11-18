"""Service-level admission edges, quota isolation, and cleanup evidence provenance."""
import base64
from datetime import datetime, timezone
import json
import os
from types import SimpleNamespace
import tempfile
from unittest import TestCase
from unittest.mock import MagicMock, patch
from uuid import uuid4

from sqlalchemy import text

from control_plane.business import _evidence
from control_plane.config import RuntimeSettings
from control_plane.persistence import RequestConflict
from control_plane.plugins.sdk import AuthorizationDenied
from control_plane.quota import QuotaExceeded
from control_plane.runtime import ControlPlaneRuntime
from tests_control_plane.p1_harness import runtime_database
from tests_control_plane.test_p2_services import deployment


class EvidenceTests(TestCase):
    def test_attempts_and_unexecuted_steps_retain_explicit_distinct_facts(self):
        env, job, group = uuid4(), uuid4(), uuid4()
        now = datetime.now(timezone.utc)
        source = SimpleNamespace(id=job, kind="create", state="failed", execution_group_id=group,
                                 execution_snapshot={"workflow": {"steps": [{"id": "provision"}, {"id": "unused"}]}})
        step = SimpleNamespace(job_id=job, step_path="provision", item_key="item1")
        ops = [SimpleNamespace(id=uuid4(), attempt=n, job_id=job, step_path="provision", item_key="item1",
                               state="failed", target_ref={"key": "fixed"}, external_execution_ref=None,
                               updated_at=now) for n in (1, 2)]
        ref = SimpleNamespace(operation_id=ops[0].id, kind="external_ref", ref_key="vm",
                              data={"id": "actual"}, revision=1, created_at=now)
        uow = MagicMock()
        uow.execute.side_effect = [MagicMock(all=MagicMock(return_value=rows))
                                   for rows in ([source], [step], ops, [ref])]
        snapshot = _evidence(uow, env)
        attempts = snapshot["steps"]["provision"]["item1"]["operations"]
        self.assertEqual([o["attempt"] for o in attempts], [1, 2])
        self.assertEqual(attempts[0]["external_refs"]["vm"],
                         {"reference": {"id": "actual"}, "revision": 1, "observed_at": now.isoformat()})
        self.assertEqual(attempts[1]["external_refs"], {})
        self.assertEqual(snapshot["steps"]["unused"], {})
        self.assertEqual(snapshot["revisions"], {str(ops[0].id): 1, str(ops[1].id): 0})


class AdmissionTests(TestCase):
    def setUp(self):
        _, url = self.enterContext(runtime_database())
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(patch.dict(os.environ, {
            "CONTROL_PLANE_SECRET_KEYRING": json.dumps({"key": base64.b64encode(os.urandom(32)).decode()}),
            "CONTROL_PLANE_SECRET_ACTIVE_KEY_ID": "key",
        }))
        self.runtime = ControlPlaneRuntime(RuntimeSettings.from_env({
            "CONTROL_PLANE_DATABASE_URL": url, "CONTROL_PLANE_RUNTIME_CONFIG": deployment(directory)}))
        self.addCleanup(self.runtime.stop)
        self.runtime.start()
        with self.runtime.fenced_transaction() as uow:
            self.admin = uow.scalar(text("""INSERT INTO control_plane.users(username,role,password_hash)
                VALUES ('admin','admin','test') RETURNING id"""))
        identity = self.runtime.services.identity
        self.teacher = identity.create_user(self.admin, "teacher", "teacher-test-pass", role="teacher")
        self.course = identity.create_course(self.teacher, self.teacher, "course")
        self.cost = {"environments": 1, "vms": 0, "vcpu": 0, "memory_mb": 0}
        definition = {"schema_version": 1, "metadata": {"name": "local"}, "parameters": {}, "quota": self.cost,
                      "create": {"steps": []}, "resources": [], "actions": {}, "readiness": {"require_steps": []},
                      "cleanup": {"steps": [], "completion": {"no_external_cleanup_required": True}}, "access": {}}
        templates = self.runtime.services.templates
        _, self.version = templates.create_draft(self.admin, definition)
        templates.publish(self.admin, self.version)
        self.business = self.runtime.services.business
        self.business.set_quota(self.admin, self.teacher, limits=self.cost)

    def create(self, key="one", actor=None, name="lab"):
        return self.business.create_environment(actor or self.teacher, course_id=self.course,
            template_version_id=self.version, name=name, parameters={}, request_key=key)

    def finish(self, job):
        self.runtime.poll()
        with self.runtime.fenced_transaction() as uow:
            row = uow.execute(text("SELECT environment_id,state FROM control_plane.jobs WHERE id=:id"),
                              {"id": job}).one()
            self.assertEqual(row.state, "succeeded")
            return row.environment_id

    def test_admin_delegated_create_and_retired_cleanup_replay(self):
        job, replay = self.create(actor=self.admin)
        self.assertFalse(replay)
        with self.assertRaises(RequestConflict):
            self.create(actor=self.admin, name="different")
        env = self.finish(job)
        with self.runtime.fenced_transaction() as uow:
            row = uow.execute(text("SELECT owner_teacher_id,created_by FROM control_plane.environments WHERE id=:id"),
                              {"id": env}).one()
        self.assertEqual(tuple(row), (self.teacher, self.admin))
        request = dict(environment_id=env, request_key="cleanup")
        cleanup, replay = self.business.cleanup(self.teacher, **request)
        self.assertFalse(replay)
        self.finish(cleanup)
        with self.runtime.fenced_transaction() as uow:
            linked = uow.execute(text("""
                SELECT child.parent_job_id,child.execution_group_id=origin.execution_group_id FROM control_plane.jobs child
                JOIN control_plane.jobs origin ON origin.id=:original WHERE child.id=:child
            """), {"original": job, "child": cleanup}).one()
        self.assertEqual(tuple(linked), (job, True))
        self.assertEqual(self.business.cleanup(self.teacher, **request), (cleanup, True))
        with self.assertRaises(AuthorizationDenied):
            self.business.cleanup(self.teacher, environment_id=env, request_key="new")
        with self.runtime.fenced_transaction() as uow:
            uow.execute(text("UPDATE control_plane.users SET active=FALSE WHERE id=:teacher"), {"teacher": self.teacher})
        with self.assertRaises(AuthorizationDenied):
            self.business.cleanup(self.teacher, **request)

    def test_quota_reduction_preserves_occupancy_and_authorized_replays(self):
        with self.assertRaises(AuthorizationDenied):
            self.business.set_quota(self.teacher, self.teacher, limits=self.cost)
        job, _ = self.create()
        self.business.set_quota(self.admin, self.teacher, limits={k: 0 for k in self.cost})
        self.assertEqual(self.create(), (job, True))
        with self.assertRaises(QuotaExceeded):
            self.create("two")
        with self.runtime.fenced_transaction() as uow:
            self.assertEqual(uow.scalar(text("SELECT count(*) FROM control_plane.quota_reservations")), 1)
            self.assertEqual(uow.scalar(text("SELECT state FROM control_plane.quota_reservations")), "reserved")
            self.assertEqual(uow.scalar(text("SELECT count(*) FROM control_plane.environments")), 1)

    def test_new_action_and_cleanup_pin_consumed_derived_output_without_install_confirmation(self):
        from time import monotonic, sleep
        from control_plane.plugins.fake import FAKE_MANIFEST, FakePlugin
        from control_plane.plugins.sdk import ExecutionResult

        class EnvironmentPlugin(FakePlugin):
            def execute(self, call, ctx):
                if call.resolved_input.get("install"):
                    ref = ctx.secrets.derive("login")
                    return ExecutionResult("succeeded", output={"credential": ref.to_dict()})
                if call.secret_refs:
                    with ctx.secrets.get(call.secret_refs[0]) as handle:
                        if not handle.reveal():
                            raise RuntimeError("missing environment credential")
                return ExecutionResult("succeeded", output={"completed": True})

        def settled(job):
            until = monotonic() + 10
            while monotonic() < until:
                self.runtime.poll()
                with self.runtime.fenced_transaction() as uow:
                    row = uow.execute(text("""
                        SELECT environment_id,state,execution_snapshot FROM control_plane.jobs WHERE id=:id
                    """), {"id": job}).one()
                if row.state not in ("queued", "running"):
                    self.assertEqual(row.state, "succeeded")
                    return row
                sleep(0.01)
            self.fail("credential workflow did not finish")

        services = self.runtime.services
        services.registry.register(EnvironmentPlugin(), FAKE_MANIFEST, code_digest="credential-test")
        with self.runtime.fenced_transaction() as uow:
            ids = {alias: uow.scalar(text("""
                INSERT INTO control_plane.plugin_instances(plugin_key,instance_alias) VALUES ('fake',:alias) RETURNING id
            """), {"alias": alias}) for alias in ("issuer", "other")}
        for instance in ids.values():
            services.configuration.put(instance, {"data": {}, "allowed_secret_refs": []}, expected_revision=0)

        created_ref = {"$ref": "environment.create_results.install.credential"}
        resource_ref = {"$ref": "resource.data.credential"}

        def step(name, args, instance="issuer"):
            return {"id": name, "plugin_instance": instance, "action": "echo", "input": args, "timeout_seconds": 5}

        def action(ref, instance="issuer", parameters=None):
            return {"roles": ["teacher"], "label": "use", "parameters": parameters or {},
                    "steps": [step("use", {"secret_refs": [ref]}, instance)]}

        env_action = action(created_ref)
        definition = {"schema_version": 1, "metadata": {"name": "credential"}, "parameters": {},
                      "quota": self.cost, "create": {"steps": [step("install", {"install": True})]},
                      "actions": {"use": env_action, "other": action(created_ref, "other")},
                      "resources": [{"key": "entry", "name": "entry", "type_label": "example",
                                     "data": {"credential": {"$ref": "steps.install.output.credential"}},
                                     "actions": {"use": action(resource_ref)}}],
                      "access": {}, "cleanup": {"steps": env_action["steps"], "completion": {"require_steps": ["use"]}},
                      "readiness": {"require_steps": ["install"]}}
        _, version = services.templates.create_draft(self.admin, definition)
        services.templates.publish(self.admin, version)
        job, _ = self.business.create_environment(self.teacher, course_id=self.course, template_version_id=version,
            request_key="create-derived", parameters={}, name="derived")
        env = settled(job).environment_id
        with self.runtime.fenced_transaction() as uow:
            resource = uow.scalar(text("SELECT id FROM control_plane.experiment_resources WHERE environment_id=:env"),
                                  {"env": env})
            source = uow.execute(text("""
                SELECT v.secret_id,v.id AS version_id,g.source_operation_id AS operation_id
                FROM control_plane.job_secret_refs g JOIN control_plane.secret_versions v ON v.id=g.secret_version_id
                WHERE g.job_id=:job AND g.derived
            """), {"job": job}).one()
            self.assertEqual(uow.scalar(text("""
                SELECT count(*) FROM control_plane.environment_credential_confirmations WHERE environment_id=:env
            """), {"env": env}), 0)
        with self.assertRaises(AuthorizationDenied):
            self.business.run_action(self.teacher, environment_id=env, action_key="other",
                                     parameters={}, request_key="wrong-instance")
        unproven = services.secrets.create(b"fixture", purpose="environment", environment_id=env)
        for forged_env, forged_ref in ((env, unproven.to_dict()), (uuid4(), {
                "secret_id": str(source.secret_id), "version_id": str(source.version_id)})):
            with self.assertRaises(AuthorizationDenied), self.runtime.fenced_transaction() as uow:
                services.configuration.capture_in(uow, ids["issuer"], services.secrets, forged_env,
                    template_credentials=[{"step": "use", "path": "resource.data.credential", "ref": forged_ref}])
        for kind, resource_id in (("environment", None), ("resource", resource)):
            action_job, _ = self.business.run_action(self.teacher, environment_id=env, action_key="use",
                                      parameters={}, request_key=kind, resource_id=resource_id)
            pin = settled(action_job).execution_snapshot["plugins"][str(ids["issuer"])]
            self.assertEqual(pin["secret_refs"], [{"secret_id": str(source.secret_id), "version_id": str(source.version_id)}])
            self.assertEqual(pin["template_credentials"][0]["source_operation_id"], str(source.operation_id))
            with self.assertRaises(AuthorizationDenied):
                services.secrets.bind(action_job, ids["issuer"], env).resolve({"secret_id": str(source.secret_id)})
        cleanup, _ = self.business.cleanup(self.teacher, environment_id=env, request_key="cleanup-derived")
        pin = settled(cleanup).execution_snapshot["plugins"][str(ids["issuer"])]
        self.assertEqual(pin["template_credentials"][0]["source_job_id"], str(job))

    def test_credential_inheritance_inspects_only_the_selected_stored_value(self):
        from control_plane.business import _template_credentials
        ref = {"secret_id": str(uuid4()), "version_id": str(uuid4())}
        step = {"id": "use", "plugin_instance": "issuer", "input": {
            "from_caller": {"$ref": "action_params.ref"}, "literal": ref, "count": {"$expr": {"length": [{"$ref": "resource.data.unused"}]}}, "whole": {"$ref": "resource.data.unspecific"}}}
        requests = _template_credentials([step], {"issuer": "instance"}, {"create_results": {}}, {"data": {"unspecific": {"nested": ref}, "unused": ref}})
        self.assertEqual(requests, {"instance": [{"step": "use", "path": "resource.data.unspecific/nested", "ref": ref}]})
        step["for_each"] = {"items": [{"boxed": {"$ref": "resource.data.fixed"}}] * 2, "max_items": 2}
        step["input"] = {"$ref": "item.boxed.credential"}
        requests = _template_credentials([step], {"issuer": "instance"}, {"create_results": {}},
                                        {"data": {"fixed": {"credential": ref}}})
        self.assertEqual(requests, {"instance": [{"step": "use", "path": "resource.data.fixed.credential", "ref": ref}]})
