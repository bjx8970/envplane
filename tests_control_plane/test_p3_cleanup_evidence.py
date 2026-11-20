import unittest
from uuid import uuid4

from sqlalchemy import text

from control_plane.business import _evidence
from control_plane.plugins.sdk import canonical_json
from control_plane.workflows import TemplateWorkflow
from tests_control_plane.test_p2_storage import ServicesFixture


class CleanupEvidenceTests(ServicesFixture, unittest.TestCase):
    def insert_job(self, uow, kind, state, flow):
        return uow.scalar(text("""
            INSERT INTO control_plane.jobs
                (environment_id,execution_group_id,actor_id,request_key,request_digest,kind,input,execution_snapshot,state)
            VALUES (:env,:group,:actor,:key,'test',:kind,'{}',CAST(:snapshot AS jsonb),:state) RETURNING id
        """), {"env": self.environment, "group": self.group, "actor": self.teacher, "key": uuid4().hex,
               "kind": kind, "state": state, "snapshot": canonical_json({"workflow": flow})})

    def test_unexpanded_cleanup_can_iterate_frozen_operation_and_ref_after_reload(self):
        with self.lease.fenced_transaction() as uow:
            source = self.insert_job(uow, "create", "failed", {
                "steps": [{"id": "provision"}, {"id": "per_host"}, {"id": "never_started"}]})
            self.configurations.pin_job_in(uow, source, self.instance, self.secrets)
        ops = {}
        for path, key in (("provision", ""), ("per_host", "unexpanded")):
            with self.lease.fenced_transaction() as uow:
                step = uow.scalar(text("""
                    INSERT INTO control_plane.job_steps(job_id,step_path,item_key)
                    VALUES (:job,:path,:key) RETURNING id
                """), {"job": source, "path": path, "key": key})
            op, _ = self.source(source, step, {}, state="failed")
            ops[path] = str(op)
            with self.lease.fenced_transaction() as uow:
                uow.execute(text("""
                    INSERT INTO control_plane.operation_evidence(operation_id,kind,ref_key,revision,data)
                    VALUES (:op,'external_ref','vm',1,CAST(:ref AS jsonb))
                """), {"op": op, "ref": canonical_json({"id": path + "-vm"})})

        with self.lease.fenced_transaction() as uow:
            evidence = _evidence(uow, self.environment)
            # This is also the evidence shape stored before the addressable view existed.
            self.assertNotIn("unexpanded", evidence)
            self.assertIn("", evidence["steps"]["provision"])
            cleanup_step = {
                "id": "release", "action": "echo", "plugin_instance": "fake", "timeout_seconds": 5,
                "for_each": {"items": {"$ref": "evidence.unexpanded.provision.operations"},
                             "item_key": {"$ref": "item.operation_id"}, "max_items": 3},
                "input": {"target": {"$ref": "item.external_refs.vm.reference.id"},
                          "expanded": {"$ref": "evidence.steps.per_host.unexpanded.operations"},
                          "skipped": {"$ref": "evidence.unexpanded.never_started.operations"}},
            }
            cleanup = self.insert_job(uow, "cleanup", "queued", {
                "instances": {"fake": str(self.instance)}, "steps": [cleanup_step], "evidence": evidence})

        with self.lease.fenced_transaction() as uow:
            stored = uow.scalar(text("SELECT execution_snapshot FROM control_plane.jobs WHERE id=:job"), {"job": cleanup})
        planned, = TemplateWorkflow().plan_steps(stored, [])
        self.assertEqual(planned["item_key"], ops["provision"])
        values = planned["input"]["input"]
        self.assertEqual(values["target"], "provision-vm")
        self.assertEqual(values["expanded"][0]["operation_id"], ops["per_host"])
        self.assertEqual(values["skipped"], [])
        self.assertEqual(stored["workflow"]["evidence"], evidence)
