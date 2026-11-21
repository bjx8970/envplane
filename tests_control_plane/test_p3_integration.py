"""Cross-service P3 acceptance through the deployed control plane and PostgreSQL."""
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import asdict
import io
import json
import multiprocessing
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import paramiko
from sqlalchemy import text

from control_plane.config import RuntimeSettings
from control_plane.execution.repository import ExecutionConflict
from control_plane.execution.wakeup import notify_jobs
from control_plane.plugins.capacity import CapacitySettings
from control_plane.plugins.sdk import AuthorizationDenied
from control_plane.quota import QuotaExceeded
from control_plane.runtime import ControlPlaneRuntime
from control_plane.templates import TemplateError
from control_plane.workflows import lock_evidence_environment, verify_cleanup_evidence
from tests_control_plane.p1_harness import runtime_database
from tests_control_plane.test_p2_services import deployment
from tests_control_plane.test_p2_ssh import _server

ROOT = Path(__file__).resolve().parents[1]


def ssh_example():
    spec = (ROOT / "docs/template-resource-contract.md").read_text(encoding="utf-8")
    return json.loads(spec.split("```json\n", 1)[1].split("```", 1)[0])


class BusinessIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.host_key = paramiko.RSAKey.generate(2048)
        key_text = io.StringIO()
        cls.host_key.write_private_key(key_text)
        cls.private_key = key_text.getvalue()

    def setUp(self):
        _, runtime_url = self.enterContext(runtime_database())
        directory = self.enterContext(tempfile.TemporaryDirectory())
        config = deployment(directory, plugin_directory=str(ROOT / "plugins"), required=["ssh"],
                            capacity=asdict(CapacitySettings(ordinary_workers=2, instance_limit=4)))
        self.enterContext(patch.dict(os.environ, {
            "CONTROL_PLANE_SECRET_KEYRING": json.dumps({"test": base64.b64encode(os.urandom(32)).decode()}),
            "CONTROL_PLANE_SECRET_ACTIVE_KEY_ID": "test",
        }))
        self.runtime = ControlPlaneRuntime(RuntimeSettings.from_env({
            "CONTROL_PLANE_DATABASE_URL": runtime_url,
            "CONTROL_PLANE_RUNTIME_CONFIG": config,
            "CONTROL_PLANE_LEASE_SECONDS": "180",
        }))
        self.addCleanup(self.runtime.stop)
        self.runtime.start()
        self.services = self.runtime.services
        # Deployment bootstrap supplies the initial administrator and trusted
        # SSH instance. All course, user, template and Job mutations below
        # enter through their public business services.
        with self.runtime.fenced_transaction() as tx:
            self.admin = tx.scalar(text("""INSERT INTO control_plane.users(username,password_hash,role)
                VALUES ('bootstrap','test-hash','admin') RETURNING id"""))
            self.instance = tx.scalar(text("""INSERT INTO control_plane.plugin_instances
                (instance_alias,plugin_key,created_by) VALUES ('ssh_lab','ssh',:admin) RETURNING id"""),
                {"admin": self.admin})

        self.identity = self.services.identity
        self.teacher = self.identity.create_user(self.admin, "teacher", "teacher-test-password", role="teacher")
        self.student = self.identity.create_user(self.teacher, "student", "student-test-password")
        self.course = self.identity.create_course(self.teacher, self.teacher, "First course")
        self.identity.enroll(self.teacher, self.course, self.student)
        self.business = self.services.business
        self.business.set_quota(self.admin, self.teacher,
                                limits={"environments": 1, "vms": 0, "vcpu": 0, "memory_mb": 0})
        self.secret = self.services.secrets.create(b"test-only-password", created_by=self.admin)
        self.services.configuration.put(self.instance, {
            "data": {}, "allowed_secret_refs": [self.secret.to_dict()],
        }, expected_revision=0)
        self.host = {
            "name": "isolated SSH endpoint", "hostname": "127.0.0.1", "port": 1, "username": "test",
            "host_key": {"type": self.host_key.get_name(), "base64": self.host_key.get_base64()},
            "credential": {"secret_id": self.secret.secret_id},
        }
        self.storage = self.services.storage.bind(self.instance)
        self.host_version = self.storage.put("hosts/test", self.host)
        self.storage.put("hosts/inventory-only", {"name": "Inventory entry"})
        _, self.version = self.services.templates.create_draft(self.admin, ssh_example())
        self.services.templates.publish(self.admin, self.version)

    @contextmanager
    def endpoint(self, mode="success"):
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe(duplex=False)
        process = context.Process(target=_server, args=(self.private_key, child, mode), daemon=True)
        process.start()
        child.close()
        try:
            self.assertTrue(parent.poll(8), "loopback SSH server did not start")
            updated = dict(self.host, port=parent.recv())
            self.host_version = self.storage.put("hosts/test", updated, self.host_version)
            yield
        finally:
            parent.close()
            process.join(.5)
            if process.is_alive():
                process.terminate()
            process.join(4)
            self.assertFalse(process.is_alive())
            process.close()

    def create(self, **changes):
        args = dict(course_id=self.course, template_version_id=self.version,
                    parameters={"target_host": "test"}, name="SSH lab", request_key="create")
        args.update(changes)
        return self.business.create_environment(self.teacher, **args)

    def one(self, query, **binds):
        with self.runtime.fenced_transaction() as tx:
            return tx.execute(text(query), binds).one()

    def finish(self, job, expected="succeeded"):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            self.runtime.poll()
            row = self.one("SELECT state,error,environment_id FROM control_plane.jobs WHERE id=:job", job=job)
            if row.state in {"succeeded", "blocked", "failed", "cancelled"}:
                self.assertEqual(row.state, expected, row.error)
                return row.environment_id
            time.sleep(.02)
        self.fail(f"Job {job} did not reach a terminal state in time")

    def test_job_admission_wakes_the_live_listener_only_on_commit(self):
        wakeup = self.runtime.wakeup
        self.assertTrue(wakeup.wait(3), "PostgreSQL listener did not subscribe")

        with self.assertRaisesRegex(RuntimeError, "intentional rollback"):
            with self.runtime.fenced_transaction() as tx:
                notify_jobs(tx)
                raise RuntimeError("intentional rollback")
        self.assertFalse(wakeup.wait(0.6))

        job, replay = self.create()
        self.assertFalse(replay)
        self.assertTrue(wakeup.wait(3), "committed job did not wake the runtime")
        self.assertEqual(self.create(), (job, True))
        self.assertFalse(wakeup.wait(0.6))

    def test_documented_ssh_template_runs_and_resource_access_tracks_live_assignments(self):
        self.assertEqual(self.business.list_candidates(self.teacher, self.course, self.version), {
            "target_host": [{"value": "inventory-only", "label": "Inventory entry"},
                            {"value": "test", "label": "isolated SSH endpoint"}],
        })
        with self.assertRaises(AuthorizationDenied):
            self.business.list_candidates(self.student, self.course, self.version)
        with self.assertRaises(TemplateError):
            self.create(parameters={"target_host": "missing"})
        with self.assertRaises(TemplateError):
            self.create(parameters={"target_host": "test", "command": "override"})
        with self.endpoint():
            create_job, replay = self.create()
            self.assertFalse(replay)
            env = self.finish(create_job)
        self.assertEqual(self.create(), (create_job, True))
        resource = self.one("""SELECT id,resource_slot,data,access_snapshot
            FROM control_plane.experiment_resources WHERE environment_id=:env""", env=env)
        self.assertEqual(resource.resource_slot, "report")
        self.assertEqual(resource.data, {"host_id": "test", "system": "test-output\n"})
        self.assertEqual(resource.access_snapshot, {})
        self.assertEqual(self.one("""SELECT e.lifecycle,q.state FROM control_plane.environments e
            JOIN control_plane.quota_reservations q ON q.environment_id=e.id WHERE e.id=:env""",
                                  env=env), ("ready", "allocated"))

        assignment = self.identity.assign(self.teacher, env, student_id=self.student)
        action = dict(environment_id=env, resource_id=resource.id, action_key="inspect_again",
                      parameters={}, request_key="inspect")
        with self.assertRaises(AuthorizationDenied):
            self.services.credentials.view(self.student, env, self.secret.secret_id)
        with self.assertRaises(AuthorizationDenied):
            self.business.cleanup(self.student, environment_id=env, request_key="delete")
        self.services.templates.disable(self.admin, self.version)
        with self.endpoint():
            inspect_job, replay = self.business.run_action(self.student, **action)
            self.assertFalse(replay)
            self.finish(inspect_job)
        self.identity.revoke_assignment(self.teacher, assignment)
        with self.assertRaises(AuthorizationDenied):
            self.business.run_action(self.student, **action)
        with self.assertRaises(AuthorizationDenied):
            self.business.run_action(self.student, **dict(action, request_key="inspect-new"))
        cleanup_job, replay = self.business.cleanup(self.teacher, environment_id=env, request_key="cleanup")
        self.assertFalse(replay)
        self.finish(cleanup_job)
        self.assertEqual(self.one("""SELECT e.lifecycle,q.state FROM control_plane.environments e
            JOIN control_plane.quota_reservations q ON q.environment_id=e.id WHERE e.id=:env""",
                                  env=env), ("deleted", "released"))

    def test_competing_courses_share_the_teachers_last_environment(self):
        second = self.identity.create_course(self.teacher, self.teacher, "Second course")
        gate = threading.Barrier(2)

        def reserve(course):
            gate.wait(5)
            try:
                job, replay = self.create(course_id=course, request_key=str(course))
            except QuotaExceeded:
                return None
            self.assertFalse(replay)
            return job

        with ThreadPoolExecutor(max_workers=2) as pool:
            jobs = list(pool.map(reserve, (self.course, second)))
        self.assertEqual(sum(job is not None for job in jobs), 1)
        self.assertEqual(self.one("""SELECT count(*),sum(environments) FROM control_plane.quota_reservations
            WHERE teacher_id=:teacher AND state='reserved'""", teacher=self.teacher), (1, 1))
        self.assertEqual(self.one("""SELECT count(*) FROM control_plane.environments
            WHERE owner_teacher_id=:teacher""", teacher=self.teacher)[0], 1)
        self.assertEqual(self.one("SELECT count(*) FROM control_plane.jobs")[0], 1)

    def test_skipped_required_cleanup_does_not_retire_environment_or_release_quota(self):
        definition = ssh_example()
        cleanup_step = dict(definition["create"]["steps"][0], id="remove", for_each={
            "items": [], "item_key": {"$ref": "item"}, "max_items": 2})
        definition["cleanup"] = {"steps": [cleanup_step], "completion": {"require_steps": ["remove"]}}
        _, version = self.services.templates.create_draft(self.admin, definition)
        self.services.templates.publish(self.admin, version)
        with self.endpoint():
            creation, _ = self.create(template_version_id=version)
            env = self.finish(creation)
        self.assertEqual(self.one("""SELECT count(*) FROM control_plane.operations
            WHERE job_id=:job AND state='succeeded' AND dispatch_intent_at IS NOT NULL""", job=creation), (1,))
        cleanup, _ = self.business.cleanup(self.teacher, environment_id=env, request_key="skipped-cleanup")
        self.finish(cleanup, expected="failed")
        self.assertEqual(self.one("SELECT state FROM control_plane.job_steps WHERE job_id=:job", job=cleanup),
                         ("skipped",))
        self.assertEqual(self.one("SELECT count(*) FROM control_plane.operations WHERE job_id=:job", job=cleanup),
                         (0,))
        self.assertEqual(self.one("""SELECT e.lifecycle,e.deleted_at,q.state,
                (SELECT count(*) FROM control_plane.conflict_protections
                 WHERE scope_key=:scope AND released_at IS NULL)
            FROM control_plane.environments e JOIN control_plane.quota_reservations q ON q.environment_id=e.id
            WHERE e.id=:env""", env=env, scope="environment:" + str(env)),
                         ("delete_failed", None, "quarantined", 1))

    def test_unknown_ssh_execution_keeps_quota_even_with_declared_empty_cleanup(self):
        with self.endpoint("disconnect"):
            job, _ = self.create()
            env = self.finish(job, expected="blocked")
        self.assertEqual(self.one("""SELECT e.lifecycle,q.state FROM control_plane.environments e
            JOIN control_plane.quota_reservations q ON q.environment_id=e.id WHERE e.id=:env""",
                                  env=env), ("blocked", "quarantined"))
        self.assertEqual(self.one("""SELECT count(*) FROM control_plane.experiment_resources
            WHERE environment_id=:env""", env=env)[0], 0)
        with self.assertRaises(ExecutionConflict):
            self.business.cleanup(self.teacher, environment_id=env, request_key="uncertain-cleanup")
        with self.assertRaises(QuotaExceeded):
            self.create(request_key="second")
        self.assertEqual(self.one("SELECT count(*) FROM control_plane.jobs")[0], 1)

    def test_output_expansion_and_generated_resources_use_the_fixed_job_inventory(self):
        definition = ssh_example()
        inventory = {"id": "inventory", "plugin_instance": "ssh_lab", "action": "list_host_options",
                     "input": {}, "timeout_seconds": 10}
        loop = {"items": {"$ref": "steps.inventory.output"}, "item_key": {"$ref": "item.id"}, "max_items": 4}
        definition["parameters"] = {}
        definition["create"]["steps"] = [
            inventory,
            dict(inventory, id="check", depends_on=["inventory"], for_each=loop),
        ]
        definition["resources"] = [{"key": "entry", "for_each": loop, "name": {"$ref": "item.name"},
                                    "type_label": "Inspection record", "data": {"host": {"$ref": "item.id"}}}]
        definition["readiness"] = {"require_steps": ["inventory", "check"], "require_resources": ["entry"]}
        _, version = self.services.templates.create_draft(self.admin, definition)
        self.services.templates.publish(self.admin, version)
        job, _ = self.create(template_version_id=version, parameters={})
        self.storage.put("hosts/after-admission", {"name": "Later inventory entry"})
        env = self.finish(job)
        with self.runtime.fenced_transaction() as tx:
            steps = tx.execute(text("""SELECT item_key,expansion FROM control_plane.job_steps
                WHERE job_id=:job AND step_path='check' ORDER BY item_key"""), {"job": job}).all()
            resources = tx.execute(text("""SELECT item_key,data FROM control_plane.experiment_resources
                WHERE environment_id=:env ORDER BY item_key"""), {"env": env}).all()
        self.assertEqual([row.item_key for row in steps], ["inventory-only", "test"])
        self.assertEqual([row.expansion["item"]["id"] for row in steps], ["inventory-only", "test"])
        self.assertEqual([(row.item_key, row.data["host"]) for row in resources],
                         [("inventory-only", "inventory-only"), ("test", "test")])

    def test_revocation_after_admission_stops_an_undispatched_resource_action(self):
        with self.endpoint():
            job, _ = self.create()
            env = self.finish(job)
        resource_id = self.one(
            "SELECT id FROM control_plane.experiment_resources WHERE environment_id=:env", env=env)[0]
        assignment = self.identity.assign(self.teacher, env, student_id=self.student)
        action_id, _ = self.business.run_action(
            self.student, environment_id=env, resource_id=resource_id,
            action_key="inspect_again", parameters={}, request_key="queued-action")
        self.identity.revoke_assignment(self.teacher, assignment)
        self.finish(action_id, expected="blocked")
        self.assertEqual(self.one("""SELECT count(*) FROM control_plane.operation_call_attempts a
            JOIN control_plane.operations o ON o.id=a.operation_id WHERE o.job_id=:job""", job=action_id)[0], 0)

    def create_with_call(self):
        with self.endpoint():
            job, _ = self.create()
            env = self.finish(job)
        source = self.one("""SELECT c.id FROM control_plane.operation_call_attempts c
            JOIN control_plane.operations o ON o.id=c.operation_id WHERE o.job_id=:job AND c.method='execute'""",
                          job=job)
        return env, source.id

    def test_cleanup_snapshot_holds_environment_lock_against_independent_late_writer(self):
        env, call = self.create_with_call()
        cleanup, _ = self.business.cleanup(self.teacher, environment_id=env, request_key="cleanup")
        job = self.one("SELECT * FROM control_plane.jobs WHERE id=:id", id=cleanup)._mapping
        # Independent connection runs the same final snapshot check. Bypass the
        # process write gate *for the reader* to exercise the PostgreSQL fence.
        with ThreadPoolExecutor(max_workers=1) as pool:
            with self.runtime._engine.begin() as checking:
                verify_cleanup_evidence(checking, job, job["execution_snapshot"]["workflow"])
                future = pool.submit(self.services.driver.repository.append_evidence, call, "external_ref",
                                     "late", {"id": "remote"}, event_id="independent-late-ref")
                self.wait_for_blocked_reader(checking, future)
            self.assertIsNotNone(future.result(5))
        # The fresh finishing transaction sees the committed fact and fails
        # closed. Neither conflicts nor quota may be released using the old view.
        self.finish(cleanup, expected="blocked")
        self.assertEqual(self.one("""SELECT q.state,(SELECT count(*) FROM control_plane.conflict_protections
            WHERE scope_key=:scope AND released_at IS NULL) AS held FROM control_plane.quota_reservations q
            WHERE q.environment_id=:env""", scope="environment:"+str(env), env=env), ("quarantined", 1))

    def test_finishing_cleanup_waits_for_new_source_fact_then_rejects_its_snapshot(self):
        env, call = self.create_with_call()
        cleanup, _ = self.business.cleanup(self.teacher, environment_id=env, request_key="cleanup")
        # Separate database writer uses the same lock protocol as _append,
        # without the coordinator's process-wide gate serializing the test.
        with ThreadPoolExecutor(max_workers=1) as pool:
            with self.runtime._engine.begin() as writing:
                source = writing.execute(text("""SELECT o.job_id,o.id FROM control_plane.operations o
                    JOIN control_plane.operation_call_attempts c ON c.operation_id=o.id WHERE c.id=:id"""),
                                         {"id": call}).one()
                lock_evidence_environment(writing, source.job_id)
                writing.execute(text("""INSERT INTO control_plane.operation_evidence
                    (operation_id,kind,ref_key,revision,data) VALUES (:id,'checkpoint','delayed',1,'{}')"""),
                                {"id": source.id})
                future = pool.submit(self.finish, cleanup, expected="blocked")
                self.wait_for_blocked_reader(writing, future)
            self.assertEqual(future.result(10), env)
        self.assertEqual(self.one("""SELECT q.state,(SELECT count(*) FROM control_plane.conflict_protections
            WHERE scope_key=:scope AND released_at IS NULL) FROM control_plane.quota_reservations q
            WHERE q.environment_id=:env""", scope="environment:" + str(env), env=env), ("quarantined", 1))

    def wait_for_blocked_reader(self, connection, future):
        # pg_blocking_pids provides an observed lock wait rather than a sleep
        # used as evidence that two transactions actually overlapped.
        pid = connection.scalar(text("SELECT pg_backend_pid()"))
        end = time.monotonic() + 5
        while not connection.scalar(text("""SELECT EXISTS(SELECT FROM pg_stat_activity
                WHERE :pid=ANY(pg_blocking_pids(pid)))"""), {"pid": pid}):
            self.assertFalse(future.done(), "database operation bypassed the evidence lock")
            self.assertLess(time.monotonic(), end, "concurrent transaction did not wait for the evidence lock")
            time.sleep(.02)

    def test_late_fact_after_cleanup_commit_only_appends_deduplicated_evidence(self):
        env, call = self.create_with_call()
        repo = self.services.driver.repository
        original = repo.append_evidence(call, "checkpoint", "seen", {"n": 1}, event_id="seen")
        cleanup, _ = self.business.cleanup(self.teacher, environment_id=env, request_key="cleanup")
        self.finish(cleanup)
        self.assertEqual(repo.append_evidence(call, "checkpoint", "seen", {"n": 1}, event_id="seen"), original)
        new = repo.append_evidence(call, "external_ref", "remote", {"id": "late-id"}, event_id="unseen")
        self.assertEqual(repo.append_evidence(call, "external_ref", "remote", {"id": "late-id"},
                                              event_id="unseen"), new)
        self.assertEqual(self.one("""SELECT data,trusted_for_derivation FROM control_plane.operation_evidence
            WHERE id=:id""", id=new), ({"id": "late-id"}, False))
        self.assertEqual(self.one("""SELECT e.lifecycle,e.deleted_at IS NOT NULL,q.state,j.state,
                (SELECT count(*) FROM control_plane.conflict_protections
                   WHERE scope_key=:scope AND released_at IS NULL)
            FROM control_plane.environments e JOIN control_plane.quota_reservations q ON q.environment_id=e.id
            JOIN control_plane.jobs j ON j.environment_id=e.id AND j.id=:job WHERE e.id=:env""",
                                  env=env, job=cleanup, scope="environment:" + str(env)),
                         ("deleted", True, "released", "succeeded", 0))
