"""HTTP contracts against an isolated, least-privilege PostgreSQL runtime."""
import base64
import json
import os
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
from time import monotonic, sleep
from unittest import TestCase
from unittest.mock import patch

from sqlalchemy import text
from starlette.testclient import TestClient

from control_plane.config import RuntimeSettings
from control_plane.identity import _hash_password
from control_plane.plugins.capacity import CapacityRejected
from control_plane.plugins.sdk import PluginError
from control_plane.runtime import ControlPlaneRuntime
from control_plane.web import create_app
from tests_control_plane.p1_harness import runtime_database
from tests_control_plane.test_p2_services import deployment

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "https://lab.test"
PASSWORD = "isolated-test-password"
COST = {"environments": 2, "vms": 0, "vcpu": 0, "memory_mb": 0}
TEMPLATE = {
    "schema_version": 1, "metadata": {"name": "HTTP contract"}, "quota": COST,
    "parameters": {"note": {"type": "string", "maxLength": 25}},
    "create": {"steps": []}, "resources": [],
    "actions": {"describe": {"label": "Describe", "roles": ["student"], "parameters": {}, "steps": [
        {"id": "options", "plugin_instance": "lab", "action": "list_host_options", "input": {}, "timeout_seconds": 5}
    ]}},
    "cleanup": {"steps": [], "completion": {"no_external_cleanup_required": True}},
    "readiness": {"require_steps": []}, "access": {},
}


class HttpTests(TestCase):
    def setUp(self):
        _, url = self.enterContext(runtime_database())
        directory = self.enterContext(TemporaryDirectory())
        self.plugin_directory = Path(directory) / "packages"
        shutil.copytree(ROOT / "plugins" / "ssh", self.plugin_directory / "ssh")
        self.enterContext(patch.dict(os.environ, {
            "CONTROL_PLANE_SECRET_KEYRING": json.dumps({"test": base64.b64encode(os.urandom(32)).decode()}),
            "CONTROL_PLANE_SECRET_ACTIVE_KEY_ID": "test",
        }))
        self.runtime = ControlPlaneRuntime(RuntimeSettings.from_env({
            "CONTROL_PLANE_DATABASE_URL": url, "CONTROL_PLANE_RUNTIME_CONFIG": deployment(
                directory, plugin_directory=str(self.plugin_directory), required=["ssh"])}))
        self.addCleanup(self.runtime.stop)
        self.runtime.start()
        self.app = create_app(self.runtime, ORIGIN)
        with self.runtime.fenced_transaction() as db:
            self.admin = str(db.scalar(text("""
                INSERT INTO control_plane.users(username,role,password_hash)
                VALUES ('admin','admin',:hash) RETURNING id
            """), {"hash": _hash_password(PASSWORD)}))
        users = self.runtime.services.identity
        self.teacher = str(users.create_user(self.admin, "teacher", PASSWORD, role="teacher"))
        self.other = str(users.create_user(self.admin, "other", PASSWORD, role="teacher"))
        self.student = str(users.create_user(self.teacher, "student", PASSWORD))
        self.course = str(users.create_course(self.teacher, self.teacher, "Course"))
        users.enroll(self.teacher, self.course, self.student)
        self.runtime.services.business.set_quota(self.admin, self.teacher, limits=COST)
        self.admin_client = self.client("admin")
        instance = self.admin_client.post("/api/admin/plugins", json={
            "plugin_key": "ssh", "instance_alias": "lab", "configuration": {"data": {}, "allowed_secret_refs": []}})
        self.assertEqual(instance.status_code, 200, instance.text)
        self.instance = instance.json()["id"]
        draft = self.admin_client.post("/api/templates", json={"definition": TEMPLATE})
        self.assertEqual(draft.status_code, 201, draft.text)
        self.version = draft.json()["version_id"]
        published = self.admin_client.post(f"/api/templates/{self.version}/publish", json={})
        self.assertEqual(published.status_code, 200, published.text)
        self.teacher_client = self.client("teacher")

    def client(self, user=None):
        client = self.enterContext(TestClient(self.app, base_url=ORIGIN))
        initial = client.get("/api/session")
        client.headers.update({"Origin": ORIGIN, "X-CSRF-Token": initial.json()["csrf_token"]})
        if user:
            result = client.post("/api/login", json={"username": user, "password": PASSWORD})
            self.assertEqual(result.status_code, 200, result.text)
            client.headers["X-CSRF-Token"] = result.json()["csrf_token"]
        return client

    def create(self, **changes):
        return self.teacher_client.post("/api/environments", json={
            "course_id": self.course, "template_version_id": self.version, "name": "lab",
            "request_key": "same", "parameters": {"note": "hello"}, **changes})

    def test_cookie_login_logout_and_origin_fail_closed(self):
        client = self.client()
        self.assertEqual(client.get("/api/environments").status_code, 401)
        self.assertEqual(client.post("/api/login", headers={"Origin": ORIGIN + ".evil"},
                                    json={"username": "teacher", "password": PASSWORD}).json()["code"], "origin_denied")
        for origin in ("", "null", "http://lab.test", "https://lab.test:444", "https://lab.test/"):
            self.assertEqual(client.post("/api/login", headers={"Origin": origin}, json={}).status_code, 403)
        self.assertEqual(client.post("/api/login", headers={"X-CSRF-Token": "bad"}, json={}).json()["code"], "csrf_denied")
        self.assertEqual(client.post("/api/login", json={"username": "teacher", "password": "bad"}).status_code, 401)
        login = client.post("/api/login", json={"username": "teacher", "password": PASSWORD})
        self.assertEqual(login.status_code, 200)
        for attribute in ("httponly", "secure", "samesite=strict"):
            self.assertIn(attribute, login.headers["Set-Cookie"].lower())
        self.assertNotEqual(login.json()["csrf_token"], client.headers["X-CSRF-Token"])
        client.headers["X-CSRF-Token"] = login.json()["csrf_token"]
        self.assertEqual(client.get("/api/session").json()["user"]["role"], "teacher")
        self.assertEqual(client.post("/api/logout", json={}).status_code, 200)
        self.assertEqual(client.get("/api/environments").status_code, 401)

    def test_jobs_202_replay_409_capacity_503_and_safe_errors(self):
        storage = "/api/admin/plugins/" + self.instance + "/storage"
        self.assertEqual(self.teacher_client.put(storage, json={"key": "test", "value": {}}).status_code, 403)
        self.assertEqual(self.admin_client.put(storage, json={}).status_code, 400)
        item = self.admin_client.put(storage, json={"key": "test", "value": {"label": "safe"}})
        self.assertEqual(item.status_code, 200, item.text)
        self.assertEqual(self.admin_client.get(storage).json()[0]["version_id"], item.json()["version_id"])
        self.assertEqual(self.create(course_id=123).status_code, 400)
        self.assertEqual(self.teacher_client.get("/api/templates").json()[0]["parameters"]["note"]["type"], "string")
        original = self.create()
        self.assertEqual(original.status_code, 202, original.text)
        url = original.headers["Location"]
        self.assertEqual(url, original.json()["status_url"])
        self.assertEqual(self.create().json()["job_id"], original.json()["job_id"])
        self.assertEqual(self.create(name="different").status_code, 409)
        self.assertEqual(self.teacher_client.get(url).json()["state"], "queued")
        self.assertEqual(self.teacher_client.get(url + "/logs").json(), [])
        with patch.object(self.runtime.services.business, "create_environment",
                          side_effect=CapacityRejected("provider-password-marker")):
            unavailable = self.create(request_key="new")
            self.assertEqual(unavailable.status_code, 503)
            self.assertEqual(unavailable.json()["code"], "capacity_unavailable")
            self.assertNotIn("provider-password-marker", unavailable.text)
        with patch.object(self.runtime.services.business, "create_environment",
                          side_effect=PluginError("failure", "provider-password-marker")):
            failure = self.create()
            self.assertEqual(failure.status_code, 502)
            self.assertNotIn("provider-password-marker", failure.text)
            self.assertEqual(set(failure.json()), {"code", "message", "request_id", "details"})

    def test_assignment_is_live_and_jobs_belong_to_requester(self):
        created = self.create()
        self.assertEqual(created.status_code, 202, created.text)
        job = created.headers["Location"]
        self.runtime.poll()
        result = self.teacher_client.get(job).json()
        self.assertEqual(result["state"], "succeeded")
        env = "/api/environments/" + result["environment_id"]
        student, other = self.client("student"), self.client("other")
        self.assertEqual(student.get(env).status_code, 403)
        self.assertEqual(other.get(env).status_code, 403)
        self.assertEqual(student.get(job).status_code, 403)
        self.assertEqual(other.post(env + "/assignments", json={"student_id": self.student}).status_code, 403)
        assignment = self.teacher_client.post(env + "/assignments", json={"student_id": self.student})
        self.assertEqual(assignment.status_code, 200, assignment.text)
        self.assertEqual(student.get(env).json()["lifecycle"], "ready")
        self.assertEqual(student.get(job + "/logs").status_code, 403)
        self.assertEqual(student.post(job + "/cancel", json={}).status_code, 403)
        self.assertEqual(self.teacher_client.get(job + "/logs").json()[0]["code"], "claimed")
        self.assertEqual(student.post(env + "/cleanup", json={"request_key": "denied"}).status_code, 403)
        self.assertEqual(student.post(env + "/actions/unknown", json={"request_key": "unknown"}).status_code, 403)
        for field in ("plugin_key", "action", "target_ref"):
            result = student.post(env + "/actions/describe", json={"request_key": "forged", field: "forged"})
            self.assertEqual(result.status_code, 400)
        accepted = student.post(env + "/actions/describe", json={"request_key": "action"})
        self.assertEqual(accepted.status_code, 202, accepted.text)
        self.assertEqual(self.teacher_client.get(accepted.headers["Location"]).status_code, 403)
        self.assertEqual(self.teacher_client.post(accepted.headers["Location"] + "/cancel", json={}).status_code, 403)
        self.assertEqual(student.post(accepted.headers["Location"] + "/cancel", json={}).status_code, 202)
        revoked = self.teacher_client.request("DELETE", "/api/assignments/" + assignment.json()["id"], json={})
        self.assertEqual(revoked.status_code, 200)
        self.assertEqual(student.get(env).status_code, 403)
        self.assertEqual(student.get(accepted.headers["Location"]).status_code, 403)

    def test_rebind_upgraded_ssh_configuration_preserves_old_job_snapshot(self):
        created = self.create()
        self.assertEqual(created.status_code, 202, created.text)
        self.runtime.poll()
        environment = self.teacher_client.get(created.headers["Location"]).json()["environment_id"]
        path = "/api/environments/" + environment
        self.assertEqual(self.teacher_client.post(path + "/assignments",
                                                 json={"student_id": self.student}).status_code, 200)
        old = self.client("student").post(path + "/actions/describe", json={"request_key": "old-package"})
        self.assertEqual(old.status_code, 202, old.text)
        before = self.runtime.services.configuration.get(self.instance)
        settings = self.runtime.settings
        self.runtime.stop()
        plugin = self.plugin_directory / "ssh" / "plugin.py"
        with plugin.open("a", encoding="utf-8") as source:
            source.write("\n# Isolated package upgrade with a new code digest.\n")
        self.runtime = ControlPlaneRuntime(settings)
        self.addCleanup(self.runtime.stop)
        self.runtime.start()
        self.app = create_app(self.runtime, ORIGIN)
        admin, student = self.client("admin"), self.client("student")
        instance = admin.get("/api/admin/plugins").json()["instances"][0]
        self.assertTrue(instance["needs_rebind"])
        self.assertFalse(instance["available"])
        republish = "/api/admin/plugins/" + self.instance + "/rebind"
        self.assertEqual(student.post(republish, json={"expected_revision": before.revision}).status_code, 403)
        self.assertEqual(admin.post(republish, json={"expected_revision": before.revision + 1}).status_code, 409)
        result = admin.post(republish, json={"expected_revision": before.revision})
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(admin.post(republish, json={"expected_revision": before.revision}).status_code, 409)
        after = self.runtime.services.configuration.get(self.instance)
        self.assertEqual(after.configuration, before.configuration)
        self.assertEqual(after.revision, before.revision + 1)
        self.assertNotEqual(after.code_digest, before.code_digest)
        self.assertTrue(admin.get("/api/admin/plugins").json()["instances"][0]["available"])
        self.runtime.poll()
        self.assertEqual(student.get(old.headers["Location"]).json()["state"], "blocked")
        new = student.post(path + "/actions/describe", json={"request_key": "new-package"})
        self.assertEqual(new.status_code, 202, new.text)
        end = monotonic() + 4
        while monotonic() < end:
            self.runtime.poll()
            if student.get(new.headers["Location"]).json()["state"] == "succeeded":
                break
            sleep(.02)
        else:
            self.fail("new Job did not finish using the rebound configuration")
        with self.runtime.fenced_transaction() as db:
            snapshots = db.execute(text("""
                SELECT configuration_revision,code_digest FROM control_plane.job_plugin_snapshots
                WHERE job_id IN (:old,:new) ORDER BY configuration_revision
            """), {"old": old.json()["job_id"], "new": new.json()["job_id"]}).all()
            self.assertEqual([tuple(row) for row in snapshots],
                             [(before.revision, before.code_digest), (after.revision, after.code_digest)])
