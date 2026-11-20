"""P5 transport contracts over PostgreSQL and actual loopback SSH PTY channels."""
from contextlib import ExitStack
from time import monotonic, sleep
from unittest import TestCase

import paramiko
from sqlalchemy import text
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from control_plane.plugins.sessions import SessionConflict
from control_plane.runtime import ControlPlaneRuntime
from control_plane.web import create_app
from tests_control_plane.p5_fixture import PASSWORD, environment, template

ORIGIN = "https://terminal.test"


class TerminalTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.host_key = paramiko.RSAKey.generate(2048)

    def setUp(self):
        self.runtime, self.ssh, self.users = self.enterContext(environment(self.host_key))
        self.app = create_app(self.runtime, ORIGIN)
        self.admin, self.teacher, self.student, self.other = (
            self.client(user) for user in ("admin", "teacher", "student", "other")
        )
        for plugin, alias, data in (("p5_fixture", "fixture", {"terminal": self.ssh.target_ref}),
                                    ("ssh_terminal", "terminal", {})):
            result = self.admin.post("/api/admin/plugins", json={
                "plugin_key": plugin, "instance_alias": alias, "configuration": {"data": data, "allowed_secret_refs": []},
            })
            self.assertEqual(result.status_code, 200, result.text)
        draft = self.admin.post("/api/templates", json={"definition": template()})
        self.assertEqual(draft.status_code, 201, draft.text)
        version = draft.json()["version_id"]
        published = self.admin.post(f"/api/templates/{version}/publish", json={})
        self.assertEqual(published.status_code, 200, published.text)
        course = self.teacher.post("/api/courses", json={"owner_teacher_id": self.users["teacher"], "name": "Course"})
        self.assertEqual(course.status_code, 200, course.text)
        course_url = "/api/courses/" + course.json()["id"]
        self.assertEqual(self.teacher.post(course_url + "/members/" + self.users["student"], json={}).status_code, 200)
        candidates = self.teacher.get(course_url + "/templates/" + version + "/candidates")
        self.assertEqual(candidates.json(), {"endpoint": [{"value": "echo", "label": "Loopback echo"}]})
        job = self.teacher.post("/api/environments", json={
            "course_id": course.json()["id"], "template_version_id": version, "name": "Test lab",
            "request_key": "create", "parameters": {"endpoint": "echo", "note": "A lab only"},
        })
        record = self.wait_job(self.teacher, job)
        self.env = record["environment_id"]
        self.env_url = "/api/environments/" + self.env
        self.access_url = self.env_url + "/access/shell"
        self.assertEqual(self.student.post(self.access_url, json={"request_key": "denied"}).status_code, 403)
        assignment = self.teacher.post(self.env_url + "/assignments", json={"student_id": self.users["student"]})
        self.assertEqual(assignment.status_code, 200, assignment.text)
        self.assignment = "/api/assignments/" + assignment.json()["id"]

    def client(self, username, app=None):
        client = self.enterContext(TestClient(app or self.app, base_url=ORIGIN))
        initial = client.get("/api/session").json()
        client.headers.update({"X-CSRF-Token": initial["csrf_token"], "Origin": ORIGIN})
        response = client.post("/api/login", json={"username": username, "password": PASSWORD})
        self.assertEqual(response.status_code, 200, response.text)
        client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
        return client

    def wait_job(self, client, response, expected="succeeded"):
        self.assertEqual(response.status_code, 202, response.text)
        url = response.headers["Location"]
        end = monotonic() + 8
        while monotonic() < end:
            self.runtime.poll()
            job = client.get(url).json()
            if job["state"] in {"failed", "succeeded", "blocked", "cancelled"}:
                if job["state"] != expected:
                    with self.runtime.fenced_transaction() as db:
                        reason = db.scalar(text("SELECT error->>'code' FROM control_plane.jobs WHERE id=:id"),
                                           {"id": job["job_id"]})
                    self.fail(f"expected {expected}, got {job['state']} ({reason})")
                return job
            sleep(.04)
        self.fail("Job did not reach the expected terminal state")

    def open(self):
        response = self.student.post(self.access_url, json={"request_key": "open"})
        job = self.wait_job(self.student, response)
        self.assertIsNotNone(job["session_id"])
        self.assertEqual(self.student.post(self.access_url, json={"request_key": "open"}).status_code, 202)
        return job["session_id"]

    def ws(self, client, session, origin=ORIGIN, *, after=None):
        suffix = "" if after is None else f"?after={after}"
        return client.websocket_connect("wss://terminal.test/realtime/sessions/" + session + suffix,
                                        headers={"Origin": origin}, subprotocols=["lab-terminal"])

    def frame(self, socket, kind, **keys):
        for _ in range(20):
            item = socket.receive_json()
            if item["type"] == kind and all(item.get(k) == v for k, v in keys.items()):
                return item
        self.fail(f"terminal did not emit expected {kind} frame")

    def test_browser_authorization_pty_observe_takeover_release_and_revocation(self):
        info = self.student.get(self.env_url).json()
        self.assertEqual(info["resources"][0]["state"], "unknown")
        self.assertNotIn("target_ref", info["resources"][0])
        resource = info["resources"][0]["id"]
        action = self.student.post(f"/api/resources/{resource}/actions/observe", json={"request_key": "probe"})
        self.wait_job(self.student, action)
        observed = self.student.get(f"/api/resources/{resource}").json()
        self.assertEqual(observed["state"], "online")
        self.assertIsNotNone(observed["observed_at"])
        credential_url = self.env_url + "/credentials/" + info["credentials"][0]["id"]
        credential = self.student.post(credential_url, json={})
        self.assertEqual(credential.status_code, 200, credential.text)
        self.assertEqual(credential.headers["Cache-Control"], "no-store")
        self.assertEqual(credential.json()["value"], self.ssh.password)
        self.assertEqual(self.other.post(credential_url, json={}).status_code, 403)
        self.assertEqual(self.student.post(self.access_url, json={"request_key": "bad", "target_ref": {}}).status_code, 400)
        self.assertEqual(self.teacher.post(self.access_url, json={"request_key": "undeclared_role"}).status_code, 403)

        session = self.open()
        for client, origin in ((self.student, "https://terminal.test.evil"), (self.other, ORIGIN)):
            with self.assertRaises(WebSocketDisconnect):
                with self.ws(client, session, origin):
                    pass

        base = "/api/terminal-sessions/" + session
        with self.ws(self.student, session, after=0) as student, self.ws(self.teacher, session, after=0) as teacher:
            self.frame(student, "control", can_input=True, epoch=0)
            self.frame(teacher, "control", can_input=False, epoch=0)
            self.frame(student, "output", data="Ready for lab input\r\n")
            self.frame(teacher, "output", data="Ready for lab input\r\n")
            teacher.send_json({"type": "input", "epoch": 0, "data": "blocked"})
            self.frame(teacher, "transport_error", code="read_only")
            student.send_json({"type": "resize", "epoch": 0, "cols": 100, "rows": 28})
            self.assertTrue(self.ssh.resized.wait(3))
            student.send_json({"type": "input", "epoch": 0, "data": "student line"})
            self.frame(teacher, "output", data="student line")
            self.assertEqual(self.other.post(base + "/takeover", json={"epoch": 0}).status_code, 403)
            self.assertEqual(self.teacher.post(base + "/takeover", json={"epoch": 0}).status_code, 200)
            self.frame(student, "control", can_input=False, epoch=1)
            self.frame(teacher, "control", can_input=True, epoch=1)
            student.send_json({"type": "input", "epoch": 0, "data": "still blocked"})
            self.frame(student, "transport_error", code="read_only")
            teacher.send_json({"type": "input", "epoch": 1, "data": "teacher line"})
            self.frame(student, "output", data="teacher line")
            self.frame(teacher, "output", data="teacher line")
            self.assertEqual(self.teacher.post(base + "/release", json={"epoch": 1}).status_code, 200)
            self.frame(student, "control", can_input=True, epoch=2)
            self.frame(teacher, "control", can_input=False, epoch=2)
            self.assertEqual(self.ssh.received, b"student lineteacher line")
            self.assertEqual(self.teacher.request("DELETE", self.assignment, json={}).status_code, 200)
            for viewer in (student, teacher):
                # A controller-state frame can already be in transit when the
                # revoke commits. No further terminal output may be delivered.
                with self.assertRaises(WebSocketDisconnect):
                    for _ in range(4):
                        self.assertNotEqual(viewer.receive_json()["type"], "output")

        self.assertEqual(self.student.post(credential_url, json={}).status_code, 403)
        self.assertEqual(self.student.post(self.access_url, json={"request_key": "reopen"}).status_code, 403)
        history = self.teacher.get(self.env_url + "/sessions").json()[0]
        self.assertEqual((history["state"], history["reason"]["code"]), ("disconnected", "access_revoked"))
        self.assertEqual(self.teacher.get(self.env_url).json()["revocations"][0]["status"], "revocation_failed")
        with self.runtime.fenced_transaction() as db:
            audit = db.scalars(text("""SELECT action FROM control_plane.audit_events
                WHERE action IN ('session.takeover','session.release','credential.view','http.authorization')
            """)).all()
        self.assertIn("session.takeover", audit)
        self.assertIn("session.release", audit)
        self.assertIn("credential.view", audit)
        self.assertIn("http.authorization", audit)
        cleanup = self.teacher.post(self.env_url + "/cleanup", json={"request_key": "cleanup"})
        self.wait_job(self.teacher, cleanup)
        self.assertEqual(self.teacher.get(self.env_url).json()["lifecycle"], "deleted")
        self.assertIsNone(self.ssh.password)

    def test_receiver_capacity_bounded_replay_and_restart_disconnect(self):
        session = self.open()
        request = self.student.post(self.access_url, json={"request_key": "second"})
        self.assertEqual(request.status_code, 503, request.text)
        service = self.runtime.services.sessions
        service.output_limit = 4096
        client = service.observe(self.users["student"], session)
        self.ssh.flood.set()
        end = monotonic() + 4
        while monotonic() < end:
            try:
                live = service._live[session]
                with live.lock:
                    if live.clients[client].disconnected:
                        break
            except KeyError:
                self.fail("terminal handle was unexpectedly lost")
            sleep(.03)
        self.ssh.flood.clear()
        with self.assertRaises(SessionConflict):
            service.poll_output(self.users["student"], session, client)
        before = bytes(self.ssh.received)
        settings = self.runtime.settings
        self.runtime.stop()
        restarted = ControlPlaneRuntime(settings)
        self.addCleanup(restarted.stop)
        restarted.start()
        after = create_app(restarted, ORIGIN)
        teacher = self.client("teacher", after)
        record = teacher.get(self.env_url + "/sessions").json()[0]
        self.assertEqual(record["state"], "disconnected")
        student = self.client("student", after)
        with self.assertRaises(WebSocketDisconnect):
            with self.ws(student, session):
                pass
        self.assertEqual(bytes(self.ssh.received), before)
