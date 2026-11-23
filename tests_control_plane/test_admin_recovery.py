"""Administrator recovery through the web, durable queue and original execution."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier, Event
from time import monotonic, sleep
from unittest import TestCase
from unittest.mock import patch
from uuid import uuid4

from sqlalchemy import text

from control_plane.execution.repository import ExecutionConflict
from control_plane.plugins.capacity import CapacityRejected
from control_plane.plugins.sdk import Deadline, ExecutionResult
from control_plane.runtime import ControlPlaneRuntime
from tests_control_plane.test_p5_terminal import TerminalFixture


class AdminRecoveryTests(TerminalFixture, TestCase):
    def block(self):
        response = self.student.post(self.env_url + "/actions/confirm", json={"request_key": str(uuid4())})
        job = self.wait_job(self.student, response, expected="blocked")
        path = "/api/admin/blocked-jobs/" + job["job_id"]
        response = self.admin.get(path)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotIn("opaque-fixture", response.text)
        detail = response.json()
        self.assertTrue(detail["recoverable"])
        operation, = detail["operations"]
        self.assertTrue(operation["has_external_reference"])
        self.assertTrue(operation["can_poll"])
        with self.runtime.fenced_transaction() as db:
            db.execute(text("""
                UPDATE control_plane.jobs SET lease_expires_at=clock_timestamp() - interval '1 second'
                WHERE id=:job
            """), {"job": job["job_id"]})
        return path, detail, operation["operation_id"]

    @staticmethod
    def payload(job, operation, *, action="poll", reason="check_remote_status", **fields):
        return {"action": action, "reason": reason, "operation_id": operation, "request_key": str(uuid4()),
                "expected_revision": job["group_revision"], **fields}

    def wait_for(self, condition, limit=4):
        end = monotonic() + limit
        while monotonic() < end:
            self.runtime.poll()
            value = condition()
            if value:
                return value
            sleep(.025)
        self.fail("recovery did not reach the expected state")

    def disposition(self, path, request_id):
        reply = self.admin.get(path)
        self.assertEqual(reply.status_code, 200, reply.text)
        return next(request for request in reply.json()["requests"] if request["request_id"] == request_id)

    def confirm(self, path, job, operation, evidence):
        detail_path = path + "/evidence/" + evidence
        review = self.payload(job, operation, action="review", reason="evidence_reviewed", evidence_id=evidence)
        self.assertEqual(self.admin.post(path + "/recovery", json=review).status_code, 409)
        self.assertEqual(self.student.get(detail_path).status_code, 403)
        detail = self.admin.get(detail_path)
        self.assertEqual(detail.status_code, 200, detail.text)
        self.assertNotIn("opaque-fixture", detail.text)
        self.assertEqual(detail.json()["outcome"], "succeeded")
        self.assertEqual(detail.json()["output"]["type"], "object")
        self.assertRegex(detail.json()["output"]["fingerprint"], r"^[a-f0-9]{32}$")
        self.assertNotIn("confirmed", detail.text)
        accepted = self.admin.post(path + "/recovery", json=review)
        self.assertEqual(accepted.status_code, 200, accepted.text)
        return accepted.json()["request_id"]

    def test_authorized_review_idempotency_and_single_poll(self):
        path, job, operation = self.block()
        self.assertEqual(self.admin.get("/api/admin/blocked-jobs").json()["jobs"][0]["job_id"], job["job_id"])
        status = self.admin.get("/api/admin/operations/status").json()
        self.assertEqual(status["status"], "ready")
        self.assertGreater(status["coordinator"]["revision"], 0)
        self.assertIn("overdue", status["capacity"]["lanes"]["control"])
        mutation = path + "/recovery"
        request = self.payload(job, operation)
        for client in (self.student, self.teacher):
            self.assertEqual(client.get(path).status_code, 403)
            self.assertEqual(client.get("/api/admin/operations/status").status_code, 403)
            self.assertEqual(client.post(mutation, json=request).status_code, 403)
        self.assertEqual(self.admin.post(mutation, headers={"X-CSRF-Token": "wrong"}, json=request).status_code, 403)
        self.assertEqual(self.admin.post(mutation, headers={"Origin": "https://elsewhere.test"}, json=request).status_code, 403)
        self.assertEqual(self.admin.post(mutation, json={**request, "operation_id": str(uuid4())}).status_code, 409)
        review = self.payload(job, operation, action="review", reason="evidence_inconclusive")
        self.assertEqual(self.admin.post(mutation, json=review).status_code, 200)
        self.assertTrue(self.admin.post(mutation, json=review).json()["replayed"])
        queued = self.admin.post(mutation, json=request)
        self.assertEqual(queued.status_code, 202, queued.text)
        key = queued.json()["request_id"]
        self.assertEqual(self.admin.post(mutation, json=request).json()["request_id"], key)
        different = self.payload(job, operation)
        self.assertEqual(self.admin.post(mutation, json=different).status_code, 409)
        self.wait_for(lambda: self.disposition(path, key)["outcome"] == "remote_succeeded")
        self.assertEqual(self.admin.get(path).json()["state"], "succeeded")
        self.assertTrue(self.admin.post(mutation, json=request).json()["replayed"])
        self.assertEqual(self.admin.post(mutation, json=different).status_code, 409)
        self.assertEqual([method for method, _ in self.ssh.recovery_calls], ["execute", "poll"])
        self.assertEqual(len({invocation for _, invocation in self.ssh.recovery_calls}), 1)
        with self.runtime.fenced_transaction() as db:
            self.assertEqual(db.scalar(text("""
                SELECT count(*) FROM control_plane.audit_events
                WHERE job_id=:job AND action='execution.admin_recovery'
            """), {"job": job["job_id"]}), 3)

    def test_concurrent_requests_and_local_application_use_original_evidence(self):
        path, job, operation = self.block()
        repo = self.runtime.services.driver.repository
        original = repo.latest_call(operation)
        evidence = repo.append_evidence(original["id"], "late_result", "test-confirmed",
                                       ExecutionResult("succeeded", output={"confirmed": True}).to_dict())
        bad = repo.append_evidence(original["id"], "late_result", "test-invalid",
                                    ExecutionResult("succeeded", output={"confirmed": False}).to_dict())
        bad_request = self.payload(job, operation, action="apply_result", reason="apply_verified_result",
                                   evidence_id=str(bad))
        self.assertEqual(self.admin.post(path + "/recovery", json=bad_request).status_code, 400)
        bad_request["confirmed_review_id"] = self.confirm(path, job, operation, str(bad))
        rejected = self.admin.post(path + "/recovery", json=bad_request)
        self.assertEqual(rejected.status_code, 202, rejected.text)
        self.wait_for(lambda: self.disposition(path, rejected.json()["request_id"])["state"] == "blocked")
        job = self.admin.get(path).json()
        payload = self.payload(job, operation, action="apply_result", reason="apply_verified_result",
                               evidence_id=str(evidence), confirmed_review_id=bad_request["confirmed_review_id"])
        self.assertEqual(self.admin.post(path + "/recovery", json=payload).status_code, 409)
        payload["confirmed_review_id"] = self.confirm(path, job, operation, str(evidence))
        barrier = Barrier(2)

        def submit(_):
            barrier.wait()
            try:
                request = {**payload, "request_key": str(uuid4())}
                return self.runtime.services.recovery.submit(self.users["admin"], job["job_id"], **request)[0]
            except ExecutionConflict:
                return None

        with ThreadPoolExecutor(2) as pool:
            winners = [result for result in pool.map(submit, range(2)) if result is not None]
        self.assertEqual(len(winners), 1)
        self.wait_for(lambda: self.disposition(path, str(winners[0]))["outcome"] == "result_applied")
        self.assertEqual(self.admin.get(path).json()["state"], "succeeded")
        self.assertEqual([method for method, _ in self.ssh.recovery_calls], ["execute"])
        with self.runtime.fenced_transaction() as db:
            audit_review = db.scalar(text("""
                SELECT data->>'confirmed_review_id' FROM control_plane.audit_events
                WHERE job_id=:job AND operation_id=:op AND action='execution.admin_recovery'
                  AND result='result_applied'
            """), {"job": job["job_id"], "op": operation})
            self.assertEqual(audit_review, payload["confirmed_review_id"])

    def test_pending_and_revocation_never_dispatch_another_call(self):
        path, job, operation = self.block()
        self.ssh.poll_override = lambda: ExecutionResult("pending_external")
        result = self.admin.post(path + "/recovery", json=self.payload(job, operation))
        self.assertEqual(result.status_code, 202, result.text)
        self.wait_for(lambda: self.disposition(path, result.json()["request_id"])["outcome"] == "remote_still_pending")
        job = self.admin.get(path).json()
        self.assertEqual(job["state"], "blocked")
        self.assertEqual(job["group_state"], "blocked")
        queued = self.admin.post(path + "/recovery", json=self.payload(job, operation))
        self.assertEqual(queued.status_code, 202, queued.text)
        self.assertEqual(self.teacher.request("DELETE", self.assignment, json={}).status_code, 200)
        self.wait_for(lambda: self.disposition(path, queued.json()["request_id"])["state"] == "blocked")
        self.assertEqual([method for method, _ in self.ssh.recovery_calls], ["execute", "poll"])
        with self.runtime.fenced_transaction() as db:
            self.assertTrue(db.scalar(text("""
                SELECT EXISTS (SELECT FROM control_plane.conflict_protections p
                    JOIN control_plane.jobs j ON j.execution_group_id=p.execution_group_id
                    WHERE j.id=:job AND p.released_at IS NULL)
            """), {"job": job["job_id"]}))

    def test_periodic_tick_claims_a_recovery_without_notification(self):
        path, job, operation = self.block()
        with patch("control_plane.execution.recovery.notify_jobs") as wake:
            result = self.admin.post(path + "/recovery", json=self.payload(job, operation))
        self.assertEqual(result.status_code, 202, result.text)
        wake.assert_called_once()
        self.assertEqual(self.disposition(path, result.json()["request_id"])["state"], "queued")
        self.wait_for(lambda: self.disposition(path, result.json()["request_id"])["outcome"] == "remote_succeeded")

    def test_poll_updates_reference_and_handles_both_null_representations(self):
        path, job, operation = self.block()

        def poll_pending(ref):
            self.ssh.poll_override = lambda: ExecutionResult("pending_external", external_execution_ref=ref)
            job = self.admin.get(path).json()
            result = self.admin.post(path + "/recovery", json=self.payload(job, operation))
            self.assertEqual(result.status_code, 202, result.text)
            self.wait_for(lambda: self.disposition(path, result.json()["request_id"])["outcome"] == "remote_still_pending")

        poll_pending({"id": "updated-reference"})
        poll_pending(None)
        self.assertEqual(self.ssh.recovery_references, [{"id": "opaque-fixture-reference"}, {"id": "updated-reference"}])
        with self.runtime.fenced_transaction() as db:
            self.assertTrue(db.scalar(text("""
                SELECT EXISTS (SELECT FROM control_plane.operation_evidence WHERE operation_id=:op
                    AND kind='late_result' AND data #>> '{external_execution_ref,id}'='opaque-fixture-reference')
            """), {"op": operation}))
        for null in ("NULL", "'null'::jsonb"):
            with self.subTest(null=null):
                with self.runtime.fenced_transaction() as db:
                    db.execute(text(f"UPDATE control_plane.operations SET external_execution_ref={null} WHERE id=:op"),
                               {"op": operation})
                self.assertFalse(self.admin.get(path).json()["operations"][0]["has_external_reference"])
                poll_pending(None)
                self.assertIsNone(self.ssh.recovery_references[-1])
                with self.runtime.fenced_transaction() as db:
                    self.assertTrue(db.scalar(text(
                        "SELECT external_execution_ref IS NULL FROM control_plane.operations WHERE id=:op"
                    ), {"op": operation}))

    def test_control_capacity_keeps_request_queued_and_retries_proven_rejection(self):
        path, job, operation = self.block()
        capacity = self.runtime.services.capacity
        with self.runtime.fenced_transaction() as db:
            instance = db.scalar(text("SELECT plugin_instance_id FROM control_plane.operations WHERE id=:op"),
                                 {"op": operation})
        gate = Event()
        self.addCleanup(gate.set)
        fillers = [capacity.submit(str(instance), lambda: gate.wait(4), lane="control",
                                   deadline_at=Deadline.after(4).expires_at)
                   for _ in range(capacity.settings.instance_limit)]
        queued = self.admin.post(path + "/recovery", json=self.payload(job, operation))
        self.assertEqual(queued.status_code, 202, queued.text)
        key = queued.json()["request_id"]
        self.runtime.poll()
        self.assertEqual(self.disposition(path, key)["state"], "queued")
        self.assertEqual(self.admin.get(path).json()["group_revision"], job["group_revision"])
        gate.set()
        for handle in fillers:
            end = monotonic() + 2
            while not handle.done() and monotonic() < end:
                sleep(.02)
            self.assertTrue(handle.done())
        with patch.object(capacity, "submit", side_effect=CapacityRejected()):
            self.runtime.poll()
        self.assertEqual(self.disposition(path, key)["state"], "queued")
        self.assertEqual([method for method, _ in self.ssh.recovery_calls], ["execute"])
        self.wait_for(lambda: self.disposition(path, key)["outcome"] == "remote_succeeded")
        self.assertEqual([method for method, _ in self.ssh.recovery_calls], ["execute", "poll"])
        with self.runtime.fenced_transaction() as db:
            self.assertTrue(db.scalar(text("""
                SELECT EXISTS (SELECT FROM control_plane.audit_events WHERE job_id=:job
                    AND action='execution.admin_recovery' AND result='dispatch_not_started'
                    AND data->>'request_id'=:id AND data->>'call_attempt_id' IS NOT NULL)
            """), {"job": job["job_id"], "id": key}))

    def test_local_constraint_rollback_retains_poll_evidence(self):
        path, job, operation = self.block()
        driver = self.runtime.services.driver

        def reject_projection(uow, _operation, _output):
            uow.execute(text("""
                INSERT INTO control_plane.audit_events(action,result,data) VALUES ('test','test','[]'::jsonb)
            """))

        with patch.object(driver.applicator, "apply", side_effect=reject_projection):
            result = self.admin.post(path + "/recovery", json=self.payload(job, operation))
            self.assertEqual(result.status_code, 202, result.text)
            self.wait_for(lambda: self.disposition(path, result.json()["request_id"])["state"] == "blocked")
        job = self.admin.get(path).json()
        self.assertEqual(job["state"], "blocked")
        self.assertEqual(job["operations"][0]["state"], "unknown")
        evidence, = [record for record in job["evidence"] if record["can_apply"]]
        request = self.payload(job, operation, action="apply_result", reason="apply_verified_result",
                               evidence_id=evidence["evidence_id"],
                               confirmed_review_id=self.confirm(path, job, operation, evidence["evidence_id"]))
        applied = self.admin.post(path + "/recovery", json=request)
        self.assertEqual(applied.status_code, 202, applied.text)
        self.wait_for(lambda: self.disposition(path, applied.json()["request_id"])["outcome"] == "result_applied")
        self.assertEqual([method for method, _ in self.ssh.recovery_calls], ["execute", "poll"])

    def test_timeout_keeps_capacity_and_late_result_is_evidence_only(self):
        path, job, operation = self.block()
        driver = self.runtime.services.driver
        driver.settings = replace(driver.settings, poll_seconds=.25)
        gate = Event()
        self.addCleanup(gate.set)

        def delayed():
            gate.wait(3)
            return ExecutionResult("succeeded", output={"confirmed": True})

        self.ssh.poll_override = delayed
        result = self.admin.post(path + "/recovery", json=self.payload(job, operation))
        self.assertEqual(result.status_code, 202, result.text)
        self.wait_for(lambda: self.disposition(path, result.json()["request_id"])["outcome"] == "call_deadline_exceeded")
        status = self.admin.get("/api/admin/operations/status")
        self.assertEqual(status.status_code, 200, status.text)
        self.assertEqual(status.json()["status"], "degraded")
        control = status.json()["capacity"]["lanes"]["control"]
        self.assertEqual((control["active"], control["overdue"]), (1, 1))
        self.assertTrue(status.json()["capacity"]["manual_restart_required"])
        gate.set()
        self.wait_for(lambda: any(row["can_apply"] for row in self.admin.get(path).json()["evidence"]))
        self.assertEqual(self.admin.get(path).json()["state"], "blocked")
        self.assertEqual([method for method, _ in self.ssh.recovery_calls], ["execute", "poll"])

    def test_restart_retains_committed_poll_intent_without_resubmission(self):
        path, job, operation = self.block()
        result = self.admin.post(path + "/recovery", json=self.payload(job, operation))
        self.assertEqual(result.status_code, 202, result.text)
        service = self.runtime.services.recovery
        request, lease = service.claim("crash-window", 30, ())
        intent = service.repository.begin_call(lease, operation, "poll", 2, recovery_id=request["id"])
        settings = self.runtime.settings
        self.runtime.stop()
        self.runtime = ControlPlaneRuntime(settings)
        self.addCleanup(self.runtime.stop)
        self.runtime.start()
        self.runtime.poll()
        with self.runtime.fenced_transaction() as db:
            recovery = db.execute(text("""
                SELECT state,outcome,call_attempt_id FROM control_plane.execution_recovery_requests WHERE id=:id
            """), {"id": request["id"]}).one()
            self.assertEqual((recovery.state, recovery.outcome, recovery.call_attempt_id),
                             ("blocked", "recovery_interrupted", intent.id))
            self.assertEqual(db.scalar(text("SELECT state FROM control_plane.jobs WHERE id=:id"),
                                       {"id": job["job_id"]}), "blocked")
        self.assertEqual([method for method, _ in self.ssh.recovery_calls], ["execute"])
