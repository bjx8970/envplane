"""Crash windows, stale generation fencing and explicit recovery CAS on PostgreSQL."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier
import unittest
from unittest import mock
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from control_plane.config import RuntimeSettings
from control_plane.execution import Repository, JobLeaseLost, ExecutionConflict, InvalidTransition
from control_plane.execution.driver import ExecutionDriver, DriverSettings
from control_plane.plugins.sdk import PreparedCall, ExecutionPolicy, ExecutionResult, CancelResult
from control_plane.runtime import ControlPlaneRuntime
from tests_control_plane.test_p2_execution import P2DatabaseCase, FakeLifecycle, FakeQuota, FakeProjector


class RecoveryTests(P2DatabaseCase):
    def test_crash_before_dispatch_recovers_prepared_without_new_operation(self):
        op = self.prepared()
        old = self.lease
        self.expire()
        recovered = self.repo.recover_expired("recovery", limit=8)
        lease = next(r for r in recovered if r.job_id == self.job)
        self.assertNotEqual(lease.token, old.token)
        self.assertGreater(lease.group_revision, old.group_revision)
        self.assertEqual(self.row("operations", op["id"])["state"], "prepared")
        self.assertIsNone(self.row("operations", op["id"])["dispatch_intent_at"])
        with self.assertRaises(JobLeaseLost):
            self.repo.begin_call(old, op["id"], "execute", 10)
        call = self.repo.begin_call(lease, op["id"], "execute", 10)
        self.assertEqual(call.operation_id, op["id"])

    def test_crash_after_intent_unknown_blocks_and_retains_scope_and_quota(self):
        op, call = self.dispatched()
        self.expire()
        self.repo.recover_expired("recovery", limit=8)
        self.assertEqual(self.row("jobs", self.job)["state"], "blocked")
        self.assertEqual(self.row("job_steps", self.step)["state"], "blocked")
        self.assertEqual(self.row("operations", op["id"])["state"], "unknown")
        self.assertEqual(self.row("quota_reservations", self.reservation)["state"], "quarantined")
        self.assertEqual(self.row("execution_groups", self.group)["state"], "blocked")
        with self.engine.connect() as c:
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.conflict_protections WHERE execution_group_id=:group AND released_at IS NULL"), {"group": self.group}), 1)
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.operation_call_attempts WHERE operation_id=:op"), {"op": op["id"]}), 1)

    def test_pending_external_recovery_polls_original_identity_not_execute(self):
        op, call = self.dispatched(ExecutionPolicy(recovery="queryable"))
        self.complete(call, ExecutionResult("pending_external", external_execution_ref={"task": "fixed"}))
        self.expire()
        lease = next(r for r in self.repo.recover_expired("recovery") if r.job_id == self.job)
        poll = self.repo.begin_call(lease, op["id"], "poll", 5)
        self.assertEqual(poll.operation_id, op["id"])
        self.assertEqual(self.row("operations", op["id"])["external_execution_ref"], {"task": "fixed"})
        with self.assertRaises(InvalidTransition):
            self.repo.begin_call(lease, op["id"], "execute", 10)

    def test_same_old_token_cannot_gain_authority_under_new_coordinator(self):
        op, call = self.dispatched()
        old_lease = self.lease
        old_expiry = self.row("jobs", self.job)["lease_expires_at"]
        self.runtime.stop()
        replacement = ControlPlaneRuntime(RuntimeSettings.from_env({"CONTROL_PLANE_DATABASE_URL": self.runtime_url}))
        replacement.start()
        self.addCleanup(replacement.stop)
        repo = Repository(replacement)
        # The Job token/expiry are unchanged and still valid in DB. Only the
        # coordinator generation changed: this is the dangerous ABA regression.
        self.assertEqual(self.row("jobs", self.job)["lease_expires_at"], old_expiry)
        self.assertNotEqual(replacement.coordinator_identity[0], old_lease.coordinator_owner)
        with self.assertRaises(JobLeaseLost):
            repo.heartbeat(old_lease)
        status = repo.record_result(old_lease, call.id, ExecutionResult("succeeded", {"late": True}),
                                    projector=self.projector, applicator=self.applicator)
        self.assertEqual(status, "late_evidence")
        self.assertEqual(self.row("operations", op["id"])["state"], "running")
        self.assertEqual(self.row("job_steps", self.step)["state"], "running")
        self.assertEqual(self.row("quota_reservations", self.reservation)["state"], "reserved")
        self.assertEqual(self.row("execution_groups", self.group)["state"], "active")
        with self.engine.connect() as c:
            evidence = c.execute(text("SELECT call_attempt_id,event_digest,observed_at,data FROM control_plane.operation_evidence WHERE operation_id=:op AND event_id=:event"), {"op": op["id"], "event": "result:" + str(call.id)}).one()
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.experiment_resources WHERE environment_id=:env"), {"env": self.env}), 0)
        self.assertEqual(evidence.call_attempt_id, call.id)
        self.assertTrue(evidence.event_digest)
        self.assertIsNotNone(evidence.observed_at)
        self.assertEqual(evidence.data["output"], {"late": True})
        repo.recover_expired("startup-scan", limit=8)
        self.assertEqual(self.row("operations", op["id"])["state"], "unknown")
        self.assertEqual(self.row("jobs", self.job)["state"], "blocked")
        self.assertEqual(self.row("quota_reservations", self.reservation)["state"], "quarantined")
        with self.engine.connect() as c:
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.operation_call_attempts WHERE operation_id=:op"), {"op": op["id"]}), 1)

    def _blocked_with_success_evidence(self):
        op, call = self.dispatched()
        self.expire()
        self.repo.recover_expired("scanner")
        evidence = self.repo.append_evidence(call.id, "late_result", "result:" + str(call.id),
            ExecutionResult("succeeded", {"confirmed": True}).to_dict(), event_id="result:" + str(call.id))
        self.expire()  # Force DB expiry, no sleeps or elapsed-time assumptions.
        return op, call, evidence

    def test_two_recoverers_revision_cas_has_one_winner(self):
        op, _, evidence = self._blocked_with_success_evidence()
        revision = self.row("execution_groups", self.group)["revision"]
        barrier = Barrier(2)
        def takeover(owner):
            barrier.wait(timeout=5)
            try:
                return self.repo.takeover_blocked(self.job, owner, expected_revision=revision,
                    evidence_id=evidence, actor_id=self.actor, reason="confirmed original result")
            except ExecutionConflict:
                return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(takeover, ("recovery-a", "recovery-b")))
        self.assertEqual(sum(r is not None for r in results), 1)
        winner = next(r for r in results if r)
        self.assertEqual(winner.group_revision, revision + 1)
        self.assertEqual(self.row("operations", op["id"])["state"], "unknown")

    def test_saved_success_replays_local_products_without_execute(self):
        op, call, evidence = self._blocked_with_success_evidence()
        revision = self.row("execution_groups", self.group)["revision"]
        lease = self.repo.takeover_blocked(self.job, "recovery", expected_revision=revision,
            evidence_id=evidence, actor_id=self.actor, reason="validated original result")
        self.assertEqual(self.repo.replay_result(lease, evidence, projector=self.projector, applicator=self.applicator), "applied")
        self.assertEqual(self.row("operations", op["id"])["state"], "succeeded")
        self.assertEqual(self.row("job_steps", self.step)["output"], {"confirmed": True})
        with self.engine.connect() as c:
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.operation_call_attempts WHERE operation_id=:op"), {"op": op["id"]}), 1)
            audit = c.scalar(text("SELECT data FROM control_plane.audit_events WHERE operation_id=:op AND action='execution.adopt_result'"), {"op": op["id"]})
        self.assertEqual(audit["source_call_attempt_id"], str(call.id))

    def test_unknown_mutation_cannot_be_reexecuted_by_new_operation_or_new_token(self):
        op, call, evidence = self._blocked_with_success_evidence()
        lease = self.repo.takeover_blocked(self.job, "recovery", expected_revision=self.row("execution_groups", self.group)["revision"],
            evidence_id=evidence, actor_id=self.actor, reason="manual observation")
        with self.assertRaises(InvalidTransition):
            self.repo.begin_call(lease, op["id"], "execute", 5, retry_of_call_id=call.id)
        self.assertEqual(self.row("operations", op["id"])["state"], "unknown")

    def test_recovery_explicit_idempotent_retry_retains_original_invocation_and_deadline(self):
        op, call = self.dispatched(ExecutionPolicy(idempotency="keyed"))
        original = self.row("operations", op["id"])
        self.expire()
        self.repo.recover_expired("scanner")
        evidence = self.repo.append_evidence(call.id, "checkpoint", "lookup", {"checked": True})
        self.expire()
        lease = self.repo.takeover_blocked(self.job, "recovery", expected_revision=self.row("execution_groups", self.group)["revision"],
            evidence_id=evidence, actor_id=self.actor, reason="reliable keyed protocol")
        with self.engine.begin() as c:
            c.execute(text("UPDATE control_plane.jobs SET available_at=clock_timestamp()+interval '1 hour' WHERE id=:job"), {"job": self.job})
        with self.assertRaises(InvalidTransition):
            self.repo.begin_call(lease, op["id"], "execute", 5, retry_of_call_id=call.id)
        with self.engine.begin() as c:
            c.execute(text("UPDATE control_plane.jobs SET available_at=clock_timestamp()-interval '1 second' WHERE id=:job"), {"job": self.job})
        retry = self.repo.begin_call(lease, op["id"], "execute", 5, retry_of_call_id=call.id)
        self.assertLessEqual(retry.deadline_at, original["deadline_at"])
        current = self.row("operations", op["id"])
        self.assertEqual(current["invocation_key"], original["invocation_key"])
        self.assertEqual(current["deadline_at"], original["deadline_at"])
        self.assertEqual(current["state"], "unknown")
        self.assertEqual(self.row("operation_call_attempts", retry.id)["retry_of_call_id"], call.id)

    def test_expired_original_execute_budget_cannot_be_refreshed_by_keyed_recovery(self):
        op = self.prepared(ExecutionPolicy(idempotency="keyed"))
        call_id = uuid4()
        # Seed the exact crash boundary with an already-ended original budget.
        # Both dispatch fields are assigned ONCE, preserving the real DB guard.
        with self.engine.begin() as c:
            c.execute(text("UPDATE control_plane.operations SET state='running',dispatch_intent_at=clock_timestamp()-interval '3 seconds',deadline_at=clock_timestamp()-interval '1 second' WHERE id=:op"), {"op": op["id"]})
            c.execute(text("""INSERT INTO control_plane.operation_call_attempts
                (id,operation_id,method,job_lease_owner,job_lease_token,coordinator_owner,
                 coordinator_revision,created_at,deadline_at)
                VALUES (:id,:op,'execute',:owner,:token,:coordinator,:revision,
                        clock_timestamp()-interval '3 seconds',clock_timestamp()-interval '1 second')"""),
                {"id": call_id, "op": op["id"], "owner": self.lease.owner, "token": self.lease.token,
                 "coordinator": self.lease.coordinator_owner, "revision": self.lease.coordinator_revision})
        self.expire()
        self.repo.recover_expired("scanner")
        evidence = self.repo.append_evidence(call_id, "checkpoint", "lookup", {"checked": True})
        self.expire()
        lease = self.repo.takeover_blocked(self.job, "recovery", expected_revision=self.row("execution_groups", self.group)["revision"],
            evidence_id=evidence, actor_id=self.actor, reason="bounded keyed recovery")
        with self.engine.begin() as c:
            c.execute(text("UPDATE control_plane.jobs SET available_at=clock_timestamp()-interval '1 second' WHERE id=:job"), {"job": self.job})
        with self.assertRaises(InvalidTransition):
            self.repo.begin_call(lease, op["id"], "execute", 30, retry_of_call_id=call_id)
        with self.engine.connect() as c:
            self.assertEqual(c.scalar(text("SELECT count(*) FROM control_plane.operation_call_attempts WHERE operation_id=:op"), {"op": op["id"]}), 1)
        self.assertEqual(self.row("operations", op["id"])["state"], "unknown")

    def test_cross_operation_evidence_cannot_be_recovery_permission(self):
        _, call = self.dispatched()
        self.expire()
        self.repo.recover_expired("scanner")
        self.expire()
        with self.assertRaises(ExecutionConflict):
            self.repo.takeover_blocked(self.job, "recovery", expected_revision=self.row("execution_groups", self.group)["revision"],
                evidence_id=uuid4(), actor_id=self.actor, reason="not owned evidence")

    def test_scan_limit_is_hard_bound_and_never_requeues_dispatched_calls(self):
        op, _ = self.dispatched()
        self.expire()
        self.repo.recover_expired("scanner", limit=1)
        self.assertEqual(self.row("jobs", self.job)["state"], "blocked")
        self.assertEqual(self.row("operations", op["id"])["state"], "unknown")
        for invalid in (0, -1, 1001):
            with self.assertRaises(ValueError):
                self.repo.recover_expired("scanner", limit=invalid)

    def test_explicit_cancel_confirmed_is_not_quota_cleanup_confirmation(self):
        op, _ = self.dispatched(ExecutionPolicy(cancellation="requestable"))
        self.repo.request_cancel(self.job)
        call = self.repo.begin_call(self.lease, op["id"], "cancel", 5)
        self.repo.record_cancel(self.lease, call.id, CancelResult("confirmed_cancelled"))
        self.assertEqual(self.row("operations", op["id"])["state"], "cancelled")
        self.assertEqual(self.row("jobs", self.job)["state"], "cancelled")
        self.assertEqual(self.row("quota_reservations", self.reservation)["state"], "quarantined")
        self.assertEqual(self.row("execution_groups", self.group)["state"], "active")

    def test_undispatched_cancel_never_fakes_remote_cleanup(self):
        op = self.prepared()
        self.repo.request_cancel(self.job)
        self.repo.cancel_undispatched(self.lease)
        self.assertEqual(self.row("jobs", self.job)["state"], "cancelled")
        self.assertEqual(self.row("operations", op["id"])["state"], "cancelled")
        # P3 adapter decides safe reservation release; kernel does not release
        # existing occupancy merely from the absence of dispatch in THIS job.
        self.assertEqual(self.row("quota_reservations", self.reservation)["state"], "reserved")


class DriverBudgetTests(unittest.TestCase):
    def test_settings_reject_unbounded_deadline_queue_and_bad_heartbeat(self):
        for kwargs in ({"execute_seconds": float("inf")}, {"max_jobs": 0},
                       {"scan_limit": 1001}, {"heartbeat_seconds": 15, "lease_seconds": 30}):
            with self.assertRaises(ValueError):
                DriverSettings(**kwargs)

    def test_noncooperating_handle_remains_tracked_after_timeout(self):
        from control_plane.plugins.sdk import Deadline
        from datetime import datetime, timedelta, timezone
        class Handle:
            def done(self): return False
        repo = mock.Mock()
        context = mock.Mock()
        driver = ExecutionDriver(repo, mock.Mock(), mock.Mock(), context)
        lease = mock.Mock()
        lease.job_id = uuid4()
        call_id = uuid4()
        driver._calls[str(call_id)] = {"handle": Handle(), "lease": lease,
            "step": {"id": uuid4()}, "stage": "execute", "attempt": mock.Mock(id=call_id),
            "deadline": Deadline.from_at(datetime.now(timezone.utc)-timedelta(seconds=1)), "timed_out": False}
        driver._leases[str(lease.job_id)] = lease
        driver.tick()  # stopped driver still harvests facts, but does not claim.
        self.assertIn(str(call_id), driver._calls)
        self.assertTrue(driver._calls[str(call_id)]["timed_out"])
        repo.block.assert_called_once_with(lease, call_id, "call_deadline_exceeded")
        driver.tick()
        repo.block.assert_called_once()
        self.assertNotIn(str(lease.job_id), driver._leases)

    def _ticking_driver(self, repo):
        capacity = mock.Mock()
        driver = ExecutionDriver(repo, capacity, mock.Mock(), mock.Mock())
        driver.start()
        repo.recover_expired.return_value = []
        repo.candidate_instances.return_value = []
        repo.claim.return_value = None
        return driver

    def test_job_fault_is_isolated_and_other_jobs_still_advance(self):
        """A scope conflict on one job must never terminate the coordinator."""
        repo = mock.Mock()
        conflicting, healthy = mock.Mock(job_id=uuid4()), mock.Mock(job_id=uuid4())
        calls = []
        driver = self._ticking_driver(repo)
        def advance(lease):
            calls.append(lease.job_id)
            if lease is conflicting:
                raise ExecutionConflict("scope has unresolved execution")
        driver._advance = advance
        driver._leases = {str(conflicting.job_id): conflicting, str(healthy.job_id): healthy}
        repo.block_job.side_effect = ExecutionConflict("already blocked")
        driver.tick()  # Must not raise despite the repeated-block conflict.
        self.assertEqual(set(calls), {conflicting.job_id, healthy.job_id})
        # Only the failing job is dropped; the healthy one keeps advancing.
        self.assertNotIn(str(conflicting.job_id), driver._leases)
        self.assertIn(str(healthy.job_id), driver._leases)
        repo.block_job.assert_called_once()

    def test_global_fault_still_propagates(self):
        repo = mock.Mock()
        lease = mock.Mock(job_id=uuid4())
        driver = self._ticking_driver(repo)
        def advance(_lease):
            raise DBAPIError("SELECT 1", {}, Exception("connection lost"))
        driver._advance = advance
        driver._leases = {str(lease.job_id): lease}
        with self.assertRaises(DBAPIError):
            driver.tick()

    def _cancelling_driver(self, cancellation_result, *, prior_cancels=0):
        lease = mock.Mock(job_id=uuid4(), token=uuid4())
        operation = {"id": uuid4(), "state": "pending_external", "protocol_error": None,
                     "prepared_call": PreparedCall("run", execution_policy=ExecutionPolicy(
                         cancellation="requestable", recovery="queryable")).to_dict(),
                     "step_id": uuid4(), "dispatch_intent_at": "set",
                     "cancellation_result": cancellation_result, "plugin_instance_id": uuid4()}
        job = {"cancel_requested_at": "set", "available_at": 0, "database_now": 1,
               "execution_snapshot": {}}
        repo = mock.Mock()
        repo.view.return_value = (job, [{"id": operation["step_id"], "step_path": "s", "item_key": "",
                                         "state": "waiting_external", "input": {}, "output": None}], [operation])
        repo.saved_success.return_value = None
        repo.method_call_count.return_value = prior_cancels
        repo.latest_call.return_value = {"id": uuid4()} if prior_cancels else None
        driver = ExecutionDriver(repo, mock.Mock(), mock.Mock(), mock.Mock())
        driver._accepting = False
        chosen = []
        driver._submit_operation = lambda *a, **k: chosen.append(a[4])
        return driver, lease, chosen

    def test_settled_cancellation_switches_from_cancel_to_poll(self):
        """A delivered or late cancellation must not repeat forever."""
        for settled in ("requested", "too_late"):
            with self.subTest(cancellation_result=settled):
                driver, lease, chosen = self._cancelling_driver(settled)
                driver._advance(lease)
                self.assertEqual(chosen, ["poll"])

    def test_open_cancellation_still_requests_cancel(self):
        driver, lease, chosen = self._cancelling_driver(None)
        driver._advance(lease)
        self.assertEqual(chosen, ["cancel"])

    def test_unsupported_cancellation_polls_the_original_task(self):
        """A plugin declaring "unsupported" must not be asked again and again."""
        driver, lease, chosen = self._cancelling_driver("unsupported", prior_cancels=1)
        driver._advance(lease)
        self.assertEqual(chosen, ["poll"])

    def test_unknown_cancellation_retry_is_bounded_then_polls(self):
        driver, lease, chosen = self._cancelling_driver("unknown", prior_cancels=1)
        driver._advance(lease)
        self.assertEqual(chosen, ["cancel"], "one retry is allowed")
        driver, lease, chosen = self._cancelling_driver(
            "unknown", prior_cancels=DriverSettings().max_cancel_attempts)
        driver._advance(lease)
        self.assertEqual(chosen, ["poll"], "retries are bounded, polling wins")

    def test_no_safe_path_persists_block_instead_of_only_dropping_the_lease(self):
        """An unrecoverable dispatched operation must become blocked, not vanish."""
        lease = mock.Mock(job_id=uuid4(), token=uuid4())
        operation = {"id": uuid4(), "state": "pending_external", "protocol_error": None,
                     "prepared_call": PreparedCall("run", execution_policy=ExecutionPolicy(
                         cancellation="unsupported", recovery="unsupported")).to_dict(),
                     "step_id": uuid4(), "dispatch_intent_at": "set",
                     "cancellation_result": None, "plugin_instance_id": uuid4()}
        job = {"cancel_requested_at": None, "available_at": 0, "database_now": 1,
               "execution_snapshot": {}}
        repo = mock.Mock()
        repo.view.return_value = (job, [{"id": operation["step_id"], "step_path": "s", "item_key": "",
                                         "state": "waiting_external", "input": {}, "output": None}], [operation])
        repo.saved_success.return_value = None
        repo.latest_call.return_value = {"id": uuid4()}
        driver = ExecutionDriver(repo, mock.Mock(), mock.Mock(), mock.Mock())
        driver._accepting = False
        driver._leases = {str(lease.job_id): lease}
        driver._advance(lease)
        repo.block.assert_called_once()
        self.assertEqual(repo.block.call_args[0][2], "no_safe_recovery_path")
        self.assertNotIn(str(lease.job_id), driver._leases)
