"""Durable, administrator-initiated reconciliation of the original execution."""
from sqlalchemy import text

from ..identity import active_role
from ..plugins.capacity import CapacityRejected
from ..plugins.sdk import AuthorizationDenied, ExecutionResult, PluginError, PreparedCall, canonical_json
from .repository import ExecutionConflict
from .wakeup import notify_jobs


REASONS = {
    "review": {"evidence_reviewed", "evidence_inconclusive", "external_success_declared"},
    "poll": {"check_remote_status"},
    "apply_result": {"apply_verified_result"},
}
CAPACITY_BACKOFF_SECONDS = .5


def _success_evidence(evidence):
    if evidence is None or evidence["kind"] != "late_result" or evidence["source_method"] not in ("execute", "poll"):
        raise ExecutionConflict("evidence is not a saved plugin result")
    result = ExecutionResult.from_dict(evidence["data"])
    if result.outcome != "succeeded" or result.protocol_error:
        raise ExecutionConflict("evidence is not a saved success result")


class RecoveryRequests:
    def __init__(self, repository, max_pending):
        self.repository = repository
        self.runtime = repository.runtime
        self.max_pending = max_pending

    @staticmethod
    def _admin(db, actor, *, lock=False):
        if active_role(db, actor, lock=lock) != "admin":
            raise AuthorizationDenied()

    @staticmethod
    def _job(db, job):
        return db.execute(text("""
            SELECT j.*,g.revision AS group_revision,g.current_job_id,g.state AS group_state,
                   clock_timestamp() AS database_now
            FROM control_plane.jobs j JOIN control_plane.execution_groups g ON g.id=j.execution_group_id
            WHERE j.id=:job FOR UPDATE OF j,g
        """), {"job": job}).mappings().first()

    @staticmethod
    def _operation(db, job, operation):
        return db.execute(text("""
            SELECT o.*,s.input AS step_input,s.current_operation_id
            FROM control_plane.operations o JOIN control_plane.job_steps s ON s.id=o.step_id
            WHERE o.id=:op AND o.job_id=:job
        """), {"op": operation, "job": job}).mappings().first()

    @staticmethod
    def _evidence(db, operation, evidence):
        return db.execute(text("""
            SELECT e.*, c.method AS source_method
            FROM control_plane.operation_evidence e
            LEFT JOIN control_plane.operation_call_attempts c ON c.id=e.call_attempt_id
                AND c.operation_id=e.operation_id
            WHERE e.id=:evidence AND e.operation_id=:op
        """), {"op": operation, "evidence": evidence}).mappings().first()

    def _validate(self, db, job, request):
        action = request["action"]
        revision = request.get("queue_revision", request["expected_revision"])
        if job is None or job["state"] != "blocked" or job["group_revision"] != revision:
            raise ExecutionConflict("blocked Job changed")
        operation_id, evidence_id = request["operation_id"], request["evidence_id"]
        operation = self._operation(db, job["id"], operation_id) if operation_id is not None else None
        evidence = self._evidence(db, operation_id, evidence_id) if evidence_id is not None else None
        if (operation_id is not None and operation is None) or (evidence_id is not None and evidence is None):
            raise ExecutionConflict("evidence or Operation does not belong to the Job")
        if action == "review":
            if request["reason"] == "external_success_declared":
                _success_evidence(evidence)
            if evidence_id is not None and request["reason"] != "evidence_inconclusive" and not db.scalar(text("""
                SELECT EXISTS (SELECT FROM control_plane.audit_events
                    WHERE job_id=:job AND operation_id=:op AND actor_id=:actor AND action='execution.evidence_view'
                      AND data->>'evidence_id'=:evidence AND data->>'group_revision'=:revision)
            """), {"job": job["id"], "op": operation_id, "actor": request["actor_id"],
                   "evidence": str(evidence_id), "revision": str(revision)}):
                raise ExecutionConflict("open the current evidence detail before recording the review")
            return
        if (job["kind"] == "session_open" or job["group_state"] != "blocked"
                or job["current_job_id"] != job["id"] or operation is None
                or operation["current_operation_id"] != operation["id"]
                or operation["state"] not in ("unknown", "pending_external")
                or operation["dispatch_intent_at"] is None):
            raise ExecutionConflict("Operation is not eligible for recovery")
        self.repository._authorize(db, job)
        if db.scalar(text("""
            SELECT EXISTS (SELECT FROM control_plane.operations
                WHERE job_id=:job AND id<>:op AND state IN ('unknown','pending_external','running'))
        """), {"job": job["id"], "op": operation_id}):
            raise ExecutionConflict("execution has more than one unresolved operation")
        prepared = PreparedCall.from_dict(operation["prepared_call"])
        if action == "poll":
            if operation["protocol_error"] is not None or prepared.execution_policy.recovery != "queryable":
                raise ExecutionConflict("Operation cannot be queried")
            if not db.scalar(text("""
                SELECT EXISTS (SELECT FROM control_plane.operation_call_attempts
                               WHERE operation_id=:op AND method='execute')
            """), {"op": operation_id}):
                raise ExecutionConflict("original invocation has no committed attempt")
        else:
            _success_evidence(evidence)
            if not db.scalar(text("""
                SELECT EXISTS (SELECT FROM control_plane.execution_recovery_requests
                    WHERE id=:review AND job_id=:job AND operation_id=:op AND evidence_id=:evidence
                      AND actor_id=:actor AND expected_revision=:revision AND action='review'
                      AND reason='external_success_declared' AND state='completed'
                      AND verification->>'conclusion'='confirmed_succeeded')
            """), {"review": request["confirmed_review_id"], "job": job["id"], "op": operation_id,
                   "evidence": evidence_id, "actor": request["actor_id"],
                   "revision": request["expected_revision"]}):
                raise ExecutionConflict("the same administrator must record external success for this evidence and revision")

    @staticmethod
    def _audit(db, request, environment, result):
        verification = request["verification"]
        audit_verification = ({key: value for key, value in verification.items() if key != "key_id"}
                              if verification is not None else None)
        db.execute(text("""
            INSERT INTO control_plane.audit_events
                (actor_id,environment_id,job_id,operation_id,action,result,data)
            VALUES (:actor,:env,:job,:op,'execution.admin_recovery',:result,
                    jsonb_build_object('request_id',CAST(:id AS uuid),'action',CAST(:action AS text),
                        'reason',CAST(:reason AS text),'evidence_id',CAST(:evidence AS uuid),
                        'expected_revision',CAST(:revision AS bigint),'confirmed_review_id',CAST(:review AS uuid),
                        'call_attempt_id',CAST(:call AS uuid),'verification',CAST(:verification AS jsonb)))
        """), {"actor": request["actor_id"], "env": environment, "job": request["job_id"],
               "op": request["operation_id"], "id": request["id"], "action": request["action"],
               "reason": request["reason"], "evidence": request["evidence_id"],
               "revision": request["expected_revision"], "review": request["confirmed_review_id"],
               "call": request["call_attempt_id"], "result": result,
               "verification": canonical_json(audit_verification) if audit_verification is not None else None})

    def submit(self, actor, job_id, *, action, reason, request_key, expected_revision,
               operation_id=None, evidence_id=None, confirmed_review_id=None, verification=None):
        if (not isinstance(action, str) or not isinstance(reason, str)
                or reason not in REASONS.get(action, ())
                or type(expected_revision) is not int or not 0 <= expected_revision < 2**63
                or request_key is None or (evidence_id is not None and operation_id is None)
                or (action != "review" and operation_id is None)
                or (action == "apply_result" and evidence_id is None)
                or ((action == "apply_result") != (confirmed_review_id is not None))
                or (action == "poll" and evidence_id is not None)
                or ((reason == "external_success_declared") != (verification is not None))
                or (verification is not None and evidence_id is None)):
            raise ValueError("invalid recovery request")
        if verification is not None:
            if (not isinstance(verification, dict)
                    or set(verification) != {"source", "method", "conclusion", "reference"}
                    or verification["source"] not in ("provider_console", "provider_api", "independent_record")
                    or verification["method"] not in ("matched_execution", "checked_resource_state", "cross_checked_records")
                    or verification["conclusion"] != "confirmed_succeeded"):
                raise ValueError("invalid external success declaration")
            reference = verification["reference"]
            if not isinstance(reference, str) or not 1 <= len(reference.strip()) <= 128 or not reference.isprintable():
                raise ValueError("invalid external verification reference")
        request = {"action": action, "reason": reason, "expected_revision": expected_revision,
                   "job_id": job_id, "operation_id": operation_id, "evidence_id": evidence_id,
                   "confirmed_review_id": confirmed_review_id}
        with self.runtime.fenced_transaction() as db:
            self._admin(db, actor, lock=True)
            previous = db.execute(text("""
                SELECT * FROM control_plane.execution_recovery_requests WHERE actor_id=:actor AND request_key=:key
            """), {"actor": actor, "key": request_key}).mappings().first()
            stored_verification = None
            if verification is not None:
                prior_verification = previous["verification"] if previous is not None else None
                key_id = prior_verification["key_id"] if prior_verification is not None else None
                stored_verification = {key: verification[key] for key in ("source", "method", "conclusion")}
                stored_verification.update(self.runtime.services.secrets.verification_reference(reference.strip(), key_id=key_id))
            if previous is not None:
                if (any(str(previous[key]) != str(value) for key, value in request.items())
                        or previous["verification"] != stored_verification):
                    raise ExecutionConflict("recovery request key has different input")
                return previous["id"], True
            job = self._job(db, job_id)
            self._validate(db, job, {**request, "actor_id": actor})
            queued = action != "review"
            review_outcome = "external_verification_declared" if verification is not None else "reviewed"
            if queued:
                if db.scalar(text("""
                    SELECT EXISTS (SELECT FROM control_plane.execution_recovery_requests
                                   WHERE group_id=:group AND state IN ('queued','running'))
                """), {"group": job["execution_group_id"]}):
                    raise ExecutionConflict("execution group already has a recovery request")
                if db.scalar(text("""
                    SELECT count(*) FROM control_plane.execution_recovery_requests
                    WHERE state IN ('queued','running')
                """)) >= self.max_pending:
                    raise CapacityRejected()
            saved = db.execute(text("""
                INSERT INTO control_plane.execution_recovery_requests
                    (job_id,group_id,actor_id,request_key,expected_revision,operation_id,evidence_id,
                     queue_revision,confirmed_review_id,verification,action,reason,state,outcome,finished_at)
                VALUES (:job_id,:group,:actor,:key,:expected_revision,:operation_id,:evidence_id,
                        :expected_revision,:confirmed_review_id,CAST(:verification AS jsonb),:action,:reason,
                        :state,CASE WHEN :queued THEN NULL ELSE CAST(:review_outcome AS text) END,
                        CASE WHEN :queued THEN NULL ELSE clock_timestamp() END)
                RETURNING *
            """), {**request, "group": job["execution_group_id"], "actor": actor, "key": request_key,
                   "state": "queued" if queued else "completed", "queued": queued,
                   "verification": canonical_json(stored_verification) if stored_verification is not None else None,
                   "review_outcome": review_outcome}).mappings().one()
            self._audit(db, saved, job["environment_id"], "accepted" if queued else review_outcome)
            if queued:
                notify_jobs(db)
            return saved["id"], False

    def claim(self, owner, seconds, busy_jobs, *, check_poll_capacity=None, limit=32):
        with self.runtime.fenced_transaction() as db:
            candidates = db.execute(text("""
                SELECT r.*,o.plugin_instance_id FROM control_plane.execution_recovery_requests r
                JOIN control_plane.jobs j ON j.id=r.job_id
                LEFT JOIN control_plane.operations o ON o.id=r.operation_id
                WHERE r.state='queued' AND NOT (j.id=ANY(CAST(:busy AS uuid[])))
                  AND (j.state<>'blocked' OR j.lease_expires_at IS NULL OR j.lease_expires_at<=clock_timestamp())
                  AND (r.deferred_until IS NULL OR r.deferred_until<=clock_timestamp())
                ORDER BY (r.action='apply_result') DESC,COALESCE(r.deferred_until,r.created_at),r.id
                LIMIT :limit FOR UPDATE OF r SKIP LOCKED
            """), {"busy": list(busy_jobs), "limit": limit}).mappings().all()
            for request in candidates:
                job = self._job(db, request["job_id"])
                try:
                    self._admin(db, request["actor_id"], lock=True)
                    self._validate(db, job, request)
                except (PluginError, ExecutionConflict, ValueError):
                    self.finish_in(db, request, job["environment_id"], "request_no_longer_eligible")
                    continue
                if request["action"] == "poll" and check_poll_capacity is not None:
                    try:
                        check_poll_capacity(str(request["plugin_instance_id"]), lane="control")
                    except CapacityRejected:
                        # Move this request behind older eligible work even after its delay expires.
                        db.execute(text("""
                            UPDATE control_plane.execution_recovery_requests
                            SET deferred_until=clock_timestamp()+make_interval(secs=>:seconds) WHERE id=:id
                        """), {"id": request["id"], "seconds": CAPACITY_BACKOFF_SECONDS})
                        continue
                lease = self.repository._takeover_in(db, job, owner, seconds)
                db.execute(text("""
                    UPDATE control_plane.execution_recovery_requests
                    SET state='running',active_revision=:revision,coordinator_revision=:coordinator,
                        deferred_until=NULL WHERE id=:id
                """), {"id": request["id"], "revision": lease.group_revision,
                       "coordinator": lease.coordinator_revision})
                return dict(request), lease
            return None

    def guard_in(self, db, request_id, lease, operation_id, action, *, call_id=None):
        request = db.execute(text("""
            SELECT * FROM control_plane.execution_recovery_requests WHERE id=:id FOR UPDATE
        """), {"id": request_id}).mappings().first()
        if (request is None or request["state"] != "running"
                or str(request["job_id"]) != str(lease.job_id)
                or str(request["operation_id"]) != str(operation_id) or request["action"] != action
                or request["active_revision"] != lease.group_revision
                or request["coordinator_revision"] != lease.coordinator_revision
                or str(request["call_attempt_id"]) != str(call_id)):
            raise ExecutionConflict("recovery request no longer owns this operation")
        self._admin(db, request["actor_id"], lock=True)
        return request

    def verify_dispatch(self, request_id, lease, operation_id, call_id):
        with self.runtime.fenced_transaction() as db:
            job = self.repository._guard(db, lease)
            self.guard_in(db, request_id, lease, operation_id, "poll", call_id=call_id)
            self.repository._authorize(db, job)

    def result(self, lease, request_id, operation_id):
        with self.runtime.fenced_transaction() as db:
            self.repository._guard(db, lease)
            request = self.guard_in(db, request_id, lease, operation_id, "apply_result")
            evidence = self._evidence(db, operation_id, request["evidence_id"])
            return ExecutionResult.from_dict(evidence["data"])

    def attach_call_in(self, db, request_id, call_id):
        db.execute(text("""
            UPDATE control_plane.execution_recovery_requests SET call_attempt_id=:call WHERE id=:id
        """), {"id": request_id, "call": call_id})

    def defer_unstarted_poll(self, request_id, lease, operation_id, call_id):
        """Capacity.submit rejected before a worker could acquire the callback."""
        with self.runtime.fenced_transaction() as db:
            job = self.repository._guard(db, lease)
            request = self.guard_in(db, request_id, lease, operation_id, "poll", call_id=call_id)
            self._audit(db, request, job["environment_id"], "dispatch_not_started")
            db.execute(text("""
                UPDATE control_plane.jobs SET state='blocked',lease_owner=NULL,lease_token=NULL,
                    lease_expires_at=NULL,heartbeat_at=NULL
                WHERE id=:job
            """), {"job": lease.job_id})
            db.execute(text("UPDATE control_plane.execution_groups SET state='blocked' WHERE id=:id"),
                       {"id": lease.group_id})
            db.execute(text("""
                UPDATE control_plane.execution_recovery_requests SET state='queued',queue_revision=active_revision,
                    active_revision=NULL,coordinator_revision=NULL,call_attempt_id=NULL,
                    deferred_until=clock_timestamp()+make_interval(secs=>:seconds) WHERE id=:id
            """), {"id": request_id, "seconds": CAPACITY_BACKOFF_SECONDS})

    def guard_report_in(self, db, job, lease, call):
        request_id = db.scalar(text("""
            SELECT id FROM control_plane.execution_recovery_requests WHERE call_attempt_id=:id
        """), {"id": call["id"]})
        if request_id is not None:
            self.guard_in(db, request_id, lease, call["operation_id"], "poll", call_id=call["id"])
            self.repository._authorize(db, job)

    def finish_in(self, db, request, environment, outcome):
        completed = outcome in ("result_applied", "remote_succeeded", "remote_failed")
        db.execute(text("""
            UPDATE control_plane.execution_recovery_requests
            SET state=:state,outcome=:outcome,finished_at=clock_timestamp() WHERE id=:id
        """), {"id": request["id"], "state": "completed" if completed else "blocked", "outcome": outcome})
        if not completed and request["active_revision"] is not None:
            db.execute(text("""
                UPDATE control_plane.jobs SET lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,heartbeat_at=NULL
                WHERE id=:job AND state='blocked'
                  AND EXISTS (SELECT FROM control_plane.execution_groups
                              WHERE id=:group AND revision=:revision AND current_job_id=:job)
            """), {"job": request["job_id"], "group": request["group_id"], "revision": request["active_revision"]})
        self._audit(db, request, environment, outcome)

    def _interrupt_in(self, db, request, code):
        job = self._job(db, request["job_id"])
        if (job["group_revision"] == request["active_revision"] and job["current_job_id"] == job["id"]
                and job["state"] in ("running", "cancel_requested") and job["group_state"] == "active"):
            operation = self._operation(db, job["id"], request["operation_id"])
            if operation["state"] in ("running", "pending_external", "unknown"):
                lease = self.repository._lease(job, job["lease_owner"], job["lease_token"], job["group_revision"])
                self.repository._block_in(db, lease, operation, code, protocol_error=operation["protocol_error"])
        self.finish_in(db, request, job["environment_id"], code)

    def abort(self, request_id, code):
        with self.runtime.fenced_transaction() as db:
            request = db.execute(text("""
                SELECT * FROM control_plane.execution_recovery_requests WHERE id=:id AND state='running' FOR UPDATE
            """), {"id": request_id}).mappings().first()
            if request is not None:
                self._interrupt_in(db, request, code)

    def reconcile(self, limit):
        with self.runtime.fenced_transaction() as db:
            _, revision = self.runtime.coordinator_identity
            requests = db.execute(text("""
                SELECT r.* FROM control_plane.execution_recovery_requests r
                JOIN control_plane.jobs j ON j.id=r.job_id
                JOIN control_plane.execution_groups g ON g.id=r.group_id
                WHERE r.state='running' AND (r.coordinator_revision<>:rev OR j.lease_expires_at IS NULL
                    OR j.lease_expires_at<=clock_timestamp() OR j.state NOT IN ('running','cancel_requested')
                    OR g.revision<>r.active_revision OR g.state<>'active' OR g.current_job_id IS DISTINCT FROM j.id)
                ORDER BY r.created_at,r.id LIMIT :limit FOR UPDATE OF r SKIP LOCKED
            """), {"rev": revision, "limit": limit}).mappings().all()
            for request in requests:
                self._interrupt_in(db, request, "recovery_interrupted")
