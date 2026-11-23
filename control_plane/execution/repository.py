"""PostgreSQL execution facts. All authoritative mutations use two fences.

Coordinator fencing alone is insufficient: an old Job callback executing under a
new coordinator must not gain authority. JobLease binds the issuing coordinator,
job owner/token/DB expiry and execution-group revision. Evidence is append-only
and may be accepted by a *current* coordinator without granting old jobs authority.
"""
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import text

from ..coordination import require_fenced_connection
from ..plugins.sdk import PreparedCall, ExecutionResult, canonical_json, json_digest
from .adapters import UNAVAILABLE
from .wakeup import notify_jobs


class JobLeaseLost(RuntimeError):
    pass


class ExecutionConflict(RuntimeError):
    pass


class InvalidTransition(RuntimeError):
    pass


@dataclass(frozen=True)
class JobLease:
    job_id: UUID
    owner: str
    token: UUID
    group_id: UUID
    group_revision: int
    coordinator_owner: str
    coordinator_revision: int


@dataclass(frozen=True)
class CallAttempt:
    id: UUID
    operation_id: UUID
    method: str
    deadline_at: datetime
    job_lease_owner: str
    job_lease_token: UUID
    coordinator_owner: str
    coordinator_revision: int


def _dict(row):
    return dict(row._mapping) if row is not None else None


def _json(value):
    """SQL NULL is distinct from JSON null for nullable object columns."""
    return None if value is None else canonical_json(value)


def _seconds(value):
    import math
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 < value <= 86400:
        raise ValueError("finite positive bounded budget required")
    return value


class Repository:
    def __init__(self, runtime, *, reference_validator=UNAVAILABLE._unavailable, source_publisher=None, safe_json=None, authorize_job=None):
        self.runtime = runtime
        self.recovery = None
        self.authorize_job = authorize_job
        self.reference_validator = reference_validator
        self.source_publisher = source_publisher
        self.safe_json = safe_json or (lambda value: value)

    def binding(self, lease, instance_id):
        with self.runtime.fenced_transaction() as uow:
            self._guard(uow, lease)
            row = uow.execute(text("""
                SELECT s.*,i.plugin_key,i.enabled FROM control_plane.job_plugin_snapshots s
                JOIN control_plane.plugin_instances i ON i.id=s.instance_id
                WHERE s.job_id=:job AND s.instance_id=:instance
            """), {"job": lease.job_id, "instance": instance_id}).first()
            if row is None or not row.enabled:
                raise ExecutionConflict("fixed plugin instance is unavailable")
            return _dict(row)

    def is_cancel_requested(self, job_id):
        with self.runtime.fenced_transaction() as uow:
            return bool(uow.scalar(text("SELECT cancel_requested_at IS NOT NULL FROM control_plane.jobs WHERE id=:job"), {"job": job_id}))

    def _identity(self):
        owner, revision = self.runtime.coordinator_identity
        return str(owner), int(revision)

    def _guard(self, uow, lease, *, terminal=False):
        require_fenced_connection(uow)
        if self._identity() != (str(lease.coordinator_owner), lease.coordinator_revision):
            raise JobLeaseLost("job lease belongs to another coordinator generation")
        row = uow.execute(text("""
            SELECT j.*,g.revision AS group_revision,g.state AS group_state,
                   g.current_job_id,clock_timestamp() AS database_now
            FROM control_plane.jobs j JOIN control_plane.execution_groups g ON g.id=j.execution_group_id
            WHERE j.id=:job FOR UPDATE OF j,g
        """), {"job": lease.job_id}).first()
        if (row is None or row.lease_owner != lease.owner or str(row.lease_token) != str(lease.token)
                or row.lease_expires_at is None or row.lease_expires_at <= row.database_now
                or str(row.execution_group_id) != str(lease.group_id)
                or row.group_revision != lease.group_revision
                or str(row.current_job_id) != str(lease.job_id)
                or (not terminal and (row.state not in ("running", "cancel_requested") or row.group_state != "active"))):
            raise JobLeaseLost("job lease or execution-group revision is no longer valid")
        return _dict(row)

    def _authorize(self, uow, job):
        if self.authorize_job is not None and not self.authorize_job(uow, job):
            from ..plugins.sdk import AuthorizationDenied
            raise AuthorizationDenied()
        workflow = job["execution_snapshot"].get("workflow")
        if isinstance(workflow, dict) and workflow.get("kind") == "cleanup":
            from ..workflows import verify_cleanup_evidence
            verify_cleanup_evidence(uow, job, workflow)

    def finish_workflow(self, lease, applicator):
        with self.runtime.fenced_transaction() as uow:
            job = self._guard(uow, lease)
            self._authorize(uow, job)
            applicator.finish(uow, job)
            self._guard(uow, lease, terminal=True)

    def _lease(self, job, owner, token, group_revision):
        coordinator_owner, coordinator_revision = self._identity()
        return JobLease(job["id"], owner, token, job["execution_group_id"], group_revision,
                        coordinator_owner, coordinator_revision)

    def candidate_instances(self, *, limit=1000):
        if not 1 <= limit <= 1000:
            raise ValueError("bounded instance scan required")
        with self.runtime.fenced_transaction() as uow:
            return list(uow.scalars(text("""
                SELECT DISTINCT s.instance_id FROM control_plane.job_plugin_snapshots s
                JOIN control_plane.jobs j ON j.id=s.job_id
                WHERE j.state='queued' AND j.available_at<=clock_timestamp()
                ORDER BY s.instance_id LIMIT :limit
            """), {"limit": limit}))

    def claim(self, owner, lease_seconds=30, *, instance_ids=None):
        """SKIP LOCKED: no prefetch can mark a queued job as running."""
        _seconds(lease_seconds)
        if not owner:
            raise ValueError("owner required")
        with self.runtime.fenced_transaction() as uow:
            row = uow.execute(text("""
                SELECT j.*,g.revision AS group_revision FROM control_plane.jobs j
                JOIN control_plane.execution_groups g ON g.id=j.execution_group_id
                WHERE j.state='queued' AND j.available_at<=clock_timestamp()
                  AND j.attempts<j.max_attempts AND g.state='active'
                  AND (g.current_job_id IS NULL OR g.current_job_id=j.id)
                  AND (:all_instances OR NOT EXISTS (
                    SELECT 1 FROM control_plane.job_plugin_snapshots s
                    WHERE s.job_id=j.id AND NOT (s.instance_id=ANY(CAST(:instances AS uuid[])))))
                ORDER BY j.priority DESC,j.available_at,j.id
                FOR UPDATE OF j,g SKIP LOCKED LIMIT 1
            """), {"all_instances": instance_ids is None, "instances": list(instance_ids or [])}).first()
            if row is None:
                return None
            token = uuid4()
            revision = uow.scalar(text("""
                UPDATE control_plane.execution_groups SET current_job_id=:job,revision=revision+1,
                  updated_at=clock_timestamp() WHERE id=:group RETURNING revision
            """), {"job": row.id, "group": row.execution_group_id})
            uow.execute(text("""
                UPDATE control_plane.jobs SET state='running',attempts=attempts+1,lease_owner=:owner,
                  lease_token=:token,lease_expires_at=clock_timestamp()+(:seconds*interval '1 second'),
                  heartbeat_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=:job
            """), {"job": row.id, "owner": owner, "token": token, "seconds": lease_seconds})
            self._log_in(uow, row.id, "claimed")
            return self._lease(_dict(row), owner, token, revision)

    def heartbeat(self, lease, lease_seconds=30):
        _seconds(lease_seconds)
        with self.runtime.fenced_transaction() as uow:
            self._guard(uow, lease)
            uow.execute(text("""
                UPDATE control_plane.jobs SET heartbeat_at=clock_timestamp(),
                  lease_expires_at=clock_timestamp()+(:seconds*interval '1 second') WHERE id=:job
            """), {"job": lease.job_id, "seconds": lease_seconds})
            self._guard(uow, lease)

    def view(self, lease):
        with self.runtime.fenced_transaction() as uow:
            job = self._guard(uow, lease)
            steps = [_dict(r) for r in uow.execute(text("SELECT * FROM control_plane.job_steps WHERE job_id=:job ORDER BY step_path,item_key"), {"job": lease.job_id})]
            operations = [_dict(r) for r in uow.execute(text("SELECT * FROM control_plane.operations WHERE job_id=:job ORDER BY created_at,id"), {"job": lease.job_id})]
            return job, steps, operations

    def add_steps(self, lease, steps):
        """Planner output only: stable persisted expansion, never stored closures."""
        if len(steps) > 1000:
            raise ValueError("step expansion limit exceeded")
        with self.runtime.fenced_transaction() as uow:
            self._guard(uow, lease)
            for step in steps:
                values = {"id": step.get("id", uuid4()), "job": lease.job_id,
                          "path": step["step_path"], "key": step.get("item_key", ""),
                          "input": canonical_json(step.get("input", {})),
                          "expansion": _json(step.get("expansion")), "state": step.get("state", "pending")}
                if values["state"] not in ("pending", "skipped"):
                    raise ValueError("invalid initial step state")
                uow.execute(text("""
                    INSERT INTO control_plane.job_steps(id,job_id,step_path,item_key,input,expansion,state)
                    VALUES (:id,:job,:path,:key,CAST(:input AS jsonb),CAST(:expansion AS jsonb),:state)
                    ON CONFLICT(job_id,step_path,item_key) DO NOTHING
                """), values)
                row = uow.execute(text("SELECT input,expansion FROM control_plane.job_steps WHERE job_id=:job AND step_path=:path AND item_key=:key"), values).one()
                if canonical_json(row.input) != values["input"] or _json(row.expansion) != values["expansion"]:
                    raise ExecutionConflict("persisted workflow expansion differs")
            self._guard(uow, lease)

    def start_prepare(self, lease, step_id, seconds):
        _seconds(seconds)
        with self.runtime.fenced_transaction() as uow:
            job = self._guard(uow, lease)
            self._authorize(uow, job)
            if job["cancel_requested_at"] is not None:
                raise ExecutionConflict("job cancellation requested")
            row = uow.execute(text("SELECT * FROM control_plane.job_steps WHERE id=:step AND job_id=:job FOR UPDATE"), {"step": step_id, "job": lease.job_id}).one()
            if row.state != "pending":
                raise InvalidTransition("only pending steps can prepare")
            if row.prepare_deadline_at is not None:
                # No transaction retry or crash can refresh the original budget.
                return row.prepare_deadline_at
            deadline = uow.scalar(text("""
                UPDATE control_plane.job_steps SET prepare_started_at=clock_timestamp(),
                  prepare_deadline_at=clock_timestamp()+(:seconds*interval '1 second'),updated_at=clock_timestamp()
                WHERE id=:step RETURNING prepare_deadline_at
            """), {"step": step_id, "seconds": seconds})
            self._guard(uow, lease)
            return deadline

    def prepare_failed(self, lease, step_id, *, code="prepare_failed"):
        error = canonical_json({"code": code, "message": "preparation did not complete; no operation dispatched"})
        with self.runtime.fenced_transaction() as uow:
            job = self._guard(uow, lease)
            uow.execute(text("""
                UPDATE control_plane.job_steps SET state='failed',prepare_error=CAST(:error AS jsonb),
                  error=CAST(:error AS jsonb),finished_at=clock_timestamp(),updated_at=clock_timestamp()
                WHERE id=:step AND job_id=:job AND state='pending'
            """), {"error": error, "step": step_id, "job": lease.job_id})
            uow.execute(text("UPDATE control_plane.jobs SET state='failed',error=CAST(:error AS jsonb),finished_at=clock_timestamp() WHERE id=:job"), {"job": lease.job_id, "error": error})
            self._interrupted(uow, job)
            self._guard(uow, lease, terminal=True)

    def _acquire_scopes(self, uow, lease, scopes):
        for scope in sorted(set(scopes)):
            inserted = uow.scalar(text("""
                INSERT INTO control_plane.conflict_protections(scope_key,execution_group_id)
                VALUES (:scope,:group) ON CONFLICT(scope_key) WHERE released_at IS NULL DO NOTHING RETURNING id
            """), {"scope": scope, "group": lease.group_id})
            if inserted is None:
                group = uow.scalar(text("SELECT execution_group_id FROM control_plane.conflict_protections WHERE scope_key=:scope AND released_at IS NULL FOR UPDATE"), {"scope": scope})
                if str(group) != str(lease.group_id):
                    raise ExecutionConflict("scope has unresolved execution")

    def commit_prepared(self, lease, step_id, prepared, instance_id):
        encoded = canonical_json(self.safe_json(prepared.to_dict()))
        with self.runtime.fenced_transaction() as uow:
            job = self._guard(uow, lease)
            self._authorize(uow, job)
            step = uow.execute(text("SELECT *,clock_timestamp() AS database_now FROM control_plane.job_steps WHERE id=:step AND job_id=:job FOR UPDATE"), {"step": step_id, "job": lease.job_id}).one()
            if step.current_operation_id is not None:
                op = _dict(uow.execute(text("SELECT * FROM control_plane.operations WHERE id=:id"), {"id": step.current_operation_id}).one())
                if canonical_json(op["prepared_call"]) != encoded or str(op["plugin_instance_id"]) != str(instance_id):
                    raise ExecutionConflict("step already has a different prepared call")
                return op
            if (step.state != "pending" or step.prepare_deadline_at is None
                    or step.prepare_deadline_at <= step.database_now or job["cancel_requested_at"] is not None):
                raise InvalidTransition("step preparation is no longer eligible")
            snapshot = uow.execute(text("SELECT * FROM control_plane.job_plugin_snapshots WHERE job_id=:job AND instance_id=:instance"), {"job": lease.job_id, "instance": instance_id}).one()
            if self.reference_validator is not None:
                self.reference_validator(uow, lease.job_id, instance_id, prepared, step_instance_id=step_id)
            self._acquire_scopes(uow, lease, ["environment:" + str(job["environment_id"])] +
                                 ["plugin:" + str(instance_id) + ":" + k for k in prepared.conflict_keys])
            operation_id = uuid4()
            row = uow.execute(text("""
                INSERT INTO control_plane.operations(id,job_id,step_id,attempt,invocation_key,
                  plugin_instance_id,plugin_version,code_digest,prepared_call)
                VALUES (:id,:job,:step,:attempt,:invocation,:instance,:version,:digest,CAST(:prepared AS jsonb)) RETURNING *
            """), {"id": operation_id, "job": lease.job_id, "step": step_id, "attempt": step.attempt,
                    "invocation": str(step_id) + ":" + str(step.attempt), "instance": instance_id,
                    "version": snapshot.plugin_version, "digest": snapshot.code_digest, "prepared": encoded}).one()
            uow.execute(text("UPDATE control_plane.job_steps SET state='running',current_operation_id=:op,updated_at=clock_timestamp() WHERE id=:step"), {"op": operation_id, "step": step_id})
            self._guard(uow, lease)
            return _dict(row)

    def begin_call(self, lease, operation_id, method, seconds, *, retry_of_call_id=None, recovery_id=None):
        """Return only after intent AND immutable call provenance have committed."""
        if method not in ("execute", "poll", "cancel"):
            raise ValueError("unsupported operation method")
        _seconds(seconds)
        with self.runtime.fenced_transaction() as uow:
            job = self._guard(uow, lease)
            self._authorize(uow, job)
            if recovery_id is not None:
                if method != "poll":
                    raise InvalidTransition("administrator recovery only dispatches poll")
                self.recovery.guard_in(uow, recovery_id, lease, operation_id, "poll")
            op = uow.execute(text("SELECT * FROM control_plane.operations WHERE id=:op AND job_id=:job FOR UPDATE"), {"op": operation_id, "job": lease.job_id}).one()
            prepared = PreparedCall.from_dict(op.prepared_call)
            policy = prepared.execution_policy
            if method == "execute":
                if op.protocol_error is not None:
                    raise InvalidTransition("output protocol errors never authorize re-execution")
                if op.state == "unknown" and uow.scalar(text("SELECT EXISTS (SELECT 1 FROM control_plane.operation_evidence WHERE operation_id=:op AND kind='late_result' AND data->>'outcome'='succeeded')"), {"op": operation_id}):
                    raise InvalidTransition("confirmed raw success must be replayed locally, not executed again")
                if op.state == "unknown" and uow.scalar(text("SELECT count(*) FROM control_plane.operation_call_attempts WHERE operation_id=:op AND method='execute'"), {"op": operation_id}) >= job["max_attempts"]:
                    raise InvalidTransition("bounded execution retry attempts exhausted")
                if op.state == "unknown" and job["available_at"] > job["database_now"]:
                    raise InvalidTransition("persisted execution retry backoff has not elapsed")
                if op.state == "prepared":
                    if job["cancel_requested_at"] is not None:
                        raise ExecutionConflict("cancelled before dispatch")
                    uow.execute(text("""
                        UPDATE control_plane.operations o SET state='running',dispatch_intent_at=clock_timestamp(),
                            deadline_at=LEAST(clock_timestamp()+(:seconds*interval '1 second'),
                                s.prepare_started_at + ((s.input->>'timeout_seconds')::double precision * interval '1 second')),
                            updated_at=clock_timestamp()
                        FROM control_plane.job_steps s WHERE o.id=:op AND s.id=o.step_id
                    """), {"op": operation_id, "seconds": seconds})
                elif not (op.state == "unknown" and retry_of_call_id is not None and
                          (policy.effect == "read_only" or policy.idempotency == "keyed")):
                    raise InvalidTransition("execute would repeat an unsafe or completed operation")
            elif method == "poll":
                if policy.recovery != "queryable" or op.state not in ("pending_external", "unknown"):
                    raise InvalidTransition("operation does not support recovery polling")
            elif policy.cancellation != "requestable" or op.state not in ("running", "pending_external", "unknown"):
                raise InvalidTransition("operation cannot receive cancellation")
            snapshot = uow.execute(text("SELECT plugin_version,code_digest FROM control_plane.job_plugin_snapshots WHERE job_id=:job AND instance_id=:instance"), {"job": lease.job_id, "instance": op.plugin_instance_id}).one()
            if (snapshot.plugin_version, snapshot.code_digest) != (op.plugin_version, op.code_digest):
                raise ExecutionConflict("operation code reference mismatch")
            if retry_of_call_id is not None:
                previous = uow.scalar(text("SELECT id FROM control_plane.operation_call_attempts WHERE id=:id AND operation_id=:op AND method=:method"), {"id": retry_of_call_id, "op": operation_id, "method": method})
                if previous is None:
                    raise ExecutionConflict("retry does not match original call")
            if self.reference_validator is not None:
                self.reference_validator(uow, lease.job_id, op.plugin_instance_id, prepared, step_instance_id=op.step_id)
            self._acquire_scopes(uow, lease, ["environment:" + str(job["environment_id"])] +
                                 ["plugin:" + str(op.plugin_instance_id) + ":" + k for k in prepared.conflict_keys])
            call_id = uuid4()
            owner, revision = self._identity()
            deadline = uow.scalar(text("""
                INSERT INTO control_plane.operation_call_attempts
                  (id,operation_id,method,job_lease_owner,job_lease_token,coordinator_owner,
                   coordinator_revision,deadline_at,retry_of_call_id)
                SELECT :id,:op,:method,:owner,:token,:coordinator,:revision,
                       CASE WHEN :method='execute' THEN LEAST(o.deadline_at,clock_timestamp()+(:seconds*interval '1 second'))
                            ELSE clock_timestamp()+(:seconds*interval '1 second') END,:retry
                FROM control_plane.operations o WHERE o.id=:op
                  AND (:method<>'execute' OR o.deadline_at>clock_timestamp()) RETURNING deadline_at
            """), {"id": call_id, "op": operation_id, "method": method, "owner": lease.owner,
                    "token": lease.token, "coordinator": owner, "revision": revision,
                    "seconds": seconds, "retry": retry_of_call_id})
            if deadline is None:
                raise InvalidTransition("original execute deadline is exhausted; recovery cannot refresh it")
            if recovery_id is not None:
                self.recovery.attach_call_in(uow, recovery_id, call_id)
            if method == "cancel":
                uow.execute(text("UPDATE control_plane.operations SET cancel_requested_at=COALESCE(cancel_requested_at,clock_timestamp()),cancellation_result='requested' WHERE id=:op"), {"op": operation_id})
            self._guard(uow, lease)
            self._log_in(uow, lease.job_id, "dispatch_" + method)
            attempt = CallAttempt(call_id, operation_id, method, deadline, lease.owner, lease.token, owner, revision)
        return attempt

    def _call(self, uow, call_id):
        return _dict(uow.execute(text("""
            SELECT c.*,o.job_id,o.prepared_call,o.plugin_instance_id,o.state AS operation_state
            FROM control_plane.operation_call_attempts c JOIN control_plane.operations o ON o.id=c.operation_id
            WHERE c.id=:id FOR UPDATE OF o
        """), {"id": call_id}).one())

    def _append(self, uow, call, kind, key, data, event_id, observed_at=None, *, trusted=False):
        require_fenced_connection(uow)
        data = self.safe_json(data)
        payload = canonical_json(data)
        digest = json_digest({"kind": kind, "ref_key": key, "data": data,
                              "call_attempt_id": str(call["id"]), "trusted_for_derivation": trusted})
        if event_id is None:
            latest = uow.execute(text("SELECT id,event_digest,call_attempt_id FROM control_plane.operation_evidence WHERE operation_id=:op AND kind=:kind AND ref_key=:key ORDER BY revision DESC LIMIT 1"),
                                 {"op": call["operation_id"], "kind": kind, "key": key}).first()
            if latest and latest.event_digest == digest and str(latest.call_attempt_id) == str(call["id"]):
                return latest.id
            event_id = str(uuid4())
        old = uow.execute(text("SELECT id,event_digest,call_attempt_id FROM control_plane.operation_evidence WHERE operation_id=:op AND event_id=:event"), {"op": call["operation_id"], "event": event_id}).first()
        if old:
            if old.event_digest != digest or str(old.call_attempt_id) != str(call["id"]):
                raise ExecutionConflict("evidence event identity has different content or call origin")
            return old.id
        # Serialize a new fact with cleanup's final revision comparison. A
        # duplicate above has no effect even if the environment was retired.
        from ..workflows import lock_evidence_environment
        lock_evidence_environment(uow, call["job_id"])
        evidence_id = uuid4()
        uow.execute(text("""
            INSERT INTO control_plane.operation_evidence
              (id,operation_id,kind,ref_key,revision,data,call_attempt_id,event_id,event_digest,observed_at,trusted_for_derivation)
            SELECT :id,:op,:kind,:key,COALESCE(max(revision),0)+1,CAST(:data AS jsonb),:call,:event,:digest,
                   COALESCE(:observed,clock_timestamp()),:trusted FROM control_plane.operation_evidence
            WHERE operation_id=:op AND kind=:kind AND ref_key=:key
        """), {"id": evidence_id, "op": call["operation_id"], "kind": kind, "key": key, "data": payload,
                "call": call["id"], "event": event_id, "digest": digest, "observed": observed_at, "trusted": trusted})
        return evidence_id

    def append_evidence(self, call_id, kind, key, data, *, event_id=None, observed_at=None):
        """Current coordinator accepts late evidence; never changes state or quota."""
        if kind not in ("external_ref", "checkpoint", "late_result") or not key or len(key) > 255:
            raise ValueError("invalid evidence identity")
        with self.runtime.fenced_transaction() as uow:
            call = self._call(uow, call_id)
            evidence = self._append(uow, call, kind, key, data, event_id, observed_at)
            return evidence

    def report(self, lease, call_id, kind, key, data, *, event_id=None):
        # Synchronous acknowledgement and any trusted derived-reference grant
        # share a transaction. A late report is append-only and grants nothing.
        try:
            with self.runtime.fenced_transaction() as uow:
                job = self._guard(uow, lease)
                call = self._call(uow, call_id)
                self._match_call(lease, call)
                if self.recovery is not None and call["method"] == "poll":
                    self.recovery.guard_report_in(uow, job, lease, call)
                evidence = self._append(uow, call, kind, key, data, event_id, trusted=True)
                if kind == "checkpoint" and self.source_publisher is not None:
                    self.source_publisher(uow, lease.job_id, call["plugin_instance_id"], call["operation_id"], evidence)
                self._guard(uow, lease)
            return evidence
        except JobLeaseLost:
            self.append_evidence(call_id, kind, key, data, event_id=event_id)
            raise

    def _match_call(self, lease, call):
        if (str(call["job_id"]) != str(lease.job_id) or call["job_lease_owner"] != lease.owner
                or str(call["job_lease_token"]) != str(lease.token)
                or str(call["coordinator_owner"]) != str(lease.coordinator_owner)
                or call["coordinator_revision"] != lease.coordinator_revision):
            raise JobLeaseLost("call attempt belongs to an old execution lease")

    def record_result(self, lease, call_id, result, *, projector=UNAVAILABLE, applicator=UNAVAILABLE,
                      recovery_id=None):
        """Raw safe evidence commits FIRST; local projection failure cannot erase it.

        Schema checks happen before this API (RuntimeAdapter); a protocol_error is
        persisted and blocks the operation without a second external execute.
        """
        if not isinstance(result, ExecutionResult):
            raise TypeError("ExecutionResult required")
        raw = self.safe_json(result.to_dict())
        result = ExecutionResult.from_dict(raw)
        with self.runtime.fenced_transaction() as evidence_uow:
            source = self._call(evidence_uow, call_id)
            evidence_id = self._append(evidence_uow, source, "late_result", "result:" + str(call_id), raw,
                                       "result:" + str(call_id))
            for kind, entries in (("external_ref", result.external_refs), ("checkpoint", result.checkpoints)):
                for index, entry in enumerate(entries):
                    stable_key = (entry.get("ref_key", entry.get("checkpoint_key", entry.get("key")))
                                  if isinstance(entry, dict) else None)
                    stable_key = stable_key or "result:" + str(call_id) + ":" + str(index)
                    self._append(evidence_uow, source, kind, stable_key, entry,
                                 "result:" + str(call_id) + ":" + kind + ":" + str(index))
        try:
            with self.runtime.fenced_transaction() as uow:
                job = self._guard(uow, lease)
                call = self._call(uow, call_id)
                self._match_call(lease, call)
                recovery = None
                if recovery_id is not None:
                    recovery = self.recovery.guard_in(uow, recovery_id, lease, call["operation_id"], "poll",
                                                      call_id=call_id)
                    self._authorize(uow, job)
                op = _dict(uow.execute(text("""
                    SELECT o.*,j.environment_id,j.logical_invocation_id,j.execution_group_id,j.kind AS job_kind
                    FROM control_plane.operations o JOIN control_plane.jobs j ON j.id=o.job_id WHERE o.id=:op
                """), {"op": call["operation_id"]}).one())
                if op["state"] in ("succeeded", "failed", "cancelled"):
                    return "already_terminal"
                if op["state"] not in ("running", "pending_external", "unknown"):
                    raise InvalidTransition("result has no committed dispatch intent")
                # The first raw transaction never authorizes derived access.
                # Only this fully fenced current-call transaction may export a
                # separately append-only accepted checkpoint and exact grant.
                for index, checkpoint in enumerate(result.checkpoints):
                    checkpoint_key = (checkpoint.get("checkpoint_key", checkpoint.get("key"))
                                      if isinstance(checkpoint, dict) else None)
                    checkpoint_key = checkpoint_key or "result:" + str(call_id) + ":" + str(index)
                    accepted = self._append(uow, call, "checkpoint", checkpoint_key, checkpoint,
                                            "accepted-result:" + str(call_id) + ":checkpoint:" + str(index), trusted=True)
                    if self.source_publisher is not None:
                        self.source_publisher(uow, lease.job_id, op["plugin_instance_id"], op["id"], accepted)
                if result.protocol_error:
                    self._block_in(uow, lease, op, "protocol_error", protocol_error=dict(result.protocol_error))
                elif result.outcome == "unknown":
                    if result.external_execution_ref is not None and op["external_execution_ref"] is None:
                        uow.execute(text("""
                            UPDATE control_plane.operations SET external_execution_ref=CAST(:ref AS jsonb)
                            WHERE id=:op
                        """), {"op": op["id"], "ref": canonical_json(result.external_execution_ref)})
                    self._block_in(uow, lease, op, "unknown_external_result")
                elif result.outcome == "pending_external":
                    policy = PreparedCall.from_dict(op["prepared_call"]).execution_policy
                    if result.external_execution_ref is None and policy.recovery != "queryable":
                        self._block_in(uow, lease, op, "missing_recovery_reference")
                    elif recovery is not None:
                        uow.execute(text("""
                            UPDATE control_plane.operations
                            SET external_execution_ref=COALESCE(external_execution_ref,CAST(:ref AS jsonb))
                            WHERE id=:op
                        """), {"op": op["id"], "ref": _json(result.external_execution_ref)})
                        self._block_in(uow, lease, op, "remote_still_pending")
                    else:
                        uow.execute(text("UPDATE control_plane.operations SET state='pending_external',external_execution_ref=CAST(:ref AS jsonb),updated_at=clock_timestamp() WHERE id=:op"), {"op": op["id"], "ref": canonical_json(result.external_execution_ref)})
                        uow.execute(text("UPDATE control_plane.job_steps SET state='waiting_external',updated_at=clock_timestamp() WHERE id=:step"), {"step": op["step_id"]})
                elif result.outcome == "failed":
                    uow.execute(text("UPDATE control_plane.operations SET state='failed',error=CAST(:error AS jsonb),finished_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=:op"), {"op": op["id"], "error": _json(raw["error"])})
                    uow.execute(text("UPDATE control_plane.job_steps SET state='failed',error=CAST(:error AS jsonb),finished_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=:step"), {"step": op["step_id"], "error": _json(raw["error"])})
                    uow.execute(text("UPDATE control_plane.jobs SET state='failed',error=CAST(:error AS jsonb),finished_at=clock_timestamp() WHERE id=:job"), {"job": lease.job_id, "error": _json(raw["error"])})
                    self._interrupted(uow, job, dispatched=True)
                else:
                    # These two trusted local adapters MUST NOT perform external I/O.
                    projection = projector.project(op, result)
                    uow.execute(text("UPDATE control_plane.operations SET state='succeeded',output=CAST(:output AS jsonb),finished_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=:op"), {"op": op["id"], "output": canonical_json(result.output)})
                    uow.execute(text("UPDATE control_plane.job_steps SET state='succeeded',output=CAST(:output AS jsonb),finished_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=:step"), {"step": op["step_id"], "output": canonical_json(result.output)})
                    if self.source_publisher is not None:
                        self.source_publisher(uow, lease.job_id, op["plugin_instance_id"], op["id"])
                    applicator.apply(uow, op, projection)
                self._log_in(uow, lease.job_id, "result_" + result.outcome)
                self._guard(uow, lease, terminal=True)
                if recovery is not None:
                    outcome = "protocol_error" if result.protocol_error else {
                        "succeeded": "remote_succeeded", "failed": "remote_failed",
                        "pending_external": "remote_still_pending", "unknown": "unknown_external_result",
                    }[result.outcome]
                    self.recovery.finish_in(uow, recovery, job["environment_id"], outcome)
            return "applied"
        except JobLeaseLost:
            # Even when a newer coordinator accepts the raw result, the original
            # lease cannot authorize *any* state write, release or quota change.
            return "late_evidence"
        except Exception:
            # Entire local projection transaction rolled back. Retain the safe
            # original result and block under a fresh, fully checked transaction.
            if recovery_id is None:
                self.block(lease, call_id, "local_result_application_failed")
            raise

    @staticmethod
    def _interrupted(uow, job, *, blocked=False, cancelled=False, dispatched=False):
        if isinstance(job["execution_snapshot"].get("workflow"), dict):
            from ..workflows import record_interruption
            record_interruption(uow, job, blocked=blocked, cancelled=cancelled)
        elif blocked or dispatched:
            # Legacy jobs have no template policy describing their effects.
            Repository._quarantine(uow, job["environment_id"])

    @staticmethod
    def _quarantine(uow, environment_id):
        uow.execute(text("UPDATE control_plane.quota_reservations SET state='quarantined',updated_at=clock_timestamp() WHERE environment_id=:environment AND state IN ('reserved','allocated')"), {"environment": environment_id})

    def _block_in(self, uow, lease, op, code, *, protocol_error=None):
        error = canonical_json({"code": code, "message": "execution requires confirmed recovery evidence"})
        uow.execute(text("UPDATE control_plane.operations SET state='unknown',protocol_error=CAST(:protocol AS jsonb),error=CAST(:error AS jsonb),updated_at=clock_timestamp() WHERE id=:op AND state IN ('running','pending_external','unknown')"), {"op": op["id"], "error": error, "protocol": _json(protocol_error)})
        uow.execute(text("UPDATE control_plane.job_steps SET state='blocked',error=CAST(:error AS jsonb),updated_at=clock_timestamp() WHERE id=:step AND state NOT IN ('succeeded','failed','cancelled','skipped')"), {"step": op["step_id"], "error": error})
        uow.execute(text("UPDATE control_plane.jobs SET state='blocked',error=CAST(:error AS jsonb),available_at=GREATEST(available_at,clock_timestamp()+interval '1 second'),updated_at=clock_timestamp() WHERE id=:job"), {"job": lease.job_id, "error": error})
        uow.execute(text("UPDATE control_plane.execution_groups SET state='blocked',reason=CAST(:error AS jsonb),updated_at=clock_timestamp() WHERE id=:group"), {"group": lease.group_id, "error": error})
        job = uow.execute(text("SELECT * FROM control_plane.jobs WHERE id=:job"), {"job": lease.job_id}).mappings().one()
        self._interrupted(uow, job, blocked=True)

    def block_operation(self, lease, operation_id, code):
        """Block an operation by identity under the *current* lease.

        Recovery runs under a fresh Job token, so it cannot satisfy
        ``_match_call``'s historical-call fencing (and must not weaken it).
        This entry point therefore validates the current coordinator, Job
        lease, execution-group revision and Operation ownership instead.
        """
        with self.runtime.fenced_transaction() as uow:
            self._guard(uow, lease)
            op = _dict(uow.execute(text(
                "SELECT * FROM control_plane.operations WHERE id=:op AND job_id=:job FOR UPDATE"),
                {"op": operation_id, "job": lease.job_id}).one())
            if op["state"] not in ("running", "pending_external", "unknown"):
                raise InvalidTransition("operation is not recoverable for blocking")
            self._block_in(uow, lease, op, code)
            self._guard(uow, lease, terminal=True)
            return True

    def block(self, lease, call_id, code):
        with self.runtime.fenced_transaction() as uow:
            self._guard(uow, lease)
            call = self._call(uow, call_id)
            self._match_call(lease, call)
            op = _dict(uow.execute(text("SELECT * FROM control_plane.operations WHERE id=:op"), {"op": call["operation_id"]}).one())
            self._block_in(uow, lease, op, code)
            self._guard(uow, lease, terminal=True)

    def block_job(self, lease, code="execution_dependency_unavailable"):
        with self.runtime.fenced_transaction() as uow:
            job = self._guard(uow, lease)
            error = canonical_json({"code": code, "message": "fixed execution dependency requires review"})
            if isinstance(job["execution_snapshot"].get("workflow"), dict):
                # A denied/revoked dispatch never touched the remote endpoint.
                # Keep the evidence but avoid a permanently "prepared" operation
                # preventing an administrator's explicit cleanup of earlier work.
                uow.execute(text("""UPDATE control_plane.operations
                    SET state='cancelled',finished_at=clock_timestamp()
                    WHERE job_id=:job AND state='prepared' AND dispatch_intent_at IS NULL"""),
                    {"job": lease.job_id})
            uow.execute(text("UPDATE control_plane.job_steps SET state='blocked',error=CAST(:error AS jsonb) WHERE job_id=:job AND state IN ('pending','running','waiting_external')"), {"job": lease.job_id, "error": error})
            uow.execute(text("UPDATE control_plane.jobs SET state='blocked',error=CAST(:error AS jsonb) WHERE id=:job"), {"job": lease.job_id, "error": error})
            uow.execute(text("UPDATE control_plane.execution_groups SET state='blocked',reason=CAST(:error AS jsonb) WHERE id=:group"), {"group": lease.group_id, "error": error})
            self._interrupted(uow, job, blocked=True)
            self._guard(uow, lease, terminal=True)

    def saved_success(self, lease, operation_id):
        with self.runtime.fenced_transaction() as uow:
            self._guard(uow, lease)
            return uow.scalar(text("""
                SELECT e.id FROM control_plane.operation_evidence e
                JOIN control_plane.operations o ON o.id=e.operation_id
                WHERE o.id=:op AND o.job_id=:job AND e.kind='late_result'
                  AND e.data->>'outcome'='succeeded'
                  AND COALESCE(e.data->'protocol_error','null'::jsonb)='null'::jsonb
                ORDER BY e.created_at DESC,e.id DESC LIMIT 1
            """), {"op": operation_id, "job": lease.job_id})

    @staticmethod
    def _log_in(uow, job_id, code, data=None):
        # The caller holds the Job lock. Only platform-defined codes are public.
        uow.execute(text("""
            INSERT INTO control_plane.job_logs(job_id,sequence,data)
            SELECT :job,COALESCE(MAX(sequence),-1)+1,
                   CAST(:data AS jsonb) || jsonb_build_object('code',CAST(:code AS text))
            FROM control_plane.job_logs WHERE job_id=:job
        """), {"job": job_id, "code": code, "data": canonical_json(data or {})})

    def report_job_event(self, lease, code, data, *, step_id, operation_id=None):
        with self.runtime.fenced_transaction() as uow:
            self._guard(uow, lease)
            self._log_in(uow, lease.job_id, code, {
                "step_id": str(step_id),
                "operation_id": str(operation_id) if operation_id is not None else None,
                "details": self.safe_json(data),
            })

    def request_cancel(self, job_id, *, actor_id=None):
        """Authorize browser cancellation in its write transaction."""
        with self.runtime.fenced_transaction() as uow:
            if actor_id is not None:
                from ..identity import can_read_environment_status
                from ..plugins.sdk import AuthorizationDenied
                row = uow.execute(text("""
                    SELECT * FROM control_plane.jobs WHERE id=:job AND actor_id=:actor FOR UPDATE
                """), {"job": job_id, "actor": actor_id}).mappings().first()
                if row is None or not can_read_environment_status(uow, actor_id, row["environment_id"]):
                    raise AuthorizationDenied()
                if row["state"] == "blocked":
                    raise ExecutionConflict("blocked Job requires reconciliation")
                self._authorize(uow, row)
            result = uow.scalar(text("""
                UPDATE control_plane.jobs SET cancel_requested_at=COALESCE(cancel_requested_at,clock_timestamp()),
                  state=CASE WHEN state='running' THEN 'cancel_requested' ELSE state END,
                  updated_at=clock_timestamp() WHERE id=:job AND state IN ('queued','running','cancel_requested','blocked') RETURNING id
            """), {"job": job_id})
            if result is not None:
                self._log_in(uow, result, "cancel_requested")
                notify_jobs(uow)
            return result

    def record_cancel(self, lease, call_id, result):
        raw = {"cancellation_result": result.status,
               "error": result.error.to_dict() if hasattr(result.error, "to_dict") else result.error}
        self.append_evidence(call_id, "late_result", "cancel:" + str(call_id), raw, event_id="cancel:" + str(call_id))
        with self.runtime.fenced_transaction() as uow:
            job = self._guard(uow, lease)
            call = self._call(uow, call_id)
            self._match_call(lease, call)
            if call["method"] != "cancel":
                raise ExecutionConflict("not a cancellation attempt")
            uow.execute(text("UPDATE control_plane.operations SET cancellation_result=:status WHERE id=:op"), {"op": call["operation_id"], "status": result.status})
            if result.status == "confirmed_cancelled" and call["operation_state"] not in ("succeeded", "failed", "cancelled"):
                uow.execute(text("UPDATE control_plane.operations SET state='cancelled',finished_at=clock_timestamp() WHERE id=:op"), {"op": call["operation_id"]})
                uow.execute(text("UPDATE control_plane.job_steps SET state='cancelled',finished_at=clock_timestamp() WHERE current_operation_id=:op"), {"op": call["operation_id"]})
                remaining = uow.scalar(text("SELECT count(*) FROM control_plane.operations WHERE job_id=:job AND state IN ('running','pending_external','unknown')"), {"job": lease.job_id})
                if not remaining:
                    uow.execute(text("UPDATE control_plane.jobs SET state='cancelled',finished_at=clock_timestamp() WHERE id=:job"), {"job": lease.job_id})
                # Cancellation confirms execution stopped, not absence of resources.
                self._interrupted(uow, job, cancelled=True, dispatched=True)
            self._guard(uow, lease, terminal=True)

    def cancel_undispatched(self, lease):
        with self.runtime.fenced_transaction() as uow:
            job = self._guard(uow, lease)
            if uow.scalar(text("SELECT count(*) FROM control_plane.operations WHERE job_id=:job AND dispatch_intent_at IS NOT NULL"), {"job": lease.job_id}):
                raise ExecutionConflict("dispatched operations require cancellation evidence")
            uow.execute(text("UPDATE control_plane.operations SET state='cancelled',finished_at=clock_timestamp() WHERE job_id=:job AND state='prepared'"), {"job": lease.job_id})
            uow.execute(text("UPDATE control_plane.job_steps SET state='cancelled',finished_at=clock_timestamp() WHERE job_id=:job AND state IN ('pending','running')"), {"job": lease.job_id})
            uow.execute(text("UPDATE control_plane.jobs SET state='cancel_requested' WHERE id=:job AND state='running'"), {"job": lease.job_id})
            uow.execute(text("UPDATE control_plane.jobs SET state='cancelled',finished_at=clock_timestamp() WHERE id=:job"), {"job": lease.job_id})
            self._interrupted(uow, job, cancelled=True)
            self._guard(uow, lease, terminal=True)

    def recover_expired(self, owner, lease_seconds=30, *, limit=32):
        """Bounded recovery scan; never blindly resets running jobs to queued."""
        _seconds(lease_seconds)
        if not 1 <= limit <= 1000:
            raise ValueError("bounded recovery limit required")
        recovered = []
        with self.runtime.fenced_transaction() as uow:
            jobs = [_dict(r) for r in uow.execute(text("""
                SELECT j.*,g.revision AS group_revision FROM control_plane.jobs j
                JOIN control_plane.execution_groups g ON g.id=j.execution_group_id
                WHERE j.state IN ('running','cancel_requested')
                  AND NOT EXISTS (SELECT FROM control_plane.execution_recovery_requests r
                                  WHERE r.job_id=j.id AND r.state='running')
                  AND (j.lease_expires_at<=clock_timestamp() OR EXISTS (
                    SELECT 1 FROM control_plane.operations o
                    JOIN control_plane.operation_call_attempts c ON c.operation_id=o.id
                    WHERE o.job_id=j.id AND c.job_lease_owner=j.lease_owner
                      AND c.job_lease_token=j.lease_token
                      AND (c.coordinator_owner<>CAST(:coordinator AS uuid)
                           OR c.coordinator_revision<>:coordinator_revision)))
                  AND g.current_job_id=j.id AND g.state='active'
                ORDER BY j.lease_expires_at,j.id FOR UPDATE OF j,g SKIP LOCKED LIMIT :limit
            """), {"limit": limit, "coordinator": self._identity()[0],
                    "coordinator_revision": self._identity()[1]})]
            for job in jobs:
                ops = [_dict(r) for r in uow.execute(text("SELECT * FROM control_plane.operations WHERE job_id=:job ORDER BY created_at FOR UPDATE"), {"job": job["id"]})]
                uncertain = [op for op in ops if op["state"] in ("running", "unknown")]
                if uncertain:
                    # Recovery acts as the valid coordinator, not as the old worker.
                    token = uuid4()
                    revision = uow.scalar(text("UPDATE control_plane.execution_groups SET revision=revision+1 WHERE id=:group RETURNING revision"), {"group": job["execution_group_id"]})
                    uow.execute(text("UPDATE control_plane.jobs SET lease_owner=:owner,lease_token=:token,lease_expires_at=clock_timestamp()+(:seconds*interval '1 second') WHERE id=:job"), {"job": job["id"], "owner": owner, "token": token, "seconds": lease_seconds})
                    lease = self._lease(job, owner, token, revision)
                    for op in uncertain:
                        self._block_in(uow, lease, op, "expired_dispatched_execution")
                    continue
                token = uuid4()
                revision = uow.scalar(text("UPDATE control_plane.execution_groups SET revision=revision+1 WHERE id=:group RETURNING revision"), {"group": job["execution_group_id"]})
                uow.execute(text("UPDATE control_plane.jobs SET lease_owner=:owner,lease_token=:token,lease_expires_at=clock_timestamp()+(:seconds*interval '1 second'),heartbeat_at=clock_timestamp() WHERE id=:job"), {"job": job["id"], "owner": owner, "token": token, "seconds": lease_seconds})
                recovered.append(self._lease(job, owner, token, revision))
        return recovered

    def takeover_blocked(self, job_id, owner, *, expected_revision, evidence_id, actor_id, reason, lease_seconds=30):
        """Explicit single-path recovery CAS. Evidence/actor/reason are mandatory.

        This resumes the same blocked Job; a linked recovery-Job admission adapter
        must use the same group row/revision and cannot run concurrently with it.
        """
        _seconds(lease_seconds)
        if not reason or not actor_id or not evidence_id:
            raise ValueError("recovery requires evidence, actor and reason")
        with self.runtime.fenced_transaction() as uow:
            require_fenced_connection(uow)
            row = uow.execute(text("SELECT j.*,g.revision AS group_revision,g.current_job_id,g.state AS group_state FROM control_plane.jobs j JOIN control_plane.execution_groups g ON g.id=j.execution_group_id WHERE j.id=:job FOR UPDATE OF j,g"), {"job": job_id}).one()
            expired = uow.scalar(text("SELECT CAST(:expiry AS timestamptz) IS NULL OR CAST(:expiry AS timestamptz)<=clock_timestamp()"), {"expiry": row.lease_expires_at})
            if (row.state != "blocked" or row.group_state != "blocked" or row.group_revision != expected_revision
                    or not expired or str(row.current_job_id) != str(job_id)):
                raise ExecutionConflict("recovery owner or revision changed")
            evidence = uow.execute(text("SELECT e.id,e.operation_id FROM control_plane.operation_evidence e JOIN control_plane.operations o ON o.id=e.operation_id WHERE e.id=:evidence AND o.job_id=:job"), {"evidence": evidence_id, "job": job_id}).first()
            if evidence is None:
                raise ExecutionConflict("recovery evidence does not belong to this job")
            if uow.scalar(text("""
                SELECT EXISTS (SELECT FROM control_plane.execution_recovery_requests
                               WHERE group_id=:group AND state IN ('queued','running'))
            """), {"group": row.execution_group_id}):
                raise ExecutionConflict("administrator recovery is already pending")
            lease = self._takeover_in(uow, _dict(row), owner, lease_seconds,
                                      reason={"actor_id": str(actor_id), "reason": reason, "evidence_id": str(evidence_id)})
            uow.execute(text("INSERT INTO control_plane.audit_events(actor_id,environment_id,job_id,operation_id,action,result,data) VALUES (:actor,:environment,:job,:operation,'execution.recover','accepted',CAST(:data AS jsonb))"), {"actor": actor_id, "environment": row.environment_id, "job": job_id, "operation": evidence.operation_id, "data": canonical_json({"reason": reason, "evidence_id": str(evidence_id), "revision": lease.group_revision})})
            return lease

    def _takeover_in(self, uow, job, owner, seconds, *, reason=None):
        revision = uow.scalar(text("""
            UPDATE control_plane.execution_groups SET state='active',revision=revision+1,
                reason=COALESCE(CAST(:reason AS jsonb),reason),updated_at=clock_timestamp()
            WHERE id=:group AND revision=:expected AND current_job_id=:job AND state='blocked'
            RETURNING revision
        """), {"job": job["id"], "group": job["execution_group_id"], "expected": job["group_revision"],
               "reason": _json(reason)})
        if revision is None:
            raise ExecutionConflict("recovery owner or revision changed")
        token = uuid4()
        uow.execute(text("""
            UPDATE control_plane.jobs SET state='running',lease_owner=:owner,lease_token=:token,
                lease_expires_at=clock_timestamp()+(:seconds*interval '1 second'),
                heartbeat_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=:job
        """), {"job": job["id"], "owner": owner, "token": token, "seconds": seconds})
        return self._lease(job, owner, token, revision)

    def latest_call(self, operation_id, method="execute"):
        with self.runtime.fenced_transaction() as uow:
            row = uow.execute(text("SELECT * FROM control_plane.operation_call_attempts WHERE operation_id=:op AND method=:method ORDER BY created_at DESC,id DESC LIMIT 1"), {"op": operation_id, "method": method}).first()
            return _dict(row)

    def method_call_count(self, operation_id, method):
        """Count committed call intents of one method (append-only provenance)."""
        with self.runtime.fenced_transaction() as uow:
            return int(uow.scalar(text("SELECT count(*) FROM control_plane.operation_call_attempts WHERE operation_id=:op AND method=:method"), {"op": operation_id, "method": method}))

    def replay_result(self, lease, evidence_id, *, projector=UNAVAILABLE, applicator=UNAVAILABLE, recovery_id=None):
        """Reapply only local mapping from saved evidence; never invokes a plugin.

        A new recovery lease cannot masquerade as the original call. Adopt the
        verified result explicitly, with a recovery call record preserving origin.
        """
        with self.runtime.fenced_transaction() as uow:
            self._guard(uow, lease)
            row = uow.execute(text("SELECT e.*,o.job_id FROM control_plane.operation_evidence e JOIN control_plane.operations o ON o.id=e.operation_id WHERE e.id=:id AND o.job_id=:job AND e.kind='late_result'"), {"id": evidence_id, "job": lease.job_id}).one()
            # Adoption is a separate, audited local recovery action, not a forged
            # network call; apply below using the current lease and original raw.
            evidence, operation_id = row.data, row.operation_id
            source_call_id = row.call_attempt_id
        return self._adopt_result(lease, operation_id, source_call_id, evidence_id, ExecutionResult.from_dict(evidence),
                                  projector, applicator, recovery_id)

    def _adopt_result(self, lease, operation_id, source_call_id, evidence_id, result, projector, applicator,
                      recovery_id=None):
        with self.runtime.fenced_transaction() as uow:
            job = self._guard(uow, lease)
            self._authorize(uow, job)
            recovery = None
            if recovery_id is not None:
                recovery = self.recovery.guard_in(uow, recovery_id, lease, operation_id, "apply_result")
                if str(recovery["evidence_id"]) != str(evidence_id):
                    raise ExecutionConflict("recovery evidence changed")
            op = _dict(uow.execute(text("SELECT o.*,j.environment_id,j.logical_invocation_id,j.execution_group_id FROM control_plane.operations o JOIN control_plane.jobs j ON j.id=o.job_id WHERE o.id=:op AND o.job_id=:job FOR UPDATE OF o"), {"op": operation_id, "job": lease.job_id}).one())
            if result.outcome != "succeeded" or result.protocol_error or op["state"] not in ("running", "unknown", "pending_external"):
                raise ExecutionConflict("saved result is not a confirmed applicable success")
            # Pure local validation is repeated; original code/target are pinned.
            projection = projector.project(op, result)
            uow.execute(text("UPDATE control_plane.operations SET state='succeeded',output=CAST(:output AS jsonb),finished_at=clock_timestamp() WHERE id=:op"), {"op": operation_id, "output": canonical_json(result.output)})
            uow.execute(text("UPDATE control_plane.job_steps SET state='succeeded',output=CAST(:output AS jsonb),finished_at=clock_timestamp() WHERE id=:step"), {"step": op["step_id"], "output": canonical_json(result.output)})
            if self.source_publisher is not None:
                self.source_publisher(uow, lease.job_id, op["plugin_instance_id"], op["id"])
            applicator.apply(uow, op, projection)
            uow.execute(text("INSERT INTO control_plane.audit_events(actor_id,environment_id,job_id,operation_id,action,result,data) VALUES (:actor,:environment,:job,:op,'execution.adopt_result','applied',CAST(:data AS jsonb))"), {"actor": job["actor_id"], "environment": job["environment_id"], "job": lease.job_id, "op": operation_id, "data": canonical_json({"evidence_id": str(evidence_id), "source_call_attempt_id": str(source_call_id)})})
            self._guard(uow, lease, terminal=True)
            if recovery is not None:
                self.recovery.finish_in(uow, recovery, job["environment_id"], "result_applied")
        return "applied"

    def recover_opening_unknown(self, operation_id, code="session_opening_interrupted"):
        """Startup-only local session recovery, with prior-coordinator proof.

        Does not call open_session or infer remote closure. A prepared opening is
        still provably undispatched and is not converted into unknown.
        """
        with self.runtime.fenced_transaction() as uow:
            require_fenced_connection(uow)
            row = uow.execute(text("""
                SELECT o.*,j.environment_id,j.execution_group_id,g.revision AS group_revision,
                  j.lease_owner,j.lease_token,j.lease_expires_at,j.state AS job_state
                FROM control_plane.operations o JOIN control_plane.jobs j ON j.id=o.job_id
                JOIN control_plane.execution_groups g ON g.id=j.execution_group_id
                WHERE o.id=:op AND EXISTS (SELECT 1 FROM control_plane.interactive_sessions s
                  WHERE s.open_operation_id=o.id AND s.job_id=o.job_id AND s.state IN ('opening','disconnected'))
                FOR UPDATE OF j,g,o
            """), {"op": operation_id}).first()
            if row is None or row.state != "running":
                return False
            call = uow.execute(text("SELECT coordinator_owner,coordinator_revision FROM control_plane.operation_call_attempts WHERE operation_id=:op AND method='execute' ORDER BY created_at DESC,id DESC LIMIT 1"), {"op": operation_id}).first()
            if call is None:
                return False  # Legacy dispatched fact needs explicit review.
            if (str(call.coordinator_owner), call.coordinator_revision) == self._identity():
                return False  # Never steal a same-generation live opening call.
            owner, revision = self._identity()
            # The old coordinator has no current authority, even if the old job
            # deadline has not yet elapsed. This is fact recovery, not execution.
            lease = JobLease(row.job_id, row.lease_owner, row.lease_token, row.execution_group_id,
                             row.group_revision, owner, revision)
            self._block_in(uow, lease, _dict(row), code)
            return True


ExecutionRepository = Repository
