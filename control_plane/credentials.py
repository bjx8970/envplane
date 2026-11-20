"""Environment credential delivery and durable remote revocation dispositions."""
from dataclasses import dataclass, field
from uuid import UUID

from sqlalchemy import text

from .coordination import require_fenced_connection
from .identity import can_access_environment, can_read_environment_status
from .execution.repository import ExecutionConflict
from .persistence import RequestConflict
from .plugins.capacity import CapacityRejected
from .plugins.sdk import AuthorizationDenied, ReferenceUnavailable, SecretRef, canonical_json


@dataclass(frozen=True)
class CredentialView:
    value: bytes = field(repr=False)

    @property
    def headers(self):
        return {"Cache-Control": "no-store", "Pragma": "no-cache"}

    def __reduce_ex__(self, protocol):
        raise TypeError("credential views cannot be serialized")


def _audit(uow, actor_id, environment_id, action, result, data):
    uow.execute(text("""
        INSERT INTO control_plane.audit_events
            (actor_id, environment_id, template_version_id, action, result, data)
        SELECT (SELECT id FROM control_plane.users WHERE id=:actor),
               e.id,e.template_version_id,:action,:result,CAST(:data AS jsonb)
        FROM (SELECT 1) AS attempted LEFT JOIN control_plane.environments e ON e.id=:env
    """), {"actor": actor_id, "env": environment_id, "action": action,
           "result": result, "data": canonical_json(data)})


def confirm_from_operation(uow, operation_id, *, replaced=()):
    """Called only by the template applicator for its declared remote setup step.

    The caller matches the configured credential reference against the confirmed
    output. The database binds the same exact reference to this Job and plugin.
    """
    require_fenced_connection(uow)
    op = uow.execute(text("""
        SELECT o.job_id,j.environment_id,o.plugin_instance_id,o.output FROM control_plane.operations o
        JOIN control_plane.jobs j ON j.id=o.job_id
        WHERE o.id=:op AND o.state='succeeded'
    """), {"op": operation_id}).first()
    if op is None or not isinstance(op.output, dict):
        return False
    ref = op.output.get("confirmed_environment_credential")
    if not isinstance(ref, dict) or set(ref) != {"secret_id", "version_id"}:
        return False
    try:
        exact = {key: str(UUID(value)) for key, value in ref.items()}
    except (TypeError, ValueError, AttributeError):
        return False
    if exact != ref:
        return False
    args = {"secret": ref["secret_id"], "version": ref["version_id"], "env": op.environment_id,
            "job": op.job_id, "instance": op.plugin_instance_id, "op": operation_id}
    if not uow.scalar(text("""
        SELECT 1 FROM control_plane.secret_versions v JOIN control_plane.secrets s ON s.id=v.secret_id
        JOIN control_plane.job_secret_refs r ON r.secret_version_id=v.id
        WHERE s.id=:secret AND v.id=:version AND s.environment_id=:env AND s.purpose='environment'
          AND r.job_id=:job AND r.plugin_instance_id=:instance
          AND v.revoked_at IS NULL AND v.invalidated_at IS NULL
    """), args):
        raise AuthorizationDenied()
    args.update(lineage=ref["version_id"], predecessor=None)
    if replaced:
        args["replaced"] = canonical_json(sorted(replaced))
        predecessor = uow.execute(text("""
            SELECT c.lineage_version_id,c.version_id FROM control_plane.environment_credential_confirmations c
            JOIN control_plane.secret_versions prior ON prior.id=c.version_id
            JOIN control_plane.secret_versions successor ON successor.id=:version
            WHERE c.secret_id=:secret AND c.environment_id=:env AND prior.version<successor.version
              AND c.version_id IN (SELECT value::uuid FROM jsonb_array_elements_text(CAST(:replaced AS jsonb)))
            ORDER BY prior.version DESC LIMIT 1
        """), args).first()
        if predecessor is None:
            return False
        args.update(lineage=predecessor.lineage_version_id, predecessor=predecessor.version_id)
    uow.execute(text("""
        INSERT INTO control_plane.environment_credential_confirmations
            (version_id,secret_id,environment_id,job_id,operation_id,lineage_version_id,predecessor_id)
        VALUES (:version,:secret,:env,:job,:op,:lineage,:predecessor) ON CONFLICT (version_id) DO NOTHING
    """), args)
    return True


def record_access_loss(uow, actor_id, student_id, environment_id):
    """Called inside the entitlement mutation after loss of the final access path."""
    require_fenced_connection(uow)
    if can_access_environment(uow, student_id, environment_id):
        return None
    args = {"actor": actor_id, "student": student_id, "env": environment_id}
    # Persist loss even when no plugin can safely change a shared account. A new
    # grant never reactivates a disconnected channel or erases pending evidence.
    revocation_id = uow.scalar(text("""
        INSERT INTO control_plane.access_revocations
            (actor_id,student_id,environment_id,exposed_versions,action_key,status,reason)
        SELECT :actor,:student,e.id,ARRAY(
            SELECT c.version_id FROM control_plane.environment_credential_confirmations c
            JOIN control_plane.secret_versions v ON v.id=c.version_id
            WHERE c.environment_id=e.id AND v.invalidated_at IS NULL ORDER BY c.version_id),
            t.definition->>'revocation_action',
            CASE WHEN t.definition->>'revocation_action' IS NULL THEN 'revocation_failed' ELSE 'revocation_pending' END,
            CASE WHEN t.definition->>'revocation_action' IS NULL THEN 'unsupported' ELSE 'awaiting_dispatch' END
        FROM control_plane.environments e JOIN control_plane.template_versions t ON t.id=e.template_version_id
        WHERE e.id=:env RETURNING id
    """), args)
    uow.execute(text("""
        UPDATE control_plane.interactive_sessions SET state='disconnected',
            reason='{"code":"access_revoked"}',closed_at=clock_timestamp()
        WHERE actor_id=:student AND environment_id=:env AND state IN ('opening','active','closing')
    """), args)
    _audit(uow, actor_id, environment_id, "access.revoked", "platform_revoked",
           {"student_id": str(student_id), "revocation_id": str(revocation_id)})
    return revocation_id


_CURRENT_VERSION = """
    SELECT v.id FROM control_plane.environment_credential_confirmations c
    JOIN control_plane.secret_versions v ON v.id=c.version_id
    JOIN control_plane.secrets s ON s.id=c.secret_id AND s.id=v.secret_id
    WHERE c.environment_id=:env AND s.environment_id=c.environment_id AND s.purpose='environment'
      AND c.secret_id=:secret ORDER BY v.version DESC LIMIT 1
"""


def confirmed_session_ref_in(uow, environment_id, declared_ref, *, pinned_version_id=None):
    """Resolve a new connection or validate a fixed version in the same confirmed chain."""
    if not isinstance(declared_ref, dict) or set(declared_ref) != {"secret_id", "version_id"}:
        raise AuthorizationDenied()
    version = uow.scalar(text(f"""
        SELECT now.version_id FROM control_plane.environment_credential_confirmations initial
        JOIN control_plane.environment_credential_confirmations now
          ON now.lineage_version_id=initial.lineage_version_id AND now.secret_id=initial.secret_id
          AND now.environment_id=initial.environment_id
        JOIN control_plane.secret_versions v ON v.id=now.version_id
        WHERE initial.version_id=:version AND initial.environment_id=:env AND initial.secret_id=:secret
          AND now.version_id=COALESCE(CAST(:pinned AS uuid), ({_CURRENT_VERSION}))
          AND v.revoked_at IS NULL AND v.invalidated_at IS NULL
    """), {"env": environment_id, "secret": declared_ref["secret_id"], "version": declared_ref["version_id"],
           "pinned": pinned_version_id})
    if version is None:
        raise AuthorizationDenied()
    return {"secret_id": declared_ref["secret_id"], "version_id": str(version)}


def is_ready_in(uow, environment_id, exact_ref):
    if not isinstance(exact_ref, dict) or set(exact_ref) != {"secret_id", "version_id"}:
        return False
    query = text(f"""
        SELECT EXISTS(SELECT FROM control_plane.secret_versions v
          WHERE v.id=({_CURRENT_VERSION}) AND v.id=:version
            AND v.revoked_at IS NULL AND v.invalidated_at IS NULL)
    """)
    return bool(uow.scalar(query, {"env": environment_id, "secret": exact_ref["secret_id"],
                                   "version": exact_ref["version_id"]}))


class CredentialService:
    def __init__(self, runtime, secrets, *, run_action=None, registry=None):
        self.runtime, self.secrets = runtime, secrets
        self.run_action, self.registry = run_action, registry

    def session_authorizer(self, actor_id, environment_id, action, *, session_id,
                           template_entry, resource_id=None, opening_binding=None):
        """Check the owner, observer and pinned entry even for buffered output."""
        from .access import resolve_session_entry_in
        from .templates import TemplateError

        if self.registry is None or action not in {
                "session.open", "session.input", "session.output", "session.resize", "session.replay",
                "session.observe", "session.reconnect", "session.close", "session.takeover", "session.release",
                "session.resume_input"}:
            return False
        with self.runtime.fenced_transaction() as uow:
            row = uow.execute(text("""
                SELECT actor_id,state,environment_id,resource_id,template_entry,plugin_instance_id,
                       session_type,secret_version_id,target_ref,controller_id FROM control_plane.interactive_sessions
                WHERE id=:session AND environment_id=:env
            """), {"session": session_id, "env": environment_id}).mappings().first()
            if row is None:
                if action != "session.open" or opening_binding is None:
                    return False
                row = opening_binding
            if row["state"] not in {"opening","active"} or str(row["resource_id"]) != str(resource_id):
                return False
            owner = row["actor_id"]
            manages = can_access_environment(uow, actor_id, environment_id, manage=True)
            if action in {"session.takeover", "session.release"} and not manages:
                return False
            if str(actor_id) != str(owner) and (not manages or action == "session.open"):
                return False
            if action == "session.resume_input" and str(actor_id) != str(owner):
                return False
            if action in {"session.input", "session.resize"} and str(row["controller_id"]) != str(actor_id):
                return False
            pinned_version = row["secret_version_id"]
            if pinned_version is None:
                return False
            try:
                entry = resolve_session_entry_in(
                    uow, self.registry, owner, environment_id, template_entry, resource_id,
                    pinned_version_id=None if action == "session.open" else pinned_version)
            except (AuthorizationDenied, ReferenceUnavailable, TemplateError, KeyError):
                return False
            return (row["template_entry"] == template_entry and row["session_type"] == entry["session_type"]
                and str(row["plugin_instance_id"]) == str(entry["plugin_instance_id"])
                and str(row["secret_version_id"]) == entry["credential_ref"]["version_id"]
                and row["target_ref"] == entry["target_ref"])


    def view(self, actor_id, environment_id, secret_id):
        # Commit the audit even on refusal. Never read ciphertext for a denied
        # actor, and never fall back past a revoked or unavailable latest version.
        value = None
        data = {}
        with self.runtime.fenced_transaction() as uow:
            # Membership, group and assignment changes take the course's write
            # lock. Account changes and lifecycle transitions lock their own
            # rows. Check the live paths in a fresh statement after any wait.
            uow.execute(text("""
                SELECT c.id FROM control_plane.courses c
                JOIN control_plane.environments e ON e.course_id=c.id
                WHERE e.id=:env FOR SHARE OF c
            """), {"env": environment_id})
            uow.execute(text("""
                SELECT e.id FROM control_plane.environments e, control_plane.users u
                WHERE e.id=:env AND u.id=:actor FOR SHARE OF e,u
            """), {"env": environment_id, "actor": actor_id})
            if can_access_environment(uow, actor_id, environment_id, require_ready=True):
                version = uow.scalar(text(_CURRENT_VERSION + " FOR SHARE OF v"),
                                     {"env": environment_id, "secret": secret_id})
                if version is not None:
                    try:
                        row = self.secrets._row(uow, SecretRef(str(secret_id), str(version)))
                        value = self.secrets._decrypt(row)
                        data = {"secret_id": str(secret_id), "version_id": str(version)}
                    except ReferenceUnavailable:
                        pass
            _audit(uow, actor_id, environment_id, "credential.view",
                   "denied" if value is None else "delivered", data)
        if value is None:
            raise AuthorizationDenied()
        return CredentialView(value)

    def revocation_status(self, actor_id, revocation_id):
        with self.runtime.fenced_transaction() as uow:
            row = uow.execute(text("""
                SELECT environment_id,student_id,status,reason,job_id FROM control_plane.access_revocations WHERE id=:id
            """), {"id": revocation_id}).mappings().first()
            if row is None or not can_read_environment_status(uow, actor_id, row["environment_id"], manage=True):
                raise AuthorizationDenied()
            return dict(row)

    def poll_revocations(self, limit=4):
        """Bounded dispatch of durable access losses through ordinary Job admission."""
        if not isinstance(limit, int) or not 1 <= limit <= 32:
            raise ValueError("revocation page must be bounded")
        with self.runtime.fenced_transaction() as uow:
            rows = uow.execute(text("""
                WITH due AS (
                    SELECT id FROM control_plane.access_revocations
                    WHERE status='revocation_pending' AND next_check_at<=clock_timestamp()
                    ORDER BY next_check_at,id LIMIT :lim FOR UPDATE SKIP LOCKED
                )
                UPDATE control_plane.access_revocations r SET next_check_at=clock_timestamp()+interval '5 seconds'
                FROM due WHERE r.id=due.id RETURNING r.*
            """), {"lim": limit}).mappings().all()
        for row in rows:
            if row["job_id"] is not None:
                self._settle(row)
            elif self.run_action is not None:
                self._dispatch(row)
        return len(rows)

    def _dispatch(self, row):
        # The durable event's actor is re-authorized on every admission. A stable
        # key recovers the same Job if this process dies before recording its id.
        try:
            job_id, _ = self.run_action(row["actor_id"], environment_id=row["environment_id"],
                action_key=row["action_key"], parameters={}, request_key="revocation/" + str(row["id"]))
        except (CapacityRejected, ExecutionConflict):
            return  # Retry on the next scheduled check, preserving the same key.
        except AuthorizationDenied:
            with self.runtime.fenced_transaction() as uow:
                self._finish(uow, row, "revocation_failed", "dispatch_forbidden")
            return
        except (ValueError, ReferenceUnavailable, RequestConflict):
            with self.runtime.fenced_transaction() as uow:
                self._finish(uow, row, "revocation_failed", "action_unavailable")
            return
        with self.runtime.fenced_transaction() as uow:
            uow.execute(text("""
                UPDATE control_plane.access_revocations SET job_id=:job,reason='awaiting_remote_confirmation'
                WHERE id=:id AND job_id IS NULL AND status='revocation_pending'
            """), {"id": row["id"], "job": job_id})

    def _settle(self, row):
        with self.runtime.fenced_transaction() as uow:
            state = uow.scalar(text("SELECT state FROM control_plane.jobs WHERE id=:job"), {"job": row["job_id"]})
            if state in {"failed", "cancelled", "blocked"}:
                self._finish(uow, row, "revocation_failed", "remote_job_" + state)
            elif state == "succeeded":
                # Job success alone says nothing about passwords saved by the student
                # or external channels. Only explicit remote evidence closes a loss.
                op = uow.execute(text("""
                    SELECT id,output->'remote_revocation' AS proof FROM control_plane.operations
                    WHERE job_id=:job AND state='succeeded' AND output ? 'remote_revocation'
                    ORDER BY finished_at DESC,id LIMIT 1
                """), {"job": row["job_id"]}).first()
                proof = op.proof if op is not None else None
                exposed = {str(version) for version in row["exposed_versions"]}
                invalidated = proof.get("invalidated_versions") if isinstance(proof, dict) else None
                known = set()
                valid_list = isinstance(invalidated, list) and all(isinstance(v, str) for v in invalidated)
                if valid_list:
                    known = exposed.intersection(invalidated)
                    uow.execute(text("""
                        UPDATE control_plane.secret_versions v SET invalidated_at=clock_timestamp()
                        WHERE v.id IN (SELECT CAST(value AS uuid) FROM jsonb_array_elements_text(CAST(:versions AS jsonb)))
                          AND v.invalidated_at IS NULL
                    """), {"versions": canonical_json(sorted(known))})
                    # The configured revocation action can confirm a shared
                    # replacement on the remote host alongside invalidation.
                    if op.proof.get("replacement_confirmed") is True:
                        try:
                            replacement = bool(known) and confirm_from_operation(uow, op.id, replaced=known)
                        except AuthorizationDenied:
                            replacement = False
                        if not replacement:
                            self._finish(uow, row, "revocation_failed", "unconfirmed_replacement")
                            return
                if (valid_list and exposed == known
                        and proof.get("remote_sessions_terminated") is True):
                    self._finish(uow, row, "confirmed", "remote_confirmed", operation_id=op.id)
                else:
                    self._finish(uow, row, "revocation_failed", "remote_evidence_missing")

    @staticmethod
    def _finish(uow, row, status, reason, *, operation_id=None):
        changed = uow.scalar(text("""
            UPDATE control_plane.access_revocations SET status=:status,reason=:reason
            WHERE id=:id AND status='revocation_pending' RETURNING id
        """), {"id": row["id"], "status": status, "reason": reason})
        if changed:
            data = {"revocation_id": str(changed), "reason": reason}
            if operation_id is not None:
                data["operation_id"] = str(operation_id)
            _audit(uow, row["actor_id"], row["environment_id"], "access.remote_revocation", status, data)
