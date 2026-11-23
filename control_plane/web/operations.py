"""Administrator projections of execution and operational facts."""
from starlette.exceptions import HTTPException

from .views import require_role, rows


_PAGE_SIZE = 50
_JOB_REASON = """
    CASE WHEN j.error->>'code' IN (
        'execution_dependency_unavailable','unknown_external_result','expired_dispatched_execution',
        'protocol_error','no_safe_recovery_path','local_result_application_failed',
        'missing_recovery_reference','call_deadline_exceeded','dispatch_capacity_unavailable',
        'remote_still_pending','recovery_interrupted','recovery_could_not_proceed')
    THEN j.error->>'code' END
"""


class OperationsViews:
    def __init__(self, runtime):
        self.runtime = runtime

    def status(self, actor):
        with self.runtime.fenced_transaction() as db:
            require_role(db, actor, "admin")
            coordinator, = rows(db, """
                SELECT revision,heartbeat_at,expires_at FROM control_plane.coordinator_leases WHERE id=1
            """)
            quota, = rows(db, """
                SELECT count(DISTINCT environment_id) AS affected_environments,
                       COALESCE(sum(environments),0)::text AS environments,
                       COALESCE(sum(vms),0)::text AS vms,COALESCE(sum(vcpu),0)::text AS vcpu,
                       COALESCE(sum(memory_mb),0)::text AS memory_mb
                FROM control_plane.quota_reservations WHERE state='quarantined'
            """)
        health = self.runtime.health()
        capacity = health["services"].get("capacity")
        return {"status": "ready" if health["ready"] and capacity is not None else "degraded",
                "coordinator": {"state": health["coordinator"], **coordinator}, "capacity": capacity,
                "quarantined_quota": {key: int(value) for key, value in quota.items()}}

    def blocked_jobs(self, actor, before):
        with self.runtime.fenced_transaction() as db:
            require_role(db, actor, "admin")
            cursor = None
            if before is not None:
                found = rows(db, "SELECT created_at FROM control_plane.jobs WHERE id=:id", id=before)
                if not found:
                    raise ValueError("invalid jobs cursor")
                cursor = found[0]["created_at"]
            jobs = rows(db, f"""
                SELECT j.id AS job_id,j.environment_id,e.name AS environment_name,j.kind,j.state,
                       j.updated_at,g.revision AS group_revision,{_JOB_REASON} AS reason
                FROM control_plane.jobs j JOIN control_plane.execution_groups g ON g.id=j.execution_group_id
                JOIN control_plane.environments e ON e.id=j.environment_id
                WHERE j.state='blocked'
                  AND (:first OR (j.created_at,j.id)<(CAST(:created AS timestamptz),CAST(:before AS uuid)))
                ORDER BY j.created_at DESC,j.id DESC LIMIT :limit
            """, first=before is None, created=cursor, before=before, limit=_PAGE_SIZE + 1)
        page = jobs[:_PAGE_SIZE]
        return {"jobs": page, "next_before": page[-1]["job_id"] if len(jobs) > _PAGE_SIZE else None}

    def blocked_job(self, actor, job):
        with self.runtime.fenced_transaction() as db:
            require_role(db, actor, "admin")
            found = rows(db, f"""
                SELECT j.id AS job_id,j.environment_id,e.name AS environment_name,j.kind,j.state,j.updated_at,
                       g.revision AS group_revision,g.state AS group_state,{_JOB_REASON} AS reason,
                       (g.current_job_id=j.id AND g.state='blocked' AND j.state='blocked'
                            AND j.kind<>'session_open') IS TRUE AS recoverable
                FROM control_plane.jobs j JOIN control_plane.execution_groups g ON g.id=j.execution_group_id
                JOIN control_plane.environments e ON e.id=j.environment_id
                WHERE j.id=:job AND (j.state='blocked' OR EXISTS
                    (SELECT FROM control_plane.execution_recovery_requests WHERE job_id=j.id))
            """, job=job)
            if not found:
                raise HTTPException(404)
            detail = found[0]
            detail["operations"] = rows(db, """
                SELECT o.id AS operation_id,s.step_path,o.state,o.dispatch_intent_at,
                       o.external_execution_ref IS NOT NULL AS has_external_reference,
                       (o.dispatch_intent_at IS NOT NULL AND o.state IN ('unknown','pending_external')
                        AND o.id=s.current_operation_id AND o.protocol_error IS NULL
                        AND o.prepared_call->'execution_policy'->>'recovery'='queryable'
                        AND EXISTS (SELECT FROM control_plane.operation_call_attempts c
                                    WHERE c.operation_id=o.id AND c.method='execute')) IS TRUE AS can_poll
                FROM control_plane.operations o JOIN control_plane.job_steps s ON s.id=o.step_id
                WHERE o.job_id=:job ORDER BY (o.state IN ('unknown','pending_external')) DESC,o.created_at DESC,o.id DESC
                LIMIT 100
            """, job=job)
            detail["evidence"] = rows(db, """
                SELECT e.id AS evidence_id,e.operation_id,e.kind,e.call_attempt_id,e.created_at,
                       (e.kind='late_result' AND c.method IN ('execute','poll')
                       AND o.state IN ('unknown','pending_external') AND o.id=s.current_operation_id
                       AND e.data->>'outcome'='succeeded'
                       AND COALESCE(e.data->'protocol_error','null'::jsonb)='null'::jsonb) IS TRUE AS can_apply
                FROM control_plane.operation_evidence e
                JOIN control_plane.operations o ON o.id=e.operation_id
                JOIN control_plane.job_steps s ON s.id=o.step_id
                LEFT JOIN control_plane.operation_call_attempts c ON c.id=e.call_attempt_id AND c.operation_id=o.id
                WHERE o.job_id=:job ORDER BY can_apply DESC,e.created_at DESC,e.id DESC LIMIT 100
            """, job=job)
            detail["requests"] = rows(db, """
                SELECT id AS request_id,actor_id,operation_id,evidence_id,action,reason,state,outcome,
                       created_at,finished_at FROM control_plane.execution_recovery_requests
                WHERE job_id=:job ORDER BY created_at DESC,id DESC LIMIT 100
            """, job=job)
            return detail
