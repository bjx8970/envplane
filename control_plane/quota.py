"""Teacher-scoped limits and reservation changes in the caller's admission transaction."""
from sqlalchemy import text

from .coordination import require_fenced_connection
from .plugins.sdk import AuthorizationDenied, canonical_json


DIMENSIONS = ("environments", "vms", "vcpu", "memory_mb")


class QuotaExceeded(ValueError):
    pass


def _validate(amounts):
    if set(amounts) != set(DIMENSIONS) or any(
        type(value) is not int or not 0 <= value <= 2**63 - 1 for value in amounts.values()
    ):
        raise ValueError("quota requires four nonnegative integer amounts")


def set_limits(uow, actor_id, teacher_id, limits):
    from .identity import active_role
    require_fenced_connection(uow)
    if active_role(uow, actor_id) != "admin" or active_role(uow, teacher_id) != "teacher":
        raise AuthorizationDenied()
    _validate(limits)
    uow.execute(text("""
        INSERT INTO control_plane.teacher_quotas(teacher_id,environments,vms,vcpu,memory_mb)
        VALUES (:teacher,:environments,:vms,:vcpu,:memory_mb)
        ON CONFLICT(teacher_id) DO UPDATE SET environments=excluded.environments,
            vms=excluded.vms, vcpu=excluded.vcpu, memory_mb=excluded.memory_mb,
            revision=control_plane.teacher_quotas.revision+1
    """), {"teacher": teacher_id, **limits})
    uow.execute(text("""
        INSERT INTO control_plane.audit_events(actor_id,action,result,data)
        VALUES (:actor,'quota.set','succeeded',jsonb_build_object('teacher_id',CAST(:teacher AS text),
                'limits',CAST(:limits AS jsonb)))
    """), {"actor": actor_id, "teacher": str(teacher_id), "limits": canonical_json(limits)})


def check_available(uow, teacher_id, requested):
    require_fenced_connection(uow)
    _validate(requested)
    limits = uow.execute(text("""
        SELECT environments,vms,vcpu,memory_mb FROM control_plane.teacher_quotas
        WHERE teacher_id=:teacher FOR UPDATE
    """), {"teacher": teacher_id}).first()
    if limits is None:
        raise QuotaExceeded("teacher quota is not configured")
    occupied = uow.execute(text("""
        SELECT COALESCE(sum(environments),0),COALESCE(sum(vms),0),
               COALESCE(sum(vcpu),0),COALESCE(sum(memory_mb),0)
        FROM control_plane.quota_reservations WHERE teacher_id=:teacher AND state <> 'released'
    """), {"teacher": teacher_id}).one()
    if any(used + requested[key] > limit for key, used, limit in zip(DIMENSIONS, occupied, limits)):
        raise QuotaExceeded("teacher quota would be exceeded")


def reserve(uow, teacher_id, job_id, environment_id, amounts):
    # check_available holds the teacher row through this INSERT and commit.
    require_fenced_connection(uow)
    uow.execute(text("""
        INSERT INTO control_plane.quota_reservations
            (teacher_id,job_id,environment_id,environments,vms,vcpu,memory_mb)
        VALUES (:teacher,:job,:environment,:environments,:vms,:vcpu,:memory_mb)
    """), {"teacher": teacher_id, "job": job_id, "environment": environment_id, **amounts})


def finish_quota(uow, environment_id, *, disposition):
    """Apply only a confirmed decision from the execution lifecycle in its fenced UoW."""
    require_fenced_connection(uow)
    if disposition not in ("allocated", "quarantined", "released"):
        raise ValueError("unknown quota disposition")
    uow.execute(text("""
        UPDATE control_plane.quota_reservations SET state=:state,updated_at=clock_timestamp(),
          released_at=CASE WHEN :state='released' THEN clock_timestamp() ELSE NULL END
        WHERE environment_id=:environment AND state <> 'released' AND state <> :state
          AND (:state <> 'allocated' OR state IN ('reserved','quarantined'))
    """), {"environment": environment_id, "state": disposition})
