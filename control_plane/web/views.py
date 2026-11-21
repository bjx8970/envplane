"""Authorized projections for browsers. Select public fields explicitly."""
from sqlalchemy import text

from ..identity import active_role, can_access_environment, can_manage_course, can_read_environment_status
from ..plugins.sdk import AuthorizationDenied
from ..quota import DIMENSIONS
from ..workflows import resource_state


def rows(db, query, **args):
    return [dict(row) for row in db.execute(text(query), args).mappings()]


def require_role(db, actor, *roles):
    role = active_role(db, actor)
    if role not in roles:
        raise AuthorizationDenied()
    return role


def parameter_fields(specs):
    return {key: {**{k: v for k, v in spec.items() if k not in {"fixed", "selector"}},
                  "selector": "selector" in spec}
            for key, spec in specs.items() if "fixed" not in spec}


def entries(specs, role, *, actions=False):
    result = {}
    for key, spec in specs.items():
        if role in spec["roles"]:
            result[key] = {"label": spec.get("label", key)}
            if actions:
                result[key]["parameters"] = parameter_fields(spec["parameters"])
    return result


class Views:
    def __init__(self, runtime):
        self.runtime = runtime

    def courses(self, actor):
        with self.runtime.fenced_transaction() as db:
            role = require_role(db, actor, "admin", "teacher")
            return rows(db, """
                SELECT id,name,owner_teacher_id FROM control_plane.courses
                WHERE deleted_at IS NULL AND (:admin OR owner_teacher_id=:actor)
                ORDER BY name,id
            """, admin=role == "admin", actor=actor)

    def course(self, actor, course):
        with self.runtime.fenced_transaction() as db:
            if not can_manage_course(db, actor, course):
                raise AuthorizationDenied()
            return {"groups": rows(db, """
                SELECT id,name FROM control_plane.groups WHERE course_id=:course AND deleted_at IS NULL
                ORDER BY name,id
            """, course=course), "members": rows(db, """
                SELECT u.id,u.username,m.group_id,u.active FROM control_plane.course_members m
                JOIN control_plane.users u ON u.id=m.student_id
                WHERE m.course_id=:course AND m.left_at IS NULL ORDER BY u.username,u.id
            """, course=course)}

    def accounts(self, actor):
        with self.runtime.fenced_transaction() as db:
            role = require_role(db, actor, "admin", "teacher")
            return rows(db, """
                SELECT id,username,role,active,
                       (:admin OR (created_by=:actor AND exclusive_management)) IS TRUE AS manageable
                FROM control_plane.users
                WHERE deleted_at IS NULL AND (:admin OR (role='student' AND (active OR
                    (created_by=:actor AND exclusive_management))))
                ORDER BY username,id
            """, admin=role == "admin", actor=actor)

    def templates(self, actor):
        with self.runtime.fenced_transaction() as db:
            role = require_role(db, actor, "admin", "teacher")
            records = rows(db, """
                SELECT v.id,v.template_id,v.version,v.status,v.definition FROM control_plane.template_versions v
                WHERE :admin OR v.status='published' ORDER BY v.created_at DESC,v.id
            """, admin=role == "admin")
            for record in records:
                definition = record["definition"] if role == "admin" else record.pop("definition")
                record["metadata"] = definition.get("metadata", {})
                if record["status"] == "published":
                    record["parameters"] = parameter_fields(definition["parameters"])
            return records

    def environments(self, actor):
        with self.runtime.fenced_transaction() as db:
            role = require_role(db, actor, "admin", "teacher", "student")
            if role == "student":
                from ..identity import _STUDENT_PATHS
                return rows(db, f"""
                    SELECT e.id,e.name,e.lifecycle,e.course_id FROM control_plane.environments e
                    WHERE EXISTS (SELECT FROM ({_STUDENT_PATHS}) p
                                  WHERE p.student_id=:actor AND p.environment_id=e.id)
                    ORDER BY e.created_at DESC,e.id
                """, actor=actor)
            return rows(db, """
                SELECT id,name,lifecycle,course_id FROM control_plane.environments
                WHERE :admin OR owner_teacher_id=:actor ORDER BY created_at DESC,id
            """, admin=role == "admin", actor=actor)

    def environment(self, actor, env):
        with self.runtime.fenced_transaction() as db:
            if not can_read_environment_status(db, actor, env):
                raise AuthorizationDenied()
            role = active_role(db, actor)
            record, = rows(db, """
                SELECT e.id,e.name,e.course_id,e.template_version_id,e.lifecycle,e.updated_at,v.definition
                FROM control_plane.environments e
                JOIN control_plane.template_versions v ON v.id=e.template_version_id WHERE e.id=:env
            """, env=env)
            definition = record.pop("definition")
            live = record["lifecycle"] != "deleted"
            ready = record["lifecycle"] == "ready"
            record["actions"] = entries(definition["actions"], role, actions=True) if ready else {}
            record["access"] = entries(definition["access"], role) if ready else {}
            record["resources"] = rows(db, """
                SELECT id,name,type_label,display,action_snapshot,access_snapshot
                FROM control_plane.experiment_resources WHERE environment_id=:env ORDER BY name,id
            """, env=env)
            for resource in record["resources"]:
                actions, access = resource.pop("action_snapshot"), resource.pop("access_snapshot")
                resource["actions"] = entries(actions, role, actions=True) if ready else {}
                resource["access"] = entries(access, role) if ready else {}
                resource.update(resource_state(db, resource["id"]))
            record["credentials"] = rows(db, """
                SELECT id FROM (
                    SELECT DISTINCT ON (c.secret_id) c.secret_id AS id,v.revoked_at,v.invalidated_at
                    FROM control_plane.environment_credential_confirmations c
                    JOIN control_plane.secret_versions v ON v.id=c.version_id
                    JOIN control_plane.secrets s ON s.id=v.secret_id
                    WHERE c.environment_id=:env AND s.environment_id=c.environment_id AND s.purpose='environment'
                    ORDER BY c.secret_id,v.version DESC
                ) current WHERE revoked_at IS NULL AND invalidated_at IS NULL ORDER BY id
            """, env=env) if ready else []
            record["cleanup"] = role in {"admin", "teacher"} and live and bool(definition["cleanup"])
            record["jobs"] = rows(db, """
                SELECT id,kind,state,created_at FROM control_plane.jobs
                WHERE environment_id=:env AND actor_id=:actor ORDER BY created_at DESC,id LIMIT 50
            """, env=env, actor=actor)
            if role in {"admin", "teacher"}:
                record["assignments"] = rows(db, """
                    SELECT id,student_id,group_id FROM control_plane.environment_assignments
                    WHERE environment_id=:env AND revoked_at IS NULL ORDER BY assigned_at,id
                """, env=env)
                record["revocations"] = rows(db, """
                    SELECT id,student_id,status,reason,job_id,created_at FROM control_plane.access_revocations
                    WHERE environment_id=:env ORDER BY created_at DESC,id LIMIT 100
                """, env=env)
            return record

    def resource_environment(self, actor, resource):
        with self.runtime.fenced_transaction() as db:
            env = db.scalar(text("""
                SELECT environment_id FROM control_plane.experiment_resources WHERE id=:resource
            """), {"resource": resource})
            if not env or not can_access_environment(db, actor, env):
                raise AuthorizationDenied()
            return env

    def job(self, actor, job, *, after=None):
        with self.runtime.fenced_transaction() as db:
            found = rows(db, """
                SELECT id AS job_id,environment_id,kind,state,created_at,updated_at,finished_at
                FROM control_plane.jobs WHERE id=:job AND actor_id=:actor
            """, job=job, actor=actor)
            if not found or not can_read_environment_status(db, actor, found[0]["environment_id"]):
                raise AuthorizationDenied()
            if after is not None:
                # Persisted plugin log bodies are opaque. Expose sequence and
                # time without transferring arbitrary vendor text to browsers.
                return rows(db, """
                    SELECT sequence,created_at,
                           CASE WHEN data->>'code' IN ('claimed','cancel_requested','dispatch_execute',
                               'dispatch_poll','dispatch_cancel','result_succeeded','result_failed',
                               'result_pending_external','result_unknown','plugin_log','plugin_progress')
                               THEN data->>'code'
                               ELSE 'event' END AS code FROM control_plane.job_logs
                    WHERE job_id=:job AND sequence>:after ORDER BY sequence LIMIT 100
                """, job=job, after=after)
            found[0]["steps"] = rows(db, """
                SELECT step_path,state,attempt FROM control_plane.job_steps WHERE job_id=:job
                ORDER BY created_at,id
            """, job=job)
            if found[0]["kind"] == "session_open":
                found[0]["session_id"] = db.scalar(text("""
                    SELECT id FROM control_plane.interactive_sessions
                    WHERE job_id=:job AND actor_id=:actor
                """), {"job": job, "actor": actor})
            return found[0]

    def terminal_sessions(self, actor, environment):
        with self.runtime.fenced_transaction() as db:
            if not can_read_environment_status(db, actor, environment):
                raise AuthorizationDenied()
            manage = can_read_environment_status(db, actor, environment, manage=True)
            return rows(db, """
                SELECT s.id,s.actor_id,u.username,s.resource_id,s.template_entry,s.state,s.controller_id,
                       s.controller_revision,
                       CASE WHEN s.reason->>'code' IN ('access_revoked','process_restart','opening_unknown',
                          'not_established','service_stop','client_close','channel_lost','remote_channel_closed',
                          'idle_timeout','lifetime_timeout','receiver_not_started')
                         THEN jsonb_build_object('code',s.reason->>'code') END AS reason,
                       s.created_at,s.closed_at
                FROM control_plane.interactive_sessions s JOIN control_plane.users u ON u.id=s.actor_id
                WHERE s.environment_id=:env AND (:manage OR s.actor_id=:actor)
                ORDER BY s.created_at DESC,s.id LIMIT 100
            """, env=environment, manage=manage, actor=actor)

    def quota(self, actor, teacher):
        with self.runtime.fenced_transaction() as db:
            role = require_role(db, actor, "admin", "teacher")
            if role != "admin" and actor != teacher:
                raise AuthorizationDenied()
            limits = rows(db, """
                SELECT environments,vms,vcpu,memory_mb FROM control_plane.teacher_quotas WHERE teacher_id=:teacher
            """, teacher=teacher)
            usage = rows(db, """
                SELECT state,sum(environments)::text AS environments,sum(vms)::text AS vms,
                       sum(vcpu)::text AS vcpu,sum(memory_mb)::text AS memory_mb
                FROM control_plane.quota_reservations WHERE teacher_id=:teacher AND state <> 'released' GROUP BY state
            """, teacher=teacher)
            return {"limits": limits[0] if limits else None,
                    "usage": {row["state"]: {k: int(row[k]) for k in DIMENSIONS} for row in usage}}
