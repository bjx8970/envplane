from dataclasses import dataclass
import json
from uuid import UUID, uuid4

from sqlalchemy import text

from .coordination import require_fenced_connection


class StorageConflict(RuntimeError):
    pass


class RequestConflict(RuntimeError):
    pass


@dataclass(frozen=True)
class StorageVersion:
    id: UUID
    version: int
    namespace_revision: int


def write_storage(connection, instance_id, key, value, *, expected_version=None, delete=False):
    require_fenced_connection(connection)
    if not isinstance(key, str) or not key or len(key) > 255:
        raise ValueError("invalid storage key")
    if not delete and not isinstance(value, dict):
        raise ValueError("storage values must be JSON objects")
    encoded = json.dumps(value, allow_nan=False) if not delete else None
    revision = connection.scalar(text(
        "SELECT namespace_revision FROM control_plane.plugin_instances WHERE id=:id FOR UPDATE"
    ), {"id": instance_id})
    if revision is None:
        raise ValueError("plugin instance does not exist")
    current = connection.execute(text("""
        SELECT v.id, v.version FROM control_plane.plugin_storage_heads h
        JOIN control_plane.plugin_storage_versions v ON v.id=h.version_id
        WHERE h.instance_id=:instance AND h.key=:key
    """), {"instance": instance_id, "key": key}).first()
    if (current is None and expected_version is not None) or (
        current is not None and str(current.id) != str(expected_version)
    ):
        raise StorageConflict("storage version changed")
    if delete and current is None:
        raise StorageConflict("storage key does not exist")
    result = StorageVersion(uuid4(), current.version + 1 if current else 1, revision + 1)
    connection.execute(text("""
        UPDATE control_plane.plugin_instances SET namespace_revision=:revision WHERE id=:instance
    """), {"revision": result.namespace_revision, "instance": instance_id})
    connection.execute(text("""
        INSERT INTO control_plane.plugin_storage_versions
          (id,instance_id,key,version,namespace_revision,value,is_tombstone)
        VALUES (:id,:instance,:key,:version,:revision,CAST(:value AS jsonb),:deleted)
    """), {"id": result.id, "instance": instance_id, "key": key, "version": result.version,
           "revision": result.namespace_revision, "value": encoded, "deleted": delete})
    connection.execute(text("""
        INSERT INTO control_plane.plugin_storage_heads(instance_id,key,version_id)
        VALUES (:instance,:key,:id)
        ON CONFLICT(instance_id,key) DO UPDATE SET version_id=EXCLUDED.version_id
    """), {"instance": instance_id, "key": key, "id": result.id})
    return result


def admit_job(connection, *, actor_id, request_key, request_digest, environment_id,
              execution_group_id, logical_invocation_id, kind, input, execution_snapshot, parent_job_id=None):
    require_fenced_connection(connection)
    job_id = uuid4()
    inserted = connection.scalar(text("""
        INSERT INTO control_plane.jobs
            (id,actor_id,request_key,request_digest,environment_id,execution_group_id,
             logical_invocation_id,kind,input,execution_snapshot,parent_job_id)
        VALUES (:id,:actor,:key,:digest,:environment,:group,:invocation,:kind,
                CAST(:input AS jsonb),CAST(:snapshot AS jsonb),:parent)
        ON CONFLICT(actor_id,request_key) DO NOTHING RETURNING id
    """), {"id": job_id, "actor": actor_id, "key": request_key, "digest": request_digest,
           "environment": environment_id, "group": execution_group_id, "parent": parent_job_id,
           "invocation": logical_invocation_id, "kind": kind,
           "input": json.dumps(input, allow_nan=False),
           "snapshot": json.dumps(execution_snapshot, allow_nan=False)})
    if inserted is not None:
        return inserted, False
    previous = connection.execute(text("""
        SELECT id,request_digest FROM control_plane.jobs
        WHERE actor_id=:actor AND request_key=:key
    """), {"actor": actor_id, "key": request_key}).one()
    if previous.request_digest != request_digest:
        raise RequestConflict("request key is already associated with a different request")
    return previous.id, True
