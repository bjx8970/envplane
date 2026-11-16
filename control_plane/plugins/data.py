"""Core-only helpers for bounded values and provenance. No plugin database API."""
from sqlalchemy import text

from .sdk import AuthorizationDenied, ReferenceUnavailable, finite_json


def ref_dict(ref):
    return ref.to_dict() if hasattr(ref, 'to_dict') else dict(ref)


def find_refs(data, kind):
    finite_json(data)
    result = []
    stack = [data]
    while stack:
        value = stack.pop()
        if isinstance(value, dict):
            required = {'secret_id', 'version_id'} if kind == 'secret' else {'instance_id', 'key', 'version_id'}
            if required.issubset(value) and all(isinstance(value[k], str) for k in required):
                result.append({k: value[k] for k in required})
            stack.extend(value.values())
        elif isinstance(value, list):
            stack.extend(value)
    return result


def trusted_source(connection, job_id, instance_id, source_operation_id, source_evidence_id=None):
    """Read only durable, same execution-group evidence; never trust caller data."""
    row = connection.execute(text('''
        SELECT o.state,o.output,o.job_id FROM control_plane.operations o
        JOIN control_plane.jobs source ON source.id=o.job_id
        JOIN control_plane.jobs target ON target.id=:job
        WHERE o.id=:operation AND o.plugin_instance_id=:instance
          AND source.execution_group_id=target.execution_group_id
          AND source.environment_id=target.environment_id
    '''), {'job': job_id, 'operation': source_operation_id, 'instance': instance_id}).first()
    if row is None:
        raise AuthorizationDenied()
    if source_evidence_id is None:
        if row.state != 'succeeded' or row.output is None:
            raise ReferenceUnavailable('successful source output is unavailable')
        return row.output
    evidence = connection.execute(text('''
        SELECT data FROM control_plane.operation_evidence
        WHERE id=:evidence AND operation_id=:operation AND kind='checkpoint' AND trusted_for_derivation
    '''), {'evidence': source_evidence_id, 'operation': source_operation_id}).first()
    if evidence is None:
        raise ReferenceUnavailable('controlled checkpoint is unavailable')
    return evidence.data


def trusted_storage_refs(connection, job_id, instance_id):
    """Only durable outputs/checkpoints published by the core qualify, not Storage writes."""
    rows = connection.execute(text('''
        SELECT o.output AS data FROM control_plane.operations o
        JOIN control_plane.jobs s ON s.id=o.job_id JOIN control_plane.jobs j ON j.id=:job
        WHERE s.execution_group_id=j.execution_group_id AND o.plugin_instance_id=:instance
          AND o.state='succeeded' AND o.output IS NOT NULL
        UNION ALL
        SELECT e.data FROM control_plane.operation_evidence e
        JOIN control_plane.operations o ON o.id=e.operation_id
        JOIN control_plane.jobs s ON s.id=o.job_id JOIN control_plane.jobs j ON j.id=:job
        WHERE s.execution_group_id=j.execution_group_id AND o.plugin_instance_id=:instance
          AND e.kind='checkpoint' AND e.trusted_for_derivation
    '''), {'job': job_id, 'instance': instance_id}).all()
    return {(r['key'], r['version_id']) for row in rows for r in find_refs(row.data, 'storage')
            if r['instance_id'] == str(instance_id)}


def active_instance(connection, instance_id):
    row = connection.execute(text('SELECT enabled FROM control_plane.plugin_instances WHERE id=:id'),
                             {'id': instance_id}).first()
    if row is None or not row.enabled:
        raise ReferenceUnavailable('plugin instance is unavailable')


def json_clone(value):
    from .sdk import canonical_json
    import json
    return json.loads(canonical_json(value))
