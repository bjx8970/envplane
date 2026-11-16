"""Identity-bound plugin capability context; database handles stay in the core."""
from dataclasses import dataclass, field
from types import MappingProxyType
from uuid import UUID

from sqlalchemy import text

from .configuration import ConfigurationService
from .data import json_clone
from .sdk import AuthorizationDenied, PreparedCall, ReferenceUnavailable, finite_json
from .storage import StorageService


@dataclass(frozen=True)
class RuntimeContext:
    plugin_instance_id: str
    environment_id: str
    job_id: str
    step_instance_id: str
    operation_id: str | None
    invocation_key: str
    lease_token: str
    deadline: object
    configuration: dict = field(repr=False)
    storage: object = field(repr=False)
    secrets: object = field(repr=False)
    logger: object = field(repr=False)
    progress: object = field(repr=False)
    cancellation: object = field(repr=False)
    report_external_ref: object = field(repr=False)
    report_checkpoint: object = field(repr=False)

    @property
    def config(self):
        return self.configuration


class _Cancellation:
    __slots__ = ('__callback',)
    def __init__(self, callback=None):
        self.__callback = callback
    def is_requested(self):
        return bool(self.__callback()) if self.__callback else False
    @property
    def requested(self):
        return self.is_requested()


class _Logger:
    __slots__ = ('__callback', '__sanitize', '__count')
    def __init__(self, callback, sanitize):
        self.__callback, self.__sanitize, self.__count = callback, sanitize, 0
    def log(self, level, message, **details):
        if level not in ('debug', 'info', 'warning', 'error') or self.__count >= 100:
            return
        data = self.__sanitize({'level': level, 'message': message, 'details': details})
        finite_json(data, max_bytes=16384, max_items=100)
        self.__count += 1
        if self.__callback:
            self.__callback(data)
    def info(self, message, **details):
        self.log('info', message, **details)
    def warning(self, message, **details):
        self.log('warning', message, **details)
    def error(self, message, **details):
        self.log('error', message, **details)
    def debug(self, message, **details):
        self.log('debug', message, **details)


class ContextBuilder:
    def __init__(self, engine, runtime, registry, secrets):
        self._engine, self._runtime, self._registry, self._secrets = engine, runtime, registry, secrets
        self._storage = StorageService(engine, runtime, safe_json=secrets.safe_json)
        self._configuration = ConfigurationService(engine, runtime, registry, safe_json=secrets.safe_json)

    def safe_json(self, value):
        return self._secrets.safe_json(value)

    def publish_from_source_in(self, uow, job_id, instance_id, source_operation_id, source_evidence_id=None):
        return self._secrets.publish_from_source_in(uow, job_id, instance_id, source_operation_id, source_evidence_id)

    def validate_prepared_in(self, connection, job_id, plugin_instance_id, prepared, *, step_instance_id=None):
        if isinstance(prepared, dict):
            prepared = PreparedCall.from_dict(prepared)
        prepared.to_dict()
        row = connection.execute(text('''SELECT p.*,j.environment_id,i.plugin_key
            FROM control_plane.job_plugin_snapshots p JOIN control_plane.jobs j ON j.id=p.job_id
            JOIN control_plane.plugin_instances i ON i.id=p.instance_id
            WHERE p.job_id=:job AND p.instance_id=:instance'''),
            {'job': job_id, 'instance': plugin_instance_id}).first()
        if row is None:
            raise AuthorizationDenied()
        config = self._configuration.get_in(connection, plugin_instance_id, row.configuration_revision)
        plugin = self._registry.get(row.plugin_key)
        plugin.validate_prepared(prepared)
        self._storage.validate_refs_in(connection, job_id, plugin_instance_id, prepared.storage_refs)
        self._secrets.validate_refs_in(connection, job_id, plugin_instance_id, row.environment_id,
                                      prepared.secret_refs, step_instance_id=step_instance_id)
        return prepared

    def validate_prepared(self, job_id, plugin_instance_id, prepared, *, step_instance_id=None):
        with self._engine.connect() as connection:
            return self.validate_prepared_in(connection, job_id, plugin_instance_id, prepared,
                                             step_instance_id=step_instance_id)

    def build(self, *, job_id, plugin_instance_id, step_instance_id, operation_id, invocation_key,
              lease_token, deadline, prepared=None, report_external_ref=None, report_checkpoint=None,
              logger=None, progress=None, cancellation=None):
        deadline.check()
        with self._engine.connect() as connection:
            row = connection.execute(text('''SELECT p.*,j.environment_id,s.id AS step_id,
                       j.lease_owner,j.execution_group_id,g.revision AS group_revision
                FROM control_plane.job_plugin_snapshots p JOIN control_plane.jobs j ON j.id=p.job_id
                JOIN control_plane.execution_groups g ON g.id=j.execution_group_id
                JOIN control_plane.job_steps s ON s.job_id=j.id
                WHERE p.job_id=:job AND p.instance_id=:instance AND s.id=:step'''),
                {'job': job_id, 'instance': plugin_instance_id, 'step': step_instance_id}).first()
            if row is None:
                raise AuthorizationDenied()
            if operation_id is not None:
                operation = connection.execute(text('''SELECT invocation_key FROM control_plane.operations
                    WHERE id=:operation AND job_id=:job AND step_id=:step AND plugin_instance_id=:instance'''),
                    {'operation': operation_id, 'job': job_id, 'step': step_instance_id, 'instance': plugin_instance_id}).first()
                if operation is None or operation.invocation_key != invocation_key:
                    raise AuthorizationDenied()
            configuration = self._configuration.get_in(connection, plugin_instance_id, row.configuration_revision)
            if prepared is not None:
                prepared = self.validate_prepared_in(connection, job_id, plugin_instance_id, prepared,
                                                      step_instance_id=step_instance_id)
            def coordinator_identity():
                if hasattr(self._runtime, 'coordinator_identity'):
                    owner, revision = self._runtime.coordinator_identity
                else:
                    owner, revision = self._runtime.owner_id, self._runtime.revision
                return str(owner), revision
            coordinator = coordinator_identity()
            lease_owner, group_id, group_revision = row.lease_owner, str(row.execution_group_id), row.group_revision
            fixed_token = str(lease_token)
            def access_guard(current):
                deadline.check()
                if coordinator_identity() != coordinator:
                    raise AuthorizationDenied()
                eligible = current.scalar(text('''SELECT j.id FROM control_plane.jobs j
                    JOIN control_plane.execution_groups g ON g.id=j.execution_group_id
                    WHERE j.id=:job AND j.lease_token=:token AND j.lease_owner=:owner
                      AND j.lease_expires_at>clock_timestamp() AND j.state IN ('running','cancel_requested')
                      AND g.id=:group AND g.revision=:revision AND g.current_job_id=j.id AND g.state='active'
                    FOR UPDATE OF j,g'''),
                    {'job': job_id, 'token': fixed_token, 'owner': lease_owner,
                     'group': group_id, 'revision': group_revision})
                if eligible is None:
                    raise AuthorizationDenied()
            access_guard(connection)
        def bounded(callback, *, object_only=False):
            def send(key, value):
                # Late evidence is appended by the bound repository callback;
                # deadline/Job loss must not turn it into authoritative success.
                if not isinstance(key, str) or not key or len(key) > 255 or callback is None:
                    raise ReferenceUnavailable('durable evidence callback is unavailable')
                safe = self._secrets.safe_json(value)
                finite_json(safe, object_only=object_only)
                return callback(key, safe)
            return send
        def report_progress(value):
            deadline.check()
            safe = self._secrets.safe_json(value)
            finite_json(safe, max_bytes=16384)
            return progress(safe) if progress else None
        return RuntimeContext(str(plugin_instance_id), str(row.environment_id), str(job_id),
            str(step_instance_id), str(operation_id) if operation_id else None, invocation_key,
            str(lease_token), deadline, json_clone(configuration.configuration['data']),
            self._storage.bind(plugin_instance_id, job_id, access_guard=access_guard),
            self._secrets.bind(job_id, plugin_instance_id, row.environment_id,
                               prepared.secret_refs if prepared is not None else None,
                               step_instance_id=step_instance_id, operation_id=operation_id, access_guard=access_guard),
            _Logger(logger, self._secrets.safe_json), report_progress, _Cancellation(cancellation),
            bounded(report_external_ref), bounded(report_checkpoint))
