"""Administrator-owned immutable configuration versions and atomic Job pinning."""
from dataclasses import dataclass
import hashlib
import hmac
import os
from uuid import uuid4

from sqlalchemy import text

from ..coordination import require_fenced_connection
from ..persistence import StorageConflict
from .data import active_instance, json_clone
from .sdk import ReferenceUnavailable, canonical_json, finite_json
from .storage import StorageService


@dataclass(frozen=True)
class ConfigurationVersion:
    id: str
    instance_id: str
    revision: int
    configuration: dict
    plugin_version: str
    code_digest: str


class ConfigurationService:
    def __init__(self, engine, runtime, registry, *, safe_json=None):
        self._engine, self._runtime, self._registry = engine, runtime, registry
        self._safe_json = safe_json or (lambda value: finite_json(value, object_only=True))
        self._storage = StorageService(engine, runtime, safe_json=safe_json)
        # A capture is consumed only in its issuing transaction. This key is not
        # a recovery fact or deployment encryption key; no pending capture survives commit.
        self.__capture_key = os.urandom(32)

    def put(self, instance_id, envelope, *, expected_revision):
        with self._runtime.fenced_transaction() as uow:
            return self.put_in(uow, instance_id, envelope, expected_revision=expected_revision)

    def put_in(self, uow, instance_id, envelope, *, expected_revision):
        require_fenced_connection(uow)
        finite_json(envelope, object_only=True)
        envelope = self._safe_json(envelope)
        if set(envelope) != {'data', 'allowed_secret_refs'} or not isinstance(envelope['data'], dict) or not isinstance(envelope['allowed_secret_refs'], list):
            raise ValueError('configuration envelope requires data and allowed_secret_refs')
        for ref in envelope['allowed_secret_refs']:
            if not isinstance(ref, dict) or not {'secret_id'}.issubset(ref) or set(ref) - {'secret_id', 'version_id'}:
                raise ValueError('invalid administrator secret allow-list')
        active_instance(uow, instance_id)
        row = uow.execute(text('''SELECT plugin_key,configuration_revision FROM control_plane.plugin_instances
                                  WHERE id=:id FOR UPDATE'''), {'id': instance_id}).one()
        if row.configuration_revision != expected_revision:
            raise StorageConflict('configuration revision changed')
        plugin = self._registry.get(row.plugin_key)
        identity, revision = str(uuid4()), expected_revision + 1
        uow.execute(text('''INSERT INTO control_plane.plugin_instance_versions
            (id,instance_id,revision,configuration,plugin_version,code_digest)
            VALUES (:id,:instance,:revision,CAST(:configuration AS jsonb),:version,:digest)'''),
            {'id': identity, 'instance': instance_id, 'revision': revision,
             'configuration': canonical_json(envelope), 'version': plugin.plugin_version, 'digest': plugin.code_digest})
        uow.execute(text('''UPDATE control_plane.plugin_instances SET configuration_revision=:revision
                             WHERE id=:id'''), {'id': instance_id, 'revision': revision})
        return ConfigurationVersion(identity, str(instance_id), revision, json_clone(envelope), plugin.plugin_version, plugin.code_digest)

    def get_in(self, connection, instance_id, revision=None):
        active_instance(connection, instance_id)
        if revision is None:
            revision = connection.scalar(text('SELECT configuration_revision FROM control_plane.plugin_instances WHERE id=:id'), {'id': instance_id})
        row = connection.execute(text('''SELECT v.*,i.plugin_key FROM control_plane.plugin_instance_versions v
            JOIN control_plane.plugin_instances i ON i.id=v.instance_id WHERE v.instance_id=:id AND v.revision=:revision'''),
            {'id': instance_id, 'revision': revision}).first()
        if row is None:
            raise ReferenceUnavailable('configuration history is unavailable')
        plugin = self._registry.get(row.plugin_key)
        if (plugin.plugin_version, plugin.code_digest) != (row.plugin_version, row.code_digest):
            raise ReferenceUnavailable('loaded plugin code does not match fixed configuration')
        return ConfigurationVersion(str(row.id), str(instance_id), revision, row.configuration, row.plugin_version, row.code_digest)

    def get(self, instance_id, revision=None):
        with self._engine.connect() as connection:
            return self.get_in(connection, instance_id, revision)

    def capture_in(self, uow, instance_id, secret_service, environment_id):
        """Core admission seam: capture before immutable Job INSERT, in the same UoW.

        Trusted policy authorizes the request/quota separately. Plugins never see
        this service or its capture/bind entry points.
        """
        require_fenced_connection(uow)
        uow.scalar(text('SELECT id FROM control_plane.plugin_instances WHERE id=:id FOR UPDATE'), {'id': instance_id})
        config = self.get_in(uow, instance_id)
        plugin_key = uow.scalar(text('SELECT plugin_key FROM control_plane.plugin_instances WHERE id=:id'), {'id': instance_id})
        snapshot = self._storage.snapshot_in(uow, instance_id)
        refs = secret_service.capture_refs_in(uow, config.id, instance_id, environment_id)
        value = {'instance_id': str(instance_id), 'environment_id': str(environment_id),
                 'plugin_key': plugin_key, 'configuration_version_id': config.id,
                 'configuration_revision': config.revision, 'storage_snapshot_id': snapshot.id,
                 'namespace_revision': snapshot.namespace_revision, 'plugin_version': config.plugin_version,
                 'code_digest': config.code_digest, 'secret_refs': refs,
                 'capture_transaction_id': str(uow.scalar(text('SELECT pg_current_xact_id()::text')))}
        value['capture_digest'] = hmac.new(self.__capture_key, canonical_json(value).encode(), hashlib.sha256).hexdigest()
        return value

    def bind_capture_in(self, uow, job_id, instance_id, capture, secret_service):
        """Consume exact capture after Job INSERT; never re-resolve a current value."""
        require_fenced_connection(uow)
        capture = json_clone(capture)
        expected_keys = {'instance_id', 'environment_id', 'plugin_key', 'configuration_version_id',
                         'configuration_revision', 'storage_snapshot_id', 'namespace_revision', 'plugin_version',
                         'code_digest', 'secret_refs', 'capture_transaction_id', 'capture_digest'}
        if set(capture) != expected_keys or capture['instance_id'] != str(instance_id):
            raise ReferenceUnavailable('invalid plugin snapshot capture')
        digest = capture.pop('capture_digest')
        expected = hmac.new(self.__capture_key, canonical_json(capture).encode(), hashlib.sha256).hexdigest()
        capture['capture_digest'] = digest
        if not isinstance(digest, str) or not hmac.compare_digest(digest, expected):
            raise ReferenceUnavailable('plugin snapshot capture changed')
        if str(uow.scalar(text('SELECT pg_current_xact_id()::text'))) != capture['capture_transaction_id']:
            raise ReferenceUnavailable('plugin snapshot capture belongs to another transaction')
        job = uow.execute(text('SELECT environment_id,execution_snapshot FROM control_plane.jobs WHERE id=:job FOR UPDATE'),
                          {'job': job_id}).first()
        if job is None or str(job.environment_id) != capture['environment_id']:
            raise ReferenceUnavailable('plugin snapshot environment mismatch')
        if job.execution_snapshot.get('plugins', {}).get(str(instance_id)) != capture:
            raise ReferenceUnavailable('immutable Job snapshot does not match capture')
        config = self.get_in(uow, instance_id, capture['configuration_revision'])
        if (config.id, config.plugin_version, config.code_digest) != (
                capture['configuration_version_id'], capture['plugin_version'], capture['code_digest']):
            raise ReferenceUnavailable('plugin snapshot configuration mismatch')
        snapshot = uow.execute(text('''SELECT namespace_revision FROM control_plane.plugin_storage_snapshots
            WHERE id=:snapshot AND instance_id=:instance'''),
            {'snapshot': capture['storage_snapshot_id'], 'instance': instance_id}).first()
        if snapshot is None or snapshot.namespace_revision != capture['namespace_revision']:
            raise ReferenceUnavailable('plugin snapshot Storage mismatch')
        uow.execute(text('''INSERT INTO control_plane.job_plugin_snapshots
            (job_id,instance_id,configuration_revision,storage_snapshot_id,plugin_version,code_digest)
            VALUES (:job,:instance,:revision,:snapshot,:version,:digest)'''),
            {'job': job_id, 'instance': instance_id, 'revision': capture['configuration_revision'],
             'snapshot': capture['storage_snapshot_id'], 'version': capture['plugin_version'], 'digest': capture['code_digest']})
        secret_service.bind_captured_refs_in(uow, job_id, instance_id, capture['environment_id'], capture['secret_refs'])
        return capture

    def pin_job_in(self, uow, job_id, instance_id, secret_service):
        require_fenced_connection(uow)
        # Lock the namespace before selecting config/storage so administrative updates serialize.
        uow.scalar(text('SELECT id FROM control_plane.plugin_instances WHERE id=:id FOR UPDATE'), {'id': instance_id})
        config = self.get_in(uow, instance_id)
        snapshot = self._storage.snapshot_in(uow, instance_id)
        uow.execute(text('''INSERT INTO control_plane.job_plugin_snapshots
            (job_id,instance_id,configuration_revision,storage_snapshot_id,plugin_version,code_digest)
            VALUES (:job,:instance,:revision,:snapshot,:version,:digest)'''),
            {'job': job_id, 'instance': instance_id, 'revision': config.revision, 'snapshot': snapshot.id,
             'version': config.plugin_version, 'digest': config.code_digest})
        secret_service.pin_job_in(uow, job_id, instance_id, config.id)
        return {'instance_id': str(instance_id), 'configuration_revision': config.revision,
                'storage_snapshot_id': snapshot.id, 'namespace_revision': snapshot.namespace_revision,
                'plugin_version': config.plugin_version, 'code_digest': config.code_digest}
