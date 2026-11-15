"""Versioned instance-bound Storage with durable as-of views and exact CAS."""
from dataclasses import dataclass
import base64
import json
from uuid import uuid4

from sqlalchemy import text

from ..coordination import require_fenced_connection
from ..persistence import StorageConflict, write_storage
from .data import active_instance, trusted_storage_refs
from .sdk import AuthorizationDenied, ReferenceUnavailable, StorageRef, canonical_json, finite_json


@dataclass(frozen=True)
class SnapshotRef:
    id: str
    instance_id: str
    namespace_revision: int

    @property
    def snapshot_id(self):
        return self.id

    def to_dict(self):
        return {'id': str(self.id), 'instance_id': str(self.instance_id),
                'namespace_revision': self.namespace_revision}


@dataclass(frozen=True)
class StorageValue:
    value: dict | None
    ref: StorageRef
    version: int
    namespace_revision: int
    is_tombstone: bool = False

    @property
    def key(self):
        return self.ref.key

    @property
    def version_id(self):
        return self.ref.version_id

    def to_dict(self):
        return {'value': self.value, 'ref': self.ref.to_dict(), 'version': self.version,
                'namespace_revision': self.namespace_revision, 'is_tombstone': self.is_tombstone}


@dataclass(frozen=True)
class StoragePage:
    items: tuple
    cursor: str | None
    snapshot_id: str


class StorageService:
    def __init__(self, engine, runtime, *, safe_json=None):
        self._engine, self._runtime = engine, runtime
        self._safe_json = safe_json or (lambda value: finite_json(value, object_only=True))

    def bind(self, instance_id, job_id=None, *, access_guard=None):
        return BoundStorage(self, str(instance_id), str(job_id) if job_id else None, access_guard)

    def snapshot_in(self, uow, instance_id):
        require_fenced_connection(uow)
        active_instance(uow, instance_id)
        revision = uow.scalar(text('''SELECT namespace_revision FROM control_plane.plugin_instances
                                      WHERE id=:id FOR UPDATE'''), {'id': instance_id})
        snapshot = SnapshotRef(str(uuid4()), str(instance_id), revision)
        uow.execute(text('''INSERT INTO control_plane.plugin_storage_snapshots(id,instance_id,namespace_revision)
                            VALUES (:id,:instance,:revision)'''),
                    {'id': snapshot.id, 'instance': instance_id, 'revision': revision})
        return snapshot

    def _snapshot(self, connection, instance_id, job_id, snapshot_id):
        active_instance(connection, instance_id)
        if job_id:
            pinned = connection.scalar(text('''SELECT storage_snapshot_id FROM control_plane.job_plugin_snapshots
                                               WHERE job_id=:job AND instance_id=:instance'''),
                                       {'job': job_id, 'instance': instance_id})
            if pinned is None or (snapshot_id is not None and str(pinned) != str(snapshot_id)):
                raise AuthorizationDenied()
            snapshot_id = pinned
        if snapshot_id is None:
            raise ValueError('snapshot_id is required outside a Job')
        row = connection.execute(text('''SELECT id,namespace_revision FROM control_plane.plugin_storage_snapshots
                                         WHERE id=:id AND instance_id=:instance'''),
                                 {'id': snapshot_id, 'instance': instance_id}).first()
        if row is None:
            raise ReferenceUnavailable('storage snapshot is unavailable')
        return SnapshotRef(str(row.id), str(instance_id), row.namespace_revision)

    def _value(self, row, instance_id):
        return StorageValue(row.value, StorageRef(str(instance_id), row.key, str(row.id)),
                            row.version, row.namespace_revision, row.is_tombstone)

    def validate_refs_in(self, connection, job_id, instance_id, refs):
        bound = self.bind(instance_id, job_id)
        for ref in refs:
            ref = ref.to_dict() if hasattr(ref, 'to_dict') else ref
            if str(ref['instance_id']) != str(instance_id):
                raise AuthorizationDenied()
            bound._get_in(connection, ref['key'], ref['version_id'], None)


class BoundStorage:
    """No public database/runtime/service or identity-switching operations."""
    __slots__ = ('__service', '__instance', '__job', '__guard')

    def __init__(self, service, instance, job, access_guard=None):
        self.__service, self.__instance, self.__job = service, instance, job
        self.__guard = access_guard

    def _check_access(self, connection):
        if self.__guard is not None:
            self.__guard(connection)

    def snapshot(self):
        if self.__job:
            with self.__service._engine.connect() as connection:
                return self.__service._snapshot(connection, self.__instance, self.__job, None)
        with self.__service._runtime.fenced_transaction() as uow:
            return self.__service.snapshot_in(uow, self.__instance)

    def _get_in(self, connection, key, version, snapshot_id):
        if not isinstance(key, str) or not key or len(key) > 255:
            raise ValueError('invalid storage key')
        snapshot = self.__service._snapshot(connection, self.__instance, self.__job, snapshot_id)
        original = connection.execute(text('''SELECT id,key,value,version,namespace_revision,is_tombstone
            FROM control_plane.plugin_storage_versions WHERE instance_id=:instance AND key=:key
            AND namespace_revision<=:revision ORDER BY namespace_revision DESC LIMIT 1'''),
            {'instance': self.__instance, 'key': key, 'revision': snapshot.namespace_revision}).first()
        if version is None:
            row = original
        else:
            if isinstance(version, StorageRef):
                if str(version.instance_id) != self.__instance or version.key != key:
                    raise AuthorizationDenied()
                version = version.version_id
            else:
                version = str(version)
            if self.__job and (original is None or str(original.id) != version):
                if (key, version) not in trusted_storage_refs(connection, self.__job, self.__instance):
                    raise AuthorizationDenied()
            row = connection.execute(text('''SELECT id,key,value,version,namespace_revision,is_tombstone
                FROM control_plane.plugin_storage_versions WHERE id=:version AND instance_id=:instance AND key=:key'''),
                {'version': version, 'instance': self.__instance, 'key': key}).first()
        if row is None:
            raise ReferenceUnavailable('storage version is unavailable')
        return self.__service._value(row, self.__instance)

    def get(self, key, version=None, snapshot_id=None):
        # Administrative reads may capture current view; Job reads can never refresh it.
        if not self.__job and snapshot_id is None:
            snapshot_id = self.snapshot().id
        with self.__service._engine.connect() as connection:
            return self._get_in(connection, key, version, snapshot_id)

    def list(self, prefix=None, cursor=None, limit=100, snapshot_id=None):
        prefix = '' if prefix is None else prefix
        if not isinstance(prefix, str) or len(prefix) > 255:
            raise ValueError('invalid prefix')
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError('invalid page size')
        last = ''
        if cursor:
            try:
                if len(cursor) > 4096:
                    raise ValueError()
                token = json.loads(base64.urlsafe_b64decode(cursor.encode('ascii')))
                if set(token) != {'snapshot', 'prefix', 'last', 'instance'}:
                    raise ValueError()
                if token['prefix'] != prefix or token['instance'] != self.__instance:
                    raise ValueError()
                if snapshot_id is not None and str(snapshot_id) != token['snapshot']:
                    raise ValueError()
                snapshot_id, last = token['snapshot'], token['last']
                if not isinstance(last, str):
                    raise ValueError()
            except Exception:
                raise ValueError('invalid storage cursor') from None
        if not self.__job and snapshot_id is None:
            snapshot_id = self.snapshot().id
        with self.__service._engine.connect() as connection:
            snapshot = self.__service._snapshot(connection, self.__instance, self.__job, snapshot_id)
            rows = connection.execute(text('''SELECT * FROM (
                SELECT DISTINCT ON (key COLLATE "C") id,key,value,version,namespace_revision,is_tombstone
                FROM control_plane.plugin_storage_versions WHERE instance_id=:instance AND namespace_revision<=:revision
                ORDER BY key COLLATE "C",namespace_revision DESC) v
                WHERE NOT is_tombstone AND left(key,length(:prefix))=:prefix AND key COLLATE "C">:last
                ORDER BY key COLLATE "C" LIMIT :limit'''),
                {'instance': self.__instance, 'revision': snapshot.namespace_revision,
                 'prefix': prefix, 'last': last, 'limit': limit + 1}).all()
        items = tuple(self.__service._value(row, self.__instance) for row in rows[:limit])
        next_cursor = None
        if len(rows) > limit:
            next_cursor = base64.urlsafe_b64encode(canonical_json({'snapshot': snapshot.id,
                'prefix': prefix, 'last': items[-1].key, 'instance': self.__instance}).encode()).decode('ascii')
        return StoragePage(items, next_cursor, snapshot.id)

    def put(self, key, value, expected_version=None):
        finite_json(value, object_only=True)
        value = self.__service._safe_json(value)
        if isinstance(expected_version, StorageRef):
            if str(expected_version.instance_id) != self.__instance or expected_version.key != key:
                raise AuthorizationDenied()
            expected_version = expected_version.version_id
        with self.__service._runtime.fenced_transaction() as uow:
            self._check_access(uow)
            active_instance(uow, self.__instance)
            result = write_storage(uow, self.__instance, key, value, expected_version=expected_version)
            self._check_access(uow)
        return StorageRef(self.__instance, key, str(result.id))

    def delete(self, key, expected_version):
        if isinstance(expected_version, StorageRef):
            if str(expected_version.instance_id) != self.__instance or expected_version.key != key:
                raise AuthorizationDenied()
            expected_version = expected_version.version_id
        with self.__service._runtime.fenced_transaction() as uow:
            self._check_access(uow)
            active_instance(uow, self.__instance)
            result = write_storage(uow, self.__instance, key, None, expected_version=expected_version, delete=True)
            self._check_access(uow)
        return StorageRef(self.__instance, key, str(result.id))
