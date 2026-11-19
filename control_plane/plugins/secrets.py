"""The sole secret plaintext boundary: AES-256-GCM and exact execution grants.

No default encryption key, latest-version fallback, secret listing or plugin DB API.
Business readiness, credential viewing and remote revocation belong to P3.
"""
from contextlib import contextmanager
import base64
import json
import os
import secrets as random_secrets
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from sqlalchemy import text

from ..coordination import require_fenced_connection
from .data import active_instance, find_refs, ref_dict, trusted_source
from .sdk import AuthorizationDenied, ReferenceUnavailable, SecretRef, canonical_json, finite_json, json_digest


class SecretHandle:
    """Explicit short-lived bytes access; repr/str/pickle never expose plaintext."""
    __slots__ = ('__value', '__check', '__closed')

    def __init__(self, value, check):
        self.__value, self.__check, self.__closed = bytearray(value), check, False

    def __repr__(self):
        return '<SecretHandle redacted>'

    __str__ = __repr__

    def __reduce_ex__(self, protocol):
        raise TypeError('SecretHandle cannot be serialized')

    def reveal(self):
        if self.__closed:
            raise ReferenceUnavailable('secret handle is closed')
        self.__check()
        return bytes(self.__value)

    def close(self):
        for index in range(len(self.__value)):
            self.__value[index] = 0
        self.__closed = True

    def __enter__(self):
        self.reveal()
        return self

    def __exit__(self, *args):
        self.close()


class SecretService:
    def __init__(self, engine, runtime, keyring, active_key_id):
        if not isinstance(keyring, dict) or not keyring or active_key_id not in keyring:
            raise ValueError('deployment encryption keyring and active key are required')
        if any(not isinstance(key, str) or not key or not isinstance(value, bytes) or len(value) != 32
               for key, value in keyring.items()):
            raise ValueError('AES-256 keyring requires named 32-byte keys')
        self._engine, self._runtime = engine, runtime
        self.__keys, self.__active = dict(keyring), active_key_id
        self.__delivered = set()
        self.__delivered_bytes = 0
        from threading import RLock
        self.__guard_lock = RLock()

    def __repr__(self):
        return '<SecretService keyring=redacted>'

    @classmethod
    def from_env(cls, engine, runtime, env=None):
        env = os.environ if env is None else env
        try:
            values = json.loads(env['CONTROL_PLANE_SECRET_KEYRING'])
            keyring = {key: base64.b64decode(value, validate=True) for key, value in values.items()}
            return cls(engine, runtime, keyring, env['CONTROL_PLANE_SECRET_ACTIVE_KEY_ID'])
        except (KeyError, ValueError, TypeError, AttributeError):
            raise ValueError('valid deployment secret keyring is required') from None

    def _remember(self, plaintext):
        # Only a process-local leak guard, never authorization or recovery state.
        try:
            value = plaintext.decode('utf-8')
        except UnicodeDecodeError:
            return
        if value:
            with self.__guard_lock:
                if value in self.__delivered:
                    return
                size = len(plaintext)
                if len(self.__delivered) >= 1024 or self.__delivered_bytes + size > 8388608:
                    raise ReferenceUnavailable('secret delivery capacity exhausted; restart required')
                self.__delivered.add(value)
                self.__delivered_bytes += size

    def safe_json(self, value):
        finite_json(value)
        encoded = canonical_json(value)
        # Check individual string leaves too, since JSON escaping changes substrings.
        with self.__guard_lock:
            delivered = tuple(self.__delivered)
        stack = [value]
        while stack:
            item = stack.pop()
            if isinstance(item, str) and any(secret in item for secret in delivered):
                raise ValueError('plaintext secrets are forbidden in JSON data')
            if isinstance(item, dict):
                stack.extend(item.values())
                stack.extend(item.keys())
            elif isinstance(item, list):
                stack.extend(item)
        return json.loads(encoded)

    def _aad(self, row):
        return canonical_json({'secret_id': str(row.secret_id), 'version_id': str(row.id),
                               'version': row.version, 'purpose': row.purpose,
                               'environment_id': str(row.environment_id) if row.environment_id else None,
                               'encryption_key_id': row.encryption_key_id}).encode()

    def _row(self, connection, ref):
        ref = ref_dict(ref)
        if not ref.get('version_id'):
            raise AuthorizationDenied()
        row = connection.execute(text('''SELECT v.*,s.purpose,s.environment_id,s.derived_key,s.derived_spec_digest
            FROM control_plane.secret_versions v JOIN control_plane.secrets s ON s.id=v.secret_id
            WHERE v.id=:version AND s.id=:secret'''),
            {'version': ref['version_id'], 'secret': ref['secret_id']}).first()
        if row is None or row.revoked_at is not None or row.invalidated_at is not None:
            raise ReferenceUnavailable('secret version is unavailable')
        return row

    def _decrypt(self, row):
        key = self.__keys.get(row.encryption_key_id)
        if key is None:
            raise ReferenceUnavailable('secret encryption key is unavailable')
        ciphertext = bytes(row.ciphertext)
        try:
            value = AESGCM(key).decrypt(ciphertext[:12], ciphertext[12:], self._aad(row))
        except (InvalidTag, ValueError):
            raise ReferenceUnavailable('secret authentication failed') from None
        self._remember(value)
        return value

    def _encrypt_in(self, uow, secret_id, purpose, environment_id, plaintext, version):
        if not isinstance(plaintext, bytes) or not 1 <= len(plaintext) <= 1048500:
            raise ValueError('secret payload must be bounded nonempty bytes')
        self._remember(plaintext)
        version_id = str(uuid4())
        from types import SimpleNamespace
        identity = SimpleNamespace(secret_id=secret_id, id=version_id, version=version,
                                   purpose=purpose, environment_id=environment_id, encryption_key_id=self.__active)
        nonce = os.urandom(12)
        ciphertext = nonce + AESGCM(self.__keys[self.__active]).encrypt(nonce, plaintext, self._aad(identity))
        uow.execute(text('''INSERT INTO control_plane.secret_versions
            (id,secret_id,version,ciphertext,encryption_key_id) VALUES (:id,:secret,:version,:ciphertext,:key)'''),
            {'id': version_id, 'secret': secret_id, 'version': version, 'ciphertext': ciphertext, 'key': self.__active})
        return SecretRef(str(secret_id), version_id)

    def create(self, plaintext, *, purpose='admin_connection', environment_id=None, created_by=None):
        with self._runtime.fenced_transaction() as uow:
            return self.create_in(uow, plaintext, purpose=purpose, environment_id=environment_id, created_by=created_by)

    def create_in(self, uow, plaintext, *, purpose='admin_connection', environment_id=None, created_by=None):
        require_fenced_connection(uow)
        if purpose not in ('admin_connection', 'environment') or (purpose == 'environment') != (environment_id is not None):
            raise ValueError('invalid secret purpose/environment')
        identity = str(uuid4())
        uow.execute(text('''INSERT INTO control_plane.secrets(id,purpose,environment_id,created_by)
                             VALUES (:id,:purpose,:environment,:actor)'''),
                    {'id': identity, 'purpose': purpose, 'environment': environment_id, 'actor': created_by})
        return self._encrypt_in(uow, identity, purpose, environment_id, plaintext, 1)

    def rotate(self, secret_id, plaintext):
        with self._runtime.fenced_transaction() as uow:
            row = uow.execute(text('SELECT * FROM control_plane.secrets WHERE id=:id FOR UPDATE'), {'id': secret_id}).first()
            if row is None:
                raise ReferenceUnavailable()
            version = uow.scalar(text('SELECT max(version) FROM control_plane.secret_versions WHERE secret_id=:id'), {'id': secret_id})
            return self._encrypt_in(uow, secret_id, row.purpose, row.environment_id, plaintext, version + 1)

    def revoke(self, ref, *, invalid=False):
        with self._runtime.fenced_transaction() as uow:
            self.revoke_in(uow, ref, invalid=invalid)

    def revoke_in(self, uow, ref, *, invalid=False):
        require_fenced_connection(uow)
        ref = ref_dict(ref)
        column = 'invalidated_at' if invalid else 'revoked_at'
        uow.execute(text(f'''UPDATE control_plane.secret_versions SET {column}=COALESCE({column},clock_timestamp())
                             WHERE id=:version AND secret_id=:secret'''),
                    {'version': ref['version_id'], 'secret': ref['secret_id']})

    def capture_refs_in(self, uow, config_version_id, instance_id, environment_id):
        """Core-only initial authorization capture; lock identities before resolving latest once."""
        require_fenced_connection(uow)
        config = uow.scalar(text('''SELECT configuration FROM control_plane.plugin_instance_versions
            WHERE id=:config AND instance_id=:instance'''), {'config': config_version_id, 'instance': instance_id})
        if config is None:
            raise AuthorizationDenied()
        candidates = config.get('allowed_secret_refs', [])
        for secret_id in sorted({str(candidate['secret_id']) for candidate in candidates}):
            exists = uow.scalar(text('SELECT id FROM control_plane.secrets WHERE id=:id FOR UPDATE'), {'id': secret_id})
            if exists is None:
                raise ReferenceUnavailable('secret identity is unavailable')
        refs = []
        for candidate in candidates:
            exact = dict(candidate)
            if not exact.get('version_id'):
                version = uow.scalar(text('''SELECT id FROM control_plane.secret_versions
                    WHERE secret_id=:secret ORDER BY version DESC LIMIT 1'''), {'secret': exact['secret_id']})
                if version is None:
                    raise ReferenceUnavailable('secret version is unavailable')
                exact['version_id'] = str(version)
            uow.scalar(text('SELECT id FROM control_plane.secret_versions WHERE id=:id FOR UPDATE'), {'id': exact['version_id']})
            row = self._row(uow, exact)
            if row.purpose == 'environment' and str(row.environment_id) != str(environment_id):
                raise AuthorizationDenied()
            refs.append(SecretRef(str(row.secret_id), str(row.id)).to_dict())
        return [{'secret_id': secret, 'version_id': version}
                for secret, version in sorted({(ref['secret_id'], ref['version_id']) for ref in refs})]

    @staticmethod
    def _derived_credential_source(uow, environment_id, instance_id, key, *, cleanup_evidence):
        """Find an independently authorized version from its creating invocation."""
        rows = uow.execute(text("""
            SELECT o.id,o.job_id,o.output,s.derived_key,j.logical_invocation_id,step.step_path,step.item_key,
                   (o.state='succeeded' AND o.protocol_error IS NULL) AS confirmed_output,
                   e.id AS evidence_id,e.data AS evidence_data
            FROM control_plane.job_secret_refs g
            JOIN control_plane.operations o ON o.id=g.source_operation_id AND o.job_id=g.job_id
            JOIN control_plane.jobs j ON j.id=o.job_id
            JOIN control_plane.job_steps step ON step.id=o.step_id AND step.job_id=j.id
            JOIN control_plane.secret_versions v ON v.id=g.secret_version_id
            JOIN control_plane.secrets s ON s.id=v.secret_id AND s.environment_id=j.environment_id
            LEFT JOIN control_plane.operation_evidence e ON e.id=g.source_evidence_id AND e.operation_id=o.id
              AND e.kind='checkpoint' AND e.trusted_for_derivation
            WHERE g.derived AND g.plugin_instance_id=:instance AND o.plugin_instance_id=:instance
              AND j.environment_id=:env
              AND ((o.state='succeeded' AND o.protocol_error IS NULL AND (j.kind='create' OR :cleanup))
                   OR (:cleanup AND e.id IS NOT NULL AND o.state IN ('succeeded','failed','cancelled')))
              AND s.purpose='environment' AND s.id=:secret AND v.id=:version AND v.version=1
              AND v.revoked_at IS NULL AND v.invalidated_at IS NULL AND s.derived_key IS NOT NULL
            FOR SHARE OF v
        """), {"env": environment_id, "instance": instance_id, "secret": key[0], "version": key[1],
               "cleanup": cleanup_evidence})
        ref = {"secret_id": key[0], "version_id": key[1]}
        for row in rows:
            identity = [str(environment_id), str(row.logical_invocation_id), row.step_path, row.item_key]
            if json.loads(row.derived_key)[:4] != identity:
                continue
            proof = {"source_job_id": str(row.job_id), "source_operation_id": str(row.id)}
            if row.confirmed_output and ref in find_refs(row.output, "secret"):
                return proof
            if cleanup_evidence and row.evidence_id is not None and ref in find_refs(row.evidence_data, "secret"):
                return {**proof, "source_evidence_id": str(row.evidence_id)}
        raise AuthorizationDenied()

    def confirmed_template_refs_in(self, uow, environment_id, instance_id, requests, configured_refs):
        """Pin exact environment credentials from verified outputs or cleanup evidence.

        Template evaluation supplies the declared step, reference path and version.
        A confirmed source Operation and its instance-scoped grant supply authority.
        The proof is signed into the immutable capture alongside the selected version.
        """
        require_fenced_connection(uow)
        finite_json(requests)
        configured = {(ref["secret_id"], ref["version_id"]) for ref in configured_refs}
        proofs, checked = [], {}
        for request in requests:
            ref = request["ref"]
            try:
                key = tuple(str(UUID(ref[name])) for name in ("secret_id", "version_id"))
            except (ValueError, TypeError, AttributeError, KeyError):
                raise AuthorizationDenied() from None
            if key in configured:
                continue
            path = request["path"]
            cleanup_evidence = path == "evidence" or path.startswith(("evidence.", "evidence/"))
            check = (key, cleanup_evidence)
            if check not in checked:
                row = uow.execute(text("""
                    SELECT c.job_id,c.operation_id FROM control_plane.environment_credential_confirmations c
                    JOIN control_plane.jobs producer ON producer.id=c.job_id AND producer.environment_id=c.environment_id
                    JOIN control_plane.operations o ON o.id=c.operation_id AND o.job_id=producer.id
                    JOIN control_plane.job_secret_refs grant_ref ON grant_ref.job_id=producer.id
                      AND grant_ref.plugin_instance_id=o.plugin_instance_id AND grant_ref.secret_version_id=c.version_id
                    JOIN control_plane.secret_versions v ON v.id=c.version_id AND v.secret_id=c.secret_id
                    JOIN control_plane.secrets s ON s.id=c.secret_id AND s.environment_id=c.environment_id
                    WHERE c.environment_id=:env AND c.secret_id=:secret AND c.version_id=:version
                      AND o.plugin_instance_id=:instance AND o.state='succeeded' AND s.purpose='environment'
                      AND v.revoked_at IS NULL AND v.invalidated_at IS NULL
                      AND o.output->'confirmed_environment_credential' =
                          jsonb_build_object('secret_id',s.id::text,'version_id',v.id::text)
                    FOR SHARE OF v
                """), {"env": environment_id, "instance": instance_id, "secret": key[0], "version": key[1]}).first()
                if row is None:
                    checked[check] = self._derived_credential_source(
                        uow, environment_id, instance_id, key, cleanup_evidence=cleanup_evidence)
                else:
                    checked[check] = {"source_job_id": str(row.job_id), "source_operation_id": str(row.operation_id)}
            proofs.append({**request, "ref": {"secret_id": key[0], "version_id": key[1]}, **checked[check]})
        return proofs

    def bind_captured_refs_in(self, uow, job_id, instance_id, environment_id, refs):
        """Bind exact captured versions, never query latest or Storage claims."""
        require_fenced_connection(uow)
        for ref in refs:
            row = self._row(uow, ref)
            if row.purpose == 'environment' and str(row.environment_id) != str(environment_id):
                raise AuthorizationDenied()
            uow.execute(text('''INSERT INTO control_plane.job_secret_refs(job_id,plugin_instance_id,secret_version_id)
                VALUES (:job,:instance,:version)'''), {'job': job_id, 'instance': instance_id, 'version': row.id})

    def pin_job_in(self, uow, job_id, instance_id, config_version_id):
        require_fenced_connection(uow)
        active_instance(uow, instance_id)
        config = uow.execute(text('''SELECT v.configuration,j.environment_id FROM control_plane.plugin_instance_versions v
            JOIN control_plane.job_plugin_snapshots p ON p.instance_id=v.instance_id AND p.configuration_revision=v.revision
            JOIN control_plane.jobs j ON j.id=p.job_id
            WHERE v.id=:config AND p.job_id=:job AND v.instance_id=:instance'''),
            {'config': config_version_id, 'job': job_id, 'instance': instance_id}).first()
        if config is None:
            raise AuthorizationDenied()
        # The administrator's explicit configuration envelope is the ONLY initial authority.
        for candidate in config.configuration.get('allowed_secret_refs', []):
            candidate = dict(candidate)
            if not candidate.get('version_id'):
                candidate['version_id'] = str(uow.scalar(text('''SELECT id FROM control_plane.secret_versions
                    WHERE secret_id=:secret ORDER BY version DESC LIMIT 1'''), {'secret': candidate['secret_id']}))
            row = self._row(uow, candidate)
            if row.purpose == 'environment' and str(row.environment_id) != str(config.environment_id):
                raise AuthorizationDenied()
            uow.execute(text('''INSERT INTO control_plane.job_secret_refs(job_id,plugin_instance_id,secret_version_id)
                VALUES (:job,:instance,:version) ON CONFLICT DO NOTHING'''),
                {'job': job_id, 'instance': instance_id, 'version': row.id})

    def bind(self, job_id, instance_id, environment_id, prepared_refs=None, *, step_instance_id=None, operation_id=None, access_guard=None):
        refs = None if prepared_refs is None else tuple(ref_dict(ref) for ref in prepared_refs)
        return BoundSecrets(self, str(job_id), str(instance_id), str(environment_id), refs,
                            str(step_instance_id) if step_instance_id else None, str(operation_id) if operation_id else None, access_guard)

    def _identity(self, connection, job_id, instance_id, environment_id, step_id):
        row = connection.execute(text('''SELECT j.environment_id,j.logical_invocation_id,s.step_path,s.item_key
            FROM control_plane.jobs j JOIN control_plane.job_steps s ON s.job_id=j.id
            JOIN control_plane.job_plugin_snapshots p ON p.job_id=j.id
            WHERE j.id=:job AND s.id=:step AND p.instance_id=:instance'''),
            {'job': job_id, 'step': step_id, 'instance': instance_id}).first()
        if row is None or str(row.environment_id) != str(environment_id):
            raise AuthorizationDenied()
        return [str(row.environment_id), str(row.logical_invocation_id), row.step_path, row.item_key]

    def _authorize(self, connection, job_id, instance_id, environment_id, ref, step_id=None, operation_id=None):
        active_instance(connection, instance_id)
        job_env = connection.scalar(text('''SELECT j.environment_id FROM control_plane.jobs j
            JOIN control_plane.job_plugin_snapshots p ON p.job_id=j.id WHERE j.id=:job AND p.instance_id=:instance'''),
            {'job': job_id, 'instance': instance_id})
        if str(job_env) != str(environment_id):
            raise AuthorizationDenied()
        row = self._row(connection, ref)
        if row.purpose == 'environment' and str(row.environment_id) != str(environment_id):
            raise AuthorizationDenied()
        granted = connection.scalar(text('''SELECT 1 FROM control_plane.job_secret_refs
            WHERE job_id=:job AND plugin_instance_id=:instance AND secret_version_id=:version'''),
            {'job': job_id, 'instance': instance_id, 'version': row.id})
        if not granted:
            # The creator may install its own stable derived password, but this is NOT a successor grant.
            own = False
            if step_id and operation_id and row.derived_key and row.version == 1:
                try:
                    identity = json.loads(row.derived_key)
                    own = identity[:4] == self._identity(connection, job_id, instance_id, environment_id, step_id)
                    operation = connection.scalar(text('''SELECT 1 FROM control_plane.operations WHERE id=:operation
                        AND job_id=:job AND step_id=:step AND plugin_instance_id=:instance
                        AND state IN ('running','pending_external','unknown')'''),
                        {'operation': operation_id, 'job': job_id, 'step': step_id, 'instance': instance_id})
                    own = own and bool(operation)
                except (ValueError, TypeError):
                    pass
            if not own:
                raise AuthorizationDenied()
        return row

    def validate_refs_in(self, connection, job_id, instance_id, environment_id, refs, *, step_instance_id=None):
        for ref in refs:
            self._authorize(connection, job_id, instance_id, environment_id, ref, step_instance_id)

    def publish_from_source_in(self, uow, job_id, instance_id, source_operation_id, source_evidence_id=None):
        require_fenced_connection(uow)
        data = trusted_source(uow, job_id, instance_id, source_operation_id, source_evidence_id)
        environment = uow.scalar(text('SELECT environment_id FROM control_plane.jobs WHERE id=:job'), {'job': job_id})
        published = []
        for ref in find_refs(data, 'secret'):
            row = self._row(uow, ref)
            if row.purpose != 'environment' or str(row.environment_id) != str(environment):
                # Existing granted administrator references can be mentioned but never expand permissions.
                existing = uow.scalar(text('''SELECT 1 FROM control_plane.job_secret_refs WHERE job_id=:job
                    AND plugin_instance_id=:instance AND secret_version_id=:version'''),
                    {'job': job_id, 'instance': instance_id, 'version': row.id})
                if not existing:
                    raise AuthorizationDenied()
                continue
            if not row.derived_key or row.version != 1:
                # Explicitly granted ordinary environment refs may be echoed but
                # publishing output never invents authorization for them.
                self._authorize(uow, job_id, instance_id, environment, ref)
                continue
            source = uow.execute(text('''SELECT o.job_id,o.step_id FROM control_plane.operations o WHERE o.id=:id'''), {'id': source_operation_id}).one()
            identity = self._identity(uow, source.job_id, instance_id, environment, source.step_id)
            if json.loads(row.derived_key)[:4] != identity:
                # Forwarding an already-authorized derived ref is allowed; arbitrary environment refs are not.
                self._authorize(uow, source.job_id, instance_id, environment, ref)
            uow.execute(text('''INSERT INTO control_plane.job_secret_refs
                (job_id,plugin_instance_id,secret_version_id,derived,source_operation_id,source_evidence_id)
                VALUES (:job,:instance,:version,true,:operation,:evidence) ON CONFLICT DO NOTHING'''),
                {'job': job_id, 'instance': instance_id, 'version': row.id,
                 'operation': source_operation_id, 'evidence': source_evidence_id})
            published.append(SecretRef(str(row.secret_id), str(row.id)))
        return tuple(published)

    def _derive(self, job_id, instance_id, environment_id, step_id, operation_id, slot, spec, access_guard=None):
        if not isinstance(slot, str) or not slot or len(slot) > 255 or not step_id or not operation_id:
            raise ValueError('stable credential slot and step are required')
        spec = {'length': 32, 'encoding': 'urlsafe'} if spec is None else dict(spec)
        finite_json(spec, object_only=True)
        if set(spec) - {'length', 'encoding'} or spec.get('encoding', 'urlsafe') != 'urlsafe':
            raise ValueError('unsupported secret generation specification')
        length = spec.get('length', 32)
        if isinstance(length, bool) or not isinstance(length, int) or not 16 <= length <= 256:
            raise ValueError('invalid generated credential length')
        normalized = {'length': length, 'encoding': 'urlsafe'}
        digest = json_digest(normalized)
        with self._runtime.fenced_transaction() as uow:
            if access_guard is not None:
                access_guard(uow)
            active_instance(uow, instance_id)
            identity = self._identity(uow, job_id, instance_id, environment_id, step_id)
            operation = uow.scalar(text('''SELECT 1 FROM control_plane.operations WHERE id=:operation
                AND job_id=:job AND step_id=:step AND plugin_instance_id=:instance
                AND state IN ('running','pending_external','unknown')'''),
                {'operation': operation_id, 'job': job_id, 'step': step_id, 'instance': instance_id})
            if not operation:
                raise AuthorizationDenied()
            key = canonical_json(identity + [slot])
            # Serialize identities using the environment row; no transient dict is recovery truth.
            uow.scalar(text('SELECT id FROM control_plane.environments WHERE id=:id FOR UPDATE'), {'id': environment_id})
            existing = uow.execute(text('SELECT * FROM control_plane.secrets WHERE derived_key=:key'), {'key': key}).first()
            if existing is not None:
                if existing.derived_spec_digest != digest:
                    raise ValueError('derived secret specification conflicts with stable identity')
                first = uow.scalar(text('SELECT id FROM control_plane.secret_versions WHERE secret_id=:id AND version=1'), {'id': existing.id})
                ref = SecretRef(str(existing.id), str(first))
                self._row(uow, ref)  # Missing/revoked/invalid version 1 must NEVER regenerate.
                if access_guard is not None:
                    access_guard(uow)
                return ref
            identity_id = str(uuid4())
            uow.execute(text('''INSERT INTO control_plane.secrets(id,purpose,environment_id,derived_key,derived_spec_digest)
                VALUES (:id,'environment',:environment,:key,:digest)'''),
                {'id': identity_id, 'environment': environment_id, 'key': key, 'digest': digest})
            plaintext = random_secrets.token_urlsafe(length)[:length].encode('ascii')
            ref = self._encrypt_in(uow, identity_id, 'environment', environment_id, plaintext, 1)
            if access_guard is not None:
                access_guard(uow)
            return ref


class BoundSecrets:
    __slots__ = ('__service', '__job', '__instance', '__environment', '__refs', '__step', '__operation', '__created', '__guard')

    def __init__(self, service, job, instance, environment, refs, step, operation, access_guard=None):
        self.__service, self.__job, self.__instance = service, job, instance
        self.__environment, self.__refs, self.__step = environment, refs, step
        self.__operation, self.__created = operation, set()
        self.__guard = access_guard

    def __repr__(self):
        return '<BoundSecrets redacted>'

    def resolve(self, ref):
        ref = ref_dict(ref)
        with self.__service._runtime.fenced_transaction() as connection:
            if self.__guard is not None:
                self.__guard(connection)
            if not ref.get('version_id'):
                rows = connection.execute(text('''SELECT v.id FROM control_plane.job_secret_refs r
                    JOIN control_plane.secret_versions v ON v.id=r.secret_version_id
                    JOIN control_plane.jobs j ON j.id=r.job_id
                    WHERE r.job_id=:job AND r.plugin_instance_id=:instance AND v.secret_id=:secret
                      AND NOT r.derived AND NOT EXISTS (
                          SELECT FROM jsonb_array_elements(COALESCE(j.execution_snapshot->'plugins'
                              ->CAST(r.plugin_instance_id AS text)->'template_credentials','[]'::jsonb)) proof
                          WHERE proof->'ref'->>'version_id'=CAST(v.id AS text))'''),
                    {'job': self.__job, 'instance': self.__instance, 'secret': ref['secret_id']}).all()
                if len(rows) != 1:
                    raise AuthorizationDenied()
                ref['version_id'] = str(rows[0].id)
            exact = SecretRef(str(ref['secret_id']), str(ref['version_id']))
            if self.__refs is not None and exact.to_dict() not in self.__refs and (exact.secret_id, exact.version_id) not in self.__created:
                raise AuthorizationDenied()
            self.__service._authorize(connection, self.__job, self.__instance, self.__environment, exact, self.__step, self.__operation if (exact.secret_id, exact.version_id) in self.__created else None)
            if self.__guard is not None:
                self.__guard(connection)
            return exact

    def get(self, ref):
        exact = self.resolve(ref)
        def check():
            self.resolve(exact)
        with self.__service._runtime.fenced_transaction() as connection:
            if self.__guard is not None:
                self.__guard(connection)
            row = self.__service._authorize(connection, self.__job, self.__instance, self.__environment, exact, self.__step, self.__operation if (exact.secret_id, exact.version_id) in self.__created else None)
            plaintext = self.__service._decrypt(row)
            if self.__guard is not None:
                self.__guard(connection)
        return SecretHandle(plaintext, check)

    def derive(self, slot, spec=None):
        ref = self.__service._derive(self.__job, self.__instance, self.__environment, self.__step, self.__operation, slot, spec, self.__guard)
        self.__created.add((ref.secret_id, ref.version_id))
        return ref
