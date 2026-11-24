import base64
from dataclasses import replace
import json
import pickle
from types import SimpleNamespace
import unittest
from uuid import uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import text

from control_plane.plugins.context import ContextBuilder
from control_plane.plugins.sdk import (AuthorizationDenied, Deadline, PreparedCall, ReferenceUnavailable,
                                       SecretRef, canonical_json, finite_json)
from control_plane.plugins.secrets import SecretHandle, SecretService
from tests_control_plane.test_p1_schema import recorded_evidence
from tests_control_plane.test_p2_storage import ServicesFixture


class SecretServiceTests(ServicesFixture, unittest.TestCase):
    def allow(self, instance, *refs):
        current = self.configurations.get(instance)
        return self.configurations.put(instance, {'data': {}, 'allowed_secret_refs': [ref.to_dict() for ref in refs]},
                                       expected_revision=current.revision)

    def bound(self, job, *, instance=None, refs=None, step=None, operation=None):
        return self.secrets.bind(job, instance or self.instance, self.environment, refs,
                                 step_instance_id=step, operation_id=operation)

    def activate(self, job):
        token = str(uuid4())
        with self.lease.fenced_transaction() as uow:
            uow.execute(text('''UPDATE control_plane.jobs SET state='running',lease_owner='test-scope',
                lease_token=:token,lease_expires_at=clock_timestamp()+interval '120 seconds' WHERE id=:job'''),
                {'job': job, 'token': token})
            uow.execute(text('''UPDATE control_plane.execution_groups SET current_job_id=:job WHERE id=:group'''),
                {'job': job, 'group': self.group})
        return token

    def next_step(self, job, path='install'):
        with self.lease.fenced_transaction() as uow:
            return uow.scalar(text('INSERT INTO control_plane.job_steps(job_id,step_path) VALUES (:job,:path) RETURNING id'),
                              {'job': job, 'path': path})

    def producing(self, *, job=None, step=None, logical=None):
        if job is None:
            job, step = self.job(logical=logical)
        operation, _ = self.source(job, step, {}, state='running')
        return job, step, operation, self.bound(job, refs=(), step=step, operation=operation)

    def publish(self, job, operation, ref, evidence=None):
        with self.lease.fenced_transaction() as uow:
            if evidence is None:
                uow.execute(text("UPDATE control_plane.operations SET state='succeeded',output=CAST(:output AS jsonb) WHERE id=:id"),
                            {'id': operation, 'output': canonical_json({'credential': ref.to_dict()})})
            return self.secrets.publish_from_source_in(uow, job, self.instance, operation, evidence)

    def test_keyring_is_explicit_and_aes256_only(self):
        for ring, active in (({}, 'default'), ({'short': b'x'}, 'short'), ({'ok': b'x'*32}, 'missing')):
            with self.assertRaises(ValueError):
                SecretService(self.engine, self.lease, ring, active)
        with self.assertRaises(ValueError):
            SecretService.from_env(self.engine, self.lease, {})
        service = SecretService.from_env(self.engine, self.lease, {
            'CONTROL_PLANE_SECRET_KEYRING': json.dumps({'one': base64.b64encode(b'q'*32).decode()}),
            'CONTROL_PLANE_SECRET_ACTIVE_KEY_ID': 'one'})
        self.assertNotIn('qqqq', repr(service))

    def test_ciphertext_and_aad_bind_all_identity_dimensions(self):
        ref = self.secrets.create(b'private-fixture-password')
        with self.engine.connect() as connection:
            row = self.secrets._row(connection, ref)
        ciphertext = bytes(row.ciphertext)
        self.assertNotIn(b'private-fixture-password', ciphertext)
        expected = AESGCM(b'k'*32).decrypt(ciphertext[:12], ciphertext[12:], self.secrets._aad(row))
        self.assertEqual(expected, b'private-fixture-password')
        identity = dict(row._mapping)
        for field, replacement in (('id', uuid4()), ('secret_id', uuid4()), ('version', 9),
                                   ('purpose', 'environment'), ('environment_id', uuid4()), ('encryption_key_id', 'other')):
            altered = {**identity, field: replacement}
            with self.subTest(field=field), self.assertRaises(InvalidTag):
                AESGCM(b'k'*32).decrypt(ciphertext[:12], ciphertext[12:], self.secrets._aad(SimpleNamespace(**altered)))

    def test_storage_and_prepare_self_report_do_not_grant(self):
        ref = self.secrets.create(b'not-authorized')
        self.admin.put('hosts/a', {'secret_ref': ref.to_dict()})
        job, step = self.job()
        with self.assertRaises(AuthorizationDenied):
            self.bound(job).get(ref)
        builder = ContextBuilder(self.engine, self.lease, self.registry, self.secrets)
        prepared = PreparedCall('echo', secret_refs=(ref,))
        with self.assertRaises(AuthorizationDenied):
            builder.validate_prepared(job, self.instance, prepared, step_instance_id=step)

    def test_exact_job_instance_grant_and_explicit_shared_admin_secret(self):
        ref = self.secrets.create(b'explicitly-shared')
        self.allow(self.instance, ref)
        job, _ = self.job(instances=(self.instance, self.other))
        with self.bound(job).get(ref) as handle:
            self.assertEqual(handle.reveal(), b'explicitly-shared')
        with self.assertRaises(AuthorizationDenied):
            self.bound(job, instance=self.other).get(ref)
        self.allow(self.other, ref)
        second, _ = self.job(instances=(self.instance, self.other))
        with self.bound(second, instance=self.other).get(ref) as handle:
            self.assertEqual(handle.reveal(), b'explicitly-shared')

    def test_unversioned_mapping_stays_at_job_acceptance_after_rotation(self):
        first = self.secrets.create(b'old-still-accepted')
        self.allow(self.instance, SecretRef(first.secret_id))
        job, _ = self.job()
        second = self.secrets.rotate(first.secret_id, b'new-password')
        bound = self.bound(job)
        self.assertEqual(bound.resolve(SecretRef(first.secret_id)), first)
        with bound.get(first) as handle:
            self.assertEqual(handle.reveal(), b'old-still-accepted')
        with self.assertRaises(AuthorizationDenied):
            bound.get(second)
        next_job, _ = self.job()
        self.assertEqual(self.bound(next_job).resolve(SecretRef(first.secret_id)), second)

    def test_prepared_call_actual_subset_is_enforced(self):
        first = self.secrets.create(b'first-password')
        second = self.secrets.create(b'second-password')
        self.allow(self.instance, first, second)
        job, _ = self.job()
        restricted = self.bound(job, refs=(first,))
        with restricted.get(first) as handle:
            self.assertEqual(handle.reveal(), b'first-password')
        with self.assertRaises(AuthorizationDenied):
            restricted.get(second)

    def test_revocation_and_known_invalidity_override_snapshots_and_handles(self):
        for invalid in (False, True):
            with self.subTest(invalid=invalid):
                ref = self.secrets.create(b'must-not-be-returned-again')
                self.allow(self.instance, ref)
                job, _ = self.job()
                bound = self.bound(job)
                handle = bound.get(ref)
                self.secrets.revoke(ref, invalid=invalid)
                with self.assertRaises(ReferenceUnavailable):
                    bound.get(ref)
                with self.assertRaises(ReferenceUnavailable):
                    handle.reveal()
                handle.close()

    def test_wrong_environment_and_ungranted_job_are_denied(self):
        ref = self.secrets.create(b'environment-only', purpose='environment', environment_id=self.environment)
        self.allow(self.instance, ref)
        job, _ = self.job()
        with self.assertRaises(AuthorizationDenied):
            self.secrets.bind(job, self.instance, uuid4()).get(ref)
        with self.assertRaises(AuthorizationDenied):
            self.secrets.bind(uuid4(), self.instance, self.environment).get(ref)

    def test_handle_repr_pickle_and_json_do_not_expose_plaintext(self):
        ref = self.secrets.create(b'no-secret-in-repr')
        self.allow(self.instance, ref)
        job, _ = self.job()
        handle = self.bound(job).get(ref)
        self.assertNotIn('no-secret-in-repr', repr(handle))
        self.assertNotIn('no-secret-in-repr', str(handle))
        with self.assertRaises(TypeError):
            pickle.dumps(handle)
        with self.assertRaises(ValueError):
            finite_json({'handle': handle})
        with self.assertRaises(ValueError):
            self.secrets.safe_json({'stdout': 'leaked no-secret-in-repr'})
        handle.close()
        with self.assertRaises(ReferenceUnavailable):
            handle.reveal()

    def test_missing_decryption_key_blocks_without_fallback(self):
        ref = self.secrets.create(b'old-key-required')
        self.allow(self.instance, ref)
        job, _ = self.job()
        replacement = SecretService(self.engine, self.lease, {'new': b'n'*32}, 'new')
        with self.assertRaises(ReferenceUnavailable):
            replacement.bind(job, self.instance, self.environment).get(ref)

    def test_derive_is_operation_only_not_prepare(self):
        job, step = self.job()
        with self.assertRaises(ValueError):
            self.bound(job, step=step).derive('password')

    def test_stable_derive_reuses_version1_and_spec_conflicts(self):
        logical = uuid4()
        job, step, operation, bound = self.producing(logical=logical)
        ref = bound.derive('password', {'length': 24})
        again = bound.derive('password', {'length': 24})
        self.assertEqual(ref, again)
        with bound.get(ref) as handle:
            self.assertEqual(len(handle.reveal()), 24)
        recovery_job, recovery_step, recovery_op, recovering = self.producing(logical=logical)
        self.assertEqual(recovering.derive('password', {'length': 24}), ref)
        with self.assertRaises(ValueError):
            recovering.derive('password', {'length': 32})
        with self.engine.connect() as connection:
            self.assertEqual(connection.scalar(text('SELECT count(*) FROM control_plane.secret_versions WHERE secret_id=:id'), {'id': ref.secret_id}), 1)

    def test_derive_does_not_grant_successor_until_successful_publish(self):
        job, step, operation, bound = self.producing()
        ref = bound.derive('password')
        successor = self.bound(job, step=self.next_step(job))
        with self.assertRaises(AuthorizationDenied):
            successor.get(ref)
        with self.lease.fenced_transaction() as uow:
            with self.assertRaises(ReferenceUnavailable):
                self.secrets.publish_from_source_in(uow, job, self.instance, operation)
        self.publish(job, operation, ref)
        with successor.get(ref) as handle:
            self.assertEqual(len(handle.reveal()), 32)

    def test_checkpoint_publish_and_same_group_recovery_job(self):
        job, step, operation, bound = self.producing()
        ref = bound.derive('password')
        with self.lease.fenced_transaction() as uow:
            evidence = recorded_evidence(uow, operation, ref_key="credential",
                                         data={"credential": ref.to_dict()}, trusted_for_derivation=True)
            self.secrets.publish_from_source_in(uow, job, self.instance, operation, evidence)
        recovery, _ = self.job()
        with self.assertRaises(AuthorizationDenied):
            self.bound(recovery).get(ref)
        with self.lease.fenced_transaction() as uow:
            self.secrets.publish_from_source_in(uow, recovery, self.instance, operation, evidence)
        with self.bound(recovery).get(ref) as handle:
            self.assertEqual(len(handle.reveal()), 32)

    def test_derived_rotation_creates_v2_without_changing_stable_v1(self):
        _, _, _, bound = self.producing()
        first = bound.derive('password')
        second = self.secrets.rotate(first.secret_id, b'explicit-rotated-password')
        self.assertNotEqual(first.version_id, second.version_id)
        self.assertEqual(bound.derive('password'), first)
        self.secrets.revoke(first, invalid=True)
        with self.assertRaises(ReferenceUnavailable):
            bound.derive('password')
        with self.engine.connect() as connection:
            row = self.secrets._row(connection, second)
        self.assertEqual(row.version, 2)

    def test_plaintext_guard_is_bounded_and_fails_closed_without_forgetting(self):
        service = SecretService(self.engine, self.lease, {'one': b'x'*32}, 'one')
        for index in range(1024):
            service._remember(('bounded-secret-%04d' % index).encode())
        with self.assertRaises(ReferenceUnavailable):
            service._remember(b'one-more-secret')
        with self.assertRaises(ValueError):
            service.safe_json({'stdout': 'bounded-secret-0000'})
        # Reusing a registered value consumes no new capacity.
        service._remember(b'bounded-secret-0000')

    def test_late_untrusted_checkpoint_cannot_publish_secret_grant(self):
        job, step, operation, bound = self.producing()
        ref = bound.derive('password')
        with self.lease.fenced_transaction() as uow:
            evidence = recorded_evidence(uow, operation, ref_key="late", data={"credential": ref.to_dict()})
        with self.assertRaises(ReferenceUnavailable):
            with self.lease.fenced_transaction() as uow:
                self.secrets.publish_from_source_in(uow, job, self.instance, operation, evidence)
        with self.assertRaises(AuthorizationDenied):
            self.bound(job).get(ref)

    def test_invalidated_derived_version1_never_regenerates(self):
        _, _, _, bound = self.producing()
        ref = bound.derive('password')
        self.secrets.revoke(ref, invalid=True)
        with self.assertRaises(ReferenceUnavailable):
            bound.derive('password')
        with self.engine.connect() as connection:
            self.assertEqual(connection.scalar(text('SELECT count(*) FROM control_plane.secret_versions WHERE secret_id=:id'), {'id': ref.secret_id}), 1)

    def test_context_json_write_callbacks_reject_delivered_plaintext(self):
        ref = self.secrets.create(b'must-not-persist-in-normal-json')
        self.allow(self.instance, ref)
        job, step = self.job()
        builder = ContextBuilder(self.engine, self.lease, self.registry, self.secrets)
        received = []
        context = builder.build(job_id=job, plugin_instance_id=self.instance, step_instance_id=step,
            operation_id=None, invocation_key=str(step), lease_token=self.activate(job), deadline=Deadline.after(10),
            report_checkpoint=lambda key, value: received.append(value), logger=received.append)
        for callback in (lambda: context.storage.put('unsafe', {'password': 'must-not-persist-in-normal-json'}),
                         lambda: context.report_checkpoint('unsafe', {'password': 'must-not-persist-in-normal-json'}),
                         lambda: context.logger.info('must-not-persist-in-normal-json')):
            with self.assertRaises(ValueError):
                callback()
        self.assertEqual(received, [])

    def test_old_context_cannot_mutate_or_deliver_after_job_scope_loss(self):
        ref = self.secrets.create(b'scope-protected-password')
        self.allow(self.instance, ref)
        builder = ContextBuilder(self.engine, self.lease, self.registry, self.secrets)
        for reason in ('token', 'expired', 'group_revision', 'group_owner'):
            with self.subTest(reason=reason):
                job, step, operation, _ = self.producing()
                token = self.activate(job)
                context = builder.build(job_id=job, plugin_instance_id=self.instance, step_instance_id=step,
                    operation_id=operation, invocation_key=str(step), lease_token=token, deadline=Deadline.after(60),
                    prepared=PreparedCall('echo', secret_refs=(ref,)))
                handle = context.secrets.get(ref)
                generated = context.secrets.derive('scope-password')
                # A successful write proves this is a real low-privilege path,
                # not merely a Fake facade that rejects everything.
                created = context.storage.put('scope-' + reason, {'allowed': True})
                with self.lease.fenced_transaction() as uow:
                    if reason == 'token':
                        uow.execute(text('UPDATE control_plane.jobs SET lease_token=:token WHERE id=:job'),
                                    {'job': job, 'token': uuid4()})
                    elif reason == 'expired':
                        uow.execute(text("UPDATE control_plane.jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=:job"), {'job': job})
                    elif reason == 'group_revision':
                        uow.execute(text('UPDATE control_plane.execution_groups SET revision=revision+1 WHERE id=:group'), {'group': self.group})
                    else:
                        uow.execute(text('UPDATE control_plane.execution_groups SET current_job_id=NULL WHERE id=:group'), {'group': self.group})
                for callback in (lambda: context.storage.put('forbidden-' + reason, {}),
                                 lambda: context.storage.delete('scope-' + reason, created),
                                 lambda: context.secrets.get(ref), lambda: handle.reveal(),
                                 lambda: context.secrets.derive('scope-password')):
                    with self.assertRaises(AuthorizationDenied):
                        callback()
                handle.close()

    def test_context_identity_is_readonly_and_services_hide_database(self):
        job, step = self.job()
        builder = ContextBuilder(self.engine, self.lease, self.registry, self.secrets)
        context = builder.build(job_id=job, plugin_instance_id=self.instance, step_instance_id=step,
            operation_id=None, invocation_key=str(step), lease_token=self.activate(job), deadline=Deadline.after(10))
        with self.assertRaises(AttributeError):
            context.environment_id = str(uuid4())
        for capability in (context.storage, context.secrets):
            for name in ('engine', 'connection', 'session', 'bind', 'execute'):
                self.assertFalse(hasattr(capability, name))
        with self.assertRaises(ValueError):
            context.secrets.derive('prepare-not-allowed')
        with self.assertRaises(AuthorizationDenied):
            builder.build(job_id=job, plugin_instance_id=self.other, step_instance_id=step,
                operation_id=None, invocation_key=str(step), lease_token=self.activate(job), deadline=Deadline.after(10))


if __name__ == '__main__':
    unittest.main()
