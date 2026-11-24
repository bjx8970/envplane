from concurrent.futures import ThreadPoolExecutor
import threading
import unittest
from uuid import uuid4

from sqlalchemy import text

from control_plane.config import COORDINATOR_LOCK_KEY
from control_plane.coordination import CoordinatorLease
from control_plane.persistence import StorageConflict
from control_plane.plugins.configuration import ConfigurationService
from control_plane.plugins.fake import FAKE_MANIFEST, FakePlugin
from control_plane.plugins.registry import PluginRegistry
from control_plane.plugins.sdk import AuthorizationDenied, ReferenceUnavailable, canonical_json
from control_plane.plugins.secrets import SecretService
from control_plane.plugins.storage import StorageService
from tests_control_plane.p1_harness import runtime_database
from tests_control_plane.pg_harness import engine_for
from tests_control_plane.test_p1_schema import insert, recorded_evidence


class ServicesFixture:
    @classmethod
    def setUpClass(cls):
        cls.admin_url, cls.runtime_url = cls.enterClassContext(runtime_database())
        cls.engine = engine_for(cls.runtime_url)
        cls.addClassCleanup(cls.engine.dispose)
        cls.lease = CoordinatorLease(cls.engine, COORDINATOR_LOCK_KEY, lease_seconds=300)
        if not cls.lease.acquire():
            raise AssertionError('isolated low-privilege coordinator unavailable')
        cls.addClassCleanup(cls.lease.release)
        cls.registry = PluginRegistry()
        cls.registry.register(FakePlugin(), FAKE_MANIFEST, code_digest='fake-code-v1')
        cls.storage = StorageService(cls.engine, cls.lease)
        cls.secrets = SecretService(cls.engine, cls.lease, {'test': b'k' * 32}, 'test')
        cls.configurations = ConfigurationService(cls.engine, cls.lease, cls.registry)

    def setUp(self):
        with self.lease.fenced_transaction() as uow:
            self.teacher = uow.scalar(text('''INSERT INTO control_plane.users(username,password_hash,role)
                VALUES (:name,'test-only','teacher') RETURNING id'''), {'name': uuid4().hex})
            course = uow.scalar(text('''INSERT INTO control_plane.courses(owner_teacher_id,name)
                VALUES (:teacher,'test') RETURNING id'''), {'teacher': self.teacher})
            template = uow.scalar(text('''INSERT INTO control_plane.templates(name,created_by)
                VALUES ('test',:teacher) RETURNING id'''), {'teacher': self.teacher})
            version = uow.scalar(text('''INSERT INTO control_plane.template_versions
                (template_id,version,definition,content_digest,created_by)
                VALUES (:template,1,'{}','test',:teacher) RETURNING id'''), {'template': template, 'teacher': self.teacher})
            self.environment = uow.scalar(text('''INSERT INTO control_plane.environments
                (owner_teacher_id,course_id,created_by,template_version_id,name)
                VALUES (:teacher,:course,:teacher,:version,'test') RETURNING id'''),
                {'teacher': self.teacher, 'course': course, 'version': version})
            self.group = uow.scalar(text('''INSERT INTO control_plane.execution_groups(environment_id)
                VALUES (:environment) RETURNING id'''), {'environment': self.environment})
            self.instance = self.new_instance_in(uow)
            self.other = self.new_instance_in(uow)
        self.admin = self.storage.bind(self.instance)

    def new_instance_in(self, uow):
        instance = insert(uow, "plugin_instances", plugin_key="fake")
        self.configurations.put_in(uow, instance, {'data': {}, 'allowed_secret_refs': []}, expected_revision=0)
        return instance

    def job(self, *, instances=None, logical=None):
        with self.lease.fenced_transaction() as uow:
            captures = {
                str(instance): self.configurations.capture_in(uow, instance, self.secrets, self.environment)
                for instance in instances or (self.instance,)
            }
            snapshot = {"workflow": {"kind": "action", "steps": []}, "plugins": captures}
            job = uow.scalar(text('''INSERT INTO control_plane.jobs
                (environment_id,execution_group_id,actor_id,request_key,request_digest,logical_invocation_id,kind,input,execution_snapshot)
                VALUES (:environment,:group,:teacher,:key,'digest',:logical,'test','{}',CAST(:snapshot AS jsonb)) RETURNING id'''),
                {'environment': self.environment, 'group': self.group, 'teacher': self.teacher,
                 'key': uuid4().hex, 'logical': logical or uuid4(), 'snapshot': canonical_json(snapshot)})
            for instance, capture in captures.items():
                self.configurations.bind_capture_in(uow, job, instance, capture, self.secrets)
            step = uow.scalar(text("INSERT INTO control_plane.job_steps(job_id,step_path) VALUES (:job,'create') RETURNING id"), {'job': job})
        return job, step

    def source(self, job, step, data, *, checkpoint=False, state='succeeded', instance=None):
        instance = instance or self.instance
        with self.lease.fenced_transaction() as uow:
            op = uow.scalar(text('''INSERT INTO control_plane.operations
                (job_id,step_id,attempt,invocation_key,plugin_instance_id,plugin_version,code_digest,prepared_call,state,output)
                VALUES (:job,:step,1,:key,:instance,'1.0.0','fake-code-v1','{}',:state,CAST(:output AS jsonb)) RETURNING id'''),
                {'job': job, 'step': step, 'key': str(step), 'instance': instance, 'state': state,
                 'output': canonical_json(data) if state == 'succeeded' else None})
            evidence = None
            if checkpoint:
                evidence = recorded_evidence(uow, op, ref_key="derived", data=data, trusted_for_derivation=True)
        return op, evidence


class StorageServiceTests(ServicesFixture, unittest.TestCase):
    def test_job_snapshot_is_asof_across_updates_and_deletes(self):
        first = self.admin.put('hosts/a', {'address': 'old'})
        self.admin.put('hosts/b', {'address': 'b'})
        job, _ = self.job()
        bound = self.storage.bind(self.instance, job)
        self.admin.put('hosts/a', {'address': 'new'}, first)
        self.admin.put('hosts/c', {'address': 'c'})
        self.assertEqual(bound.get('hosts/a').value, {'address': 'old'})
        self.assertEqual([item.key for item in bound.list('hosts/').items], ['hosts/a', 'hosts/b'])
        with self.assertRaises(AttributeError):
            bound.snapshot_id = self.admin.snapshot().id

    def test_list_stable_cursor_survives_concurrent_changes(self):
        refs = {key: self.admin.put(key, {'key': key}) for key in ('a', 'b', 'c')}
        job, _ = self.job()
        bound = self.storage.bind(self.instance, job)
        page = bound.list(limit=1)
        self.admin.delete('b', refs['b'])
        self.admin.put('aa', {})
        second = bound.list(limit=1, cursor=page.cursor)
        third = bound.list(limit=1, cursor=second.cursor)
        self.assertEqual([page.items[0].key, second.items[0].key, third.items[0].key], ['a', 'b', 'c'])
        self.assertIsNone(third.cursor)
        with self.assertRaises(ValueError):
            bound.list(prefix='new', cursor=page.cursor)
        with self.assertRaises(ValueError):
            bound.list(snapshot_id=self.admin.snapshot().id, cursor=page.cursor)

    def test_job_cannot_refresh_snapshot(self):
        self.admin.put('key', {})
        job, _ = self.job()
        bound = self.storage.bind(self.instance, job)
        self.assertEqual(bound.snapshot().id, bound.snapshot().id)
        with self.assertRaises(AuthorizationDenied):
            bound.get('key', snapshot_id=self.admin.snapshot().id)

    def test_instance_scope_cannot_be_changed(self):
        ref = self.storage.bind(self.other).put('key', {'foreign': True})
        self.admin.put('key', {'local': True})
        job, _ = self.job()
        bound = self.storage.bind(self.instance, job)
        with self.assertRaises(AuthorizationDenied):
            bound.get('key', version=ref.version_id)
        with self.assertRaises(AuthorizationDenied):
            bound.put('key', {}, expected_version=ref)

    def test_write_does_not_authorize_guessing_new_version(self):
        first = self.admin.put('key', {'version': 1})
        job, _ = self.job()
        bound = self.storage.bind(self.instance, job)
        new = bound.put('key', {'version': 2}, first)
        self.assertEqual(bound.get('key').ref, first)
        with self.assertRaises(AuthorizationDenied):
            bound.get('key', version=new.version_id)

    def test_successful_output_and_checkpoint_are_trusted_derived_sources(self):
        first = self.admin.put('key', {'version': 1})
        job, step = self.job()
        bound = self.storage.bind(self.instance, job)
        new = bound.put('key', {'version': 2}, first)
        self.source(job, step, {'derived': new.to_dict()})
        self.assertEqual(bound.get('key', version=new.version_id).value, {'version': 2})

    def test_failed_output_is_not_a_trusted_derived_source(self):
        first = self.admin.put('key', {})
        job, step = self.job()
        new = self.admin.put('key', {'new': True}, first)
        self.source(job, step, {'derived': new.to_dict()}, state='failed')
        with self.assertRaises(AuthorizationDenied):
            self.storage.bind(self.instance, job).get('key', version=new.version_id)

    def test_late_untrusted_checkpoint_cannot_authorize_storage(self):
        first = self.admin.put('key', {'old': True})
        job, step = self.job()
        new = self.admin.put('key', {'new': True}, first)
        operation, _ = self.source(job, step, {}, state='running')
        with self.lease.fenced_transaction() as uow:
            recorded_evidence(uow, operation, ref_key="late", data={"derived": new.to_dict()})
        with self.assertRaises(AuthorizationDenied):
            self.storage.bind(self.instance, job).get('key', version=new.version_id)

    def test_controlled_checkpoint_can_authorize_storage(self):
        first = self.admin.put('key', {'old': True})
        job, step = self.job()
        new = self.admin.put('key', {'new': True}, first)
        self.source(job, step, {'derived': new.to_dict()}, checkpoint=True, state='running')
        self.assertEqual(self.storage.bind(self.instance, job).get('key', version=new.version_id).ref, new)

    def test_page_limit_is_bounded_at_1000(self):
        self.assertEqual(self.admin.list(limit=1000).items, ())
        for limit in (0, -1, 1001, True):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                self.admin.list(limit=limit)

    def test_tombstone_recreation_requires_exact_cas(self):
        first = self.admin.put('key', {'first': True})
        tombstone = self.admin.delete('key', first)
        with self.assertRaises(StorageConflict):
            self.admin.put('key', {'reset': True})
        with self.assertRaises(StorageConflict):
            self.admin.put('key', {'reset': True}, first)
        restored = self.admin.put('key', {'restored': True}, tombstone)
        self.assertEqual(self.admin.get('key', restored.version_id).version, 3)
        self.assertTrue(self.admin.get('key', tombstone.version_id).is_tombstone)
        self.assertEqual(self.admin.get('key', first.version_id).value, {'first': True})

    def test_two_concurrent_cas_writers_have_one_winner(self):
        first = self.admin.put('key', {})
        barrier = threading.Barrier(2)
        def update(index):
            barrier.wait(timeout=5)
            try:
                return self.admin.put('key', {'writer': index}, first)
            except StorageConflict:
                return None
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(update, (1, 2)))
        self.assertEqual(sum(result is not None for result in results), 1)

    def test_nonfinite_large_or_deep_json_is_rejected(self):
        for value in ({'nan': float('nan')}, {'items': [0] * 1001}, {'payload': 'x' * 1048577}):
            with self.assertRaises(ValueError):
                self.admin.put('invalid', value)

    def test_configuration_cas_and_history_pinned_to_job(self):
        old = self.configurations.get(self.instance)
        job, _ = self.job()
        new = self.configurations.put(self.instance, {'data': {'changed': True}, 'allowed_secret_refs': []}, expected_revision=1)
        self.assertEqual(new.revision, 2)
        self.assertEqual(self.configurations.get(self.instance, old.revision).configuration['data'], {})
        with self.assertRaises(StorageConflict):
            self.configurations.put(self.instance, {'data': {}, 'allowed_secret_refs': []}, expected_revision=1)
        with self.engine.connect() as conn:
            revision = conn.scalar(text('SELECT configuration_revision FROM control_plane.job_plugin_snapshots WHERE job_id=:job'), {'job': job})
        self.assertEqual(revision, 1)

    def captured_job_in(self, uow, capture):
        return uow.scalar(text('''INSERT INTO control_plane.jobs
            (environment_id,execution_group_id,actor_id,request_key,request_digest,kind,input,execution_snapshot)
            VALUES (:environment,:group,:teacher,:key,'digest','test','{}',CAST(:snapshot AS jsonb)) RETURNING id'''),
            {'environment': self.environment, 'group': self.group, 'teacher': self.teacher,
             'key': uuid4().hex, 'snapshot': canonical_json({
                 "workflow": {"kind": "action", "steps": []}, "plugins": {str(self.instance): capture},
             })})

    def test_capture_binds_exact_original_config_storage_and_secret_map(self):
        from control_plane.plugins.sdk import SecretRef
        first = self.secrets.create(b'capture-original-secret')
        self.configurations.put(self.instance,
            {'data': {'revision': 'original'}, 'allowed_secret_refs': [SecretRef(first.secret_id).to_dict()]}, expected_revision=1)
        original_storage = self.admin.put('captured', {'revision': 'original'})
        with self.lease.fenced_transaction() as uow:
            capture = self.configurations.capture_in(uow, self.instance, self.secrets, self.environment)
            # Even if trusted admission code changes current values in this same
            # transaction, binding consumes the capture rather than re-reading latest.
            self.configurations.put_in(uow, self.instance,
                {'data': {'revision': 'changed'}, 'allowed_secret_refs': []}, expected_revision=2)
            from control_plane.persistence import write_storage
            write_storage(uow, self.instance, 'captured', {'revision': 'changed'}, expected_version=original_storage.version_id)
            self.secrets._encrypt_in(uow, first.secret_id, 'admin_connection', None, b'capture-new-secret', 2)
            job = self.captured_job_in(uow, capture)
            self.configurations.bind_capture_in(uow, job, self.instance, capture, self.secrets)
        self.assertEqual(capture['configuration_revision'], 2)
        self.assertEqual(capture['secret_refs'], [first.to_dict()])
        self.assertEqual(self.storage.bind(self.instance, job).get('captured').ref, original_storage)
        with self.secrets.bind(job, self.instance, self.environment).get(first) as handle:
            self.assertEqual(handle.reveal(), b'capture-original-secret')
        with self.engine.connect() as connection:
            persisted = connection.scalar(text('SELECT execution_snapshot FROM control_plane.jobs WHERE id=:job'), {'job': job})
        self.assertEqual(persisted['plugins'][str(self.instance)], capture)

    def test_capture_tamper_or_immutable_snapshot_mismatch_is_rejected(self):
        import copy
        with self.lease.fenced_transaction() as uow:
            capture = self.configurations.capture_in(uow, self.instance, self.secrets, self.environment)
            changed = copy.deepcopy(capture)
            changed['namespace_revision'] += 1
            job = self.captured_job_in(uow, changed)
            with self.assertRaises(ReferenceUnavailable):
                self.configurations.bind_capture_in(uow, job, self.instance, changed, self.secrets)
            with self.assertRaises(ReferenceUnavailable):
                self.configurations.bind_capture_in(uow, job, self.instance, capture, self.secrets)

    def test_capture_cannot_be_consumed_after_commit_or_config_update(self):
        with self.lease.fenced_transaction() as uow:
            capture = self.configurations.capture_in(uow, self.instance, self.secrets, self.environment)
        self.configurations.put(self.instance, {'data': {'new': True}, 'allowed_secret_refs': []}, expected_revision=1)
        with self.lease.fenced_transaction() as uow:
            job = self.captured_job_in(uow, capture)
            with self.assertRaises(ReferenceUnavailable):
                self.configurations.bind_capture_in(uow, job, self.instance, capture, self.secrets)

    def test_bound_facade_has_no_database_or_bind_api(self):
        bound = self.storage.bind(self.instance)
        for name in ('engine', 'runtime', 'connection', 'session', 'bind', 'execute'):
            self.assertFalse(hasattr(bound, name))


if __name__ == '__main__':
    unittest.main()
