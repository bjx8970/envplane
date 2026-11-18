"""Template publication invariants before any external call or HTTP entry point."""
from copy import deepcopy
import json
from pathlib import Path
import unittest
from uuid import uuid4

from sqlalchemy import text

from control_plane.config import RuntimeSettings
from control_plane.plugins.registry import PluginRegistry
from control_plane.plugins.sdk import AuthorizationDenied
from control_plane.runtime import ControlPlaneRuntime
from control_plane.templates import (
    TemplateError, TemplateService, expand_items, load_version, order_steps,
    quota_cost, resolve, resolve_access, validate_parameters, validate_template,
)
from tests_control_plane.p1_harness import runtime_database


ROOT = Path(__file__).resolve().parents[1]


def example():
    spec = (ROOT / 'docs/template-resource-contract.md').read_text(encoding='utf-8')
    return json.loads(spec.split('```json\n', 1)[1].split('```', 1)[0])


class TemplateContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ssh = PluginRegistry().load(ROOT / 'plugins', required=['ssh']).get('ssh')

    def lookup(self, alias):
        self.assertEqual(alias, 'ssh_lab')
        return self.ssh

    def test_documented_example_and_selector(self):
        template = example()
        validate_template(template, self.lookup)
        self.assertEqual(quota_cost(template, {}), template['quota'])
        specs = template['parameters']
        selected = {'target_host': 'a'}
        rows = {'target_host': [{'id': 'a', 'name': 'A'}]}
        self.assertEqual(validate_parameters(specs, selected, selector_values=rows), selected)
        for bad in (None, {}, {'target_host': []}, {'target_host': [{}]},
                    {'target_host': rows['target_host'] * 2}):
            with self.subTest(rows=bad), self.assertRaises(TemplateError):
                validate_parameters(specs, selected, selector_values=bad)
        for supplied in ({}, {'target_host': 'other'}, {**selected, 'command': 'extra'}):
            with self.subTest(supplied=supplied), self.assertRaises(TemplateError):
                validate_parameters(specs, supplied, selector_values=rows)

    def test_publish_rejects_invalid_declarations(self):
        # Mutate one field of the real SSH example per case.
        cases = [
            ((), 'unsupported', 1),
            (('parameters', 'target_host'), 'type', 'file'),
            (('parameters', 'target_host', 'selector'), 'action', 'execute_command'),
            (('parameters', 'target_host', 'selector'), 'value_field', 'missing'),
            (('create', 'steps', 0), 'action', 'absent'),
            (('create', 'steps', 0), 'depends_on', ['inspect']),
            (('create', 'steps', 0), 'input', {'$ref': 'params.target_host'}),
            (('create', 'steps', 0, 'input'), 'command', {'$ref': 'params.target_host'}),
            (('create', 'steps', 0, 'input'), 'command', 123),
            (('create', 'steps', 0), 'for_each', {
                'items': [], 'item_key': {'$ref': 'item'}, 'max_items': 1001}),
            (('resources', 0, 'data'), 'host_id', {'$ref': 'params.missing'}),
            (('resources', 0, 'data'), 'system', {'$ref': 'steps.inspect.output.absent'}),
            (('resources', 0, 'data'), 'system', {'$ref': 'evidence.source_job_ids'}),
            (('resources', 0, 'actions', 'inspect_again'), 'roles', ['owner']),
            (('readiness',), 'require_resources', ['other']),
            (('readiness',), 'require_steps', ['other']),
            (('readiness',), 'conditions', [{'not_an_operator': True}]),
            (('cleanup',), 'completion', {}),
            (('quota',), 'vms', {'$expr': {'unimplemented': [1]}}),
            (('quota',), 'vms', {'$ref': 'params.target_host'}),
            (('quota',), 'vms', {'$expr': {'divide': [1, 0]}}),
            (('quota',), 'memory_mb', 2**63),
        ]
        for path, key, value in cases:
            with self.subTest(path=path, key=key, value=value):
                template = example()
                node = template
                for part in path:
                    node = node[part]
                node[key] = value
                with self.assertRaises(TemplateError):
                    validate_template(template, self.lookup)

    def test_ordering_uses_dependencies_from_refs(self):
        tail = deepcopy(example()['create']['steps'][0])
        tail['id'] = 'finish'
        tail['input']['host_id'] = {'$ref': 'steps.inspect.output.stdout'}
        template = example()
        template['create']['steps'].insert(0, tail)
        validate_template(template, self.lookup)
        self.assertEqual([step['id'] for step in order_steps(template['create']['steps'])],
                         ['inspect', 'finish'])
        template['create']['steps'][1]['depends_on'] = ['finish']
        with self.assertRaises(TemplateError):
            validate_template(template, self.lookup)

    def test_bounded_costs_and_stable_item_keys(self):
        template = example()
        template['parameters']['guests'] = {'type': 'array', 'maxItems': 5, 'uniqueItems': True}
        count = {'$expr': {'length': [{'$ref': 'params.guests'}]}}
        template['quota']['vcpu'] = {'$expr': {'multiply': [2, count]}}
        validate_template(template, self.lookup)
        params = {'guests': ['a', 'b']}
        self.assertEqual(quota_cost(template, params)['vcpu'], 4)
        loop = {'items': {'$ref': 'params.guests'}, 'item_key': {'$ref': 'item'}, 'max_items': 3}
        self.assertEqual(expand_items(loop, {'params': params}), [('a', 'a'), ('b', 'b')])
        for bad in (['a', 'a'], [1], ['a', 'b', 'c', 'd']):
            with self.subTest(bad=bad), self.assertRaises(TemplateError):
                expand_items(loop, {'params': {'guests': bad}})
        for op, args in [('divide', [1, 0]), ('subtract', [1, 2]),
                         ('multiply', [2**62, 2]), ('length', [False])]:
            with self.subTest(op=op), self.assertRaises(TemplateError):
                resolve({'$expr': {op: args}}, {})

    def test_resolved_output_and_parameters_are_independent_copies(self):
        values = {'data': {'name': 'a'}}
        result = resolve({'$ref': 'params.data'}, {'params': values})
        result['name'] = 'other'
        self.assertEqual(values['data'], {'name': 'a'})
        spec = {'hosts': {'type': 'array', 'fixed': ['a']}}
        params = validate_parameters(spec, {})
        params['hosts'].append('b')
        self.assertEqual(spec['hosts']['fixed'], ['a'])
        with self.assertRaises(TemplateError):
            validate_parameters(spec, {'hosts': ['b']})
        with self.assertRaises(TemplateError):
            resolve({'$ref': 'steps.failed.output.id'}, {'steps': {}})

    def test_access_resolution_requires_declared_role_capability_and_exact_ref(self):
        class SessionPlugin:
            manifest = {'sessions': {'terminal': {'input_schema': {'type': 'object'}}}}

            def validate_input(self, session, value):
                if session != 'terminal' or value != {'host': 'target'}:
                    raise AssertionError('unexpected session input')

        access = {'web': {'roles': ['student'], 'plugin_instance': 'ssh_lab',
                          'session_type': 'terminal', 'target_ref': {'$ref': 'resource.data.host'},
                          'input': {'host': {'$ref': 'resource.data.host'}},
                          'credential_ref': {'$ref': 'resource.data.credential'}}}
        ref = {'secret_id': str(uuid4()), 'version_id': str(uuid4())}
        ctx = {'resource': {'data': {'host': 'target', 'credential': ref}}}
        lookup = lambda alias: SessionPlugin()
        result = resolve_access(access, 'web', ctx, 'student', lookup)
        self.assertEqual(result['target_ref'], 'target')
        self.assertEqual(result['credential_ref'], ref)
        with self.assertRaises(AuthorizationDenied):
            resolve_access(access, 'web', ctx, 'teacher', lookup)
        del ref['version_id']
        with self.assertRaises(TemplateError):
            resolve_access(access, 'web', ctx, 'student', lookup)


class TemplatePublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, url = cls.enterClassContext(runtime_database())
        cls.runtime = ControlPlaneRuntime(RuntimeSettings.from_env({'CONTROL_PLANE_DATABASE_URL': url}))
        cls.runtime.start()
        cls.addClassCleanup(cls.runtime.stop)
        ssh = PluginRegistry().load(ROOT / 'plugins', required=['ssh']).get('ssh')
        cls.service = TemplateService(cls.runtime, lambda name: ssh)

    def setUp(self):
        with self.runtime.fenced_transaction() as uow:
            def user(role):
                return uow.scalar(text("""INSERT INTO control_plane.users (username,password_hash,role)
                                       VALUES (:username,'test',:role) RETURNING id"""),
                                  {'username': uuid4().hex, 'role': role})
            self.admin = user('admin')
            self.teacher = user('teacher')

    def test_permissions_and_irreversible_publication(self):
        template = example()
        with self.assertRaises(AuthorizationDenied):
            self.service.create_draft(self.teacher, template)
        stable, v1 = self.service.create_draft(self.admin, template)
        with self.assertRaises(AuthorizationDenied):
            self.service.publish(self.teacher, v1)
        original = deepcopy(template)
        self.service.publish(self.admin, v1)
        template['metadata']['name'] = 'Second version'
        with self.assertRaises(TemplateError):
            self.service.edit_draft(self.admin, v1, template)
        _, v2 = self.service.create_draft(self.admin, template, template_id=stable)
        self.service.publish(self.admin, v2)
        self.service.disable(self.admin, v1)
        with self.runtime.fenced_transaction() as uow:
            self.assertEqual(load_version(uow, v1, for_create=False), original)
            self.assertEqual(load_version(uow, v2, for_create=True), template)
            with self.assertRaises(TemplateError):
                load_version(uow, v1, for_create=True)
            self.assertEqual(uow.scalar(text("""SELECT count(*) FROM control_plane.audit_events
                             WHERE template_version_id=:id AND actor_id=:actor"""),
                             {'id': v1, 'actor': self.admin}), 3)

    def test_secret_guard_runs_before_draft_or_edit_is_persisted(self):
        class RejectedPlaintext(ValueError):
            pass

        def safe_json(value):
            if value['metadata']['name'] == 'delivered-test-value':
                raise RejectedPlaintext()
            return value

        service = TemplateService(self.runtime, self.service.lookup, safe_json=safe_json)
        original = example()
        invalid = deepcopy(original)
        invalid['metadata']['name'] = 'delivered-test-value'
        with self.assertRaises(RejectedPlaintext):
            service.create_draft(self.admin, invalid)
        _, version = service.create_draft(self.admin, original)
        with self.assertRaises(RejectedPlaintext):
            service.edit_draft(self.admin, version, invalid)
        service.publish(self.admin, version)
        with self.runtime.fenced_transaction() as uow:
            self.assertEqual(load_version(uow, version, for_create=True), original)

    def test_failed_publish_keeps_editable_draft(self):
        invalid = example()
        invalid['readiness']['require_steps'] = ['missing']
        _, version = self.service.create_draft(self.admin, invalid)
        with self.assertRaises(TemplateError):
            self.service.publish(self.admin, version)
        self.service.edit_draft(self.admin, version, example())
        self.service.publish(self.admin, version)
        with self.runtime.fenced_transaction() as uow:
            self.assertEqual(load_version(uow, version, for_create=True), example())


if __name__ == '__main__':
    unittest.main()
