import copy
import json
from pathlib import Path
import tempfile
import unittest

from jsonschema.exceptions import ValidationError

from control_plane.plugins.fake import FAKE_MANIFEST, FakePlugin
from control_plane.plugins.registry import (LocalSchemas, ManifestError, PluginRegistry,
                                            StartupPluginError, code_digest, safe_yaml)
from control_plane.plugins.sdk import ExecutionPolicy, PreparedCall, finite_json


class PluginLoadingTests(unittest.TestCase):
    def package(self, root, name='fake', manifest=None):
        path = Path(root) / name
        path.mkdir()
        manifest = copy.deepcopy(FAKE_MANIFEST if manifest is None else manifest)
        (path / 'manifest.yaml').write_text(json.dumps(manifest), encoding='utf-8')
        (path / 'plugin.py').write_text(
            'from control_plane.plugins.fake import FakePlugin\n', encoding='utf-8')
        return path

    def test_safe_yaml_accepts_real_yaml(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'doc.yaml'
            path.write_text('name: example\nlist:\n  - one\n  - two\n', encoding='utf-8')
            self.assertEqual(safe_yaml(path), {'name': 'example', 'list': ['one', 'two']})

    def test_duplicate_yaml_and_json_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'doc.yaml'
            for document in ('a: 1\na: 2', '{"a":1,"a":2}', 'a:\n  b: 1\n  b: 2'):
                path.write_text(document, encoding='utf-8')
                with self.subTest(document=document), self.assertRaises(ManifestError):
                    safe_yaml(path)

    def test_yaml_python_tags_and_alias_cycles_are_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'doc.yaml'
            for document in ('!!python/object/apply:os.system [echo]', 'a: &a [*a]'):
                path.write_text(document, encoding='utf-8')
                with self.subTest(document=document), self.assertRaises(ManifestError):
                    safe_yaml(path)

    def test_required_missing_fails_optional_missing_is_status_only(self):
        with tempfile.TemporaryDirectory() as root:
            registry = PluginRegistry().load(root, optional=['missing'])
            self.assertEqual(registry.unavailable['missing'], 'plugin_missing')
            with self.assertRaises(StartupPluginError):
                PluginRegistry().load(root, required=['missing'])

    def test_load_records_digest_and_is_startup_only(self):
        with tempfile.TemporaryDirectory() as root:
            path = self.package(root)
            registry = PluginRegistry().load(root, required=['fake'])
            self.assertEqual(registry.get('fake').code_digest, code_digest(path))
            self.assertEqual(registry.get('fake').plugin_version, '1.0.0')
            with self.assertRaises(StartupPluginError):
                registry.load(root)
            with self.assertRaises(TypeError):
                registry.plugins['new'] = None

    def test_malformed_optional_plugin_key_does_not_escape_loader(self):
        with tempfile.TemporaryDirectory() as root:
            manifest = copy.deepcopy(FAKE_MANIFEST)
            manifest['plugin_key'] = {'malformed': 'identity'}
            self.package(root, 'broken', manifest)
            registry = PluginRegistry().load(root, optional=['broken'])
            self.assertEqual(registry.unavailable['broken'], 'plugin_load_failed')
            self.assertEqual(dict(registry.plugins), {})

    def test_duplicate_plugin_keys_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            self.package(root, 'one')
            self.package(root, 'two')
            registry = PluginRegistry().load(root)
            self.assertNotIn('fake', registry.plugins)
            self.assertIn('fake', registry.unavailable)

    def test_digest_includes_auxiliary_files(self):
        with tempfile.TemporaryDirectory() as root:
            path = self.package(root)
            first = code_digest(path)
            (path / 'helper.py').write_text('VALUE = 2', encoding='utf-8')
            self.assertNotEqual(first, code_digest(path))

    def test_entrypoint_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            manifest = copy.deepcopy(FAKE_MANIFEST)
            manifest['entrypoint'] = '../outside:FakePlugin'
            self.package(root, manifest=manifest)
            with self.assertRaises(StartupPluginError):
                PluginRegistry().load(root, required=['fake'])

    def test_schema_2020_local_file_refs(self):
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / 'shape.yaml').write_text('type: integer\nminimum: 1', encoding='utf-8')
            validator = LocalSchemas(root).compile({'$schema': 'https://json-schema.org/draft/2020-12/schema',
                'type': 'object', 'properties': {'count': {'$ref': 'shape.yaml'}}, 'required': ['count']})
            validator.validate({'count': 2})
            with self.assertRaises(ValidationError):
                validator.validate({'count': 0})

    def test_missing_local_fragment_is_rejected_at_startup(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(ManifestError):
                LocalSchemas(root).compile({'$ref': '#/$defs/missing'})

    def test_in_document_id_subschema_needs_no_file_on_disk(self):
        # `$ref` may target a nested `$id` sub-schema of the same document; no
        # matching item.json file is required (review finding).
        with tempfile.TemporaryDirectory() as root:
            validator = LocalSchemas(root).compile({
                '$schema': 'https://json-schema.org/draft/2020-12/schema',
                '$defs': {'item': {'$id': 'item.json', 'type': 'integer'}},
                '$ref': 'item.json'})
            validator.validate(42)
            with self.assertRaises(ValidationError):
                validator.validate('abc')
            self.assertFalse((Path(root) / 'item.json').exists())

    def test_nested_relative_id_changes_reference_base(self):
        with tempfile.TemporaryDirectory() as root:
            validator = LocalSchemas(root).compile({
                '$schema': 'https://json-schema.org/draft/2020-12/schema',
                '$defs': {'a': {'$id': 'folder/a.json',
                                '$defs': {'x': {'type': 'string'}}, '$ref': '#/$defs/x'}},
                '$ref': 'folder/a.json'})
            validator.validate('hello')
            with self.assertRaises(ValidationError):
                validator.validate(5)

    def test_remote_absolute_and_escaping_schema_refs_are_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            for ref in ('https://example.org/schema', 'file:///etc/passwd', '../outside.json', '//example.org/a', '%2e%2e/outside.json'):
                with self.subTest(ref=ref), self.assertRaises(ManifestError):
                    LocalSchemas(root).compile({'$ref': ref})

    def test_declared_methods_and_describe_must_agree(self):
        bad = FakePlugin()
        bad.poll = None
        with self.assertRaises(ManifestError):
            PluginRegistry().register(bad, copy.deepcopy(FAKE_MANIFEST))
        bad = FakePlugin()
        bad.describe = lambda: {'different': True}
        with self.assertRaises(ManifestError):
            PluginRegistry().register(bad, copy.deepcopy(FAKE_MANIFEST))

    def test_session_prepared_policy_and_namespace_are_checked(self):
        manifest = copy.deepcopy(FAKE_MANIFEST)
        manifest['sessions'] = {'terminal': {'display_name': 'Terminal', 'input_schema': {'type': 'object'}}}
        fake = FakePlugin()
        fake.describe = lambda: copy.deepcopy(manifest)
        for method in ('prepare_session', 'open_session', 'send', 'receive', 'close_session'):
            setattr(fake, method, lambda *args: None)
        loaded = PluginRegistry().register(fake, manifest)
        loaded.validate_prepared(PreparedCall('terminal'))
        with self.assertRaises(ValueError):
            loaded.validate_prepared(PreparedCall('terminal', execution_policy=ExecutionPolicy('read_only')))
        manifest['sessions']['echo'] = manifest['sessions'].pop('terminal')
        with self.assertRaises(ManifestError):
            PluginRegistry().register(fake, manifest)

    def test_prepare_cannot_elevate_guarantees(self):
        manifest = copy.deepcopy(FAKE_MANIFEST)
        plugin = PluginRegistry().register(FakePlugin(), manifest)
        with self.assertRaises(ValueError):
            plugin.validate_prepared(PreparedCall('echo', execution_policy=ExecutionPolicy('read_only', 'keyed', 'queryable', 'requestable')))

    def test_json_is_bounded_and_rejects_handles(self):
        for value in ({'value': float('nan')}, {'value': float('inf')}, {'bytes': b'secret'}, {'items': [1] * 1001}):
            with self.subTest(kind=type(value)), self.assertRaises(ValueError):
                finite_json(value)
        nested = {}
        value = nested
        for _ in range(33):
            value['next'] = {}
            value = value['next']
        with self.assertRaises(ValueError):
            finite_json(nested)


if __name__ == '__main__':
    unittest.main()
