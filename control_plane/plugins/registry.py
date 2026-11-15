"""Trusted-directory startup loader. No dynamic installation or remote schemas."""
from dataclasses import dataclass, field
import hashlib
import importlib.util
from pathlib import Path
import re
import sys
from types import MappingProxyType
from urllib.parse import unquote, urljoin, urlsplit
from urllib.request import url2pathname
from uuid import uuid4

import yaml
from jsonschema import Draft202012Validator
from referencing import Registry as ReferenceRegistry, Resource
from referencing.jsonschema import DRAFT202012

from .sdk import ExecutionPolicy, ReferenceUnavailable, canonical_json, finite_json, json_digest


class ManifestError(ValueError):
    pass


class StartupPluginError(RuntimeError):
    pass


class _UniqueLoader(yaml.SafeLoader):
    pass


def _mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in result:
            raise ManifestError('duplicate or non-string YAML key')
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def safe_yaml(path):
    path = Path(path)
    if path.stat().st_size > 1048576:
        raise ManifestError('document size limit exceeded')
    try:
        value = yaml.load(path.read_text(encoding='utf-8'), Loader=_UniqueLoader)
        finite_json(value)
        return value
    except (yaml.YAMLError, ValueError, RecursionError, TypeError):
        raise ManifestError('invalid bounded YAML document') from None


def _inside(root, path):
    path = path.resolve()
    if not path.is_relative_to(root):
        raise ManifestError('package path escapes trusted directory')
    return path


def code_digest(directory):
    root = Path(directory).resolve()
    digest = hashlib.sha256()
    count, size = 0, 0
    for path in sorted(root.rglob('*')):
        if '__pycache__' in path.parts or path.suffix == '.pyc':
            continue
        checked = _inside(root, path)
        if path.is_symlink():
            raise ManifestError('package symlinks are not supported')
        if not checked.is_file():
            continue
        count += 1
        size += checked.stat().st_size
        if count > 1000 or size > 16777216:
            raise ManifestError('package size limit exceeded')
        name = path.relative_to(root).as_posix().encode()
        digest.update(len(name).to_bytes(4, 'big') + name)
        content = checked.read_bytes()
        digest.update(len(content).to_bytes(8, 'big') + content)
    return digest.hexdigest()


class LocalSchemas:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self._documents = {}

    def compile(self, schema):
        Draft202012Validator.check_schema(schema)
        # The in-document resource is registered FIRST so refs to a nested `$id`
        # sub-schema resolve without requiring a matching file on disk.
        base_uri = (self.root / '__inline_schema__.json').as_uri()
        wrapper = dict(schema) if isinstance(schema, dict) else schema
        if isinstance(wrapper, dict):
            wrapper['$id'] = base_uri
        registry = ReferenceRegistry().with_resource(
            base_uri, Resource.from_contents(wrapper, default_specification=DRAFT202012))
        seen = set()

        def resolves(base, reference):
            """True when the reference is satisfiable by already-registered content."""
            try:
                registry.resolver(base_uri=base).lookup(reference)
                return True
            except Exception:
                return False

        def filesystem_path(base, reference):
            """Resolve a package-relative reference against the current base URI."""
            resolved = urljoin(base, reference)
            parts = urlsplit(resolved)
            if parts.scheme not in ('', 'file') or parts.netloc:
                raise ManifestError('only package-local schema references are allowed')
            return _inside(self.root, Path(url2pathname(parts.path)))

        def walk(value, base):
            nonlocal registry
            if isinstance(value, dict):
                # Absolute IDs can silently change ref resolution; package schemas use file/local IDs only.
                if '$id' in value:
                    identity = urlsplit(value['$id'])
                    if identity.scheme or identity.netloc or identity.path.startswith(('/', '\\\\')):
                        raise ManifestError('schema IDs must be package-local')
                    if identity.path:
                        filesystem_path(base, value['$id'])
                        base = urljoin(base, value['$id'])
                for keyword in ('$ref', '$dynamicRef'):
                    if keyword not in value:
                        continue
                    uri = urlsplit(value[keyword])
                    if uri.scheme or uri.netloc or uri.query or uri.path.startswith(('/', '\\')):
                        raise ManifestError('only package-local schema references are allowed')
                    # In-document `$id` sub-schemas and already loaded package files
                    # are resolved from the registry, not from the filesystem.
                    if resolves(base, value[keyword]):
                        continue
                    if not uri.path:
                        raise ManifestError('unresolvable local schema reference')
                    path = filesystem_path(base, value[keyword])
                    if not path.is_file():
                        raise ManifestError('local schema reference is missing')
                    resource_uri = path.as_uri()
                    if path not in seen:
                        seen.add(path)
                        document = safe_yaml(path)
                        Draft202012Validator.check_schema(document)
                        resource = Resource.from_contents(document, default_specification=DRAFT202012)
                        registry = registry.with_resource(resource_uri, resource)
                        walk(document, resource_uri)
                for child in value.values():
                    walk(child, base)
            elif isinstance(value, list):
                for child in value:
                    walk(child, base)

        walk(schema, base_uri)
        # Explicit retrieve callback always refuses network/unknown resources.
        def retrieve(uri):
            raise ManifestError('unregistered schema reference')
        registry = ReferenceRegistry(retrieve=retrieve).with_resources(registry.items())
        validator = Draft202012Validator(wrapper, registry=registry)
        return validator


@dataclass(frozen=True)
class LoadedPlugin:
    manifest: dict
    implementation: object = field(repr=False)
    code_digest: str
    root: Path
    validators: dict = field(repr=False)

    @property
    def plugin_key(self):
        return self.manifest['plugin_key']

    @property
    def plugin_version(self):
        return self.manifest['plugin_version']

    def validate_input(self, action_key, value):
        finite_json(value)
        self.validators[(action_key, 'input')].validate(value)

    def validate_output(self, action_key, value):
        finite_json(value)
        self.validators[(action_key, 'output')].validate(value)

    def validate_prepared(self, prepared):
        capability = self.manifest['actions'].get(prepared.action_key)
        if capability is None:
            capability = self.manifest.get('sessions', {}).get(prepared.action_key)
        if capability is None:
            raise ManifestError('undeclared action or session capability')
        policy = ExecutionPolicy.from_dict(capability.get('execution', {}))
        prepared.execution_policy.validate_against(policy)
        prepared.to_dict()


class PluginRegistry:
    def __init__(self):
        self._plugins = {}
        self._unavailable = {}
        self._started = False

    @property
    def plugins(self):
        return MappingProxyType(self._plugins)

    @property
    def unavailable(self):
        return MappingProxyType(self._unavailable)

    def get(self, key):
        if key not in self._plugins:
            raise ReferenceUnavailable('plugin is unavailable')
        return self._plugins[key]

    def load(self, directory, *, required=(), optional=()):
        if self._started:
            raise StartupPluginError('registry is startup-only')
        self._started = True
        root = Path(directory).resolve()
        required, optional = set(required), set(optional)
        if required & optional:
            raise StartupPluginError('plugin cannot be both required and optional')
        discovered = {}
        failures = {}
        if root.is_dir():
            for package in sorted(root.iterdir()):
                if not package.is_dir():
                    continue
                key = package.name
                try:
                    _inside(root, package)
                    if package.is_symlink():
                        raise ManifestError('package symlink rejected')
                    manifest = safe_yaml(_inside(package.resolve(), package / 'manifest.yaml'))
                    candidate_key = manifest.get('plugin_key', key)
                    if isinstance(candidate_key, str):
                        key = candidate_key
                    if key in discovered or key in failures:
                        discovered.pop(key, None)
                        raise ManifestError('duplicate plugin key')
                    discovered[key] = self._load_package(package, manifest)
                except Exception:
                    # Never leak import/config/secret exception text in status or logs.
                    failures[key] = 'plugin_load_failed'
        for key in required | optional:
            if key not in discovered:
                failures.setdefault(key, 'plugin_missing')
        for key in failures:
            discovered.pop(key, None)
        self._plugins, self._unavailable = discovered, failures
        if required & failures.keys():
            raise StartupPluginError('required plugin unavailable')
        return self

    def register(self, implementation, manifest, *, code_digest='test-only'):
        """Explicit trusted Fake/test registration; never called by manifest data."""
        if manifest['plugin_key'] in self._plugins:
            raise ManifestError('duplicate plugin key')
        validators = self._validate_manifest(manifest, Path.cwd())
        self._validate_methods(implementation, manifest)
        self._plugins[manifest['plugin_key']] = LoadedPlugin(manifest, implementation, code_digest, Path.cwd(), validators)
        return self._plugins[manifest['plugin_key']]

    def _validate_manifest(self, manifest, root):
        finite_json(manifest, object_only=True)
        required = {'manifest_version', 'api_version', 'plugin_key', 'plugin_version', 'display_name', 'entrypoint', 'actions'}
        if not required.issubset(manifest) or type(manifest['manifest_version']) is not int or manifest['manifest_version'] != 1 or manifest['api_version'] != '1':
            raise ManifestError('unsupported or incomplete manifest')
        for field in ('plugin_key', 'plugin_version', 'display_name', 'entrypoint'):
            if not isinstance(manifest[field], str) or not manifest[field] or len(manifest[field]) > 255:
                raise ManifestError('invalid manifest field')
        if not re.fullmatch(r'[a-z][a-z0-9_.-]*', manifest['plugin_key']):
            raise ManifestError('invalid plugin key')
        if not isinstance(manifest['actions'], dict) or not isinstance(manifest.get('sessions', {}), dict):
            raise ManifestError('invalid capabilities')
        if set(manifest['actions']) & set(manifest.get('sessions', {})):
            raise ManifestError('action and session capability keys must be distinct')
        validators = {}
        schemas = LocalSchemas(root)
        for kind in ('actions', 'sessions'):
            for key, action in manifest.get(kind, {}).items():
                if not isinstance(action, dict) or not {'display_name', 'input_schema', 'output_schema', 'execution'}.issubset(action):
                    if kind == 'sessions' and isinstance(action, dict) and 'input_schema' in action:
                        validators[(key, 'input')] = schemas.compile(action['input_schema'])
                        continue
                    raise ManifestError('invalid capability')
                if set(action['execution']) != {'effect', 'idempotency', 'recovery', 'cancellation'}:
                    raise ManifestError('incomplete execution policy')
                ExecutionPolicy.from_dict(action['execution'])
                for side in ('input', 'output'):
                    validators[(key, side)] = schemas.compile(action[side + '_schema'])
        return validators

    def _validate_methods(self, implementation, manifest):
        for name in ('describe', 'prepare', 'execute'):
            if not callable(getattr(implementation, name, None)):
                raise ManifestError('missing operation method')
        if json_digest(implementation.describe()) != json_digest(manifest):
            raise ManifestError('describe disagrees with manifest')
        for flag, value, method in (('recovery', 'queryable', 'poll'), ('cancellation', 'requestable', 'cancel')):
            declared = any(a['execution'][flag] == value for a in manifest['actions'].values())
            if declared != callable(getattr(implementation, method, None)):
                raise ManifestError('execution capability/method mismatch')
        if manifest.get('sessions'):
            for name in ('prepare_session', 'open_session', 'send', 'receive', 'close_session'):
                if not callable(getattr(implementation, name, None)):
                    raise ManifestError('missing session method')

    def _load_package(self, package, manifest):
        root = package.resolve()
        validators = self._validate_manifest(manifest, root)
        entry = manifest['entrypoint']
        if not re.fullmatch(r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*:[A-Za-z_]\w*', entry):
            raise ManifestError('invalid package entrypoint')
        module_name, class_name = entry.split(':')
        module_path = _inside(root, root.joinpath(*module_name.split('.')).with_suffix('.py'))
        if not module_path.is_file():
            raise ManifestError('entrypoint missing')
        digest = code_digest(root)
        package_name = '_control_plane_plugin_' + uuid4().hex
        spec = importlib.util.spec_from_file_location(package_name, root / '__init__.py', submodule_search_locations=[str(root)])
        if (root / '__init__.py').is_file():
            module = importlib.util.module_from_spec(spec)
            sys.modules[package_name] = module
            spec.loader.exec_module(module)
        else:
            import types
            module = types.ModuleType(package_name)
            module.__path__ = [str(root)]
            sys.modules[package_name] = module
        loaded = importlib.import_module(package_name + '.' + module_name)
        implementation = getattr(loaded, class_name)()
        self._validate_methods(implementation, manifest)
        return LoadedPlugin(manifest, implementation, digest, root, validators)


Registry = PluginRegistry
