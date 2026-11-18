"""Versioned v1 template publication, bounded expressions and business inputs."""
from collections.abc import Mapping
from copy import deepcopy
from functools import lru_cache
from graphlib import CycleError, TopologicalSorter
import re
from uuid import UUID

from jsonschema import Draft202012Validator, SchemaError, ValidationError
from sqlalchemy import text

from .plugins.sdk import AuthorizationDenied, canonical_json, finite_json, json_digest


class TemplateError(ValueError):
    """A template or a business input violates the v1 contract."""


_NAME = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_-]{0,127}\Z')
_MAX_COST = 2**63 - 1
_DIMENSIONS = {'environments', 'vms', 'vcpu', 'memory_mb'}
_ROLES = {'admin', 'teacher', 'student'}
_ARITY = {'multiply': 2, 'add': 2, 'subtract': 2, 'divide': 2, 'length': 1}
_PARAM_TYPES = {'string', 'integer', 'number', 'array', 'object', 'boolean'}
_SCHEMA_FIELDS = {'type', 'enum', 'minLength', 'maxLength', 'minimum', 'maximum',
                  'minItems', 'maxItems', 'uniqueItems', 'items', 'properties',
                  'additionalProperties'}


def _check(condition, message):
    if not condition:
        raise TemplateError(message)


def _fields(obj, required=(), optional=()):
    _check(isinstance(obj, dict) and set(required) <= obj.keys() <= set(required) | set(optional),
           'missing or unsupported template field')


def _name(name):
    _check(isinstance(name, str) and _NAME.fullmatch(name), 'invalid identifier')
    return name


def _map(value):
    _check(isinstance(value, dict), 'expected an object')
    for key in value:
        _name(key)
    return value


def _list(value):
    _check(isinstance(value, list), 'expected an array')
    return value


def _label(value):
    _check(isinstance(value, str) and 0 < len(value.strip()) <= 255, 'invalid label')


def _integer(value, lower, upper):
    _check(type(value) is int and lower <= value <= upper, 'integer outside allowed range')
    return value


def _ref_path(value):
    _check(isinstance(value, str), 'reference must be a path')
    parts = value.split('.')
    _check(len(parts) <= 32, 'reference too deep')
    for part in parts:
        _name(part)
    return parts


def _references(value):
    """Walk only data expressions, never keys or ordinary strings."""
    if isinstance(value, list):
        for child in value:
            yield from _references(child)
    if not isinstance(value, dict):
        return
    if '$ref' in value:
        _fields(value, ['$ref'])
        yield _ref_path(value['$ref'])
    elif '$expr' in value:
        _fields(value, ['$expr'])
        tree = value['$expr']
        _check(isinstance(tree, dict) and len(tree) == 1, 'invalid expression')
        op, operands = next(iter(tree.items()))
        _check(op in _ARITY and len(_list(operands)) == _ARITY[op], 'invalid operator or arity')
        yield from _references(operands)
    else:
        for key, child in value.items():
            _check(not key.startswith('$'), 'unknown expression')
            yield from _references(child)


def resolve(value, context):
    """Resolve finite JSON against explicit namespaces. Missing data fails closed."""
    finite_json(value)
    list(_references(value))
    budget = 1048576

    def walk(node):
        nonlocal budget
        if isinstance(node, list):
            return [walk(child) for child in node]
        if not isinstance(node, dict):
            return node
        if '$ref' in node:
            data = context
            for key in _ref_path(node['$ref']):
                _check(isinstance(data, Mapping) and key in data, 'unavailable reference')
                data = data[key]
            budget -= len(canonical_json(data).encode('utf-8'))
            _check(budget >= 0, 'resolved value exceeds size limit')
            return deepcopy(data)
        if '$expr' in node:
            op, args = next(iter(node['$expr'].items()))
            args = [walk(child) for child in args]
            if op == 'length':
                _check(isinstance(args[0], (str, list, dict)), 'length requires a collection')
                return len(args[0])
            left, right = (_integer(arg, 0, _MAX_COST) for arg in args)
            if op == 'multiply':
                result = left * right
            elif op == 'add':
                result = left + right
            elif op == 'subtract':
                result = left - right
            else:
                _check(right > 0 and left % right == 0, 'division must yield a finite integer')
                result = left // right
            return _integer(result, 0, _MAX_COST)
        return {key: walk(child) for key, child in node.items()}

    result = walk(value)
    finite_json(result)
    return result


def quota_cost(definition, params):
    costs = resolve(definition['quota'], {'params': params})
    _fields(costs, _DIMENSIONS)
    return {key: _integer(value, 0, _MAX_COST) for key, value in costs.items()}


def expand_items(for_each, context):
    if for_each is None:
        return [('', None)]
    values = _list(resolve(for_each['items'], context))
    _check(len(values) <= _integer(for_each['max_items'], 1, 1000), 'expansion exceeds limit')
    seen, items = set(), []
    for value in values:
        key = resolve(for_each['item_key'], {**context, 'item': value})
        _check(isinstance(key, str) and 0 < len(key) <= 255 and key not in seen,
               'expansion requires unique stable string keys')
        seen.add(key)
        items.append((key, value))
    return items


def order_steps(steps):
    by_id, graph = {}, {}
    for step in _list(steps):
        _fields(step, ['id', 'action', 'plugin_instance', 'input', 'timeout_seconds'],
                ['depends_on', 'for_each'])
        key = _name(step['id'])
        _check(key not in by_id, 'duplicate step id')
        by_id[key] = step
        explicit = [_name(dep) for dep in _list(step.get('depends_on', []))]
        _check(len(explicit) == len(set(explicit)), 'duplicate dependency')
        graph[key] = set(explicit)
        for path in _references([step['input'], step.get('for_each')]):
            if path[0] == 'steps':
                _check(len(path) >= 3 and path[2] == 'output', 'expected a confirmed step output')
                graph[key].add(path[1])
    _check(all(deps <= by_id.keys() for deps in graph.values()), 'unknown step dependency')
    try:
        return [by_id[key] for key in TopologicalSorter(
            {key: sorted(deps) for key, deps in graph.items()}).static_order()]
    except CycleError:
        raise TemplateError('cyclic step dependencies') from None


def _param_schema(schema):
    _fields(schema, ['type'], _SCHEMA_FIELDS - {'type'})
    _check(isinstance(schema['type'], str) and schema['type'] in _PARAM_TYPES, 'unknown parameter type')
    allowed = {
        'array': {'minItems', 'maxItems', 'uniqueItems', 'items'},
        'integer': {'minimum', 'maximum'}, 'number': {'minimum', 'maximum'},
        'string': {'minLength', 'maxLength'}, 'boolean': set(),
        'object': {'properties', 'additionalProperties'},
    }[schema['type']]
    _check(schema.keys() <= allowed | {'type', 'enum'}, 'constraint does not match parameter type')
    if 'items' in schema:
        _param_schema(schema['items'])
    if 'properties' in schema:
        for child in _map(schema['properties']).values():
            _param_schema(child)
    if 'additionalProperties' in schema:
        _check(type(schema['additionalProperties']) is bool, 'invalid object property policy')
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError:
        raise TemplateError('invalid parameter schema') from None
    for low, high in (('minimum', 'maximum'), ('minLength', 'maxLength'), ('minItems', 'maxItems')):
        if low in schema and high in schema:
            _check(schema[low] <= schema[high], 'inverted bounds')
    return schema


def _schema_for(spec):
    return {k: v for k, v in spec.items() if k in _SCHEMA_FIELDS}


def _validate_value(schema, value):
    try:
        Draft202012Validator(schema).validate(value)
    except ValidationError:
        raise TemplateError('parameter violates its declared schema') from None


def selector_options(spec, rows):
    """Validate provider candidates and expose just the declared selection fields."""
    finite_json(rows)
    selector = spec['selector']
    seen, options = set(), []
    for row in _list(rows):
        _check(isinstance(row, dict) and selector['value_field'] in row
               and isinstance(row.get(selector['label_field']), str), 'invalid option row')
        value = row[selector['value_field']]
        _validate_value(_schema_for(spec), value)
        encoded = canonical_json(value)
        _check(encoded not in seen, 'duplicate selector option')
        seen.add(encoded)
        if 'fixed' not in spec or encoded == canonical_json(spec['fixed']):
            options.append({'value': value, 'label': row[selector['label_field']]})
    return options


def validate_parameters(specs, supplied, *, selector_values=None):
    """Use selection rows from trusted fixed-view reads, never from user inputs."""
    finite_json(supplied, object_only=True)
    _check(supplied.keys() <= specs.keys(), 'unknown business parameter')
    values = {}
    for key, spec in specs.items():
        if 'fixed' in spec:
            _check(key not in supplied, 'fixed parameter cannot be overridden')
            value = spec['fixed']
        elif key in supplied:
            value = supplied[key]
        elif 'default' in spec:
            value = spec['default']
        else:
            _check(not spec.get('required', False), 'missing required business parameter')
            continue
        _validate_value(_schema_for(spec), value)
        if 'selector' in spec:
            options = selector_options(spec, (selector_values or {}).get(key))
            _check(any(canonical_json(value) == canonical_json(option['value']) for option in options),
                   'selected option unavailable')
        values[key] = deepcopy(value)
    finite_json(values, object_only=True)
    return values


def _validate_specs(specs, lookup):
    for spec in _map(specs).values():
        _fields(spec, ['type'], _SCHEMA_FIELDS | {
            'required', 'default', 'fixed', 'label', 'description', 'selector'})
        schema = _param_schema(_schema_for(spec))
        _check(type(spec.get('required', False)) is bool, 'invalid required flag')
        _check(not ('fixed' in spec and 'default' in spec), 'conflicting fixed value and default')
        for key in ('label', 'description'):
            if key in spec:
                _check(isinstance(spec[key], str), 'invalid presentation text')
        for key in ('fixed', 'default'):
            if key in spec:
                _validate_value(schema, spec[key])
        if 'selector' not in spec:
            continue
        selector = spec['selector']
        _fields(selector, ['plugin_instance', 'action', 'value_field', 'label_field'], ['input'])
        _name(selector['value_field'])
        _name(selector['label_field'])
        plugin, cap = _capability(lookup, selector)
        _check(cap['execution']['effect'] == 'read_only', 'selector must be read-only')
        _check(not list(_references(selector.get('input', {}))), 'selector input must be fixed')
        try:
            plugin.validate_input(selector['action'], selector.get('input', {}))
        except ValidationError:
            raise TemplateError('selector input violates action schema') from None
        out = cap['output_schema']
        if isinstance(out, dict) and 'type' in out:
            _check(out['type'] == 'array', 'selector must return an array')
            row = out.get('items', {})
            if isinstance(row, dict) and row.get('additionalProperties') is False:
                _check({selector['value_field'], selector['label_field']} <= row.get('properties', {}).keys(),
                       'unknown selector field')


def _capability(lookup, spec, *, session=False):
    instance = _name(spec['plugin_instance'])
    key = _name(spec['session_type' if session else 'action'])
    plugin = lookup(instance)
    capabilities = plugin.manifest.get('sessions' if session else 'actions', {})
    _check(key in capabilities, 'missing manifest capability')
    return plugin, capabilities[key]


def _referenced_schema(schema, fields):
    """Reject paths that a closed schema proves impossible; open schemas stay dynamic."""
    for field in fields:
        if not isinstance(schema, dict) or not schema:
            return {}
        if 'type' in schema:
            _check(schema['type'] == 'object', 'reference traverses a non-object')
        properties = schema.get('properties', {})
        _check(field in properties or schema.get('additionalProperties') is not False,
               'reference names an undeclared property')
        schema = properties.get(field, schema.get('additionalProperties', {}))
    return schema


def _validate_cost(node, params, *, collection=False):
    if isinstance(node, dict) and '$ref' in node:
        path = _ref_path(node['$ref'])
        _validate_refs(node, {'params': params})
        schema = _referenced_schema(params[path[1]], path[2:])
        if isinstance(schema, dict) and 'type' in schema:
            kinds = {'string', 'array', 'object'} if collection else {'integer'}
            _check(schema['type'] in kinds, 'quota parameter type mismatch')
        return
    if isinstance(node, dict) and '$expr' in node:
        _check(not collection, 'length requires a collection')
        operator, operands = next(iter(node['$expr'].items()))
        for operand in operands:
            _validate_cost(operand, params, collection=operator == 'length')
        if operator == 'divide' and not list(_references(operands[1])):
            _integer(resolve(operands[1], {}), 1, _MAX_COST)
        if not list(_references(node)):
            _integer(resolve(node, {}), 0, _MAX_COST)
    elif collection:
        _check(isinstance(node, (list, dict, str)), 'length requires a collection')
    else:
        _integer(node, 0, _MAX_COST)


def _validate_refs(value, scope):
    for path in _references(value):
        root = path[0]
        _check(root in scope, 'reference outside this context')
        if root in ('params', 'action_params', 'steps', 'environment'):
            _check(len(path) > 1 and path[1] in scope[root], 'unknown reference')
        if root in ('params', 'action_params'):
            _referenced_schema(scope[root][path[1]], path[2:])
        if root == 'steps':
            _check(len(path) >= 3 and path[2] == 'output', 'expected a confirmed step output')
            _referenced_schema(scope[root][path[1]], path[3:])
        if root == 'resource':
            _check(len(path) > 1 and path[1] in ('id', 'data', 'target_ref'), 'invalid resource reference')


def _expand_scope(block, scope):
    if 'for_each' not in block:
        return scope
    loop = block['for_each']
    _fields(loop, ['items', 'item_key', 'max_items'])
    _integer(loop['max_items'], 1, 1000)
    _validate_refs(loop['items'], scope)
    if not list(_references(loop['items'])):
        _check(len(_list(resolve(loop['items'], {}))) <= loop['max_items'], 'expansion exceeds limit')
    scope = {**scope, 'item': None}
    _validate_refs(loop['item_key'], scope)
    return scope


def _validate_input_parts(plugin, key, value, schema):
    """Check known fields/literals now; validate the full resolved input again at dispatch."""
    if not isinstance(schema, dict) or isinstance(value, dict) and '$ref' in value:
        return
    if not list(_references(value)):
        try:
            plugin.validators[(key, 'input')].evolve(schema=schema).validate(resolve(value, {}))
        except ValidationError:
            raise TemplateError('fixed input violates action schema') from None
    elif schema.get('type') == 'object':
        _check(isinstance(value, dict), 'action input must be an object')
        properties = schema.get('properties', {})
        _check(set(schema.get('required', [])) <= value.keys(), 'missing required action input')
        if schema.get('additionalProperties') is False:
            _check(value.keys() <= properties.keys(), 'unknown action input')
        for field in value.keys() & properties.keys():
            _validate_input_parts(plugin, key, value[field], properties[field])
    elif schema.get('type') == 'array' and isinstance(value, list):
        for child in value:
            _validate_input_parts(plugin, key, child, schema.get('items'))


def _flow(steps, scope, lookup):
    ordered = order_steps(steps)
    done = {}
    max_steps = 0
    for step in ordered:
        plugin, cap = _capability(lookup, step)
        _integer(step['timeout_seconds'], 1, 86400)
        active = _expand_scope(step, {**scope, 'steps': done})
        max_steps += step.get('for_each', {}).get('max_items', 1)
        _check(max_steps <= 1000, 'workflow expansion exceeds limit')
        inputs = step['input']
        _validate_refs(inputs, active)
        schema = cap['input_schema']
        _validate_input_parts(plugin, step['action'], inputs, schema)
        for field in cap.get('template_fixed_inputs', []):
            _check(isinstance(inputs, dict) and field in inputs and not list(_references(inputs[field])),
                   'capability requires administrator-fixed input')
        # An expanded step exposes a stable-key map outside its item context.
        done[step['id']] = {} if 'for_each' in step else cap['output_schema']
    return done


def _roles(roles):
    roles = [_name(role) for role in _list(roles)]
    _check(roles and len(roles) == len(set(roles)) and set(roles) <= _ROLES, 'invalid roles')


def _actions(actions, scope, lookup):
    for key, spec in _map(actions).items():
        _check(key not in {'create', 'delete', 'cleanup', 'assign', 'plugin_management'},
               'reserved lifecycle or administration action')
        _fields(spec, ['label', 'roles', 'parameters', 'steps'], ['state_mapping'])
        _label(spec['label'])
        _roles(spec['roles'])
        _validate_specs(spec['parameters'], lookup)
        local = {**scope, 'action_params': spec['parameters']}
        _check(spec['steps'], 'action requires steps')
        done = _flow(spec['steps'], local, lookup)
        if 'state_mapping' in spec:
            mapping = spec['state_mapping']
            _fields(mapping, ['value', 'ttl_seconds'])
            _integer(mapping['ttl_seconds'], 1, 86400)
            _validate_refs(mapping['value'], {**local, 'steps': done})


def _conditions(spec, scope):
    for condition in _list(spec.get('conditions', [])):
        if isinstance(condition, dict) and 'equals' in condition:
            _fields(condition, ['equals'])
            _check(len(_list(condition['equals'])) == 2, 'equals requires two operands')
            _validate_refs(condition['equals'], scope)
        else:
            _check(isinstance(condition, bool) or isinstance(condition, dict) and '$ref' in condition,
                   'condition must resolve to a boolean')
            _validate_refs(condition, scope)


def _access(access, scope, lookup):
    for spec in _map(access).values():
        _fields(spec, ['roles', 'plugin_instance', 'session_type', 'target_ref', 'credential_ref'],
                ['label', 'input'])
        _roles(spec['roles'])
        plugin, cap = _capability(lookup, spec, session=True)
        _validate_refs(spec['target_ref'], scope)
        cred = spec['credential_ref']
        _fields(cred, ['$ref'])
        path = _ref_path(cred['$ref'])
        _check(path[:2] in (['resource', 'data'], ['environment', 'create_results']),
               'session credential must come from confirmed environment products')
        _validate_refs(cred, scope)
        inputs = spec.get('input', {})
        _validate_refs(inputs, scope)
        _validate_input_parts(plugin, spec['session_type'], inputs, cap['input_schema'])


def resolve_access(access, entry_key, context, role, lookup):
    """Resolve only administrator-declared template entries, on a confirmed environment."""
    entry = access.get(entry_key)
    if entry is None or role not in entry['roles']:
        raise AuthorizationDenied()
    plugin, _ = _capability(lookup, entry, session=True)
    inputs = resolve(entry.get('input', {}), context)
    try:
        plugin.validate_input(entry['session_type'], inputs)
    except ValidationError:
        raise TemplateError('session input violates declared schema') from None
    ref = resolve(entry['credential_ref'], context)
    _fields(ref, ['secret_id', 'version_id'])
    for key in ref:
        _check(isinstance(ref[key], str), 'invalid credential reference')
        try:
            UUID(ref[key])
        except ValueError:
            raise TemplateError('invalid credential reference') from None
    return {'plugin_instance': entry['plugin_instance'], 'session_type': entry['session_type'],
            'target_ref': resolve(entry['target_ref'], context), 'credential_ref': ref, 'input': inputs}


def validate_template(definition, lookup):
    finite_json(definition, object_only=True)
    # All capabilities in one publication come from the same pinned runtime and UoW.
    lookup = lru_cache(maxsize=1000)(lookup)
    _fields(definition, ['schema_version', 'metadata', 'parameters', 'quota', 'create', 'resources',
                         'actions', 'cleanup', 'readiness', 'access'], ['revocation_action'])
    _integer(definition['schema_version'], 1, 1)
    metadata = definition['metadata']
    _fields(metadata, ['name'], ['description', 'tags'])
    _label(metadata['name'])
    _check(isinstance(metadata.get('description', ''), str), 'invalid description')
    for tag in _list(metadata.get('tags', [])):
        _label(tag)
    params = definition['parameters']
    _validate_specs(params, lookup)
    quota = definition['quota']
    _fields(quota, _DIMENSIONS)
    for amount in quota.values():
        _validate_refs(amount, {'params': params})
        _validate_cost(amount, params)
    scope = {'params': params, 'environment': {'id', 'name', 'create_results'}}
    _fields(definition['create'], ['steps'])
    done = _flow(definition['create']['steps'], scope, lookup)
    create_scope = {**scope, 'steps': done}
    slots = set()
    max_resources = 0
    resources = _list(definition['resources'])
    _check(done or not resources, 'resources require a producing create step')
    for resource in resources:
        _fields(resource, ['key', 'name', 'type_label', 'data'],
                ['display', 'for_each', 'actions', 'access', 'target_ref'])
        slot = _name(resource['key'])
        _check(slot not in slots, 'duplicate resource slot')
        slots.add(slot)
        data_scope = _expand_scope(resource, create_scope)
        max_resources += resource.get('for_each', {}).get('max_items', 1)
        _check(max_resources <= 1000, 'resource expansion exceeds limit')
        for field in ('name', 'type_label'):
            if not list(_references(resource[field])):
                _label(resource[field])
        for field in ('data', 'display'):
            if field in resource:
                _check(isinstance(resource[field], dict), 'resource data/display must be objects')
        for key in ('name', 'type_label', 'data', 'display', 'target_ref'):
            _validate_refs(resource.get(key), data_scope)
        _actions(resource.get('actions', {}), {**scope, 'resource': None}, lookup)
        _access(resource.get('access', {}), {**scope, 'resource': None}, lookup)
    _actions(definition['actions'], scope, lookup)
    if 'revocation_action' in definition:
        key = _name(definition['revocation_action'])
        action = definition['actions'].get(key)
        _check(action and set(action['roles']) <= {'admin', 'teacher'},
               'revocation must use an administrative environment action')
        # Automatic dispatch submits an empty parameter object. Check every
        # consumed path against exactly the values available on that path.
        defaults = {name: spec.get('fixed', spec.get('default'))
                    for name, spec in action['parameters'].items() if 'fixed' in spec or 'default' in spec}
        _check(all(not spec.get('required') or name in defaults for name, spec in action['parameters'].items()),
               'revocation must run without user inputs')
        for path in _references([action['steps'], action.get('state_mapping')]):
            if path[0] == 'action_params':
                resolve({'$ref': '.'.join(path)}, {'action_params': defaults})
    _access(definition['access'], scope, lookup)
    ready = definition['readiness']
    _fields(ready, ['require_steps'], ['require_resources', 'conditions', 'credential_confirmation'])
    _check(all(_name(k) in done for k in _list(ready['require_steps'])), 'unknown readiness step')
    _check(all(_name(k) in slots for k in _list(ready.get('require_resources', []))), 'unknown readiness resource')
    _conditions(ready, create_scope)
    if 'credential_confirmation' in ready:
        confirm = ready['credential_confirmation']
        _fields(confirm, ['step', 'credential'])
        _check(_name(confirm['step']) in done, 'unknown credential confirmation step')
        _fields(confirm['credential'], ['$ref'])
        _validate_refs(confirm['credential'], {'params': params, 'steps': done})
    cleanup = definition['cleanup']
    if cleanup is not None:
        _fields(cleanup, ['steps', 'completion'])
        cleanup_scope = {**scope, 'evidence': None}
        cleanup_steps = _flow(cleanup['steps'], cleanup_scope, lookup)
        completion = cleanup['completion']
        if not cleanup_steps:
            _check(completion == {'no_external_cleanup_required': True}
                   and completion['no_external_cleanup_required'] is True, 'empty cleanup requires explicit completion')
        else:
            _fields(completion, ['require_steps'], ['conditions'])
            required = _list(completion['require_steps'])
            _check(required and all(_name(k) in cleanup_steps for k in required), 'invalid cleanup completion')
            _conditions(completion, {**cleanup_scope, 'steps': cleanup_steps})
    return definition


def load_version(uow, version_id, *, for_create):
    row = uow.execute(text("""
        SELECT v.definition, v.status, t.deleted_at FROM control_plane.template_versions v
          JOIN control_plane.templates t ON t.id=v.template_id
         WHERE v.id=:id FOR SHARE OF v,t
    """), {'id': version_id}).first()
    _check(row and row.status in ('published', 'disabled'), 'published template version unavailable')
    if for_create:
        _check(row.status == 'published' and row.deleted_at is None, 'template unavailable for new environments')
    return row.definition


class TemplateService:
    def __init__(self, runtime, lookup=None, *, registry=None, safe_json=finite_json):
        _check((lookup is None) != (registry is None), 'a trusted capability resolver is required')
        self.runtime, self.lookup, self.registry = runtime, lookup, registry
        self.safe_json = safe_json

    @staticmethod
    def _require_admin(uow, actor):
        if not uow.scalar(text("""
            SELECT TRUE FROM control_plane.users WHERE id=:actor
              AND active AND deleted_at IS NULL AND role='admin' FOR SHARE
        """), {'actor': actor}):
            raise AuthorizationDenied()

    @staticmethod
    def _audit(uow, actor, version, action):
        uow.execute(text("""
            INSERT INTO control_plane.audit_events(actor_id,template_version_id,action,result)
            VALUES (:actor,:version,:action,'succeeded')
        """), {'actor': actor, 'version': version, 'action': action})

    def create_draft(self, actor_id, definition, *, template_id=None):
        definition = self.safe_json(definition)
        _check(isinstance(definition, dict), 'draft must be an object')
        with self.runtime.fenced_transaction() as uow:
            self._require_admin(uow, actor_id)
            if template_id is None:
                metadata = definition.get('metadata')
                _check(isinstance(metadata, dict), 'draft metadata required')
                title = metadata.get('name')
                _label(title)
                template_id = uow.scalar(text("""
                    INSERT INTO control_plane.templates(name,created_by) VALUES (:name,:actor) RETURNING id
                """), {'name': title, 'actor': actor_id})
            else:
                _check(uow.scalar(text("""
                    SELECT id FROM control_plane.templates WHERE id=:id AND deleted_at IS NULL FOR UPDATE
                """), {'id': template_id}), 'template unavailable')
            version = uow.scalar(text("""
                INSERT INTO control_plane.template_versions(template_id,version,definition,content_digest,created_by)
                SELECT :template,COALESCE(MAX(version),0)+1,CAST(:definition AS jsonb),:digest,:actor
                  FROM control_plane.template_versions WHERE template_id=:template RETURNING id
            """), {'template': template_id, 'actor': actor_id, 'definition': canonical_json(definition),
                   'digest': json_digest(definition)})
            self._audit(uow, actor_id, version, 'template.draft.create')
            return template_id, version

    def edit_draft(self, actor_id, version_id, definition):
        definition = self.safe_json(definition)
        _check(isinstance(definition, dict), 'draft must be an object')
        with self.runtime.fenced_transaction() as uow:
            self._require_admin(uow, actor_id)
            updated = uow.scalar(text("""
                UPDATE control_plane.template_versions SET definition=CAST(:definition AS jsonb),content_digest=:digest
                 WHERE id=:id AND status='draft' RETURNING id
            """), {'id': version_id, 'definition': canonical_json(definition), 'digest': json_digest(definition)})
            _check(updated, 'editable draft unavailable')
            self._audit(uow, actor_id, version_id, 'template.draft.edit')

    def publish(self, actor_id, version_id):
        with self.runtime.fenced_transaction() as uow:
            self._require_admin(uow, actor_id)
            definition = uow.scalar(text("""
                SELECT definition FROM control_plane.template_versions WHERE id=:id AND status='draft' FOR UPDATE
            """), {'id': version_id})
            _check(definition is not None, 'editable draft unavailable')
            if self.lookup is None:
                from .business import instance_binding

                def lookup(alias):
                    _, key = instance_binding(uow, alias)
                    return self.registry.get(key)
            else:
                lookup = self.lookup
            validate_template(self.safe_json(definition), lookup)
            uow.execute(text("""
                UPDATE control_plane.template_versions SET status='published',published_by=:actor,
                       published_at=clock_timestamp() WHERE id=:id
            """), {'actor': actor_id, 'id': version_id})
            self._audit(uow, actor_id, version_id, 'template.publish')

    def disable(self, actor_id, version_id):
        with self.runtime.fenced_transaction() as uow:
            self._require_admin(uow, actor_id)
            updated = uow.scalar(text("""
                UPDATE control_plane.template_versions SET status='disabled' WHERE id=:id AND status='published'
                RETURNING id
            """), {'id': version_id})
            _check(updated, 'published version unavailable')
            self._audit(uow, actor_id, version_id, 'template.disable')
