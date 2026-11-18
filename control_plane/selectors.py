"""Resolve template selectors against a fixed configuration and Storage view.

The caller authorizes access to the template before reading candidates and compares
the returned revisions with the captures made in the Job's admission transaction.
"""
from functools import partial
from types import SimpleNamespace

from sqlalchemy import text

from .plugins.sdk import Deadline, ReferenceUnavailable, canonical_json, finite_json


class _SnapshotReader:
    def __init__(self, bound, snapshot_id):
        self._bound = bound
        self._snapshot_id = snapshot_id

    def get(self, key):
        return self._bound.get(key, snapshot_id=self._snapshot_id)

    def list(self, prefix=None, cursor=None, limit=100):
        return self._bound.list(prefix, cursor, limit, snapshot_id=self._snapshot_id)


class SelectorService:
    def __init__(self, runtime, configuration, storage, registry, capacity):
        self.runtime = runtime
        self.configuration = configuration
        self.storage = storage
        self.registry = registry
        self.capacity = capacity

    def prepare(self, specs, instance_ids):
        selectors = {name: spec['selector'] for name, spec in specs.items() if 'selector' in spec}
        if not selectors:
            return {}, {}
        finite_json(selectors)
        views, versions = {}, {}
        with self.runtime.fenced_transaction() as uow:
            for alias in sorted({selector['plugin_instance'] for selector in selectors.values()}):
                identity = instance_ids[alias]
                snapshot = self.storage.snapshot_in(uow, identity)
                config = self.configuration.get_in(uow, identity)
                key = uow.scalar(text("SELECT plugin_key FROM control_plane.plugin_instances WHERE id=:id"),
                                 {'id': identity})
                views[alias] = (self.registry.get(key), config.configuration['data'],
                                _SnapshotReader(self.storage.bind(identity), snapshot.id))
                versions[alias] = (config.revision, snapshot.namespace_revision)

        values = {}
        deadline = Deadline.after(10)
        for name, spec in selectors.items():
            alias, action = spec['plugin_instance'], spec['action']
            plugin, config, reader = views[alias]
            context = SimpleNamespace(plugin_instance_id=str(instance_ids[alias]), deadline=deadline,
                                      configuration=config, config=config, storage=reader)
            read_options = partial(self._options, plugin, action, spec.get('input', {}), context)
            handle = self.capacity.submit(instance_ids[alias], read_options, deadline_at=deadline.expires_at)
            rows = handle.result(timeout=deadline.check())
            value_field, label_field = spec['value_field'], spec['label_field']
            options = []
            seen = set()
            for row in rows:
                if not isinstance(row, dict) or value_field not in row or not isinstance(row.get(label_field), str):
                    raise ValueError('selector returned an invalid candidate')
                identity = canonical_json(row[value_field])
                if identity in seen:
                    raise ValueError('selector returned duplicate values')
                seen.add(identity)
                options.append({value_field: row[value_field], label_field: row[label_field]})
            values[name] = options
            finite_json(values)
        return values, versions

    @staticmethod
    def _options(plugin, action, inputs, context):
        capability = plugin.manifest['actions'].get(action, {})
        if capability.get('execution', {}).get('effect') != 'read_only':
            raise ValueError('selector requires a read-only action')
        context.deadline.check()
        plugin.validate_input(action, inputs)
        prepared = plugin.implementation.prepare(action, inputs, context)
        if prepared.action_key != action or prepared.secret_refs:
            raise ValueError('invalid selector preparation')
        plugin.validate_prepared(prepared)
        context.deadline.check()
        result = plugin.implementation.execute(prepared, context)
        context.deadline.check()
        if result.outcome != 'succeeded' or result.protocol_error:
            raise ReferenceUnavailable('selector did not return confirmed candidates')
        plugin.validate_output(action, result.output)
        if not isinstance(result.output, list) or len(result.output) > 1000:
            raise ValueError('selector must return a bounded candidate list')
        return result.output
