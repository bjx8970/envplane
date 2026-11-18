"""Selector admission uses the published filter and exposes only declared fields."""
from contextlib import nullcontext
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from control_plane.plugins.capacity import CapacitySupervisor
from control_plane.plugins.sdk import ExecutionResult, PreparedCall
from control_plane.selectors import SelectorService


class SelectorTests(unittest.TestCase):
    def test_published_filter_reaches_both_plugin_phases(self):
        plugin = Mock()
        plugin.manifest = {'actions': {'options': {'execution': {'effect': 'read_only'}}}}
        plugin.implementation.prepare.side_effect = lambda action, inputs, ctx: PreparedCall(action, inputs)
        rows = [{'id': 12, 'name': 'Lab', 'internal_note': 'inventory metadata'}]
        plugin.implementation.execute.return_value = ExecutionResult('succeeded', output=rows)
        registry = Mock()
        registry.get.return_value = plugin
        runtime = Mock()
        runtime.fenced_transaction.return_value = nullcontext(Mock())
        config = Mock()
        config.get_in.return_value = SimpleNamespace(configuration={'data': {}}, revision=2)
        storage = Mock()
        storage.snapshot_in.return_value = SimpleNamespace(id='fixed', namespace_revision=5)
        capacity = CapacitySupervisor()
        capacity.start()
        self.addCleanup(capacity.stop)
        service = SelectorService(runtime, config, storage, registry, capacity)
        fixed = {'course': 'lab'}
        spec = {'selector': {'plugin_instance': 'host', 'action': 'options', 'value_field': 'id',
                             'label_field': 'name', 'input': fixed}}
        candidates, revisions = service.prepare({'target': spec}, {'host': 'instance'})
        plugin.validate_input.assert_called_once_with('options', fixed)
        self.assertEqual(plugin.implementation.execute.call_args.args[0].resolved_input, fixed)
        self.assertEqual(candidates, {'target': [{'id': 12, 'name': 'Lab'}]})
        self.assertEqual(revisions, {'host': (2, 5)})
