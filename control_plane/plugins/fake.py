"""Deterministic trusted Fake plugin for protocol and crash/fault tests."""
from copy import deepcopy
import threading

from .sdk import ExecutionPolicy, ExecutionResult, PreparedCall, SafeError


FAKE_MANIFEST = {
    'manifest_version': 1, 'api_version': '1', 'plugin_key': 'fake',
    'plugin_version': '1.0.0', 'display_name': 'Fake', 'entrypoint': 'plugin:FakePlugin',
    'actions': {'echo': {'display_name': 'Echo', 'input_schema': {'type': 'object'},
        'output_schema': {'type': 'object'}, 'execution': {
            'effect': 'mutating', 'idempotency': 'keyed', 'recovery': 'queryable',
            'cancellation': 'requestable'}}}}


class FakePlugin:
    def __init__(self, *, mode='succeeded', gate=None):
        self.mode, self.gate = mode, gate
        self.calls = []
        self._results = {}
        self._lock = threading.Lock()

    def describe(self):
        return deepcopy(FAKE_MANIFEST)

    def prepare(self, action_key, input, context):
        context.deadline.check()
        refs, target = (), deepcopy(input.get('target', {}))
        if 'storage_key' in input:
            entry = context.storage.get(input['storage_key'])
            refs = (entry.ref,)
            target = deepcopy(entry.value)
        secret_refs = tuple(context.secrets.resolve(ref) for ref in input.get('secret_refs', []))
        return PreparedCall(action_key, deepcopy(input), target, refs, secret_refs,
                            tuple(input.get('conflict_keys', [])),
                            ExecutionPolicy('mutating', 'keyed', 'queryable', 'requestable'))

    def execute(self, prepared_call, context):
        context.deadline.check()
        key = context.invocation_key
        with self._lock:
            if key in self._results:
                return self._results[key]
            self.calls.append(('execute', key, prepared_call.to_dict()))
        if self.gate is not None:
            self.gate.wait()  # Explicit uncooperative Fake for finite-capacity tests.
        if self.mode == 'raise':
            raise RuntimeError('fake vendor exception must not be surfaced')
        if self.mode == 'checkpoint':
            context.report_checkpoint('accepted', {'target_ref': prepared_call.target_ref})
        if self.mode == 'unknown':
            return ExecutionResult('unknown', external_refs=({'key': 'partial', 'reference': prepared_call.target_ref},))
        if self.mode == 'pending_external':
            return ExecutionResult('pending_external', external_execution_ref={'id': key})
        if self.mode == 'failed':
            return ExecutionResult('failed', error=SafeError('fake_failure', 'controlled failure'))
        result = ExecutionResult('succeeded', output={'target': prepared_call.target_ref, 'input': prepared_call.resolved_input})
        with self._lock:
            self._results[key] = result
        return result

    def poll(self, prepared_call, execution_ref, context):
        context.deadline.check()
        self.calls.append(('poll', context.invocation_key, execution_ref))
        return self._results.get(context.invocation_key, ExecutionResult('unknown', external_execution_ref=execution_ref))

    def cancel(self, prepared_call, execution_ref, context):
        from .sdk import CancelResult
        context.deadline.check()
        self.calls.append(('cancel', context.invocation_key, execution_ref))
        return CancelResult('requested')
