"""A nonblocking tick driver for an explicitly started single-process service.

No thread/connection starts on import. PostgreSQL contains recovery facts; this
small in-memory map contains only *live* call handles and never authorizes replay.
The service calls tick periodically even when NOTIFY is lost.
"""
from dataclasses import dataclass
from time import monotonic
from uuid import uuid4

from ..plugins.sdk import Deadline, PreparedCall, ExecutionResult, CancelResult, PluginError
from .adapters import UNAVAILABLE, AdapterUnavailable
from .repository import JobLeaseLost, ExecutionConflict, InvalidTransition


class DriverDiagnostic(RuntimeError):
    """Internal marker for a job-scoped failure already persisted as blocked."""


# Job-scoped failures must never terminate the coordinator. Anything else (DB
# connectivity, coordinator leadership) is a global fault and must still surface.
JOB_FAULTS = (ExecutionConflict, InvalidTransition, AdapterUnavailable, PluginError,
              ValueError, KeyError, DriverDiagnostic)


@dataclass(frozen=True)
class DriverSettings:
    lease_seconds: float = 30
    heartbeat_seconds: float = 5
    prepare_seconds: float = 10
    execute_seconds: float = 30
    poll_seconds: float = 10
    cancel_seconds: float = 10
    poll_interval_seconds: float = 1
    recovery_interval_seconds: float = 5
    max_jobs: int = 16
    scan_limit: int = 32
    max_cancel_attempts: int = 2

    def __post_init__(self):
        from .repository import _seconds
        for name in ("lease_seconds", "heartbeat_seconds", "prepare_seconds", "execute_seconds",
                     "poll_seconds", "cancel_seconds", "poll_interval_seconds", "recovery_interval_seconds"):
            _seconds(getattr(self, name))
        if isinstance(self.max_cancel_attempts, bool) or not isinstance(self.max_cancel_attempts, int) \
                or not 1 <= self.max_cancel_attempts <= 10:
            raise ValueError("cancel retry attempts must be a small bounded integer")
        if self.heartbeat_seconds * 2 >= self.lease_seconds:
            raise ValueError("heartbeat must fit job lease")
        if not 1 <= self.max_jobs <= 1000 or not 1 <= self.scan_limit <= 1000:
            raise ValueError("bounded job and scan limits required")


class ExecutionDriver:
    def __init__(self, repository, capacity, registry, context_builder, *, planner=UNAVAILABLE,
                 projector=UNAVAILABLE, applicator=UNAVAILABLE, settings=None, owner=None):
        self.repository, self.capacity, self.registry = repository, capacity, registry
        self.context_builder = context_builder
        # Pin validation and secret leak/provenance checks are core capabilities,
        # never plugin-supplied functions. Fake builders live only in tests.
        repository.reference_validator = context_builder.validate_prepared_in
        repository.safe_json = context_builder.safe_json
        repository.source_publisher = context_builder.publish_from_source_in
        self.planner, self.projector, self.applicator = planner, projector, applicator
        self.settings = settings or DriverSettings()
        self.owner = owner or "driver:" + str(uuid4())
        self._leases = {}
        self._calls = {}
        self._last_heartbeat = 0
        self._last_scan = 0
        self._next_poll = {}
        self._accepting = False

    def start(self):
        if self._accepting:
            raise RuntimeError("execution driver already started")
        self._accepting = True
        self._last_scan = self._last_heartbeat = 0

    def stop(self):
        # capacity.stop handles bounded grace; this method never claims a Python
        # thread has stopped merely because its future was abandoned.
        self._accepting = False

    def adopt(self, lease):
        """Service may explicitly hand over a same-coordinator recovery lease."""
        if len(self._leases) >= self.settings.max_jobs:
            raise ExecutionConflict("driver job capacity exhausted")
        self._leases[str(lease.job_id)] = lease

    def tick(self):
        self._harvest()
        if not self._accepting:
            return
        now = monotonic()
        if now - self._last_heartbeat >= self.settings.heartbeat_seconds:
            for key, lease in list(self._leases.items()):
                try:
                    self.repository.heartbeat(lease, self.settings.lease_seconds)
                except JobLeaseLost:
                    self._leases.pop(key, None)
            self._last_heartbeat = now
        if now - self._last_scan >= self.settings.recovery_interval_seconds:
            # No recovery plugin code runs in the scan or ordinary pool.
            room = self.settings.max_jobs - len(self._leases)
            if room > 0:
                for lease in self.repository.recover_expired(self.owner, self.settings.lease_seconds,
                                                            limit=min(room, self.settings.scan_limit)):
                    self._leases[str(lease.job_id)] = lease
            self._last_scan = now
        if len(self._leases) < self.settings.max_jobs:
            try:
                self.capacity.check_admission()
                eligible = []
                from ..plugins.capacity import CapacityRejected
                for instance in self.repository.candidate_instances():
                    try:
                        self.capacity.check_admission(str(instance))
                        eligible.append(instance)
                    except CapacityRejected:
                        pass  # Saturated-instance jobs remain durably queued.
                lease = self.repository.claim(self.owner, self.settings.lease_seconds, instance_ids=eligible)
                if lease:
                    self._leases[str(lease.job_id)] = lease
            except Exception as exc:
                # Capacity rejection is an expected bounded refusal, not a DB or
                # leadership error. Never hide an arbitrary persistence failure.
                from ..plugins.capacity import CapacityRejected
                if not isinstance(exc, CapacityRejected):
                    raise
        for key, lease in list(self._leases.items()):
            try:
                self._advance(lease)
            except JobLeaseLost:
                self._leases.pop(key, None)
            except JOB_FAULTS as exc:
                self._isolate(lease, exc)

    def _isolate(self, lease, exc):
        """Persist a job-scoped failure as blocked and never re-raise it.

        Repeated blocking is not an error: a job that is already blocked (or
        whose lease/group has moved on) is simply dropped from this worker.
        Global faults are re-raised by the caller's exception filter, not here.
        """
        try:
            self.repository.block_job(lease)
        except (JobLeaseLost, ExecutionConflict, InvalidTransition):
            pass  # Already blocked/terminal, or no longer authoritative.
        except Exception as block_error:  # noqa: BLE001 - classified by caller
            if isinstance(block_error, JOB_FAULTS):
                pass
            else:
                raise
        finally:
            self._leases.pop(str(lease.job_id), None)
        return exc

    def _cancel_retry_exhausted(self, operation_id):
        """Bounded cancel retries; the count comes from durable call intents."""
        return self.repository.method_call_count(operation_id, "cancel") >= self.settings.max_cancel_attempts

    def _binding(self, lease, instance_id):
        return self.repository.binding(lease, instance_id)

    def _loaded(self, binding):
        loaded = self.registry.get(binding["plugin_key"])
        if (loaded.plugin_version, loaded.code_digest) != (binding["plugin_version"], binding["code_digest"]):
            raise ExecutionConflict("pinned plugin code is unavailable")
        return loaded

    def _context(self, lease, step, instance_id, deadline, *, operation=None, attempt=None, prepared=None):
        def report(kind):
            if attempt is None:
                return None
            return lambda key, data: self.repository.report(lease, attempt.id, kind, key, data)
        return self.context_builder.build(job_id=lease.job_id, plugin_instance_id=instance_id,
            step_instance_id=step["id"], operation_id=operation["id"] if operation else None,
            invocation_key=operation["invocation_key"] if operation else str(step["id"]) + ":" + str(step["attempt"]),
            lease_token=str(lease.token), deadline=deadline, prepared=prepared,
            report_external_ref=report("external_ref"), report_checkpoint=report("checkpoint"),
            cancellation=lambda: self.repository.is_cancel_requested(lease.job_id))

    def _advance(self, lease):
        key = str(lease.job_id)
        live = [c for c in self._calls.values() if str(c["lease"].job_id) == key]
        if live:
            return
        job, steps, operations = self.repository.view(lease)
        if job["cancel_requested_at"] is not None and not any(o["dispatch_intent_at"] for o in operations):
            self.repository.cancel_undispatched(lease)
            self._leases.pop(key, None)
            return
        current = next((op for op in operations if op["state"] in ("prepared", "pending_external", "unknown", "running")), None)
        if current:
            step = next(s for s in steps if s["id"] == current["step_id"])
            if current["protocol_error"]:
                # Output protocol failure is only recoverable by explicit local
                # correction; it never becomes a fresh external execution.
                self._leases.pop(key, None)
                return
            prepared = PreparedCall.from_dict(current["prepared_call"])
            if current["state"] == "unknown":
                evidence = self.repository.saved_success(lease, current["id"])
                if evidence is not None:
                    self.repository.replay_result(lease, evidence, projector=self.projector, applicator=self.applicator)
                    return
            # A cancellation attempt is only useful before its outcome is known.
            # `requested`/`too_late` mean the request was already delivered (or
            # arrived too late) and `unsupported` means the plugin declared it
            # cannot cancel this call: repeating it never observes the remote
            # task, so the original task must be polled instead. `unknown` may be
            # retried, but only a bounded number of times before polling wins.
            cancellation_result = current.get("cancellation_result")
            cancel_attempted = self.repository.latest_call(current["id"], "cancel") is not None
            recovery_possible = (current["state"] in ("pending_external", "unknown")
                                 and prepared.execution_policy.recovery == "queryable")
            if job["cancel_requested_at"] is not None and prepared.execution_policy.cancellation == "requestable":
                if cancellation_result is None and not cancel_attempted:
                    method = "cancel"
                elif cancellation_result == "unknown" and not self._cancel_retry_exhausted(current["id"]):
                    method = "cancel"
                elif recovery_possible:
                    method = "poll"
                else:
                    method = None
            elif current["state"] == "prepared":
                method = "execute"
            elif recovery_possible:
                method = "poll"
            elif current["state"] == "unknown" and (prepared.execution_policy.effect == "read_only" or prepared.execution_policy.idempotency == "keyed"):
                method = "execute"
            else:
                method = None
            if method is None:
                # No safe progress path exists. Persist the block first: leaving
                # the fact in running/waiting_external would be re-claimed after
                # lease expiry and silently dropped again. A recovery lease has a
                # new token, so the historical-call fencing cannot apply; use the
                # current-lease, operation-scoped block instead.
                self.repository.block_operation(lease, current["id"], "no_safe_recovery_path")
                self._leases.pop(key, None)
                return
            if method == "execute" and current["state"] == "unknown" and job["available_at"] > job["database_now"]:
                return  # Persisted retry backoff, not an in-memory retry timer.
            if monotonic() < self._next_poll.get(str(current["id"]), 0):
                return
            self._submit_operation(lease, step, current, prepared, method)
            return
        outputs = {s["step_path"] + ":" + s["item_key"]: s["output"] for s in steps if s["state"] == "succeeded"}
        planned = self.planner.plan(job["execution_snapshot"], outputs)
        if planned:
            self.repository.add_steps(lease, planned)
            job, steps, operations = self.repository.view(lease)
        pending = next((s for s in steps if s["state"] == "pending" and
                        all(any(t["step_path"] == dep and t["state"] == "succeeded" for t in steps)
                            for dep in s["input"].get("depends_on", []))), None)
        if pending:
            self._submit_prepare(lease, pending)
        elif not steps or all(s["state"] in ("succeeded", "skipped") for s in steps):
            # Readiness for zero-step flows must be an explicit business policy.
            self._leases.pop(key, None)
            raise AdapterUnavailable("workflow completion requires explicit lifecycle adapter")

    def _submit_prepare(self, lease, step):
        args = step["input"]
        instance_id, action_key = args["plugin_instance_id"], args["action_key"]
        binding = self._binding(lease, instance_id)
        loaded = self._loaded(binding)
        loaded.validate_input(action_key, args.get("input", {}))
        deadline = Deadline.from_at(self.repository.start_prepare(lease, step["id"], self.settings.prepare_seconds))
        if deadline.expired:
            self.repository.prepare_failed(lease, step["id"], code="prepare_timeout")
            return
        context = self._context(lease, step, instance_id, deadline)
        def prepare():
            deadline.check()
            prepared = loaded.implementation.prepare(action_key, args.get("input", {}), context)
            if not isinstance(prepared, PreparedCall) or prepared.action_key != action_key:
                raise ValueError("invalid prepared call")
            loaded.validate_prepared(prepared)
            self.context_builder.validate_prepared(lease.job_id, instance_id, prepared, step_instance_id=step["id"])
            deadline.check()
            return prepared
        call_id = uuid4()
        handle = self.capacity.submit(str(instance_id), prepare, deadline_at=deadline.expires_at, call_id=call_id)
        self._calls[str(call_id)] = {"handle": handle, "lease": lease, "step": step,
            "instance_id": instance_id, "stage": "prepare", "deadline": deadline, "timed_out": False}

    def _submit_operation(self, lease, step, operation, prepared, method):
        instance_id = operation["plugin_instance_id"]
        loaded = self._loaded(self._binding(lease, instance_id))
        self.context_builder.validate_prepared(lease.job_id, instance_id, prepared, step_instance_id=step["id"])
        seconds = getattr(self.settings, method + "_seconds")
        previous = self.repository.latest_call(operation["id"], method)
        retry = previous["id"] if method == "execute" and operation["state"] == "unknown" and previous else None
        attempt = self.repository.begin_call(lease, operation["id"], method, seconds, retry_of_call_id=retry)
        deadline = Deadline.from_at(attempt.deadline_at)
        context = self._context(lease, step, instance_id, deadline, operation=operation, attempt=attempt, prepared=prepared)
        def invoke():
            deadline.check()
            if method == "execute":
                result = loaded.implementation.execute(prepared, context)
            else:
                result = getattr(loaded.implementation, method)(prepared, operation["external_execution_ref"], context)
            if method == "cancel":
                if not isinstance(result, CancelResult):
                    raise ValueError("invalid cancel protocol")
                return result
            if not isinstance(result, ExecutionResult):
                return ExecutionResult("unknown", protocol_error={"code": "protocol_error", "message": "invalid execution result"})
            # Preserve the bounded safe original result when output schema fails.
            result.to_dict()
            if result.outcome == "succeeded":
                try:
                    loaded.validate_output(prepared.action_key, result.output)
                except Exception:
                    return ExecutionResult("succeeded", output=result.output,
                        external_execution_ref=result.external_execution_ref, external_refs=result.external_refs,
                        checkpoints=result.checkpoints, error=result.error,
                        protocol_error={"code": "protocol_error", "message": "output schema validation failed"})
            return result
        # Capacity rejection after a committed dispatch intent is conservatively
        # unknown, never "unsent"; blocking it must not surface as a global fault.
        try:
            handle = self.capacity.submit(str(instance_id), invoke, deadline_at=attempt.deadline_at,
                                          call_id=attempt.id, lane="ordinary" if method == "execute" else "control")
        except Exception as exc:
            try:
                self.repository.block(lease, attempt.id, "dispatch_capacity_unavailable")
            except (JobLeaseLost, ExecutionConflict, InvalidTransition):
                pass
            if isinstance(exc, JOB_FAULTS):
                raise DriverDiagnostic("dispatch capacity unavailable") from None
            raise
        self._calls[str(attempt.id)] = {"handle": handle, "lease": lease, "step": step,
            "stage": method, "operation": operation, "attempt": attempt, "deadline": deadline, "timed_out": False}

    def _harvest(self):
        for key, call in list(self._calls.items()):
            handle, lease = call["handle"], call["lease"]
            if not handle.done():
                if call["deadline"].expired and not call["timed_out"]:
                    call["timed_out"] = True
                    try:
                        if call["stage"] == "prepare":
                            self.repository.prepare_failed(lease, call["step"]["id"], code="prepare_timeout")
                        else:
                            self.repository.block(lease, call["attempt"].id, "call_deadline_exceeded")
                    except JobLeaseLost:
                        pass
                    self._leases.pop(str(lease.job_id), None)
                continue  # Do NOT free a slot/handle while the thread is alive.
            self._calls.pop(key)
            try:
                result = handle.result()
            except Exception:
                if call["stage"] == "prepare":
                    if not call["timed_out"]:
                        try:
                            self.repository.prepare_failed(lease, call["step"]["id"])
                        except JobLeaseLost:
                            pass
                    self._leases.pop(str(lease.job_id), None)
                    continue
                result = (CancelResult("unknown") if call["stage"] == "cancel" else
                          ExecutionResult("unknown", error={"code": "unavailable", "message": "external call result is not confirmed"}))
            if call["stage"] == "prepare":
                if not call["timed_out"]:
                    try:
                        self.repository.commit_prepared(lease, call["step"]["id"], result, call["instance_id"])
                    except JobLeaseLost:
                        self._leases.pop(str(lease.job_id), None)
                    except JOB_FAULTS as exc:
                        # A conflicting scope or an invalid transition belongs to
                        # this job alone; never escalate to a coordinator exit.
                        self._isolate(lease, exc)
                continue
            try:
                if call["stage"] == "cancel":
                    self.repository.record_cancel(lease, call["attempt"].id, result)
                else:
                    self.repository.record_result(lease, call["attempt"].id, result,
                                                  projector=self.projector, applicator=self.applicator)
            except JobLeaseLost:
                self._leases.pop(str(lease.job_id), None)
            except JOB_FAULTS as exc:
                self._isolate(lease, exc)
            self._next_poll[str(call["operation"]["id"])] = monotonic() + self.settings.poll_interval_seconds


Driver = ExecutionDriver
