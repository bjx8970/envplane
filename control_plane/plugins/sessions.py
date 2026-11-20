"""Bounded, transport-independent interactive sessions (no HTTP/browser adapter).

Only metadata is durable. Handles, queued input and replay are process-local and
are never a restart recovery mechanism. Opening execution is delegated to the
Operation dispatcher through OpeningAdapter; this module never re-dispatches an
ordinary JSON execute as a terminal.
"""
from __future__ import annotations

from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import json
import threading
from time import monotonic
from typing import Any, Protocol
from uuid import uuid4

from sqlalchemy import text

from .sdk import (Deadline, PluginError, PreparedCall, SessionOpenResult,
                  finite_json, require_authorized)


class SessionConflict(PluginError):
    def __init__(self, message="session controller or state changed"):
        super().__init__("conflict", message)


class OpeningNotEstablished(PluginError):
    """Adapter has durable proof that no external session was established."""


@dataclass(frozen=True)
class OpeningPlan:
    operation_id: str
    job_id: str
    environment_id: str
    actor_id: str
    plugin_instance_id: str
    secret_version_id: str
    template_entry: str
    prepared_call: PreparedCall
    plugin: Any = field(repr=False)
    context: Any = field(repr=False)
    resource_id: str | None = None
    session_type: str = "terminal"
    session_id: str | None = None
    execution_lease: Any = field(default=None, repr=False)


class OpeningAdapter(Protocol):
    """Core execution adapter, not a plugin capability.

    prepare persists prepared Operation + running Step atomically using the Job
    execution repository. dispatch commits dispatch intent before open_session
    and records its result, excluding the in-memory handle. unknown appends facts
    and blocks the original Operation/Step/Job; it MUST NOT execute again.
    """
    def prepare(self, request: Any) -> OpeningPlan: ...
    def dispatch(self, plan: OpeningPlan) -> SessionOpenResult: ...
    def unknown(self, operation_id: str, reason: str) -> None: ...


class SessionTransport(Protocol):
    """Trusted session capability. Each call must honor the supplied deadline.

    receive returns one bounded event or None after a bounded wait; it must not
    return an unbounded iterator. close confirms the platform channel only.
    """
    def prepare_session(self, session_type: str, input: Any, context: Any) -> PreparedCall: ...
    def open_session(self, prepared_call: PreparedCall, context: Any) -> SessionOpenResult: ...
    def send(self, handle: Any, input_frame: dict, *, deadline: Deadline) -> None: ...
    def receive(self, handle: Any, *, deadline: Deadline) -> dict | None: ...
    def close_session(self, handle: Any, reason: str, *, deadline: Deadline) -> Any: ...


class RepositoryOpeningAdapter:
    """Bridge to the execution repository; business planning remains injected.

    ``prepare_plan`` performs the existing bounded prepare/commit_prepared path
    and returns (OpeningPlan, JobLease). It must not create a fresh Job or resolve
    latest configuration. ``projector``/``applicator`` are the same mandatory pure
    local business policies used by execution. Plugin open runs only in bounded
    ordinary capacity, never the coordinator thread or a receive slot.
    """
    def __init__(self, repository, capacity, *, prepare_plan, projector, applicator, context_builder=None):
        if context_builder is not None:
            repository.reference_validator = context_builder.validate_prepared_in
            repository.source_publisher = context_builder.publish_from_source_in
            repository.safe_json = context_builder.safe_json
        if not callable(repository.reference_validator) or not callable(repository.source_publisher):
            raise PluginError("unavailable", "opening reference and secret provenance guards are unavailable")
        self.repository, self.capacity = repository, capacity
        self.prepare_plan, self.projector, self.applicator = prepare_plan, projector, applicator

    def prepare(self, request):
        plan, lease = self.prepare_plan(request)
        if not isinstance(plan, OpeningPlan) or str(plan.job_id) != str(lease.job_id):
            raise PluginError("protocol_error", "opening plan is not bound to its execution lease")
        return replace(plan, execution_lease=lease)

    def dispatch(self, plan):
        from .sdk import ExecutionResult
        lease = plan.execution_lease
        attempt = self.repository.begin_call(lease, plan.operation_id, "execute", plan.context.deadline.check())
        deadline = Deadline.from_at(attempt.deadline_at)
        parent = self

        class ApplyOpening:
            def apply(self, uow, operation, projection):
                changed = uow.scalar(text("""
                    UPDATE control_plane.interactive_sessions
                    SET state='active',opened_at=clock_timestamp(),last_activity_at=clock_timestamp()
                    WHERE id=:id AND state='opening' AND open_operation_id=:operation RETURNING id
                """), {"id": plan.session_id, "operation": operation["id"]})
                if changed is None:
                    raise SessionConflict("opening session is no longer attachable")
                parent.applicator.apply(uow, operation, projection)

        def invoke():
            result = None
            try:
                deadline.check()
                # Use exactly the committed invocation budget, not a refreshed one.
                context = replace(plan.context, deadline=deadline)
                result = plan.plugin.open_session(plan.prepared_call, context)
                if not isinstance(result, SessionOpenResult) or result.session_handle is None:
                    raise PluginError("protocol_error", "session opener returned no handle")
                deadline.check()
                safe = ExecutionResult("succeeded", output={}, external_execution_ref=result.external_execution_ref)
                status = self.repository.record_result(lease, attempt.id, safe,
                    projector=self.projector, applicator=ApplyOpening())
                if status != "applied":
                    raise PluginError("unavailable", "opening completion lost execution authority")
                return result
            except OpeningNotEstablished as exc:
                from .sdk import SafeError
                self.repository.record_result(lease, attempt.id, ExecutionResult("failed",
                    error=SafeError(exc.code, "session transport confirmed it was not established")))
                raise
            except Exception:
                if result is not None:
                    try:
                        plan.plugin.close_session(result.session_handle, "opening_unattached", deadline=Deadline.after(1))
                    except Exception:
                        pass
                raise

        try:
            call = self.capacity.submit(str(plan.plugin_instance_id), invoke, lane="ordinary",
                                        deadline_at=attempt.deadline_at, call_id=str(attempt.id))
            return call.result(timeout=deadline.check())
        except Exception:
            # Current live invocation can block under its own lease. Restart
            # recovery below uses repository fencing, never an old lease.
            try:
                self.repository.block(lease, attempt.id, "opening_unknown")
            except Exception:
                pass
            raise

    def unknown(self, operation_id, reason):
        return self.repository.recover_opening_unknown(operation_id, reason)


CLIENT_FRAME_SCHEMAS = {
    "input": {"type", "data", "epoch"},
    "resize": {"type", "cols", "rows", "epoch"},
    "close": {"type", "reason"},
}
SERVER_FRAME_SCHEMAS = {
    "output": {"type", "seq", "data"},
    "state": {"type", "seq", "state", "epoch"},
    "error": {"type", "seq", "code"},
    "closed": {"type", "seq", "reason"},
}


def validate_client_frame(frame, *, max_bytes=16384):
    finite_json(frame, object_only=True, max_bytes=max_bytes, max_depth=3, max_items=8)
    kind = frame.get("type")
    if kind not in CLIENT_FRAME_SCHEMAS or set(frame) != CLIENT_FRAME_SCHEMAS[kind]:
        raise PluginError("invalid_frame", "invalid session frame schema")
    if kind in ("input", "resize"):
        epoch = frame["epoch"]
        if isinstance(epoch, bool) or not isinstance(epoch, int) or not 0 <= epoch < 2**63:
            raise PluginError("invalid_frame", "invalid session controller epoch")
    if kind == "input" and (not isinstance(frame["data"], str) or not frame["data"]):
        raise PluginError("invalid_frame", "input must be a nonempty string")
    if kind == "resize":
        for key in ("cols", "rows"):
            if isinstance(frame[key], bool) or not isinstance(frame[key], int) or not 1 <= frame[key] <= 1000:
                raise PluginError("invalid_frame", "invalid terminal dimensions")
    if kind == "close" and (not isinstance(frame["reason"], str) or len(frame["reason"]) > 128):
        raise PluginError("invalid_frame", "invalid close reason")
    return frame


def validate_server_frame(frame, *, max_bytes=16384):
    finite_json(frame, object_only=True, max_bytes=max_bytes, max_depth=3, max_items=8)
    kind = frame.get("type")
    if kind not in SERVER_FRAME_SCHEMAS or set(frame) != SERVER_FRAME_SCHEMAS[kind]:
        raise PluginError("invalid_frame", "invalid server frame schema")
    if isinstance(frame["seq"], bool) or not isinstance(frame["seq"], int) or not 0 < frame["seq"] < 2**63:
        raise PluginError("invalid_frame", "invalid output sequence")
    if kind == "output" and not isinstance(frame["data"], str):
        raise PluginError("invalid_frame", "invalid terminal output")
    if kind == "state" and (frame["state"] not in ("active", "closing", "disconnected", "failed")
                            or isinstance(frame["epoch"], bool) or not isinstance(frame["epoch"], int) or not 0 <= frame["epoch"] < 2**63):
        raise PluginError("invalid_frame", "invalid session state")
    if kind in ("closed", "error") and not isinstance(frame.get("reason", frame.get("code")), str):
        raise PluginError("invalid_frame", "invalid session event")
    return frame


class SessionStore:
    def __init__(self, engine, lease):
        self.engine, self.lease = engine, lease

    def get(self, session_id):
        with self.engine.connect() as connection:
            row = connection.execute(text("SELECT * FROM control_plane.interactive_sessions WHERE id=:id"), {"id": session_id}).mappings().first()
        if row is None:
            raise PluginError("not_found", "session does not exist")
        return dict(row)

    def create(self, session_id, plan):
        with self.lease.fenced_transaction() as connection:
            connection.execute(text("""
                INSERT INTO control_plane.interactive_sessions
                (id,environment_id,resource_id,job_id,open_operation_id,actor_id,plugin_instance_id,
                 target_ref,secret_version_id,template_entry,controller_id,session_type)
                VALUES (:id,:environment,:resource,:job,:operation,:actor,:instance,CAST(:target AS jsonb),
                        :secret,:entry,:actor,:type)
            """), {"id": session_id, "environment": plan.environment_id, "resource": plan.resource_id,
                   "job": plan.job_id, "operation": plan.operation_id, "actor": plan.actor_id,
                   "instance": plan.plugin_instance_id, "target": json.dumps(plan.prepared_call.target_ref),
                   "secret": plan.secret_version_id, "entry": plan.template_entry, "type": plan.session_type})

    @staticmethod
    def _audit(connection, row, actor_id, action, data=None):
        connection.execute(text("""
            INSERT INTO control_plane.audit_events(actor_id,environment_id,resource_id,job_id,operation_id,action,result,data)
            VALUES (:actor,:environment,:resource,:job,:operation,:action,'confirmed',CAST(:data AS jsonb))
        """), {"actor": actor_id, "environment": row["environment_id"], "resource": row["resource_id"],
               "job": row["job_id"], "operation": row["open_operation_id"], "action": action,
               "data": json.dumps(data or {})})

    def transition(self, session_id, previous, state, reason=None, actor_id=None):
        with self.lease.fenced_transaction() as connection:
            row = connection.execute(text("""
                UPDATE control_plane.interactive_sessions SET state=:state,
                  opened_at=CASE WHEN :state='active' THEN clock_timestamp() ELSE opened_at END,
                  closed_at=CASE WHEN :state IN ('closed','failed','disconnected') THEN clock_timestamp() ELSE closed_at END,
                  last_activity_at=clock_timestamp(),reason=CAST(:reason AS jsonb)
                WHERE id=:id AND state=:previous RETURNING *
            """), {"id": session_id, "previous": previous, "state": state,
                   "reason": json.dumps({"code": reason}) if reason else None}).mappings().first()
            if row is None:
                raise SessionConflict()
            if state in ("closed", "disconnected", "failed"):
                self._audit(connection, row, actor_id, "session." + state, {"reason": reason})
        return dict(row)

    def controller(self, session_id, actor_id, expected_revision, controller_id, action):
        with self.lease.fenced_transaction() as connection:
            row = connection.execute(text("""
                UPDATE control_plane.interactive_sessions
                SET controller_id=:controller,controller_revision=controller_revision+1
                WHERE id=:id AND state='active' AND controller_revision=:revision
                  AND controller_id IS DISTINCT FROM CAST(:controller AS uuid) RETURNING *
            """), {"id": session_id, "controller": controller_id, "revision": expected_revision}).mappings().first()
            if row is None:
                raise SessionConflict()
            self._audit(connection, row, actor_id, "session." + action,
                        {"controller_id": str(controller_id), "epoch": row["controller_revision"]})
        return dict(row)

    def audit(self, row, actor_id, action):
        with self.lease.fenced_transaction() as connection:
            self._audit(connection, row, actor_id, "session." + action)

    def touch(self, session_id):
        with self.lease.fenced_transaction() as connection:
            connection.execute(text("UPDATE control_plane.interactive_sessions SET last_activity_at=clock_timestamp() WHERE id=:id AND state='active'"), {"id": session_id})

    def disconnect_on_restart(self, *, limit=100, deadline=None, before=None):
        """One bounded batch. Completed rows leave the predicate (no OFFSET skip)."""
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("invalid restart recovery page limit")
        with self.engine.connect() as connection:
            rows = [dict(row) for row in connection.execute(text("""
                SELECT * FROM control_plane.interactive_sessions
                WHERE state IN ('opening','active','closing')
                  AND created_at < CAST(:before AS timestamptz) ORDER BY id LIMIT :limit
            """), {"limit": limit, "before": before or datetime.now(timezone.utc)}).mappings()]
        for row in rows:
            if deadline is not None and deadline.expired:
                return
            self.transition(row["id"], row["state"], "disconnected", "process_restart")
            yield row


@dataclass
class _Client:
    actor_id: str
    frames: deque = field(default_factory=deque)
    bytes: int = 0
    disconnected: bool = False


@dataclass
class _Live:
    plan: OpeningPlan
    handle: Any = field(repr=False)
    lock: Any = field(default_factory=threading.RLock)
    inputs: deque = field(default_factory=deque)
    input_bytes: int = 0
    replay: deque = field(default_factory=deque)
    replay_bytes: int = 0
    clients: dict = field(default_factory=dict)
    seq: int = 0
    stop: Any = field(default_factory=threading.Event)
    last_activity: float = field(default_factory=monotonic)
    receiver: Any = None
    received: bool = False
    close_confirmed: bool = False


class SessionService:
    def __init__(self, engine, lease, capacity, *, authorizer=None, opening_adapter=None,
                 store=None, max_frame_bytes=16384, input_bytes=65536, output_bytes=262144,
                 replay_bytes=262144, max_clients=16, max_sessions=64, receive_wait=0.25, idle_seconds=900,
                 close_seconds=2, lifetime_seconds=86400, startup_seconds=5,
                 recovery_seconds=.25, recovery_batch=100):
        limits = (max_frame_bytes, input_bytes, output_bytes, replay_bytes, max_clients, max_sessions,
                  receive_wait, idle_seconds, close_seconds, lifetime_seconds, startup_seconds,
                  recovery_seconds, recovery_batch)
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not 0 < v < float("inf") for v in limits):
            raise ValueError("session limits must be finite and positive")
        if not 256 <= max_frame_bytes <= 1048576:
            raise ValueError("invalid session frame bound")
        for name, value, maximum in (("input_bytes", input_bytes, 4194304),
                ("output_bytes", output_bytes, 4194304), ("replay_bytes", replay_bytes, 4194304),
                ("max_clients", max_clients, 128), ("max_sessions", max_sessions, 1024),
                ("receive_wait", receive_wait, 30), ("idle_seconds", idle_seconds, 86400),
                ("close_seconds", close_seconds, 120), ("lifetime_seconds", lifetime_seconds, 86400),
                ("startup_seconds", startup_seconds, 120), ("recovery_seconds", recovery_seconds, 5),
                ("recovery_batch", recovery_batch, 100)):
            if value > maximum:
                raise ValueError("session limit exceeds maximum: " + name)
        self.store = store or SessionStore(engine, lease)
        self.capacity, self.authorizer, self.opening = capacity, authorizer, opening_adapter
        self.max_frame, self.input_limit, self.output_limit = max_frame_bytes, input_bytes, output_bytes
        for value in (max_frame_bytes, input_bytes, output_bytes, replay_bytes, max_clients, max_sessions, recovery_batch):
            if not isinstance(value, int):
                raise ValueError("session capacities must be integers")
        self.replay_limit, self.max_clients, self.max_sessions = replay_bytes, max_clients, max_sessions
        self.receive_wait, self.idle_seconds = receive_wait, idle_seconds
        self.close_seconds, self.lifetime_seconds = close_seconds, lifetime_seconds
        self.startup_seconds, self.recovery_seconds, self.recovery_batch = startup_seconds, recovery_seconds, recovery_batch
        self._live, self._lock, self._started = {}, threading.RLock(), False
        self._pending = {}
        self._closing = set()
        self._close_retry = set()
        self._close_inflight = {}
        self._restart_before = datetime.now(timezone.utc)
        self._opening_count = 0

    @contextmanager
    def _live_guard(self, live):
        # An uncooperative send may own the lock as well as its capacity slot.
        # API/close/takeover waits must still terminate without claiming success.
        if not live.lock.acquire(timeout=self.close_seconds):
            raise PluginError("unavailable", "session transport is not cooperating")
        try:
            yield
        finally:
            live.lock.release()

    def _authorize(self, actor_id, row, action):
        # A plan has no durable session row before store.create(). Pass its
        # fixed binding only for this initial check; later checks read the row.
        binding = {"opening_binding": row} if row.get("provisional") else {}
        require_authorized(self.authorizer, str(actor_id), str(row["environment_id"]),
                           "session." + action, session_id=str(row["id"]),
                           resource_id=str(row["resource_id"]) if row["resource_id"] else None,
                           template_entry=row["template_entry"], **binding)

    def start(self):
        if self._started:
            raise RuntimeError("session service already started")
        # One bounded startup page; poll() continues old-process metadata
        # recovery. Operation recovery stays in execution, never a dispatcher here.
        self._recover_batch(Deadline.after(self.startup_seconds))
        self._started = True

    def _recover_batch(self, deadline):
        for row in self.store.disconnect_on_restart(limit=self.recovery_batch, deadline=deadline, before=self._restart_before):
            if row["state"] == "opening" and self.opening is not None:
                self.opening.unknown(str(row["open_operation_id"]), "process_restart")

    def poll(self):
        self._ensure_started()
        self._recover_batch(Deadline.after(self.recovery_seconds))
        self._sweep_queued_receivers()

    def _mark_closing(self, session_id, live):
        """Claim the one-time cleanup of a queued receiver; False if taken."""
        with self._lock:
            if live.received or session_id in self._closing:
                return False
            self._closing.add(session_id)
            return True

    def _sweep_queued_receivers(self):
        """Finalize receivers that expired before their loop ever started.

        A receiver queued in the session lane may expire before a worker picks
        it up; ``_receive_loop`` then never runs, so its own cleanup never runs.
        This sweep performs only bounded local bookkeeping on the coordinator
        thread: the actual plugin close is handed to supervised *control*
        capacity, because a non-cooperating plugin must never block polling.
        Receivers that already ran (``live.received``) own their cleanup.
        """
        with self._lock:
            candidates = [(session_id, live) for session_id, live in self._live.items()
                          if live.receiver is not None and not live.received
                          and session_id not in self._closing]
            pending = list(self._close_retry)
        # Retry closes whose submission was rejected or whose queued task never
        # started: the remote channel may still be open, so retain the local
        # cleanup obligation until a supervised close confirms otherwise.
        for session_id in pending:
            live = self._live.get(session_id)
            if live is None:
                with self._lock:
                    self._close_retry.discard(session_id)
                continue
            self._schedule_close(session_id, live, "receiver_queue_expired")
        for session_id, live in candidates:
            handle = live.receiver
            # `received` records that the loop actually began. A capacity
            # rejection marks the handle started too, so `running` cannot
            # distinguish "never ran" from "already finished".
            if live.received or not handle.expired:
                continue  # The loop owns its cleanup, or the budget is still valid.
            if not self._mark_closing(session_id, live):
                continue
            live.stop.set()
            # Durable bookkeeping first so the fact survives a failed close.
            try:
                row = self.store.get(session_id)
                if row["state"] in ("active", "closing"):
                    self.store.transition(session_id, row["state"], "disconnected",
                                          "receiver_queue_expired")
            except Exception:
                pass  # Recovery facts remain; never claim the remote was stopped.
            with self._lock:
                self._close_retry.add(session_id)
            self._schedule_close(session_id, live, "receiver_queue_expired")

    def _schedule_close(self, session_id, live, reason):
        """Run the plugin close on supervised control capacity, never inline.

        Unstarted failures (submission rejected, or the queued task expired
        before the lambda ran) keep the session in ``_close_retry`` so the next
        bounded sweep retries. A close that actually started keeps its capacity
        slot and is never re-submitted concurrently.
        """
        with self._lock:
            handle = self._close_inflight.get(session_id)
            if handle is not None and not handle.done():
                return True  # Queued or running, even if overdue: retain the slot.
            # done() is set only after capacity has left the callable. It also
            # covers queue expiry before the callable was ever entered; neither
            # case can depend on a callback inside that callable for cleanup.
            self._close_inflight.pop(session_id, None)
            if live.close_confirmed:
                self._close_retry.discard(session_id)
                return True
            try:
                # Keep admission and registration atomic relative to another
                # sweep/open. The worker never removes its own tracking entry.
                self._close_inflight[session_id] = self.capacity.submit(
                    str(live.plan.plugin_instance_id),
                    lambda: self._close_handle(live, reason),
                    lane="control", deadline_at=Deadline.after(self.close_seconds).expires_at,
                    call_id="session-close:" + session_id)
            except Exception:
                return False  # A later sweep retries; the channel may remain open.
            return True

    def quiesce(self):
        """Non-waiting ingress/forwarding revocation, safe before lease release."""
        self._started = False
        for live in list(self._live.values()):
            live.stop.set()

    def stop(self, grace=2):
        if isinstance(grace, bool) or not isinstance(grace, (int, float)) or not 0 <= grace <= 120:
            raise ValueError("invalid stop grace")
        self.quiesce()
        end = monotonic() + grace
        # Quiesce must run before any I/O. Losing the lease must not prevent all
        # other handles from observing stop; restart can finalize metadata later.
        items = list(self._live.items())
        pending = list(self._pending)
        for session_id in set(pending + [key for key, _ in items]):
            try:
                row = self.store.get(session_id)
                if row["state"] in ("active", "closing", "opening"):
                    self.store.transition(session_id, row["state"], "disconnected", "service_stop")
            except Exception:
                pass
        # Cooperative receiver owns its handle; never run a concurrent close on a
        # stuck plugin, kill a thread, or refund its capacity before actual exit.
        for _, live in items:
            if live.receiver is not None and not live.receiver.done() and monotonic() < end:
                try:
                    live.receiver.result(timeout=max(0, end - monotonic()))
                except Exception:
                    pass

    def open(self, request):
        if not self._started or self.opening is None:
            raise PluginError("unavailable", "session opening adapter is unavailable")
        with self._lock:
            # Bound retained replay/clients too, not only active receivers. Only
            # actual completed calls are evicted; stuck calls keep their slots.
            for key, old in list(self._live.items()):
                close = self._close_inflight.get(key)
                if (old.stop.is_set() and old.receiver is not None and old.receiver.done()
                        and (key not in self._closing or old.close_confirmed)
                        and key not in self._close_retry and (close is None or close.done())):
                    del self._live[key]
                    self._close_inflight.pop(key, None)
                    self._closing.discard(key)
            if len(self._live) + self._opening_count >= self.max_sessions:
                raise PluginError("capacity", "session capacity is exhausted")
            self._opening_count += 1
        try:
            return self._open(request)
        finally:
            with self._lock:
                self._opening_count -= 1

    def _open(self, request):
        plan = self.opening.prepare(request)
        session_id = str(uuid4())
        provisional = {"id": session_id, "environment_id": plan.environment_id,
                       "resource_id": plan.resource_id, "template_entry": plan.template_entry,
                       "provisional": True, "state": "opening", "actor_id": plan.actor_id,
                       "controller_id": plan.actor_id, "plugin_instance_id": plan.plugin_instance_id,
                       "target_ref": plan.prepared_call.target_ref, "secret_version_id": plan.secret_version_id,
                       "session_type": plan.session_type}
        self._authorize(plan.actor_id, provisional, "open")
        plan.context.deadline.check()
        plan = replace(plan, session_id=session_id)
        with self._lock:
            if not self._started:
                raise PluginError("unavailable", "session service is stopping")
            self.store.create(session_id, plan)
            self._pending[session_id] = plan
        try:
            self._authorize(plan.actor_id, self.store.get(session_id), "open")
            if not self._started:
                raise PluginError("unavailable", "session service is stopping")
            result = self.opening.dispatch(plan)
            if not isinstance(result, SessionOpenResult) or result.session_handle is None:
                raise PluginError("protocol_error", "session opener returned no handle")
            live = _Live(plan, result.session_handle)
            with self._lock:
                self._live[session_id] = live
            if not self._started:
                raise PluginError("unavailable", "session service stopped during opening")
            row = self.store.get(session_id)
            if row["state"] == "opening":
                self.store.transition(session_id, "opening", "active")
            elif row["state"] != "active":
                raise SessionConflict("opening metadata is no longer attachable")
            # Independent session lane. Ordinary execute slots are never borrowed.
            live.receiver = self.capacity.submit(str(plan.plugin_instance_id),
                lambda: self._receive_loop(session_id, live), lane="session",
                deadline_at=Deadline.after(self.lifetime_seconds).expires_at,
                call_id="session:" + session_id)
            return self.store.get(session_id)
        except OpeningNotEstablished:
            try:
                self.store.transition(session_id, "opening", "failed", "not_established", plan.actor_id)
            except Exception:
                pass  # Lease loss leaves restart recovery facts, not a false success.
            raise
        except Exception:
            try:
                row = self.store.get(session_id)
                if row["state"] in ("opening", "active"):
                    self.store.transition(session_id, row["state"], "disconnected", "opening_unknown", plan.actor_id)
            except Exception:
                pass
            try:
                self.opening.unknown(plan.operation_id, "opening_unknown")
            except Exception:
                pass
            # Closing after receiver admission failure uses independent bounded
            # control capacity; a saturated session lane cannot hide a live handle.
            live = self._live.get(session_id)
            if live is not None:
                live.stop.set()
                try:
                    live.receiver = self.capacity.submit(str(plan.plugin_instance_id), lambda: self._close_handle(live, "opening_unknown"),
                        lane="control", deadline_at=Deadline.after(self.close_seconds).expires_at)
                except Exception:
                    pass
            raise
        finally:
            with self._lock:
                self._pending.pop(session_id, None)

    def _ensure_started(self):
        if not self._started:
            raise PluginError("unavailable", "session service is stopped")

    def _active(self, session_id):
        self._ensure_started()
        row = self.store.get(session_id)
        live = self._live.get(str(session_id))
        if row["state"] != "active" or live is None:
            raise SessionConflict("session is not attached")
        return row, live

    def observe(self, actor_id, session_id, *, client_id=None, after_seq=None, reconnect=False):
        row, live = self._active(session_id)
        self._authorize(actor_id, row, "reconnect" if reconnect else "observe")
        self._authorize(actor_id, row, "replay")
        if after_seq is not None and (isinstance(after_seq, bool) or not isinstance(after_seq, int) or after_seq < 0):
            raise PluginError("invalid_frame", "invalid replay sequence")
        client_id = client_id or str(uuid4())
        with self._live_guard(live):
            self._ensure_started()
            if client_id not in live.clients and len(live.clients) >= self.max_clients:
                raise PluginError("capacity", "session observer limit reached")
            if client_id in live.clients and live.clients[client_id].actor_id != str(actor_id):
                raise SessionConflict()
            client = _Client(str(actor_id))
            live.clients[client_id] = client
            if after_seq is not None:
                first = live.replay[0][0]["seq"] if live.replay else live.seq + 1
                if after_seq < first - 1:
                    raise PluginError("replay_lost", "requested output is no longer retained")
                for frame, size in live.replay:
                    if frame["seq"] > after_seq:
                        self._enqueue(client, frame, size)
            self.store.audit(row, actor_id, "reconnect" if reconnect else "observe")
        return client_id

    def poll_output(self, actor_id, session_id, client_id, *, limit=100):
        if not self._started:
            raise PluginError("unavailable", "session service is stopped")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("invalid output page limit")
        row = self.store.get(session_id)
        self._authorize(actor_id, row, "output")
        live = self._live.get(str(session_id))
        if live is None:
            raise SessionConflict("session handle is unavailable")
        with self._live_guard(live):
            self._ensure_started()
            client = live.clients.get(client_id)
            if client is None or client.actor_id != str(actor_id) or client.disconnected:
                raise SessionConflict("observer disconnected; reconnect explicitly")
            result = []
            while client.frames and len(result) < limit:
                self._ensure_started()
                self._authorize(actor_id, self.store.get(session_id), "output")
                frame, size = client.frames.popleft()
                client.bytes -= size
                result.append(dict(frame))
            return result

    def frame(self, actor_id, session_id, frame):
        validate_client_frame(frame, max_bytes=self.max_frame)
        if frame["type"] == "close":
            return self.close(actor_id, session_id, frame["reason"])
        row, live = self._active(session_id)
        self._authorize(actor_id, row, frame["type"])
        if frame["type"] == "resize" and not callable(getattr(live.plan.plugin, "resize", None)):
            raise PluginError("unsupported", "session transport does not support resize")
        size = len(json.dumps(frame, ensure_ascii=False).encode("utf-8"))
        with self._live_guard(live):
            self._ensure_started()
            row = self.store.get(session_id)
            self._authorize(actor_id, row, frame["type"])
            self._ensure_started()
            if str(row["controller_id"]) != str(actor_id) or row["controller_revision"] != frame["epoch"]:
                raise SessionConflict()
            if live.input_bytes + size > self.input_limit:
                raise PluginError("backpressure", "session input queue is full")
            live.inputs.append((str(actor_id), dict(frame), size))
            live.input_bytes += size
            live.last_activity = monotonic()
        return {"queued": True, "epoch": frame["epoch"]}

    def takeover(self, actor_id, session_id, expected_revision):
        return self._controller(actor_id, session_id, expected_revision, actor_id, "takeover")

    def release(self, actor_id, session_id, expected_revision):
        row, _ = self._active(session_id)
        if str(row["controller_id"]) != str(actor_id):
            raise SessionConflict()
        # Verify the original owner can receive control again before the CAS.
        # Actual input always requires the current controller and epoch.
        self._authorize(row["actor_id"], row, "resume_input")
        return self._controller(actor_id, session_id, expected_revision, row["actor_id"], "release")

    def _controller(self, actor_id, session_id, expected_revision, controller_id, action):
        if isinstance(expected_revision, bool) or not isinstance(expected_revision, int) or not 0 <= expected_revision < 2**63 - 1:
            raise PluginError("invalid_frame", "invalid controller revision")
        row, live = self._active(session_id)
        self._authorize(actor_id, row, action)
        with self._live_guard(live):
            self._ensure_started()
            self._authorize(actor_id, self.store.get(session_id), action)
            self._ensure_started()
            row = self.store.controller(session_id, actor_id, expected_revision, controller_id, action)
            # Epoch binding is also checked at send; dropping here bounds stale data.
            live.inputs.clear()
            live.input_bytes = 0
            self._publish(session_id, live, {"type": "state", "state": "active", "epoch": row["controller_revision"]})
            return row

    def close(self, actor_id, session_id, reason="client_close"):
        row, live = self._active(session_id)
        self._authorize(actor_id, row, "close")
        with self._live_guard(live):
            self._ensure_started()
            self.store.transition(session_id, "active", "closing", "client_close", actor_id)
            self.store.audit(row, actor_id, "close_requested")
            live.inputs.clear()
            live.input_bytes = 0
            live.stop.set()
        return {"state": "closing"}

    def _enqueue(self, client, frame, size):
        if client.bytes + size > self.output_limit:
            client.frames.clear()
            client.bytes = 0
            client.disconnected = True
            return
        if not client.disconnected:
            client.frames.append((dict(frame), size))
            client.bytes += size

    def _publish(self, session_id, live, frame):
        if not self._started or (live.stop.is_set() and frame.get("type") == "output"):
            return
        with self._live_guard(live):
            if not self._started or (live.stop.is_set() and frame.get("type") == "output"):
                return
            live.seq += 1
            frame = {**frame, "seq": live.seq}
            validate_server_frame(frame, max_bytes=self.max_frame)
            size = len(json.dumps(frame, ensure_ascii=False).encode("utf-8"))
            live.replay.append((frame, size))
            live.replay_bytes += size
            while live.replay and live.replay_bytes > self.replay_limit:
                _, removed = live.replay.popleft()
                live.replay_bytes -= removed
            row = self.store.get(session_id)
            for client in live.clients.values():
                try:
                    self._authorize(client.actor_id, row, "output")
                except Exception:
                    client.frames.clear()
                    client.bytes = 0
                    client.disconnected = True
                    continue
                if not self._started or (live.stop.is_set() and frame["type"] == "output"):
                    return
                self._enqueue(client, frame, size)

    def _drain_one(self, session_id, live):
        with self._live_guard(live):
            if not live.inputs or live.stop.is_set():
                return
            actor_id, frame, size = live.inputs.popleft()
            live.input_bytes -= size
            row = self.store.get(session_id)
            if row["state"] != "active" or str(row["controller_id"]) != actor_id or row["controller_revision"] != frame["epoch"]:
                return
            self._authorize(actor_id, row, frame["type"])
            # Lock serializes successful CAS takeover with actual forwarding.
            # A stuck call retains its real receiver slot; no replacement thread.
            deadline = Deadline.after(self.receive_wait)
            if frame["type"] == "input":
                live.plan.plugin.send(live.handle, frame, deadline=deadline)
            else:
                live.plan.plugin.resize(live.handle, {"cols": frame["cols"], "rows": frame["rows"]}, deadline=deadline)
            self.store.touch(session_id)

    def _receive_loop(self, session_id, live):
        with self._lock:
            # Capacity can pass its deadline check, then be descheduled before
            # entering here. If the expiry sweep won ownership meanwhile, its
            # control call alone closes the handle; do not run our finally too.
            if session_id in self._closing:
                return
            live.received = True
        end = monotonic() + self.lifetime_seconds
        reason = "channel_lost"
        try:
            while not live.stop.is_set():
                row = self.store.get(session_id)
                self._authorize(row["actor_id"], row, "output")
                if monotonic() - live.last_activity >= self.idle_seconds or monotonic() >= end:
                    reason = "idle_timeout" if monotonic() < end else "lifetime_timeout"
                    self.store.transition(session_id, "active", "closing", reason)
                    break
                self._drain_one(session_id, live)
                # One bounded receive, never an unbounded generator/ordinary pool.
                event = live.plan.plugin.receive(live.handle, deadline=Deadline.after(self.receive_wait))
                if event is None:
                    live.stop.wait(min(.005, self.receive_wait))
                    continue
                if isinstance(event, dict) and event == {"type": "closed"}:
                    self._authorize(row["actor_id"], self.store.get(session_id), "output")
                    self.store.transition(session_id, "active", "closing", "remote_channel_closed")
                    self.store.transition(session_id, "closing", "closed", "remote_channel_closed")
                    self._publish(session_id, live, {"type": "closed", "reason": "remote_channel_closed"})
                    break
                if not isinstance(event, dict) or set(event) != {"type", "data"} or event["type"] != "output" or not isinstance(event["data"], str):
                    raise PluginError("protocol_error", "invalid transport output")
                self._authorize(row["actor_id"], self.store.get(session_id), "output")
                self._publish(session_id, live, event)
                # Remote output is not client activity: a noisy process must not
                # keep an unattended session alive indefinitely.
        except Exception:
            row = self.store.get(session_id)
            if row["state"] in ("active", "closing"):
                self.store.transition(session_id, row["state"], "disconnected", reason)
        finally:
            live.stop.set()
            self._close_handle(live, reason)
            row = self.store.get(session_id)
            if row["state"] == "closing":
                # Only explicit transport confirmation closes the platform channel.
                state = "closed" if live.close_confirmed else "disconnected"
                self.store.transition(session_id, "closing", state, reason)
                self._publish(session_id, live, {"type": "closed", "reason": reason} if state == "closed"
                              else {"type": "state", "state": state, "epoch": row["controller_revision"]})

    def _close_handle(self, live, reason):
        try:
            result = live.plan.plugin.close_session(live.handle, reason, deadline=Deadline.after(self.close_seconds))
            live.close_confirmed = result is True or (isinstance(result, dict) and result.get("channel_closed") is True)
        except Exception:
            live.close_confirmed = False
        # closed says nothing about remote background commands or direct SSH.
        return live.close_confirmed
