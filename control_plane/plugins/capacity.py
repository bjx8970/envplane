"""Explicitly started, bounded in-process call supervision.

Timeout is an observation, NOT thread termination. A timed-out running callable
keeps its lane and instance reservation until its Python frame really returns.
No replacement threads are spawned. This is logical isolation, not a sandbox.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from queue import Empty, Full, Queue
from threading import Event, Lock, Thread, current_thread
from time import monotonic
from uuid import uuid4

from .sdk import BudgetExceeded, Deadline, PluginError


class CapacityRejected(PluginError):
    def __init__(self, message="execution capacity unavailable"):
        super().__init__("capacity_exhausted", message, details={"retryable": True, "http_status": 503})


@dataclass(frozen=True)
class CapacitySettings:
    ordinary_workers: int = 4
    control_workers: int = 2
    session_workers: int = 4
    queue_limit: int = 8
    instance_limit: int = 2
    overdue_threshold: int = 1
    shutdown_grace_seconds: float = 2.0

    def __post_init__(self):
        for name in ("ordinary_workers", "control_workers", "session_workers", "queue_limit", "instance_limit", "overdue_threshold"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 1024:
                raise ValueError("capacity counts must be finite positive integers")
        if self.instance_limit > self.ordinary_workers + self.queue_limit:
            raise ValueError("instance concurrency exceeds ordinary capacity")
        if not 0 < self.shutdown_grace_seconds <= 120:
            raise ValueError("shutdown grace must be finite and bounded")


class CallHandle:
    def __init__(self, instance_id, call_id, lane, deadline, fn):
        self.instance_id = str(instance_id)
        self.call_id = str(call_id)
        self.lane = lane
        self.deadline = deadline
        self._fn = fn
        self._event = Event()
        self._value = None
        self._error = None
        self._started = False

    def __repr__(self):
        return f"CallHandle(call_id={self.call_id!r}, lane={self.lane!r}, done={self.done()})"

    def done(self):
        return self._event.is_set()

    @property
    def expired(self):
        return self.deadline.expired

    @property
    def running(self):
        return self._started and not self.done()

    def result(self, timeout=None):
        if not self._event.wait(timeout):
            raise TimeoutError("call is still running")
        if self._error is not None:
            raise self._error
        return self._value


class CapacitySupervisor:
    LANES = ("ordinary", "control", "session")

    def __init__(self, settings=None):
        self.settings = settings or CapacitySettings()
        self._lock = Lock()
        self._stop = Event()
        self._state = "stopped"
        self._threads = []
        self._queues = {lane: Queue(maxsize=self.settings.queue_limit) for lane in self.LANES}
        self._handles = {}
        self._instances = {}

    def start(self):
        with self._lock:
            if self._state != "stopped" or self._threads:
                raise RuntimeError("capacity supervisor cannot be restarted")
            self._state = "running"
            for lane in self.LANES:
                for index in range(getattr(self.settings, f"{lane}_workers")):
                    # Daemon avoids pretending an uncooperative plugin supports
                    # graceful process shutdown. stop() reports remaining calls.
                    worker = Thread(target=self._worker, args=(lane,), name=f"p2-{lane}-{index}", daemon=True)
                    self._threads.append(worker)
            threads = list(self._threads)
        for worker in threads:
            worker.start()

    def _lane_count(self, lane):
        return sum(handle.lane == lane for handle in self._handles.values())

    def _unavailable(self, instance_id=None, lane="ordinary"):
        if self._state != "running":
            return True
        handles = [v for v in self._handles.values() if v.lane == lane]
        if len(handles) >= getattr(self.settings, f"{lane}_workers") + self.settings.queue_limit:
            return True
        # Instance limits are lane-specific: a hung execute must not consume
        # the finite control-query allocation needed to inspect that operation.
        if instance_id is not None:
            same = [v for v in handles if v.instance_id == str(instance_id)]
            if len(same) >= self.settings.instance_limit:
                return True
            if sum(v.running and v.expired for v in same) >= self.settings.overdue_threshold:
                return True
        if sum(v.running and v.expired for v in handles) >= getattr(self.settings, f"{lane}_workers"):
            return True
        return False

    def check_admission(self, instance_id=None, *, lane="ordinary"):
        if lane not in self.LANES:
            raise ValueError("unknown call lane")
        with self._lock:
            if self._unavailable(instance_id, lane):
                raise CapacityRejected()
        return True

    admit = check_admission

    def submit(self, instance_id, fn, *, deadline_at: datetime, call_id=None, lane="ordinary"):
        if lane not in self.LANES or not callable(fn):
            raise ValueError("invalid call submission")
        deadline = Deadline.from_at(deadline_at)
        deadline.check()
        handle = CallHandle(instance_id, call_id or uuid4(), lane, deadline, fn)
        with self._lock:
            if self._unavailable(instance_id, lane) or handle.call_id in self._handles:
                raise CapacityRejected()
            self._handles[handle.call_id] = handle
            try:
                self._queues[lane].put_nowait(handle)
            except Full:
                self._handles.pop(handle.call_id)
                raise CapacityRejected() from None
        return handle

    def _worker(self, lane):
        queue = self._queues[lane]
        while not self._stop.is_set():
            try:
                handle = queue.get(timeout=0.05)
            except Empty:
                continue
            try:
                with self._lock:
                    handle._started = True
                    stopping = self._state != "running"
                if stopping:
                    raise CapacityRejected("control plane is stopping")
                handle.deadline.check()
                handle._value = handle._fn()
            except BaseException as error:
                handle._error = error
            finally:
                # Release only after the callable has actually exited; even
                # BaseException cannot leak or prematurely return a slot.
                handle._fn = None
                with self._lock:
                    self._handles.pop(handle.call_id, None)
                    handle._event.set()
                queue.task_done()

    def snapshot(self):
        with self._lock:
            lanes = {}
            for lane in self.LANES:
                handles = [v for v in self._handles.values() if v.lane == lane]
                lanes[lane] = {"workers": getattr(self.settings, f"{lane}_workers"), "active": sum(v.running for v in handles),
                               "queued": sum(not v._started for v in handles),
                               "overdue": sum(v.running and v.expired for v in handles)}
            unavailable = self._unavailable()
            degraded = self._state != "running" or any(v["overdue"] for v in lanes.values()) or unavailable
            return {"state": self._state, "ready": not degraded, "degraded": degraded,
                    "manual_restart_required": any(v["overdue"] for v in lanes.values()),
                    "lanes": lanes, "retained_calls": len(self._handles)}

    def stop(self, grace=None):
        grace = self.settings.shutdown_grace_seconds if grace is None else grace
        if not isinstance(grace, (int, float)) or not 0 <= grace <= 120:
            raise ValueError("shutdown grace must be bounded")
        with self._lock:
            self._state = "stopping"
            self._stop.set()
            # Queued work has provably never entered plugin code. It may be
            # cancelled locally, unlike work already running in another thread.
            for queue in self._queues.values():
                while True:
                    try:
                        handle = queue.get_nowait()
                    except Empty:
                        break
                    handle._error = CapacityRejected("control plane is stopping")
                    handle._fn = None
                    self._handles.pop(handle.call_id, None)
                    handle._event.set()
                    queue.task_done()
        end = monotonic() + grace
        for worker in self._threads:
            if worker is not current_thread():
                worker.join(max(0, end - monotonic()))
        with self._lock:
            self._state = "stopped" if not self._handles else "degraded"
        return self.snapshot()
