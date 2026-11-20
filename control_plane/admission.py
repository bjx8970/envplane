"""Bounded core admission boundary; P3 supplies authorization and quota policy.

This is an internal service, not an HTTP or arbitrary plugin execution endpoint.
A replay checks current authorization but never repeats quota/environment writes.
"""
from sqlalchemy import text

from .execution.adapters import UNAVAILABLE, admit_request
from .persistence import RequestConflict
from .plugins.capacity import CapacityRejected
from .plugins.sdk import AuthorizationDenied


class AdmissionController:
    def __init__(self, runtime, capacity, *, max_pending_jobs, authorize=None, policy=UNAVAILABLE):
        if isinstance(max_pending_jobs, bool) or not isinstance(max_pending_jobs, int) or not 1 <= max_pending_jobs <= 100000:
            raise ValueError('pending job bound must be finite and positive')
        self.runtime, self.capacity = runtime, capacity
        self.max_pending_jobs, self.authorize, self.policy = max_pending_jobs, authorize, policy

    def submit(self, request):
        """All local writes share one fenced UoW, including quota and snapshots."""
        if self.authorize is None:
            raise AuthorizationDenied()
        with self.runtime.fenced_transaction() as uow:
            # Serialize first-use and replay before authorizing the stored operation.
            uow.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key,0))"),
                        {"key": str(request["actor_id"]) + ":" + request["request_key"]})
            if not self.authorize(uow, request):
                raise AuthorizationDenied()
            old = uow.execute(text('''SELECT id,request_digest FROM control_plane.jobs
                                      WHERE actor_id=:actor AND request_key=:key'''),
                              {'actor': request['actor_id'], 'key': request['request_key']}).first()
            if old is not None:
                if old.request_digest != request['request_digest']:
                    raise RequestConflict('request key has different content')
                return old.id, True
            self.capacity.check_admission()
            for instance in request.get('plugin_instance_ids', ()):
                self.capacity.check_admission(str(instance))
            pending = uow.scalar(text("SELECT count(*) FROM control_plane.jobs WHERE state IN ('queued','running','cancel_requested')"))
            if pending >= self.max_pending_jobs:
                raise CapacityRejected('durable job queue is full')
            result = admit_request(uow, request, admission=self.policy)
            # Admission did no external work; overload discovered before commit
            # rolls back the entire environment/quota/job write set.
            self.capacity.check_admission()
            return result
