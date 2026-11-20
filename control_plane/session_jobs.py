"""Durable admission and dispatch of template-declared interactive openings."""
from uuid import uuid4

from sqlalchemy import text

from .access import resolve_session_entry_in
from .admission import AdmissionController
from .business import _group
from .execution.repository import InvalidTransition, JobLeaseLost
from .persistence import admit_job
from .plugins.capacity import CapacityRejected
from .plugins.sdk import AuthorizationDenied, Deadline, ExecutionPolicy, PreparedCall, PluginError, json_digest
from .plugins.sessions import OpeningPlan, RepositoryOpeningAdapter, SessionService
from .templates import TemplateError

OPEN_SECONDS = 12


def authorize_opening(uow, registry, job):
    """Compare current authorization to the exact target and credential already pinned."""
    if registry is None:
        return False
    flow = job["execution_snapshot"]["workflow"]
    fixed = flow["entry"]
    try:
        current = resolve_session_entry_in(
            uow, registry, job["actor_id"], job["environment_id"], flow["entry_key"], flow["resource_id"],
            pinned_version_id=fixed["credential_ref"]["version_id"])
    except (PluginError, TemplateError, KeyError):
        return False
    return {**current, "plugin_instance_id": str(current["plugin_instance_id"])} == fixed


class SessionOpenJobs:
    def __init__(self, services, repository, workflow, *, max_pending_jobs):
        self.services, self.repository = services, repository
        self.capacity, self.runtime = services.capacity, services.runtime
        self.admission = AdmissionController(self.runtime, self.capacity, max_pending_jobs=max_pending_jobs,
                                            authorize=self._authorize_request, policy=self)
        self.calls = {}
        adapter = RepositoryOpeningAdapter(repository, self.capacity, prepare_plan=self._prepare,
                                           projector=workflow, applicator=workflow, context_builder=services.contexts)
        self.sessions = SessionService(self.runtime._engine, self.runtime, self.capacity,
            authorizer=services.credentials.session_authorizer, opening_adapter=adapter,
            output_guard=services.secrets.safe_json)

    def submit(self, actor, environment, entry_key, resource, request_key):
        if not isinstance(request_key, str) or not 1 <= len(request_key) <= 255 or "\x00" in request_key:
            raise ValueError("bounded session request key required")
        payload = {"environment_id": str(environment), "entry_key": entry_key, "resource_id": resource}
        return self.admission.submit({**payload, "actor_id": actor, "request_key": request_key,
                                      "request_digest": json_digest({"kind": "session_open", **payload})})

    def _authorize_request(self, db, request):
        job = db.execute(text("""
            SELECT * FROM control_plane.jobs WHERE actor_id=:actor_id AND request_key=:request_key
        """), request).mappings().first()
        if job is not None:
            return self.repository.authorize_job(db, job)
        self._resolve(db, request)
        return True

    def _resolve(self, db, request):
        entry = resolve_session_entry_in(
            db, self.services.registry, request["actor_id"], request["environment_id"],
            request["entry_key"], request["resource_id"])
        return {**entry, "plugin_instance_id": str(entry["plugin_instance_id"])}

    def authorize_and_reserve(self, db, request):
        environment, actor = request["environment_id"], request["actor_id"]
        version = db.scalar(text("""
            SELECT template_version_id FROM control_plane.environments WHERE id=:id FOR UPDATE
        """), {"id": environment})
        entry = self._resolve(db, request)
        instance = entry["plugin_instance_id"]
        self.capacity.check_admission(instance)
        self.capacity.check_admission(instance, lane="control")
        self.capacity.check_admission(instance, lane="session")
        # A receiver occupies its slot for the life of a PTY. Bound outstanding
        # opens against the number of real receiver threads, including queued jobs.
        occupied = db.execute(text("""
            WITH reserved AS (
                SELECT p.instance_id FROM control_plane.jobs j
                JOIN control_plane.job_plugin_snapshots p ON p.job_id=j.id
                WHERE j.kind='session_open' AND j.state IN ('queued','running','cancel_requested')
                UNION ALL
                SELECT s.plugin_instance_id FROM control_plane.interactive_sessions s
                JOIN control_plane.jobs j ON j.id=s.job_id
                WHERE s.state IN ('active','closing') AND j.state='succeeded'
            )
            SELECT count(*) AS total, count(*) FILTER (WHERE instance_id=:instance) AS per_instance
            FROM reserved
        """), {"instance": instance}).one()
        limits = self.capacity.settings
        if (occupied.total >= min(limits.session_workers, self.sessions.max_sessions)
                or occupied.per_instance >= limits.instance_limit):
            raise CapacityRejected("session receiver capacity exhausted")
        group, parent = _group(db, environment, "session_open")
        capture = self.services.configuration.capture_in(
            db, instance, self.services.secrets, environment, session_credential=entry["credential_ref"])
        flow = {"kind": "session_open", "steps": [{"id": "open"}], "entry": entry,
                "entry_key": request["entry_key"], "resource_id": request["resource_id"]}
        snapshot = self.services.secrets.safe_json({
            "workflow": flow, "plugins": {instance: capture}, "template_version_id": str(version),
        })
        job, _ = admit_job(db, actor_id=actor, request_key=request["request_key"],
                           request_digest=request["request_digest"], environment_id=environment,
                           execution_group_id=group, logical_invocation_id=uuid4(), kind="session_open",
                           input={}, execution_snapshot=snapshot, parent_job_id=parent)
        db.execute(text("UPDATE control_plane.execution_groups SET current_job_id=:job WHERE id=:group"),
                   {"job": job, "group": group})
        self.services.configuration.bind_capture_in(db, job, instance, capture, self.services.secrets)
        db.execute(text("""
            INSERT INTO control_plane.audit_events(actor_id,environment_id,resource_id,job_id,template_version_id,action,result)
            VALUES (:actor,:env,:resource,:job,:version,'session.open','admitted')
        """), {"actor": actor, "env": environment, "resource": request["resource_id"], "job": job, "version": version})
        return job

    def poll(self):
        for key, call in list(self.calls.items()):
            if call.done():
                del self.calls[key]
                try:
                    call.result(timeout=0)
                except (CapacityRejected, JobLeaseLost):
                    pass

    def advance(self, lease, job, steps, operations):
        key = str(lease.job_id)
        if key in self.calls:
            return
        if operations:
            # A restarted prepared opening proved it did not dispatch. A
            # dispatched one is never replayed as a replacement PTY.
            if any(op["dispatch_intent_at"] for op in operations):
                for op in operations:
                    if op["state"] in {"running", "unknown"}:
                        self.repository.block_operation(lease, op["id"], "session_open_interrupted")
            else:
                self.repository.cancel_undispatched(lease)
            return
        if not steps:
            self.repository.add_steps(lease, [{"step_path": "open", "input": {"timeout_seconds": OPEN_SECONDS}}])
            job, steps, _ = self.repository.view(lease)
        step = steps[0]
        if (job["database_now"] - job["created_at"]).total_seconds() > 30:
            self.repository.prepare_failed(lease, step["id"], code="session_request_expired")
            return
        flow = job["execution_snapshot"]["workflow"]
        instance = flow["entry"]["plugin_instance_id"]
        try:
            self.calls[key] = self.capacity.submit(instance, lambda: self._run(lease, job, step),
                lane="control", deadline_at=Deadline.after(2 * OPEN_SECONDS).expires_at)
        except CapacityRejected:
            return  # The durable running job can wait for control capacity.

    def _run(self, lease, job, step):
        try:
            self.sessions.open((lease, job, step))
        except Exception as exc:
            try:
                _, _, operations = self.repository.view(lease)
                if not operations:
                    code = "session_capacity" if isinstance(exc, CapacityRejected) else "session_prepare_failed"
                    self.repository.prepare_failed(lease, step["id"], code=code)
                else:
                    op = operations[0]
                    if op["dispatch_intent_at"] is None:
                        self.repository.cancel_undispatched(lease)
                    elif op["state"] in {"running", "unknown"}:
                        self.repository.block_operation(lease, op["id"], "session_open_unknown")
            except (JobLeaseLost, InvalidTransition):
                # The adapter or a newer generation already dispositioned the Job.
                pass

    def _prepare(self, request):
        lease, job, step = request
        flow = job["execution_snapshot"]["workflow"]
        entry = flow["entry"]
        instance, kind = entry["plugin_instance_id"], entry["session_type"]
        binding = self.repository.binding(lease, instance)
        plugin = self.services.registry.get(binding["plugin_key"])
        if (plugin.plugin_version, plugin.code_digest) != (binding["plugin_version"], binding["code_digest"]):
            raise PluginError("unavailable", "session plugin revision changed")
        deadline = Deadline.from_at(self.repository.start_prepare(lease, step["id"], OPEN_SECONDS))
        identity = str(step["id"]) + ":" + str(step["attempt"])

        def context(operation=None, prepared=None):
            return self.services.contexts.build(job_id=lease.job_id, plugin_instance_id=instance,
                step_instance_id=step["id"], operation_id=operation, invocation_key=identity,
                lease_token=lease.token, deadline=deadline, prepared=prepared)

        def prepare():
            plugin.validate_input(kind, entry["input"])
            prepared = plugin.implementation.prepare_session(kind, {
                "input": entry["input"], "target_ref": entry["target_ref"], "credential_ref": entry["credential_ref"],
            }, context())
            if (not isinstance(prepared, PreparedCall) or prepared.action_key != kind
                    or prepared.target_ref != entry["target_ref"]
                    or prepared.to_dict()["secret_refs"] != [entry["credential_ref"]]
                    or prepared.execution_policy != ExecutionPolicy()):
                raise PluginError("protocol_error", "session preparation changed the authorized binding")
            return prepared

        call = self.capacity.submit(instance, prepare, deadline_at=deadline.expires_at)
        prepared = call.result(timeout=deadline.check())
        op = self.repository.commit_prepared(lease, step["id"], prepared, instance)
        return OpeningPlan(str(op["id"]), str(lease.job_id), str(job["environment_id"]), str(job["actor_id"]),
                           instance, entry["credential_ref"]["version_id"], flow["entry_key"], prepared,
                           plugin.implementation, context(op["id"], prepared), flow["resource_id"], kind), lease
