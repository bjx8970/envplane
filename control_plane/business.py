"""Template-bound P3 business admission. All authoritative writes share one fenced UoW."""
from uuid import UUID, uuid4

from sqlalchemy import text

from .admission import AdmissionController
from .execution.repository import ExecutionConflict
from .identity import can_access_environment, can_manage_course, can_read_environment_status
from .persistence import RequestConflict, admit_job
from .plugins.sdk import AuthorizationDenied, ReferenceUnavailable, canonical_json, json_digest
from .quota import check_available, reserve, set_limits
from .templates import TemplateError, load_version, quota_cost, validate_parameters
from .workflows import cleanup_evidence_context


def instance_binding(uow, alias):
    """Accept a deployment alias or canonical UUID. Ambiguity fails closed."""
    rows = uow.execute(text("""
        SELECT id,plugin_key FROM control_plane.plugin_instances
        WHERE enabled AND (instance_alias=:alias OR id::text=:alias) FOR SHARE
    """), {"alias": alias}).all()
    if len(rows) != 1:
        raise ReferenceUnavailable("template plugin instance is unavailable")
    return str(rows[0].id), rows[0].plugin_key


def _identifier(value):
    return str(UUID(str(value)))


def _evidence(uow, environment):
    """Collect bounded immutable source identities. Pending remote calls retain their scope."""
    jobs = uow.execute(text("""
        SELECT id,kind,execution_group_id,state,execution_snapshot FROM control_plane.jobs
        WHERE environment_id=:env ORDER BY created_at,id LIMIT 1001
    """), {"env": environment}).all()
    if len(jobs) > 1000 or any(j.state in ("queued", "running", "cancel_requested") for j in jobs):
        raise ExecutionConflict("cleanup requires a bounded, quiescent execution history")
    create = next((j for j in jobs if j.kind == "create"), None)
    if create is None:
        raise ExecutionConflict("cleanup source creation is unavailable")
    snapshot = {
        "snapshot_id": str(uuid4()), "execution_group_id": str(create.execution_group_id),
        "source_job_ids": [str(j.id) for j in jobs], "revisions": {}, "jobs": {}, "steps": {},
    }
    for job in jobs:
        definitions = job.execution_snapshot.get("workflow", {}).get("steps", ())
        snapshot["jobs"][str(job.id)] = {item["id"]: {} for item in definitions}
    steps = uow.execute(text("""
        SELECT s.job_id,s.step_path,s.item_key FROM control_plane.job_steps s
        JOIN control_plane.jobs j ON j.id=s.job_id WHERE j.environment_id=:env LIMIT 1001
    """), {"env": environment}).all()
    if len(steps) > 1000:
        raise ExecutionConflict("cleanup step history exceeds the supported bound")
    for step in steps:
        indexed = snapshot["jobs"][str(step.job_id)].setdefault(step.step_path, {})
        indexed[step.item_key] = {"operations": []}
    operations = uow.execute(text("""
        SELECT o.id,o.job_id,o.attempt,o.state,o.prepared_call->'target_ref' AS target_ref,
               o.external_execution_ref,o.updated_at,s.step_path,s.item_key
        FROM control_plane.operations o JOIN control_plane.job_steps s ON s.id=o.step_id
        JOIN control_plane.jobs j ON j.id=o.job_id WHERE j.environment_id=:env
        ORDER BY o.job_id,s.step_path,s.item_key,o.attempt,o.id LIMIT 1001
    """), {"env": environment}).all()
    if len(operations) > 1000 or any(o.state in ("prepared", "running", "pending_external", "unknown") for o in operations):
        raise ExecutionConflict("cleanup requires confirmed, bounded operation evidence")
    entries = uow.execute(text("""
        SELECT e.operation_id,e.kind,e.ref_key,e.data,e.revision,e.created_at
        FROM control_plane.operation_evidence e JOIN control_plane.operations o ON o.id=e.operation_id
        JOIN control_plane.jobs j ON j.id=o.job_id WHERE j.environment_id=:env
        ORDER BY e.operation_id,e.kind,e.ref_key,e.revision LIMIT 1001
    """), {"env": environment}).all()
    if len(entries) > 1000:
        raise ExecutionConflict("cleanup evidence exceeds the supported bound")
    by_id = {}
    for op in operations:
        fact = {"operation_id": str(op.id), "attempt": op.attempt, "state": op.state, "target_ref": op.target_ref,
                "external_execution_ref": op.external_execution_ref,
                "external_refs": {}, "checkpoints": {}, "confirmed_at": op.updated_at.isoformat()}
        by_id[str(op.id)] = fact
        snapshot["revisions"][str(op.id)] = 0
        snapshot["jobs"][str(op.job_id)][op.step_path][op.item_key]["operations"].append(fact)
    for entry in entries:
        key = str(entry.operation_id)
        snapshot["revisions"][key] += 1
        if entry.kind in ("external_ref", "checkpoint"):
            section = "external_refs" if entry.kind == "external_ref" else "checkpoints"
            by_id[key][section][entry.ref_key] = {
                "reference": entry.data, "revision": entry.revision, "observed_at": entry.created_at.isoformat(),
            }
    snapshot["steps"] = snapshot["jobs"].get(str(create.id), {})
    return snapshot


def _group(uow, environment_id, kind, source_group=None):
    scope = "environment:" + str(environment_id)
    args = {"env": environment_id, "scope": scope}
    held = uow.execute(text("""
        SELECT g.id,g.current_job_id,j.state AS job_state FROM control_plane.conflict_protections p
        JOIN control_plane.execution_groups g ON g.id=p.execution_group_id
        LEFT JOIN control_plane.jobs j ON j.id=g.current_job_id
        WHERE p.scope_key=:scope AND p.released_at IS NULL AND g.environment_id=:env
        FOR UPDATE OF g,p
    """), args).first()
    if held is not None:
        if kind != "cleanup" or held.job_state not in ("failed", "cancelled", "blocked"):
            raise ExecutionConflict("environment already has an execution in progress")
        # Cleanup inherits all held scopes and advances the generation. Old leases fail fencing.
        uow.execute(text("""
            UPDATE control_plane.execution_groups SET revision=revision+1,state='active',
                reason=NULL,updated_at=clock_timestamp() WHERE id=:id
        """), {"id": held.id})
        return held.id, held.current_job_id
    parent = None
    if kind == "cleanup":
        # Even after successful creation released the old scopes, a cleanup
        # continues its authoritative group and carries immutable parentage.
        previous = uow.execute(text("""
            SELECT id,current_job_id,state FROM control_plane.execution_groups
            WHERE id=:source AND environment_id=:env FOR UPDATE
        """), {**args, "source": source_group}).one()
        if previous.state != "released" or previous.current_job_id is None:
            raise ExecutionConflict("cleanup source group is unavailable")
        group, parent = previous.id, previous.current_job_id
        uow.execute(text("""
            UPDATE control_plane.execution_groups SET state='active',reason=NULL,revision=revision+1,
                updated_at=clock_timestamp() WHERE id=:group
        """), {"group": group})
    else:
        group = uow.scalar(text("""
            INSERT INTO control_plane.execution_groups(environment_id) VALUES (:env) RETURNING id
        """), args)
    uow.execute(text("""
        INSERT INTO control_plane.conflict_protections(scope_key,execution_group_id)
        VALUES (:scope,:group)
    """), {"scope": scope, "group": group})
    return group, parent


def _input_refs(expression, tail=()):
    """References whose *values* enter a step. Operators produce scalars, never grants."""
    if isinstance(expression, dict):
        if "$ref" in expression:
            yield tuple(expression["$ref"].split(".")) + tuple(tail)
        elif "$expr" not in expression:
            if tail:
                if tail[0] in expression:
                    yield from _input_refs(expression[tail[0]], tail[1:])
            else:
                for child in expression.values():
                    yield from _input_refs(child)
    elif isinstance(expression, list) and not tail:
        for child in expression:
            yield from _input_refs(child)


def _template_credentials(steps, instances, environment, resource, evidence=None):
    """Read the template-selected parts of fixed products; data is never evaluated as a template."""
    products = {("environment", "create_results"): environment["create_results"],
                ("resource", "data"): resource["data"] if resource else None,
                ("evidence",): cleanup_evidence_context(evidence) if evidence else None}
    requests, inspected = {}, set()
    # The same fixed collection may appear in many step inputs or expanded items.
    budget = 1_048_576
    count = 0

    def scan(instance, step, source, data):
        nonlocal budget
        budget -= len(source) + 1
        if budget < 0:
            raise TemplateError("credential input inspection exceeds the workflow bound")
        identity = (instance, step, source)
        if identity in inspected:
            return
        inspected.add(identity)
        trail = []

        def visit(value):
            nonlocal budget, count
            budget -= 1
            if budget < 0:
                raise TemplateError("credential input inspection exceeds the workflow bound")
            if isinstance(value, dict) and set(value) == {"secret_id", "version_id"}:
                count += 1
                # Charge repeated output paths before allocating or escaping them.
                budget -= len(source) + sum(2 * len(key) + 1 for key in trail)
                if count > 1000 or budget < 0:
                    raise TemplateError("too many template credential references")
                path = source + "".join("/" + key.replace("~", "~0").replace("/", "~1") for key in trail)
                requests.setdefault(instance, []).append({"step": step, "path": path, "ref": value})
                return
            if not isinstance(value, (dict, list)):
                return
            for key, child in (value.items() if isinstance(value, dict) else enumerate(value)):
                trail.append(str(key))
                visit(child)
                trail.pop()

        visit(data)

    def read(data, parts):
        for key in parts:
            if not isinstance(data, dict) or key not in data:
                raise TemplateError("referenced product is unavailable")
            data = data[key]
        return data

    def fixed(path):
        for prefix, value in products.items():
            if value is not None and path[:len(prefix)] == prefix:
                yield ".".join(path), read(value, path[len(prefix):])
            elif value is not None and path == prefix[:1]:
                yield ".".join(prefix), value

    for step in steps:
        instance, name = instances[step["plugin_instance"]], step["id"]
        refs = sorted(set(_input_refs(step["input"])))
        loop = step.get("for_each")
        item_refs = [p[1:] for p in refs if p[0] == "item"]
        if loop:
            items = loop["items"]
            if isinstance(items, list):
                if not items:
                    continue
                # Literal containers preserve only explicitly referenced portions.
                for item in items:
                    for tail in item_refs:
                        for path in _input_refs(item, tail):
                            for source, value in fixed(path):
                                scan(instance, name, source, value)
            elif isinstance(items, dict) and "$ref" in items:
                for source, values in fixed(tuple(items["$ref"].split("."))):
                    if not isinstance(values, list) or len(values) > loop["max_items"]:
                        raise TemplateError("invalid fixed credential expansion")
                    for index, item in enumerate(values):
                        for tail in item_refs:
                            path = f"{source}/{index}" + "".join("/" + part for part in tail)
                            scan(instance, name, path, read(item, tail))
                    if not values:
                        refs = []
        for path in refs:
            for source, value in fixed(path):
                scan(instance, name, source, value)
    return requests


def authorize_job(uow, job):
    workflow = job["execution_snapshot"].get("workflow")
    if not isinstance(workflow, dict):
        return False
    if job["kind"] == "cleanup":
        # Owners can replay a successful cleanup after it retires the environment.
        return can_read_environment_status(uow, job["actor_id"], job["environment_id"], manage=True)
    if job["kind"] == "create":
        return can_access_environment(uow, job["actor_id"], job["environment_id"], manage=True)
    if job["kind"] in ("environment_action", "resource_action"):
        return can_access_environment(uow, job["actor_id"], job["environment_id"], roles=workflow.get("roles", []))
    return False


class BusinessService:
    def __init__(self, services, selectors, *, max_pending_jobs):
        self.runtime = services.runtime
        self.registry = services.registry
        self.configuration = services.configuration
        self.secrets = services.secrets
        self.capacity = services.capacity
        self.selectors = selectors
        self._controller = AdmissionController(self.runtime, self.capacity, max_pending_jobs=max_pending_jobs,
                                               authorize=self._authorize, policy=self)

    def set_quota(self, actor_id, teacher_id, *, limits):
        with self.runtime.fenced_transaction() as uow:
            set_limits(uow, actor_id, teacher_id, limits)

    def list_candidates(self, actor_id, course_id, template_version_id):
        """Read teacher-visible options from a published template in the teacher's course."""
        from .templates import selector_options

        with self.runtime.fenced_transaction() as uow:
            if not can_manage_course(uow, actor_id, course_id):
                raise AuthorizationDenied()
            definition = load_version(uow, template_version_id, for_create=True)
            specs = definition["parameters"]
            instances = self._instances(uow, {"steps": []}, specs)
        candidates, _ = self.selectors.prepare(specs, instances)
        with self.runtime.fenced_transaction() as uow:
            if not can_manage_course(uow, actor_id, course_id):
                raise AuthorizationDenied()
            load_version(uow, template_version_id, for_create=True)
        return self.secrets.safe_json({key: selector_options(specs[key], rows) for key, rows in candidates.items()})

    def create_environment(self, actor_id, *, course_id, template_version_id, name, parameters, request_key):
        if not isinstance(name, str) or not name.strip() or len(name) > 255:
            raise ValueError("environment name is required")
        return self._submit(actor_id, request_key, {"kind": "create", "course_id": _identifier(course_id),
                            "template_version_id": _identifier(template_version_id), "name": name,
                            "parameters": parameters})

    def run_action(self, actor_id, *, environment_id, action_key, parameters, request_key, resource_id=None):
        if not isinstance(action_key, str) or not action_key or len(action_key) > 255:
            raise ValueError("action key is required")
        return self._submit(actor_id, request_key, {
            "kind": "resource_action" if resource_id is not None else "environment_action",
            "environment_id": _identifier(environment_id), "action_key": action_key, "parameters": parameters,
            "resource_id": _identifier(resource_id) if resource_id is not None else None})

    def cleanup(self, actor_id, *, environment_id, request_key):
        return self._submit(actor_id, request_key, {"kind": "cleanup", "environment_id": _identifier(environment_id)})

    def _authorize(self, uow, request):
        actor = request["actor_id"]
        old = uow.execute(text("""
            SELECT id,kind,actor_id,environment_id,execution_snapshot FROM control_plane.jobs
            WHERE actor_id=:actor_id AND request_key=:request_key
        """), request).mappings().first()
        if old is not None:
            return authorize_job(uow, old)
        if request["kind"] == "create":
            return can_manage_course(uow, actor, request["course_id"])
        return can_access_environment(uow, actor, request["environment_id"], manage=request["kind"] == "cleanup")

    def _context(self, uow, request):
        kind = request["kind"]
        if kind == "create":
            definition = load_version(uow, request["template_version_id"], for_create=True)
            return definition, definition["create"], definition["parameters"], None, None
        env = uow.execute(text("""
            SELECT id,name,template_version_id,parameters,create_results,lifecycle,owner_teacher_id,course_id
            FROM control_plane.environments WHERE id=:environment FOR UPDATE
        """), {"environment": request["environment_id"]}).one()
        definition = load_version(uow, env.template_version_id, for_create=False)
        if kind == "cleanup":
            if not definition.get("cleanup"):
                raise TemplateError("template has no cleanup workflow")
            return definition, definition["cleanup"], {}, env, None
        resource = None
        actions = definition["actions"]
        if kind == "resource_action":
            row = uow.execute(text("""
                SELECT id,data,display,target_ref,resource_slot,item_key,name,type_label,action_snapshot
                FROM control_plane.experiment_resources WHERE id=:id AND environment_id=:env FOR SHARE
            """), {"id": request["resource_id"], "env": env.id}).first()
            if row is None:
                raise AuthorizationDenied()
            resource = {"id": str(row.id), "name": row.name, "type_label": row.type_label, "data": row.data,
                        "display": row.display, "target_ref": row.target_ref, "resource_slot": row.resource_slot,
                        "item_key": row.item_key}
            actions = row.action_snapshot
        flow = actions.get(request["action_key"])
        if not flow or not can_access_environment(uow, request["actor_id"], env.id, roles=flow["roles"]):
            raise AuthorizationDenied()
        return definition, flow, flow["parameters"], env, resource

    def _instances(self, uow, flow, specs):
        aliases = {step["plugin_instance"] for step in flow["steps"]}
        aliases.update(spec["selector"]["plugin_instance"] for spec in specs.values() if "selector" in spec)
        bindings = {alias: instance_binding(uow, alias) for alias in sorted(aliases)}
        for step in flow["steps"]:
            plugin = self.registry.get(bindings[step["plugin_instance"]][1])
            if step["action"] not in plugin.manifest["actions"]:
                raise ReferenceUnavailable("declared action is unavailable")
        return {alias: binding[0] for alias, binding in bindings.items()}

    def _submit(self, actor_id, request_key, payload):
        if not isinstance(request_key, str) or not 1 <= len(request_key) <= 255:
            raise ValueError("bounded request key required")
        # The caller cannot provide trusted snapshots, selectors, authorization or idempotency digests.
        payload = self.secrets.safe_json(payload)
        request = {**payload, "actor_id": _identifier(actor_id), "request_key": request_key,
                   "request_digest": json_digest(payload)}
        with self.runtime.fenced_transaction() as uow:
            if not self._authorize(uow, request):
                raise AuthorizationDenied()
            existing = uow.execute(text("""
                SELECT * FROM control_plane.jobs WHERE actor_id=:actor_id AND request_key=:request_key
            """), request).mappings().first()
            if existing:
                if existing["request_digest"] != request["request_digest"]:
                    raise RequestConflict("request key has different content")
                return existing["id"], True
            _, flow, specs, _, _ = self._context(uow, request)
            instances = self._instances(uow, flow, specs)
        # A selector is trusted read-only plugin code; it never runs inside the admission transaction.
        candidates, versions = self.selectors.prepare(specs, instances)
        request.update(candidates=candidates, selector_versions=versions,
                       preview_instances=instances, plugin_instance_ids=tuple(instances.values()))
        return self._controller.submit(request)

    def authorize_and_reserve(self, uow, request):
        kind, actor = request["kind"], request["actor_id"]
        definition, flow, specs, env, resource = self._context(uow, request)
        instances = self._instances(uow, flow, specs)
        if instances != request["preview_instances"]:
            raise RequestConflict("plugin instance changed during selection")
        params = validate_parameters(specs, request.get("parameters", {}), selector_values=request["candidates"])
        if kind == "create":
            teacher = uow.scalar(text("""
                SELECT owner_teacher_id FROM control_plane.courses WHERE id=:id AND deleted_at IS NULL FOR SHARE
            """), {"id": request["course_id"]})
            if not teacher or not can_manage_course(uow, actor, request["course_id"]):
                raise AuthorizationDenied()
            cost = quota_cost(definition, params)
            check_available(uow, teacher, cost)
            version = request["template_version_id"]
            environment = uow.scalar(text("""
                INSERT INTO control_plane.environments(owner_teacher_id,course_id,created_by,template_version_id,name,parameters)
                VALUES (:teacher,:course,:actor,:version,:name,CAST(:params AS jsonb)) RETURNING id
            """), {"teacher": teacher, "course": request["course_id"], "actor": actor, "version": version,
                   "name": request["name"], "params": canonical_json(params)})
        else:
            environment, version = env.id, env.template_version_id
            if kind != "cleanup" and env.lifecycle != "ready":
                raise ExecutionConflict("environment is not ready for actions")
        evidence = _evidence(uow, environment) if kind == "cleanup" else {}
        group, parent = _group(uow, environment, kind, evidence.get("execution_group_id"))
        if kind == "cleanup":
            uow.execute(text("""
                UPDATE control_plane.environments SET lifecycle='deleting',updated_at=clock_timestamp()
                WHERE id=:env
            """), {"env": environment})
        environment_context = {"id": str(environment), "name": request["name"] if kind == "create" else env.name,
                               "create_results": {} if kind == "create" else env.create_results}
        inherited = {} if kind == "create" else _template_credentials(
            flow["steps"], instances, environment_context, resource, evidence)
        captures = {}
        for instance_id in sorted(set(instances.values())):
            self.capacity.check_admission(instance_id)
            captures[instance_id] = self.configuration.capture_in(
                uow, instance_id, self.secrets, environment, template_credentials=inherited.get(instance_id, ()))
        for alias, revisions in request["selector_versions"].items():
            pin = captures[instances[alias]]
            if (pin["configuration_revision"], pin["namespace_revision"]) != tuple(revisions):
                raise RequestConflict("selector view changed before admission")
        workflow = {
            "kind": kind if kind in ("create", "cleanup") else "action", "steps": flow["steps"],
            "params": params if kind == "create" else env.parameters,
            "action_params": params if kind.endswith("_action") else {}, "instances": instances,
            "environment": environment_context,
            "resource": resource, "evidence": evidence, "roles": flow.get("roles", []),
            "resources": definition["resources"] if kind == "create" else [],
            "readiness": definition["readiness"] if kind == "create" else {},
            "completion": flow.get("completion", {}), "state_mapping": flow.get("state_mapping"),
        }
        selections = {}
        for key, rows in request["candidates"].items():
            if key not in params:
                continue
            selector = specs[key]["selector"]
            selected = next(row for row in rows if canonical_json(row[selector["value_field"]]) == canonical_json(params[key]))
            selections[key] = {"instance_id": instances[selector["plugin_instance"]], "action": selector["action"],
                               "value": params[key], "label": selected[selector["label_field"]]}
        snapshot = self.secrets.safe_json({"workflow": workflow, "plugins": captures, "selections": selections,
                                           "template_version_id": str(version)})
        business_input = {k: request[k] for k in ("action_key", "resource_id", "parameters") if k in request}
        job, _ = admit_job(uow, actor_id=actor, request_key=request["request_key"], request_digest=request["request_digest"],
                           environment_id=environment, execution_group_id=group, logical_invocation_id=uuid4(),
                           kind=kind, input=business_input, execution_snapshot=snapshot, parent_job_id=parent)
        uow.execute(text("UPDATE control_plane.execution_groups SET current_job_id=:job WHERE id=:group"),
                    {"job": job, "group": group})
        for instance_id, capture in captures.items():
            self.configuration.bind_capture_in(uow, job, instance_id, capture, self.secrets)
        if kind == "create":
            reserve(uow, teacher, job, environment, cost)
        uow.execute(text("""
            INSERT INTO control_plane.audit_events(actor_id,environment_id,resource_id,job_id,template_version_id,action,result)
            VALUES (:actor,:env,:resource,:job,:version,:action,'admitted')
        """), {"actor": actor, "env": environment, "resource": request.get("resource_id"), "job": job,
               "version": version, "action": "environment." + kind})
        return job
