"""Template workflows over fixed admission snapshots and PostgreSQL execution facts."""
from collections import defaultdict
from uuid import uuid4

from sqlalchemy import text

from .execution.adapters import LocalOutcomeApplicator, Projection
from .plugins.sdk import canonical_json
from .templates import expand_items, order_steps, resolve


def _group_steps(steps):
    grouped = defaultdict(list)
    for step in steps:
        grouped[step["step_path"]].append(step)
    return grouped


def _completed(rows, *, allow_skipped=True):
    accepted = {"succeeded", "skipped"} if allow_skipped else {"succeeded"}
    return bool(rows) and all(s["state"] in accepted for s in rows)


def _context(flow, grouped, item_key=None):
    # Unexpanded steps expose a single output; expanded steps expose the stable
    # key map, or the corresponding item inside another identically keyed loop.
    outputs = {}
    for path, rows in grouped.items():
        matching = next((r for r in rows if item_key and r["item_key"] == item_key
                         and r["state"] == "succeeded"), None)
        if matching is not None:
            outputs[path] = {"output": matching["output"]}
        elif _completed(rows):
            if len(rows) == 1 and rows[0]["expansion"] is None:
                outputs[path] = {"output": rows[0]["output"]}
            elif not item_key:
                outputs[path] = {"output": {r["item_key"]: r["output"] for r in rows
                                            if r["state"] == "succeeded"}}
    context = {key: flow[key] for key in ("params", "action_params", "environment", "resource", "evidence")
               if flow.get(key) is not None}
    context["steps"] = outputs
    return context


def _step_refs(value):
    """Only future step references may postpone a mapping; other errors fail closed."""
    if isinstance(value, dict):
        if set(value) == {"$ref"} and value["$ref"].startswith("steps."):
            yield value["$ref"].split(".")[1]
        else:
            for child in value.values():
                yield from _step_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from _step_refs(child)


def lock_evidence_environment(uow, job_id):
    """Serialize source evidence and cleanup on a stable row, including old jobs."""
    uow.execute(text("""
        SELECT e.id FROM control_plane.jobs j JOIN control_plane.environments e ON e.id=j.environment_id
        WHERE j.id=:job FOR UPDATE OF e
    """), {"job": job_id}).one()


def verify_cleanup_evidence(uow, job, flow):
    # A late report can change the target even if its original Operation is
    # terminal. Compare every historical Operation, including new ones, while
    # the environment scope is held. Never use another environment's evidence.
    # New evidence takes the same environment lock before insertion. Use two
    # statements so READ COMMITTED sees facts committed while waiting.
    lock_evidence_environment(uow, job["id"])
    rows = uow.execute(text("""
        SELECT o.id,o.state,count(e.id) AS revision
        FROM control_plane.jobs j JOIN control_plane.operations o ON o.job_id=j.id
        LEFT JOIN control_plane.operation_evidence e ON e.operation_id=o.id
        WHERE j.environment_id=:env AND j.id<>:job
        GROUP BY o.id,o.state
    """), {"env": job["environment_id"], "job": job["id"]})
    revisions = {}
    for row in rows:
        if row.state not in ("succeeded", "failed", "cancelled"):
            raise ValueError("cleanup overlaps unresolved external execution")
        revisions[str(row.id)] = row.revision
    if revisions != flow["evidence"]["revisions"]:
        raise ValueError("cleanup evidence changed after admission")


def _requirements(requirements, context, grouped, slots, *, allow_skipped=True):
    if any(not _completed(grouped.get(key), allow_skipped=allow_skipped)
           for key in requirements.get("require_steps", ())):
        return False
    if not set(requirements.get("require_resources", ())).issubset(slots):
        return False
    for condition in requirements.get("conditions", ()):
        if isinstance(condition, dict) and set(condition) == {"equals"}:
            left, right = resolve(condition["equals"], context)
            if canonical_json(left) != canonical_json(right):
                return False
        elif resolve(condition, context) is not True:
            return False
    return True


def _observe_state(uow, job, state, ttl_seconds):
    resource_id = job["input"].get("resource_id")
    uow.execute(text("""
        INSERT INTO control_plane.audit_events(actor_id,environment_id,job_id,resource_id,action,result,data)
        VALUES (:actor,:env,:job,:resource,:action,'observed',CAST(:data AS jsonb))
    """), {"actor": job["actor_id"], "env": job["environment_id"], "job": job["id"], "resource": resource_id,
           "action": "resource.state_observed" if resource_id else "environment.state_observed",
           "data": canonical_json({"state": state, "ttl_seconds": ttl_seconds})})


def resource_state(uow, resource_id):
    """Read the most recent confirmed observation and apply its database-clock TTL."""
    row = uow.execute(text("""
        SELECT data,created_at,
               created_at + ((data->>'ttl_seconds')::int * interval '1 second') > clock_timestamp() AS fresh
        FROM control_plane.audit_events WHERE resource_id=:resource AND action='resource.state_observed'
        ORDER BY created_at DESC,id DESC LIMIT 1
    """), {"resource": resource_id}).first()
    return {"state": row.data["state"] if row and row.fresh else "unknown",
            "observed_at": row.created_at if row else None, "fresh": bool(row and row.fresh)}


class TemplateWorkflow:
    """Serial topological planning, durable expansion and local result application."""

    def plan_steps(self, snapshot, steps):
        flow = snapshot["workflow"]
        grouped = _group_steps(steps)
        context = _context(flow, grouped)
        for definition in order_steps(flow["steps"]):
            path = definition["id"]
            if path in grouped:
                if _completed(grouped[path]):
                    continue
                return []  # Observe existing expansion. Never query or re-expand it.
            loop = definition.get("for_each")
            items = expand_items(loop, context)
            if len(steps) + max(1, len(items)) > 1000:
                raise ValueError("workflow exceeds maximum expanded step count")
            if not items:
                return [{"step_path": path, "state": "skipped", "expansion": [], "input": {}}]
            planned = []
            for key, item in items:
                item_context = _context(flow, grouped, key)
                if loop is not None:
                    item_context["item"] = item
                arguments = {
                    "plugin_instance_id": flow["instances"][definition["plugin_instance"]],
                    "action_key": definition["action"],
                    "input": resolve(definition["input"], item_context),
                }
                if "timeout_seconds" in definition:
                    arguments["timeout_seconds"] = definition["timeout_seconds"]
                planned.append({"step_path": path, "item_key": key, "input": arguments,
                                "expansion": {"item": item} if loop is not None else None})
            return planned
        return []

    def project(self, operation, result):
        # The repository validates the output and commits safe raw evidence first.
        # The same immutable result reaches apply() during explicit local replay.
        return result.output

    @staticmethod
    def _facts(uow, job_id):
        rows = uow.execute(text("""
            SELECT * FROM control_plane.job_steps WHERE job_id=:job ORDER BY step_path,item_key
        """), {"job": job_id})
        return _group_steps(rows.mappings())

    def _map_resources(self, uow, job, flow, grouped, completing_operation_id):
        context = _context(flow, grouped)
        rows = uow.execute(text("""
            SELECT * FROM control_plane.local_resource_items
            WHERE environment_id=:env AND logical_invocation_id=:invocation
        """), {"env": job["environment_id"], "invocation": job["logical_invocation_id"]})
        existing = {(r.resource_slot, r.item_key): r for r in rows}
        count = 0
        for spec in flow["resources"]:
            loop = spec.get("for_each")
            if not set(_step_refs(loop)).issubset(context["steps"]):
                continue
            for key, item in expand_items(loop, context):
                count += 1
                if count > 1000:
                    raise ValueError("resource expansion exceeds limit")
                previous = existing.get((spec["key"], key))
                if previous is not None and previous.state == "completed":
                    continue
                item_context = _context(flow, grouped, key)
                if loop is not None:
                    item_context["item"] = item
                mapping = {k: spec[k] for k in ("name", "type_label", "data", "display", "target_ref") if k in spec}
                refs = set(_step_refs(mapping))
                available = refs.issubset(item_context["steps"])
                # Each item in a resource loop belongs to its own producing
                # Operation, even when several rows were expanded in one tick.
                inputs = [row for ref in sorted(refs | set(_step_refs(loop))) for row in grouped.get(ref, ())
                          if row["state"] == "succeeded" and (not key or row["item_key"] in ("", key))]
                producers = [row for row in inputs if row["step_path"] in refs] if refs else inputs
                if refs and not previous and not producers:
                    continue
                # Keep the original provenance even if a later success supplies the
                # last argument. A new source Operation must never duplicate the slot.
                source = (previous.source_operation_id if previous else
                          producers[0]["current_operation_id"] if producers else completing_operation_id)
                if source is None:
                    continue  # A skipped step cannot supply a source Operation.
                local_id = previous.id if previous else uuid4()
                facts = {"id": local_id, "resource_slot": spec["key"], "item_key": key,
                         "confirmed_input_refs": {"source_operation_id": str(source)},
                         "state": "completed" if available else "pending"}
                resources = ()
                if available:
                    product = resolve(mapping, item_context)
                    product.update(resource_slot=spec["key"], item_key=key, local_resource_item_id=local_id,
                                   action_snapshot=spec.get("actions", {}), access_snapshot=spec.get("access", {}))
                    facts["data"] = {"input_operations": [str(row["current_operation_id"]) for row in inputs],
                                     "resource_data": product["data"]}
                    resources = (product,)
                provenance = {"id": source, "job_id": job["id"], "environment_id": job["environment_id"],
                              "logical_invocation_id": job["logical_invocation_id"]}
                LocalOutcomeApplicator.write_products(uow, provenance, Projection(resources=resources, local_items=(facts,)))

    def apply(self, uow, operation, output):
        job = uow.execute(text("SELECT * FROM control_plane.jobs WHERE id=:job"),
                          {"job": operation["job_id"]}).mappings().one()
        flow = job["execution_snapshot"]["workflow"]
        grouped = self._facts(uow, job["id"])
        complete = all(_completed(grouped.get(step["id"])) for step in flow["steps"])
        if flow["kind"] == "create":
            context = _context(flow, grouped)
            step = next(r for rows in grouped.values() for r in rows if r["id"] == operation["step_id"])
            path = step["step_path"]
            if path in context["steps"]:
                LocalOutcomeApplicator.write_products(uow, operation, Projection(create_results={
                    path: context["steps"][path]["output"]}))
            confirmation = flow["readiness"].get("credential_confirmation")
            if confirmation and confirmation["step"] == path:
                from .credentials import confirm_from_operation
                expected = resolve(confirmation["credential"], context)
                if (not isinstance(output, dict) or output.get("confirmed_environment_credential") != expected
                        or not confirm_from_operation(uow, operation["id"])):
                    raise ValueError("environment credential setup was not confirmed")
            if not complete:
                self._map_resources(uow, job, flow, grouped, operation["id"])
        if complete:
            self.finish(uow, job, grouped, completing_operation_id=operation["id"])

    def finish(self, uow, job, grouped=None, *, completing_operation_id=None):
        from .quota import finish_quota
        flow = job["execution_snapshot"]["workflow"]
        grouped = self._facts(uow, job["id"]) if grouped is None else grouped
        if any(not _completed(grouped.get(step["id"])) for step in flow["steps"]):
            raise ValueError("workflow still has incomplete definitions")
        kind = flow["kind"]
        context = _context(flow, grouped)
        values = {"job": job["id"], "env": job["environment_id"], "group": job["execution_group_id"],
                  "actor": job["actor_id"], "lifecycle": None}
        success = True
        if kind == "create":
            # A trailing empty expansion can resolve pending mappings without a
            # plugin callback. Apply local products before evaluating readiness.
            self._map_resources(uow, job, flow, grouped, completing_operation_id)
            rows = uow.execute(text("""
                SELECT resource_slot,item_key,state FROM control_plane.local_resource_items
                WHERE environment_id=:env AND logical_invocation_id=:invocation
            """), {**values, "invocation": job["logical_invocation_id"]}).all()
            slots = {row.resource_slot for row in rows if row.state == "completed"}
            success = all(row.state == "completed" for row in rows)
            # Each declared, non-empty expansion must have a confirmed source.
            completed_keys = {(r.resource_slot, r.item_key) for r in rows if r.state == "completed"}
            for spec in flow["resources"]:
                for key, _ in expand_items(spec.get("for_each"), context):
                    if (spec["key"], key) not in completed_keys:
                        success = False
            success = success and _requirements(flow["readiness"], context, grouped, slots)
            values["lifecycle"] = "ready" if success else "create_failed"
            finish_quota(uow, values["env"], disposition="allocated" if success else "quarantined")
        elif kind == "cleanup":
            verify_cleanup_evidence(uow, job, flow)
            completion = flow["completion"]
            # An empty expansion advances planning but proves no remote cleanup.
            success = bool(completion) and _requirements(completion, context, grouped, set(), allow_skipped=False)
            if not flow["steps"]:
                success = success and completion.get("no_external_cleanup_required") is True
            values["lifecycle"] = "deleted" if success else "delete_failed"
            finish_quota(uow, values["env"], disposition="released" if success else "quarantined")
        elif kind == "action" and flow.get("state_mapping"):
            mapping = flow["state_mapping"]
            state = resolve(mapping["value"], context)
            if not isinstance(state, str) or not state:
                raise ValueError("invalid observed state")
            _observe_state(uow, job, state, mapping["ttl_seconds"])
        elif kind not in {"action", "session_open"}:
            raise ValueError("unknown workflow kind")
        if values["lifecycle"]:
            uow.execute(text("""
                UPDATE control_plane.environments SET lifecycle=:lifecycle,updated_at=clock_timestamp(),
                deleted_at=CASE WHEN :lifecycle='deleted' THEN clock_timestamp() ELSE deleted_at END
                WHERE id=:env
            """), values)
        if success:
            unresolved = uow.scalar(text("""
                SELECT EXISTS(SELECT 1 FROM control_plane.operations o JOIN control_plane.jobs j ON j.id=o.job_id
                              WHERE j.execution_group_id=:group AND o.state NOT IN ('succeeded','failed','cancelled'))
            """), values)
            if unresolved:
                raise ValueError("unresolved operations retain their conflicts")
            uow.execute(text("""
                UPDATE control_plane.conflict_protections SET released_at=clock_timestamp()
                WHERE execution_group_id=:group AND released_at IS NULL
            """), values)
        values.update(group_state="released" if success else "blocked", job_state="succeeded" if success else "failed")
        uow.execute(text("""
            UPDATE control_plane.execution_groups SET state=:group_state,updated_at=clock_timestamp() WHERE id=:group
        """), values)
        uow.execute(text("""
            UPDATE control_plane.jobs SET state=:job_state,finished_at=clock_timestamp(),updated_at=clock_timestamp()
            WHERE id=:job
        """), values)
        uow.execute(text("""
            INSERT INTO control_plane.audit_events(actor_id,environment_id,job_id,action,result,data)
            VALUES (:actor,:env,:job,'workflow.complete',:job_state,CAST(:data AS jsonb))
        """), {**values, "data": canonical_json({"kind": kind, "lifecycle": values["lifecycle"]})})


def record_interruption(uow, job, *, blocked, cancelled=False):
    """Preserve ownership and partial outputs across failures, blocks, and cancellations."""
    from .quota import finish_quota
    flow = job["execution_snapshot"]["workflow"]
    kind = flow["kind"]
    values = {"env": job["environment_id"], "group": job["execution_group_id"], "job": job["id"],
              "actor": job["actor_id"]}
    # Creation owns the original reservation. A later action owns its
    # execution group's scope; earlier environment creation is not its effect.
    # Include every job in the group so a continuation cannot discard earlier
    # dispatches merely because its own request was stopped before dispatch.
    effects = uow.execute(text("""
        SELECT count(*) > 0 AS dispatched,
               count(*) FILTER (WHERE o.state IN ('running','pending_external','unknown','failed','cancelled')
                   AND o.prepared_call #>> '{execution_policy,effect}' IS DISTINCT FROM 'read_only') > 0 AS uncertain
        FROM control_plane.operations o JOIN control_plane.jobs j ON j.id=o.job_id
        WHERE j.environment_id=:env AND (:creation OR j.execution_group_id=:group)
          AND o.dispatch_intent_at IS NOT NULL
    """), {**values, "creation": kind == "create"}).one()
    release_creation = kind == "create" and not effects.dispatched
    release_scope = (release_creation or (kind == "action" and not effects.dispatched)
                     or (kind == "session_open" and not blocked))
    if kind in ("create", "cleanup"):
        values["state"] = "blocked" if blocked else {"create": "create_failed", "cleanup": "delete_failed"}[kind]
        uow.execute(text("""
            UPDATE control_plane.environments SET lifecycle=:state,updated_at=clock_timestamp() WHERE id=:env
        """), values)
    if kind == "action" and effects.dispatched and flow.get("state_mapping"):
        _observe_state(uow, job, "unknown", flow["state_mapping"]["ttl_seconds"])
    if kind in ("create", "cleanup") or (kind != "session_open" and effects.uncertain):
        finish_quota(uow, values["env"], disposition="released" if release_creation else "quarantined")
    if release_scope:
        uow.execute(text("""
            UPDATE control_plane.conflict_protections SET released_at=clock_timestamp()
            WHERE execution_group_id=:group AND released_at IS NULL
        """), values)
    uow.execute(text("""
        UPDATE control_plane.execution_groups SET state=:group_state,updated_at=clock_timestamp() WHERE id=:group
    """), {**values, "group_state": "released" if release_scope else "blocked"})
    uow.execute(text("""
        INSERT INTO control_plane.audit_events(actor_id,environment_id,job_id,action,result)
        VALUES (:actor,:env,:job,'workflow.interrupted',:result)
    """), {**values, "result": "cancelled" if cancelled else ("blocked" if blocked else "failed")})
