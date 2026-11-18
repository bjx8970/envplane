"""P3 integration seams. No implicit business authorizer or fake production policy."""
from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol


class AdapterUnavailable(RuntimeError):
    pass


class AdmissionPolicy(Protocol):
    def authorize_and_reserve(self, uow, fixed_request: Mapping[str, Any]): ...


class WorkflowPlanner(Protocol):
    def plan(self, snapshot, confirmed_outputs): ...


class ResultProjector(Protocol):
    """Pure, bounded local mapping; MUST NOT call plugins or perform external I/O."""
    def project(self, operation, result): ...


@dataclass(frozen=True)
class Projection:
    """Confirmed local products. Identity comes from the Operation, never a plugin."""
    create_results: Mapping[str, Any] = field(default_factory=dict)
    resources: tuple = ()
    local_items: tuple = ()
    lifecycle: str | None = None
    job_complete: bool = False
    release_conflicts: bool = False
    quota_facts: Mapping[str, Any] = field(default_factory=dict)


class OutcomeApplicator(Protocol):
    """Trusted bounded local DML in the same fenced transaction as Step success.

    Must re-evaluate readiness/quota disposition from confirmed facts. No external
    I/O, transaction control, inference of cleanup, or automatic compensation.
    """
    def apply(self, uow, operation, projection: Projection): ...


class UnavailableAdapter:
    """Default production wiring fails closed until a P3 business adapter exists."""
    def _unavailable(self, *args, **kwargs):
        raise AdapterUnavailable("business execution adapter is not configured")

    authorize_and_reserve = plan = project = apply = _unavailable


UNAVAILABLE = UnavailableAdapter()


class LocalOutcomeApplicator:
    """Generic local product writer, with mandatory explicit lifecycle/quota policy.

    The injected policy is the only component allowed to decide environment
    readiness, conflict release or quota disposition. It runs inside this UoW.
    """
    def __init__(self, lifecycle_policy=UNAVAILABLE, quota_policy=UNAVAILABLE):
        self.lifecycle_policy = lifecycle_policy
        self.quota_policy = quota_policy

    @staticmethod
    def write_products(uow, operation, projection):
        if len(projection.resources) > 1000 or len(projection.local_items) > 1000:
            raise ValueError("bounded local projection required")
        if projection.release_conflicts and not projection.job_complete:
            raise ValueError("unfinished jobs cannot release their execution scope")
        from sqlalchemy import text
        from uuid import uuid4
        from ..plugins.sdk import canonical_json
        base = {"environment": operation["environment_id"],
                "invocation": operation["logical_invocation_id"],
                "job": operation["job_id"], "operation": operation["id"]}
        if projection.create_results:
            # Conflicting keys must never overwrite a previously confirmed output.
            current = uow.scalar(text("SELECT create_results FROM control_plane.environments WHERE id=:environment FOR UPDATE"), base)
            for key, value in projection.create_results.items():
                if key in current and current[key] != value:
                    raise ValueError("confirmed output identity conflict")
            uow.execute(text("UPDATE control_plane.environments SET create_results=create_results || CAST(:data AS jsonb),updated_at=clock_timestamp() WHERE id=:environment"),
                        {**base, "data": canonical_json(dict(projection.create_results))})
        for item in projection.local_items:
            uow.execute(text("""
                INSERT INTO control_plane.local_resource_items
                  (id,environment_id,logical_invocation_id,resource_slot,item_key,
                   source_job_id,source_operation_id,confirmed_input_refs,data,state)
                VALUES (:id,:environment,:invocation,:slot,:item,:job,:operation,
                        CAST(:refs AS jsonb),CAST(:data AS jsonb),:state)
                ON CONFLICT(environment_id,logical_invocation_id,resource_slot,item_key) DO NOTHING
            """), {**base, "id": item.get("id", uuid4()), "slot": item["resource_slot"], "item": item.get("item_key", ""),
                    "refs": canonical_json(item["confirmed_input_refs"]),
                    "data": canonical_json(item.get("data", {})), "state": item.get("state", "pending")})
            existing = uow.execute(text("SELECT * FROM control_plane.local_resource_items WHERE environment_id=:environment AND logical_invocation_id=:invocation AND resource_slot=:slot AND item_key=:item FOR UPDATE"),
                                   {**base, "slot": item["resource_slot"], "item": item.get("item_key", "")}).one()
            if (str(existing.source_operation_id) != str(operation["id"])
                    or existing.confirmed_input_refs != item["confirmed_input_refs"]):
                raise ValueError("local product provenance conflict")
            if existing.state == "completed" and (existing.data != item.get("data", {}) or item.get("state", "pending") != "completed"):
                raise ValueError("completed local product is immutable")
            if existing.state != "completed":
                uow.execute(text("UPDATE control_plane.local_resource_items SET state=:state,data=CAST(:data AS jsonb),updated_at=clock_timestamp() WHERE id=:id"),
                            {"id": existing.id, "state": item.get("state", "pending"), "data": canonical_json(item.get("data", {}))})
        for resource in projection.resources:
            uow.execute(text("""
                INSERT INTO control_plane.experiment_resources
                  (id,environment_id,logical_invocation_id,resource_slot,item_key,source_job_id,
                   source_operation_id,local_resource_item_id,name,type_label,display,data,
                   target_ref,action_snapshot,access_snapshot)
                VALUES (:id,:environment,:invocation,:slot,:item,:job,:operation,:local,:name,:type,
                        CAST(:display AS jsonb),CAST(:data AS jsonb),CAST(:target AS jsonb),
                        CAST(:actions AS jsonb),CAST(:access AS jsonb))
                ON CONFLICT(environment_id,logical_invocation_id,resource_slot,item_key) DO NOTHING
            """), {**base, "id": uuid4(), "slot": resource["resource_slot"], "item": resource.get("item_key", ""),
                    "local": resource.get("local_resource_item_id"), "name": resource["name"],
                    "type": resource["type_label"], "display": canonical_json(resource.get("display", {})),
                    "data": canonical_json(resource["data"]), "target": canonical_json(resource.get("target_ref")),
                    "actions": canonical_json(resource.get("action_snapshot", {})),
                    "access": canonical_json(resource.get("access_snapshot", {}))})
            existing = uow.execute(text("SELECT * FROM control_plane.experiment_resources WHERE environment_id=:environment AND logical_invocation_id=:invocation AND resource_slot=:slot AND item_key=:item FOR UPDATE"),
                                   {**base, "slot": resource["resource_slot"], "item": resource.get("item_key", "")}).one()
            expected = {"name": resource["name"], "type_label": resource["type_label"],
                        "data": resource["data"], "display": resource.get("display", {}),
                        "target_ref": resource.get("target_ref"),
                        "action_snapshot": resource.get("action_snapshot", {}),
                        "access_snapshot": resource.get("access_snapshot", {})}
            if (str(existing.source_operation_id) != str(operation["id"])
                    or any(canonical_json(existing._mapping[key]) != canonical_json(value) for key, value in expected.items())):
                raise ValueError("resource logical identity or target conflict")

    def apply(self, uow, operation, projection):
        from sqlalchemy import text
        base = {"group": operation["execution_group_id"], "job": operation["job_id"]}
        self.write_products(uow, operation, projection)
        self.lifecycle_policy.apply(uow, operation, projection)
        self.quota_policy.apply(uow, operation, projection.quota_facts)
        if projection.release_conflicts:
            # Policy must first verify the absence of unresolved external facts.
            if uow.scalar(text("SELECT count(*) FROM control_plane.operations o JOIN control_plane.jobs j ON j.id=o.job_id WHERE j.execution_group_id=:group AND o.state IN ('running','pending_external','unknown')"),
                          {"group": operation["execution_group_id"]}):
                raise ValueError("unresolved operations retain conflict protection")
            uow.execute(text("UPDATE control_plane.conflict_protections SET released_at=clock_timestamp() WHERE execution_group_id=:group AND released_at IS NULL"),
                        {"group": operation["execution_group_id"]})
            uow.execute(text("UPDATE control_plane.execution_groups SET state='released',updated_at=clock_timestamp() WHERE id=:group"),
                        {"group": operation["execution_group_id"]})
            # Keep the observed revision through Repository's final job guard;
            # a released group and terminal Job cannot be revived by this lease.
        if projection.job_complete:
            uow.execute(text("UPDATE control_plane.jobs SET state='succeeded',finished_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=:job"), base)


def admit_request(uow, fixed_request, *, admission=UNAVAILABLE):
    """Admission adapter owns authorization, immutable snapshots and quota atomically.

    Lock request identity *before* policy execution so a duplicate cannot reserve
    twice. The adapter must call persistence.admit_job in this same UoW and return
    that Job id. No new environment, snapshot or quota is created on a duplicate.
    """
    from sqlalchemy import text
    from ..coordination import require_fenced_connection
    from ..persistence import RequestConflict
    require_fenced_connection(uow)
    actor, key = fixed_request["actor_id"], fixed_request["request_key"]
    uow.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:identity,0))"),
                {"identity": str(actor) + ":" + key})
    existing = uow.execute(text("SELECT id,request_digest FROM control_plane.jobs WHERE actor_id=:actor AND request_key=:key"),
                           {"actor": actor, "key": key}).first()
    if existing:
        if existing.request_digest != fixed_request["request_digest"]:
            raise RequestConflict("request key is already associated with a different request")
        return existing.id, True
    return admission.authorize_and_reserve(uow, fixed_request), False
