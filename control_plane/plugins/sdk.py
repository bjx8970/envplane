"""Plugin API v1 value types. Importing this module performs no I/O.

This is a contract for trusted Python plugins, not a sandbox. Only the core
constructs contexts and capabilities; persistent values contain references, never
SecretHandle objects or database handles.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
from time import monotonic
from typing import Any, Callable, Mapping, Protocol


class PluginError(RuntimeError):
    """Safe error: the core must not stringify vendor exceptions."""

    def __init__(self, code: str, message: str = "plugin operation unavailable", *, details=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}


class BudgetExceeded(PluginError):
    def __init__(self):
        super().__init__("timeout", "call budget exhausted")


class ReferenceUnavailable(PluginError):
    def __init__(self, message="fixed reference is unavailable"):
        super().__init__("unavailable", message)


class AuthorizationDenied(PluginError):
    def __init__(self):
        super().__init__("forbidden", "operation is not authorized")


def finite_json(value: Any, *, object_only=False, max_bytes=1048576, max_depth=32, max_items=1000):
    """Validate before encoding, so cyclic/deep data cannot exhaust serialization."""
    if object_only and not isinstance(value, dict):
        raise ValueError("JSON object required")
    stack = [(value, 1)]
    seen_nodes = 0
    while stack:
        item, depth = stack.pop()
        seen_nodes += 1
        if depth > max_depth or seen_nodes > max_bytes:
            raise ValueError("JSON limit exceeded")
        if item is None or isinstance(item, (str, bool, int)):
            if isinstance(item, str) and len(item) > max_bytes:
                raise ValueError("JSON limit exceeded")
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError("JSON numbers must be finite")
        elif isinstance(item, (list, dict)):
            if len(item) > max_items:
                raise ValueError("JSON collection limit exceeded")
            if isinstance(item, dict):
                if not all(isinstance(key, str) for key in item):
                    raise ValueError("JSON keys must be strings")
                stack.extend((child, depth + 1) for child in item.values())
            else:
                stack.extend((child, depth + 1) for child in item)
        else:
            raise ValueError("value is not finite JSON")
    encoded = json.dumps(value, allow_nan=False, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > max_bytes:
        raise ValueError("JSON size limit exceeded")
    return value


def canonical_json(value: Any) -> str:
    finite_json(value)
    return json.dumps(value, allow_nan=False, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def json_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Deadline:
    """UTC persistence boundary plus monotonic local waiting budget."""

    expires_at: datetime
    _end: float = field(repr=False)

    @classmethod
    def after(cls, seconds: float) -> "Deadline":
        if not isinstance(seconds, (int, float)) or isinstance(seconds, bool) or not math.isfinite(seconds) or seconds <= 0:
            raise ValueError("deadline must be finite and positive")
        return cls(datetime.now(timezone.utc) + timedelta(seconds=seconds), monotonic() + seconds)

    @classmethod
    def from_at(cls, expires_at: datetime) -> "Deadline":
        if expires_at.tzinfo is None:
            raise ValueError("deadline must be timezone aware")
        seconds = max(0.0, (expires_at - datetime.now(timezone.utc)).total_seconds())
        return cls(expires_at, monotonic() + seconds)

    def remaining(self) -> float:
        return max(0.0, self._end - monotonic())

    def check(self) -> float:
        remaining = self.remaining()
        if remaining <= 0:
            raise BudgetExceeded()
        return remaining

    @property
    def expired(self) -> bool:
        return self.remaining() <= 0


@dataclass(frozen=True)
class ExecutionPolicy:
    effect: str = "mutating"
    idempotency: str = "unsupported"
    recovery: str = "unsupported"
    cancellation: str = "unsupported"

    def __post_init__(self):
        for key, allowed in (("effect", ("read_only", "mutating")), ("idempotency", ("unsupported", "keyed")),
                             ("recovery", ("unsupported", "queryable")), ("cancellation", ("unsupported", "requestable"))):
            if getattr(self, key) not in allowed:
                raise ValueError("invalid execution policy")

    def to_dict(self):
        return {key: getattr(self, key) for key in ("effect", "idempotency", "recovery", "cancellation")}

    @classmethod
    def from_dict(cls, value):
        return cls(**dict(value))

    def validate_against(self, declared: "ExecutionPolicy"):
        """A prepared call may lose guarantees, never invent stronger ones."""
        if self.effect == "read_only" and declared.effect != "read_only":
            raise ValueError("prepare elevated execution guarantee")
        for key in ("idempotency", "recovery", "cancellation"):
            if getattr(self, key) != "unsupported" and getattr(self, key) != getattr(declared, key):
                raise ValueError("prepare elevated execution guarantee")
        return self


@dataclass(frozen=True)
class StorageRef:
    instance_id: str
    key: str
    version_id: str

    def to_dict(self):
        return {"instance_id": str(self.instance_id), "key": self.key, "version_id": str(self.version_id)}


@dataclass(frozen=True)
class SecretRef:
    secret_id: str
    version_id: str | None = None

    def to_dict(self):
        result = {"secret_id": str(self.secret_id)}
        if self.version_id is not None:
            result["version_id"] = str(self.version_id)
        return result


@dataclass(frozen=True)
class PreparedCall:
    action_key: str
    resolved_input: Any = field(default_factory=dict)
    target_ref: Any = field(default_factory=dict)
    storage_refs: tuple = ()
    secret_refs: tuple = ()
    conflict_keys: tuple[str, ...] = ()
    execution_policy: ExecutionPolicy = field(default_factory=ExecutionPolicy)

    def to_dict(self):
        def ref(value):
            return value.to_dict() if hasattr(value, "to_dict") else value
        result = {"action_key": self.action_key, "resolved_input": self.resolved_input,
                  "target_ref": self.target_ref, "storage_refs": [ref(v) for v in self.storage_refs],
                  "secret_refs": [ref(v) for v in self.secret_refs], "conflict_keys": list(self.conflict_keys),
                  "execution_policy": self.execution_policy.to_dict()}
        finite_json(result, object_only=True)
        return result

    @classmethod
    def from_dict(cls, value):
        return cls(action_key=value["action_key"], resolved_input=value.get("resolved_input", {}),
                   target_ref=value.get("target_ref", {}), storage_refs=tuple(value.get("storage_refs", ())),
                   secret_refs=tuple(value.get("secret_refs", ())), conflict_keys=tuple(value.get("conflict_keys", ())),
                   execution_policy=ExecutionPolicy.from_dict(value.get("execution_policy", {})))


@dataclass(frozen=True)
class SafeError:
    code: str
    message: str
    details: Mapping[str, Any] = field(default_factory=dict)
    retry_hint: str | None = None

    def to_dict(self):
        return {"code": self.code, "message": self.message, "details": dict(self.details), "retry_hint": self.retry_hint}


@dataclass(frozen=True)
class ExecutionResult:
    outcome: str
    output: Any = None
    external_execution_ref: Any = None
    external_refs: tuple = ()
    checkpoints: tuple = ()
    error: SafeError | Mapping | None = None
    protocol_error: Mapping | None = None

    def __post_init__(self):
        if self.outcome not in ("succeeded", "failed", "pending_external", "unknown"):
            raise ValueError("invalid execution outcome")
        if self.outcome != "succeeded" and self.output is not None:
            raise ValueError("only successful results carry output")

    def to_dict(self):
        result = {"outcome": self.outcome, "output": self.output, "external_execution_ref": self.external_execution_ref,
                  "external_refs": list(self.external_refs), "checkpoints": list(self.checkpoints),
                  "error": self.error.to_dict() if hasattr(self.error, "to_dict") else self.error,
                  "protocol_error": self.protocol_error}
        finite_json(result, object_only=True)
        return result

    @classmethod
    def from_dict(cls, value):
        return cls(**value)


@dataclass(frozen=True)
class CancelResult:
    status: str
    error: SafeError | Mapping | None = None

    def __post_init__(self):
        if self.status not in ("unsupported", "requested", "confirmed_cancelled", "too_late", "unknown"):
            raise ValueError("invalid cancellation result")


@dataclass(frozen=True)
class SessionOpenResult:
    session_handle: Any = field(repr=False)
    external_execution_ref: Any = None


class Plugin(Protocol):
    def describe(self) -> Mapping[str, Any]: ...
    def prepare(self, action_key: str, input: Any, context: Any) -> PreparedCall: ...
    def execute(self, prepared_call: PreparedCall, context: Any) -> ExecutionResult: ...


class AdmissionPolicy(Protocol):
    def authorize_and_reserve(self, uow: Any, fixed_request: Mapping[str, Any]) -> Any: ...


class WorkflowPlanner(Protocol):
    def plan(self, snapshot: Mapping[str, Any], confirmed_outputs: Mapping[str, Any]) -> Any: ...


class ResultProjector(Protocol):
    def project(self, operation: Mapping[str, Any], result: ExecutionResult) -> Any: ...


class LifecyclePolicy(Protocol):
    def apply(self, uow: Any, operation: Mapping[str, Any], projection: Any) -> None: ...


class QuotaDisposition(Protocol):
    def apply(self, uow: Any, operation: Mapping[str, Any], facts: Any) -> None: ...


class Authorizer(Protocol):
    def __call__(self, actor_id: str, environment_id: str, action: str, **context: Any) -> bool: ...


def require_authorized(authorizer: Callable | None, actor_id, environment_id, action, **context):
    if authorizer is None or not authorizer(actor_id, environment_id, action, **context):
        raise AuthorizationDenied()


SNAPSHOT_VERSION = 1
API_VERSION = "1"
