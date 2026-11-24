"""Same-origin HTTP boundary for the control plane."""
import base64
from contextlib import asynccontextmanager
from datetime import datetime
import json
import logging
from pathlib import Path
from uuid import UUID, uuid4

import anyio
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException
from starlette.requests import ClientDisconnect
from starlette.responses import FileResponse, Response
from starlette.routing import Route

from ..coordination import LeaseLost
from ..execution.repository import ExecutionConflict, Repository
from ..identity import _audit, active_role
from ..persistence import RequestConflict, StorageConflict
from ..plugins.capacity import CapacityRejected
from ..plugins.sdk import AuthorizationDenied, PluginError, finite_json
from ..quota import QuotaExceeded
from ..runtime import LeadershipLost
from ..templates import TemplateError
from .auth import BrowserOrigin, BrowserSessions, COOKIE, HttpError, LIFETIME
from .operations import OperationsViews
from .terminal import metadata, route as terminal_route, terminal_service
from .views import Views, require_role, rows

LOG = logging.getLogger(__name__)
MAX_BODY = 1024 * 1024
ASSETS = Path(__file__).parent / "assets"
XTERM_ASSETS = ASSETS / "vendor" / "xterm"


def _serialize(value):
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError("unsupported response value")


def response(data, status=200, headers=None):
    return Response(json.dumps(data, default=_serialize, allow_nan=False, separators=(",", ":")),
                    status, headers, media_type="application/json")


def job_accepted(result):
    job, replayed = result
    location = f"/api/jobs/{job}"
    return response({"job_id": job, "status_url": location, "replayed": replayed},
                    202, {"Location": location})


def _id(value):
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("identifier must be a UUID string")
    return str(UUID(value))


def _fields(data, required=(), optional=()):
    if not set(required) <= data.keys() or data.keys() - set(required) - set(optional):
        raise HttpError(400, "invalid_fields", "Supply only the fields accepted by this endpoint.")
    return data


def _parameters(data):
    value = data.get("parameters", {})
    if not isinstance(value, dict):
        raise ValueError()
    return value


def safe_error(exc):
    if isinstance(exc, HttpError):
        return exc.status, exc.code, exc.message
    if isinstance(exc, AuthorizationDenied):
        return 403, "forbidden", "You are not authorized for this request."
    if isinstance(exc, (RequestConflict, StorageConflict, ExecutionConflict)):
        return 409, "conflict", "The request key or current object state conflicts with this request."
    if isinstance(exc, QuotaExceeded):
        return 409, "quota_exceeded", "The requested capacity exceeds the teacher's quota."
    if isinstance(exc, CapacityRejected):
        return 503, "capacity_unavailable", "Execution capacity is currently unavailable. Try again later."
    if isinstance(exc, (LeaseLost, LeadershipLost, SQLAlchemyError)) and not isinstance(exc, IntegrityError):
        return 503, "service_unavailable", "The control plane is currently unavailable."
    if isinstance(exc, PluginError):
        if exc.code == "capacity":
            return 503, "capacity_unavailable", "Execution capacity is currently unavailable. Try again later."
        if exc.code in {"unavailable", "budget_exceeded", "reference_unavailable", "deadline_exceeded", "timeout"}:
            return 503, "dependency_unavailable", "A required execution dependency is unavailable."
        if exc.code in {"conflict", "backpressure"}:
            return 409, exc.code, "The session state or buffer changed."
        if exc.code == "not_found":
            return 404, "not_found", "This entry does not exist."
        if exc.code in {"invalid_json", "invalid_frame", "invalid_input"}:
            return 400, "invalid_input", "The submitted input is invalid."
        return 502, "plugin_failure", "The plugin could not complete this request."
    if isinstance(exc, TemplateError):
        return 400, "invalid_template_value", "The template or submitted parameters failed validation."
    if isinstance(exc, IntegrityError):
        return 409, "conflict", "The current object state conflicts with this request."
    if isinstance(exc, (ValueError, TypeError, RecursionError, ClientDisconnect)):
        return 400, "invalid_input", "The submitted values did not pass validation."
    if isinstance(exc, HTTPException):
        return exc.status_code, {404: "not_found", 405: "method_not_allowed"}.get(
            exc.status_code, "http_error"), "This endpoint or method is unavailable."
    return 500, "internal_error", "The control plane could not complete the request."


def decorate(result, request_id):
    result.headers.update({"X-Request-ID": request_id, "Cache-Control": "no-store",
                           "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
                           "Content-Security-Policy": "default-src 'self'; script-src 'self'; "
                           "style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'; "
                           "base-uri 'none'; form-action 'self'"})
    return result


async def _read_body(request):
    if request.headers.get("content-type", "").split(";", 1)[0].lower() != "application/json":
        raise HttpError(415, "json_required", "Send an application/json request body.")
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_BODY:
            raise HttpError(413, "body_too_large", "The request body exceeds the size limit.")
        body.extend(chunk)
    value = json.loads(body)
    return finite_json(value, object_only=True)


class HttpAPI:
    def __init__(self, runtime, origin):
        self.runtime, self.origin = runtime, BrowserOrigin.parse(origin)
        self.sessions = BrowserSessions(runtime)
        self.views = Views(runtime)
        self.operations = OperationsViews(runtime)
        self.login_slots = anyio.CapacityLimiter(4)
        self.websocket_slots = anyio.CapacityLimiter(64)

    @property
    def services(self):
        return self.runtime.services

    def dispatch(self, request, handler, body, public):
        token = request.cookies.get(COOKIE, "")
        if request.method not in {"HEAD", "GET"}:
            self.sessions.check_csrf(token, request.headers.get("x-csrf-token"))
        actor = self.sessions.actor(token)
        if actor is None and not public:
            raise HttpError(401, "authentication_required", "Sign in to continue.")
        params = {key: str(value) for key, value in request.path_params.items()}
        try:
            return handler(actor, token, body, params, request.query_params)
        except AuthorizationDenied:
            if actor is not None:
                self.audit_denial(actor["id"], handler.__name__)
            raise

    def audit_denial(self, actor, action):
        with self.runtime.fenced_transaction() as db:
            db.execute(text("""
                INSERT INTO control_plane.audit_events(actor_id,action,result,data)
                VALUES (:actor,'http.authorization','denied',jsonb_build_object('entry',CAST(:entry AS text)))
            """), {"actor": actor, "entry": action})

    def cookie(self, result, token):
        result.set_cookie(COOKIE, token, max_age=LIFETIME, path="/", httponly=True,
                          samesite="strict", secure=self.origin.secure)
        return result

    def session(self, actor, token, body, path, query):
        if not actor and (len(token) > 128 or not self.sessions.valid_anonymous(token)):
            token = self.sessions.anonymous()
            return self.cookie(response({"user": None, "csrf_token": self.sessions.csrf(token)}), token)
        return {"user": actor, "csrf_token": self.sessions.csrf(token)}

    def login(self, actor, token, body, path, query):
        _fields(body, ("username", "password"))
        token = self.sessions.login(token, body["username"], body["password"])
        actor = self.sessions.actor(token)
        return self.cookie(response({"user": actor, "csrf_token": self.sessions.csrf(token)}), token)

    def logout(self, actor, token, body, path, query):
        _fields(body)
        self.sessions.logout(token)
        result = response({"signed_out": True})
        result.delete_cookie(COOKIE, path="/", httponly=True, samesite="strict", secure=self.origin.secure)
        return result

    def health(self, actor, token, body, path, query):
        health = self.runtime.health()
        ready = health["ready"] and self.services.business is not None
        return response({"status": "ready" if ready else "degraded"}, 200 if ready else 503)

    def operations_status(self, actor, token, body, path, query):
        return self.operations.status(actor["id"])

    def blocked_jobs(self, actor, token, body, path, query):
        return self.operations.blocked_jobs(actor["id"], _id(query.get("before")))

    def blocked_job(self, actor, token, body, path, query):
        return self.operations.blocked_job(actor["id"], path["job_id"])

    def recovery_evidence(self, actor, token, body, path, query):
        return self.operations.evidence_detail(actor["id"], path["job_id"], path["evidence_id"])

    def submit_recovery(self, actor, token, body, path, query):
        _fields(body, ("action", "reason", "request_key", "expected_revision"),
                ("operation_id", "evidence_id", "confirmed_review_id", "verification"))
        service = self.services.recovery
        if service is None:
            raise LeadershipLost("execution recovery is unavailable")
        key, replayed = service.submit(
            actor["id"], path["job_id"], action=body["action"], reason=body["reason"],
            request_key=_id(body["request_key"]), expected_revision=body["expected_revision"],
            operation_id=_id(body.get("operation_id")), evidence_id=_id(body.get("evidence_id")),
            confirmed_review_id=_id(body.get("confirmed_review_id")),
            verification=body.get("verification"),
        )
        location = "/api/admin/blocked-jobs/" + path["job_id"]
        return response({"request_id": key, "status_url": location, "replayed": replayed},
                        200 if body["action"] == "review" else 202, {"Location": location})

    def create_environment(self, actor, token, body, path, query):
        _fields(body, ("course_id", "template_version_id", "name", "request_key"), ("parameters",))
        return job_accepted(self.services.business.create_environment(
            actor["id"], course_id=_id(body["course_id"]), template_version_id=_id(body["template_version_id"]),
            request_key=body["request_key"], name=body["name"], parameters=_parameters(body)))

    def action_scope(self, actor, path):
        resource = path.get("resource_id")
        env = self.views.resource_environment(actor, resource) if resource else path["environment_id"]
        return env, resource

    def run_action(self, actor, token, body, path, query):
        _fields(body, ("request_key",), ("parameters",))
        env, resource = self.action_scope(actor["id"], path)
        return job_accepted(self.services.business.run_action(actor["id"], environment_id=env,
            resource_id=resource, action_key=path["action_key"], request_key=body["request_key"],
            parameters=_parameters(body)))

    def candidates(self, actor, token, body, path, query):
        return self.services.business.list_candidates(actor["id"], path["course_id"], path["version_id"])

    def action_candidates(self, actor, token, body, path, query):
        env, resource = self.action_scope(actor["id"], path)
        return self.services.business.action_candidates(actor["id"], env, path["action_key"], resource_id=resource)

    def open_session(self, actor, token, body, path, query):
        _fields(body, ("request_key",))
        if self.services.session_openings is None:
            raise HttpError(503, "session_unavailable", "Interactive sessions are unavailable.")
        env, resource = self.action_scope(actor["id"], path)
        return job_accepted(self.services.session_openings.submit(
            actor["id"], env, path["entry_key"], resource, body["request_key"]))

    def session_control(self, actor, token, body, path, query):
        _fields(body, ("epoch",))
        service = terminal_service(self)
        session_id = path["session_id"]
        if path["operation"] == "takeover":
            row = service.takeover(actor["id"], session_id, body["epoch"])
        elif path["operation"] == "release":
            row = service.release(actor["id"], session_id, body["epoch"])
        else:
            raise HttpError(404, "not_found", "Unknown session control.")
        return metadata(row, actor["id"])

    def session_close(self, actor, token, body, path, query):
        _fields(body)
        return terminal_service(self).close(actor["id"], path["session_id"])

    def cleanup(self, actor, token, body, path, query):
        _fields(body, ("request_key",))
        return job_accepted(self.services.business.cleanup(actor["id"], environment_id=path["environment_id"],
                                                          request_key=body["request_key"]))

    def credential(self, actor, token, body, path, query):
        _fields(body)
        credential = self.services.credentials.view(actor["id"], path["environment_id"], path["secret_id"])
        try:
            data = {"encoding": "utf-8", "value": credential.value.decode("utf-8")}
        except UnicodeDecodeError:
            data = {"encoding": "base64", "value": base64.b64encode(credential.value).decode("ascii")}
        return response(data, headers=credential.headers)

    def cancel_job(self, actor, token, body, path, query):
        _fields(body)
        driver = self.services.driver
        repository = getattr(driver, "repository", None)
        if not isinstance(repository, Repository):
            raise HttpError(503, "service_unavailable", "Job cancellation is unavailable.")
        job = repository.request_cancel(path["job_id"], actor_id=actor["id"])
        if job is None:
            raise ExecutionConflict("job is already terminal")
        return job_accepted((job, False))

    def job_logs(self, actor, token, body, path, query):
        after = int(query.get("after", "-1"))
        if not -1 <= after < 2**63:
            raise ValueError()
        return self.views.job(actor["id"], path["job_id"], after=after)

    def create_draft(self, actor, token, body, path, query):
        _fields(body, ("definition",), ("template_id",))
        template, version = self.services.templates.create_draft(
            actor["id"], body["definition"], template_id=_id(body.get("template_id")))
        return response({"template_id": template, "version_id": version}, 201)

    def plugins(self, actor, token, body, path, query):
        with self.runtime.fenced_transaction() as db:
            require_role(db, actor["id"], "admin")
            instances = rows(db, """
                SELECT i.id,i.plugin_key,i.instance_alias,i.enabled,i.configuration_revision,v.configuration,v.plugin_version,v.code_digest
                FROM control_plane.plugin_instances i LEFT JOIN control_plane.plugin_instance_versions v
                  ON v.instance_id=i.id AND v.revision=i.configuration_revision ORDER BY i.instance_alias,i.id
            """)
            loaded = self.services.registry.plugins
            for item in instances:
                package = loaded.get(item["plugin_key"])
                revision = item.pop("plugin_version"), item.pop("code_digest")
                item["available"] = bool(item["enabled"] and package
                    and revision == (package.plugin_version, package.code_digest))
                item["needs_rebind"] = bool(item["enabled"] and package and revision[1]
                    and revision != (package.plugin_version, package.code_digest))
            return {"loaded": sorted(loaded), "instances": instances,
                    "unavailable": sorted(self.services.registry.unavailable)}

    def put_plugin(self, actor, token, body, path, query):
        instance = path.get("instance_id")
        _fields(body, ("configuration", "expected_revision") if instance else
                      ("plugin_key", "instance_alias", "configuration"))
        with self.runtime.fenced_transaction() as db:
            if active_role(db, actor["id"], lock=True) != "admin":
                raise AuthorizationDenied()
            revision = body.get("expected_revision", 0)
            if type(revision) is not int or not 0 <= revision < 2**63 - 1:
                raise ValueError()
            if not instance:
                alias = body["instance_alias"]
                if not isinstance(alias, str) or not alias or len(alias) > 255 or "\x00" in alias:
                    raise ValueError()
                self.services.registry.get(body["plugin_key"])
                instance = db.scalar(text("""
                    INSERT INTO control_plane.plugin_instances(plugin_key,instance_alias,created_by)
                    VALUES (:key,:alias,:actor) RETURNING id
                """), {"key": body["plugin_key"], "alias": alias, "actor": actor["id"]})
            config = self.services.configuration.put_in(db, instance, body["configuration"],
                                                       expected_revision=revision)
            _audit(db, actor["id"], "plugin.configure", instance_id=instance)
            return {"id": instance, "revision": config.revision}

    def rebind_plugin(self, actor, token, body, path, query):
        _fields(body, ("expected_revision",))
        revision = body["expected_revision"]
        if type(revision) is not int or not 1 <= revision < 2**63 - 1:
            raise ValueError()
        with self.runtime.fenced_transaction() as db:
            if active_role(db, actor["id"], lock=True) != "admin":
                raise AuthorizationDenied()
            instance = path["instance_id"]
            config = self.services.configuration.rebind_in(db, instance, expected_revision=revision)
            _audit(db, actor["id"], "plugin.rebind_configuration", instance_id=instance,
                   previous_revision=revision, revision=config.revision, code_digest=config.code_digest)
            return {"id": instance, "revision": config.revision}

    def plugin_enabled(self, actor, token, body, path, query):
        _fields(body, ("enabled",))
        if not isinstance(body["enabled"], bool):
            raise ValueError()
        with self.runtime.fenced_transaction() as db:
            if active_role(db, actor["id"], lock=True) != "admin":
                raise AuthorizationDenied()
            if not db.scalar(text("""
                UPDATE control_plane.plugin_instances SET enabled=:enabled WHERE id=:id RETURNING id
            """), {"id": path["instance_id"], "enabled": body["enabled"]}):
                raise HttpError(404, "not_found", "Plugin instance not found.")
            _audit(db, actor["id"], "plugin.set_enabled", instance_id=path["instance_id"])
        return {}

    def plugin_storage(self, actor, token, body, path, query):
        with self.runtime.fenced_transaction() as db:
            require_role(db, actor["id"], "admin")
            return rows(db, """
                SELECT h.key,v.id AS version_id,v.value
                FROM control_plane.plugin_storage_heads h JOIN control_plane.plugin_storage_versions v
                  ON v.id=h.version_id
                WHERE h.instance_id=:instance AND NOT v.is_tombstone ORDER BY h.key LIMIT 1000
            """, instance=path["instance_id"])

    def put_plugin_storage(self, actor, token, body, path, query):
        _fields(body, ("key", "value"), ("expected_version",))

        def admin_only(db):
            if active_role(db, actor["id"], lock=True) != "admin":
                raise AuthorizationDenied()

        storage = self.services.storage.bind(path["instance_id"], access_guard=admin_only)
        ref = storage.put(body["key"], body["value"], expected_version=_id(body.get("expected_version")))
        return ref.to_dict()

    def admin_secret(self, actor, token, body, path, query):
        _fields(body, ("value",))
        if not isinstance(body["value"], str) or not body["value"]:
            raise ValueError()
        with self.runtime.fenced_transaction() as db:
            if active_role(db, actor["id"], lock=True) != "admin":
                raise AuthorizationDenied()
            ref = self.services.secrets.create_in(db, body["value"].encode(), created_by=actor["id"])
            _audit(db, actor["id"], "secret.create", secret_id=ref.secret_id)
        return response(ref.to_dict(), 201)

    def endpoint(self, handler, public=False):
        async def endpoint(request):
            request_id = uuid4().hex
            try:
                mutation = request.method not in {"GET", "HEAD"}
                self.origin.check(request.headers, origin_required=mutation)
                body = await _read_body(request) if mutation else {}
                if handler == self.login:
                    try:
                        self.login_slots.acquire_nowait()
                    except anyio.WouldBlock:
                        raise CapacityRejected("login capacity is exhausted") from None
                    try:
                        result = await run_in_threadpool(self.dispatch, request, handler, body, public)
                    finally:
                        self.login_slots.release()
                else:
                    result = await run_in_threadpool(self.dispatch, request, handler, body, public)
                if not isinstance(result, Response):
                    result = response(result)
            except Exception as exc:
                result = self.error_response(exc, request_id)
            return decorate(result, request_id)
        return endpoint

    @staticmethod
    def error_response(exc, request_id):
        status, code, message = safe_error(exc)
        if status >= 500 and status != 503:
            LOG.warning("Request %s failed: %s", request_id, type(exc).__name__)
        headers = {"Retry-After": "2"} if status == 503 else None
        details = {"retryable": True} if code == "capacity_unavailable" else {}
        return response({"code": code, "message": message, "request_id": request_id, "details": details},
                        status, headers)

    def routes(self):
        def route(path, method, handler, *, public=False):
            return Route(path, self.endpoint(handler, public), methods=[method])

        def view(path, name, *keys):
            def read(actor, token, body, params, query):
                return getattr(self.views, name)(actor["id"], *(params[key] for key in keys))
            read.__name__ = "read_" + name
            return route(path, "GET", read)

        def service(path, method, name, *keys, service_name="identity", required=(), optional=(), ids=()):
            def call(actor, token, body, params, query):
                _fields(body, required, optional)
                target = getattr(getattr(self.services, service_name), name)
                args = {key: _id(value) if key in ids else value for key, value in body.items()}
                result = target(actor["id"], *(params[key] for key in keys), **args)
                return {} if result is None else result if isinstance(result, dict) else {"id": result}
            call.__name__ = name
            return route(path, method, call)

        env = "/api/environments/{environment_id:uuid}"
        res = "/api/resources/{resource_id:uuid}"
        course = "/api/courses/{course_id:uuid}"
        version = "/api/templates/{version_id:uuid}"
        user = "/api/users/{user_id:uuid}"
        job = "/api/jobs/{job_id:uuid}"
        blocked = "/api/admin/blocked-jobs/{job_id:uuid}"
        plugin = "/api/admin/plugins/{instance_id:uuid}"
        return [
            route("/health/ready", "GET", self.health, public=True),
            route("/api/admin/operations/status", "GET", self.operations_status),
            route("/api/admin/blocked-jobs", "GET", self.blocked_jobs),
            route(blocked, "GET", self.blocked_job),
            route(blocked + "/evidence/{evidence_id:uuid}", "GET", self.recovery_evidence),
            route(blocked + "/recovery", "POST", self.submit_recovery),
            route("/api/session", "GET", self.session, public=True),
            route("/api/login", "POST", self.login, public=True),
            route("/api/logout", "POST", self.logout),
            route("/api/environments", "POST", self.create_environment),
            route(env + "/actions/{action_key}", "POST", self.run_action),
            route(res + "/actions/{action_key}", "POST", self.run_action),
            route(env + "/actions/{action_key}/candidates", "GET", self.action_candidates),
            route(res + "/actions/{action_key}/candidates", "GET", self.action_candidates),
            route(env + "/cleanup", "POST", self.cleanup),
            route(env + "/access/{entry_key}", "POST", self.open_session),
            route(res + "/access/{entry_key}", "POST", self.open_session),
            view(env + "/sessions", "terminal_sessions", "environment_id"),
            route("/api/terminal-sessions/{session_id:uuid}/close", "POST", self.session_close),
            route("/api/terminal-sessions/{session_id:uuid}/{operation}", "POST", self.session_control),
            route(env + "/credentials/{secret_id:uuid}", "POST", self.credential),
            route(course + "/templates/{version_id:uuid}/candidates", "GET", self.candidates),
            route(job + "/logs", "GET", self.job_logs),
            route(job + "/cancel", "POST", self.cancel_job),
            route("/api/templates", "POST", self.create_draft),
            route("/api/admin/plugins", "GET", self.plugins),
            route("/api/admin/plugins", "POST", self.put_plugin),
            route(plugin, "PUT", self.put_plugin),
            route(plugin + "/rebind", "POST", self.rebind_plugin),
            route(plugin + "/enabled", "PUT", self.plugin_enabled),
            route(plugin + "/storage", "GET", self.plugin_storage),
            route(plugin + "/storage", "PUT", self.put_plugin_storage),
            route("/api/admin/secrets", "POST", self.admin_secret),
            view("/api/users", "accounts"),
            view("/api/courses", "courses"),
            view(course, "course", "course_id"),
            view("/api/templates", "templates"),
            view("/api/environments", "environments"),
            view(env, "environment", "environment_id"),
            view(job, "job", "job_id"),
            view("/api/quota/{teacher_id:uuid}", "quota", "teacher_id"),
            service(user, "GET", "get_user", "user_id"),
            service(user, "PATCH", "rename_user", "user_id", required=("username",)),
            service(user, "DELETE", "delete_user", "user_id"),
            service(user + "/active", "PUT", "set_active", "user_id", required=("active",)),
            service(user + "/role", "PUT", "set_role", "user_id", required=("role",)),
            service(user + "/password", "PUT", "reset_password", "user_id", required=("password",)),
            service("/api/users", "POST", "create_user", required=("username", "password"), optional=("role",)),
            service("/api/me/password", "PUT", "change_password", required=("current_password", "new_password")),
            service("/api/courses", "POST", "create_course", required=("owner_teacher_id", "name"),
                    ids=("owner_teacher_id",)),
            service(course, "DELETE", "delete_course", "course_id"),
            service(course + "/groups", "POST", "create_group", "course_id", required=("name",)),
            service(course + "/groups/{group_id:uuid}", "DELETE", "delete_group", "course_id", "group_id"),
            service(course + "/members/{student_id:uuid}", "POST", "enroll", "course_id", "student_id",
                    optional=("group_id",), ids=("group_id",)),
            service(course + "/members/{student_id:uuid}", "PUT", "move_student", "course_id", "student_id",
                    required=("group_id",), ids=("group_id",)),
            service(course + "/members/{student_id:uuid}", "DELETE", "leave_course", "course_id", "student_id"),
            service(env + "/assignments", "POST", "assign", "environment_id",
                    optional=("group_id", "student_id"), ids=("group_id", "student_id")),
            service("/api/assignments/{assignment_id:uuid}", "DELETE", "revoke_assignment", "assignment_id"),
            service(res, "GET", "resource_status", "resource_id"),
            service(version, "PUT", "edit_draft", "version_id", service_name="templates", required=("definition",)),
            service(version + "/publish", "POST", "publish", "version_id", service_name="templates"),
            service(version + "/disable", "POST", "disable", "version_id", service_name="templates"),
            service("/api/quota/{teacher_id:uuid}", "PUT", "set_quota", "teacher_id", service_name="business",
                    required=("limits",)),
        ]


def create_app(runtime, origin, *, poll=False, on_failure=None):
    api = HttpAPI(runtime, origin)
    poll_slot = anyio.CapacityLimiter(1)

    async def poll_runtime():
        while True:
            await anyio.to_thread.run_sync(
                runtime.wakeup.wait, runtime.settings.lock_poll_seconds, abandon_on_cancel=True,
                limiter=poll_slot,
            )
            try:
                await anyio.to_thread.run_sync(runtime.poll, limiter=poll_slot)
            except Exception as exc:
                LOG.error("Control-plane polling stopped: %s", type(exc).__name__)
                if on_failure:
                    on_failure()
                return

    @asynccontextmanager
    async def lifespan(app):
        async with anyio.create_task_group() as group:
            if poll:
                group.start_soon(poll_runtime)
            try:
                yield
            finally:
                group.cancel_scope.cancel()
                if poll:
                    runtime.wakeup.notify()

    async def http_error(request, exc):
        request_id = uuid4().hex
        return decorate(api.error_response(exc, request_id), request_id)

    def asset(file, directory=ASSETS):
        async def read(request):
            request_id = uuid4().hex
            try:
                api.origin.check(request.headers, origin_required=False)
                return decorate(FileResponse(directory / file), request_id)
            except HttpError as exc:
                return decorate(api.error_response(exc, request_id), request_id)
        return read

    assets = [Route("/", asset("index.html"))]
    assets += [Route("/assets/" + file, asset(file)) for file in ("app.js", "style.css", "terminal.js")]
    assets += [Route("/assets/" + file, asset(file, XTERM_ASSETS))
               for file in ("xterm.js", "xterm.min.css", "xterm-addon-fit.js")]
    return Starlette(routes=assets + api.routes() + [terminal_route(api)], lifespan=lifespan, exception_handlers={HTTPException: http_error})
