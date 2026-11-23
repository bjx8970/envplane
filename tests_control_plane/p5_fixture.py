"""Disposable provisioning fixture and loopback SSH echo endpoint for P5.

The endpoint implements password authentication, PTY, shell and resize
requests. It echoes UTF-8 bytes and never launches an operating-system shell.
"""
import base64
from contextlib import contextmanager, suppress
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import shutil
import signal
import socket
from tempfile import TemporaryDirectory
import threading
from unittest.mock import patch

import paramiko
from sqlalchemy import text

from control_plane.config import RuntimeSettings
from control_plane.identity import _hash_password
from control_plane.plugins.capacity import CapacitySettings
from control_plane.plugins.sdk import ExecutionPolicy, ExecutionResult, PreparedCall
from control_plane.runtime import ControlPlaneRuntime
from tests_control_plane.p1_harness import runtime_database
from tests_control_plane.test_p2_services import deployment

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "p5-platform-test-only"
COST = {"environments": 1, "vms": 0, "vcpu": 0, "memory_mb": 0}
SERVERS = {}


def capability(effect, output):
    return {"display_name": "P5 fixture", "input_schema": {"type": "object"}, "output_schema": output,
            "execution": ExecutionPolicy(effect=effect).to_dict()}


MANIFEST = {
    "manifest_version": 1, "api_version": "1", "plugin_key": "p5_fixture",
    "plugin_version": "1.0.0", "display_name": "P5 isolated provisioner",
    "entrypoint": "plugin:Provisioner", "sessions": {},
    "actions": {
        "options": capability("read_only", {"type": "array", "items": {"type": "object", "properties": {
            "id": {"type": "string"}, "label": {"type": "string"}}}}),
        "install": capability("mutating", {"type": "object", "properties": {
            "target": {"type": "object"},
            "credential": {"type": "object"},
            "confirmed_environment_credential": {"type": "object"},
        }}),
        "observe": capability("read_only", {"type": "object", "properties": {"state": {"type": "string"}}}),
        "retire": capability("mutating", {"type": "object"}),
        "confirm": {
            **capability("mutating", {"type": "object", "required": ["confirmed"],
                                      "properties": {"confirmed": {"const": True}}}),
            "execution": ExecutionPolicy(effect="mutating", recovery="queryable").to_dict(),
        },
    },
}


class Provisioner:
    def describe(self):
        return MANIFEST

    def prepare(self, action_key, input, context):
        context.deadline.check()
        policy = ExecutionPolicy.from_dict(MANIFEST["actions"][action_key]["execution"])
        return PreparedCall(action_key, input, execution_policy=policy)

    def execute(self, prepared, context):
        context.deadline.check()
        target = context.configuration["terminal"]
        fixture = SERVERS[target["port"]]
        if prepared.action_key == "options":
            return ExecutionResult("succeeded", output=[{"id": "echo", "label": "Loopback echo"}])
        if prepared.action_key == "install":
            if prepared.resolved_input != {"endpoint": "echo"}:
                raise ValueError("unexpected fixture endpoint")
            ref = context.secrets.derive("environment_login", {"length": 32})
            with context.secrets.get(ref) as handle:
                fixture.password = handle.reveal().decode()
            return ExecutionResult("succeeded", output={
                "target": target, "credential": ref.to_dict(), "confirmed_environment_credential": ref.to_dict(),
            })
        if prepared.action_key == "observe":
            return ExecutionResult("succeeded", output={"state": "online" if fixture.password else "offline"})
        if prepared.action_key == "retire":
            fixture.password = None
            return ExecutionResult("succeeded", output={})
        if prepared.action_key == "confirm":
            fixture.recovery_calls.append(("execute", context.invocation_key))
            return ExecutionResult("unknown", external_execution_ref={"id": "opaque-fixture-reference"},
                                   external_refs=({"key": "partial", "reference": "opaque-fixture-evidence"},))
        raise AssertionError("unexpected fixture action")

    def poll(self, prepared, execution_ref, context):
        context.deadline.check()
        fixture = SERVERS[context.configuration["terminal"]["port"]]
        fixture.recovery_calls.append(("poll", context.invocation_key))
        if prepared.action_key != "confirm" or execution_ref != {"id": "opaque-fixture-reference"}:
            raise ValueError("unexpected recovery target")
        if fixture.poll_override is not None:
            return fixture.poll_override()
        return ExecutionResult("succeeded", output={"confirmed": True})


class EchoHandler(paramiko.ServerInterface):
    def __init__(self, server):
        self.server = server
        self.shell = threading.Event()

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        if username == "education" and password == self.server.password:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return term == b"xterm-256color"

    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        self.server.resized.set()
        return True

    def check_channel_shell_request(self, channel):
        self.shell.set()
        return True


@contextmanager
def echo_server(host_key):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        listener.settimeout(.1)
        stop = threading.Event()
        target = {"hostname": "127.0.0.1", "port": listener.getsockname()[1], "username": "education",
                  "host_key": {"type": host_key.get_name(), "base64": host_key.get_base64()}}

        class EchoServer:
            password = None
            received = bytearray()
            resized = threading.Event()
            target_ref = target
            flood = threading.Event()

        server = EchoServer()
        server.recovery_calls = []
        server.poll_override = None

        def serve():
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                except TimeoutError:
                    continue
                with conn, paramiko.Transport(conn) as transport:
                    try:
                        behavior = EchoHandler(server)
                        transport.add_server_key(host_key)
                        transport.start_server(server=behavior)
                        channel = transport.accept(3)
                        if channel is None or not behavior.shell.wait(2):
                            continue
                        channel.settimeout(.15)
                        channel.sendall(b"Ready for lab input\r\n")
                        while transport.is_active() and not stop.is_set():
                            if server.flood.is_set():
                                channel.sendall(b"Z" * 4096)
                                continue
                            try:
                                data = channel.recv(2048)
                            except TimeoutError:
                                continue
                            if not data:
                                break
                            server.received.extend(data)
                            channel.sendall(data)
                    except (EOFError, OSError, paramiko.SSHException):
                        pass

        worker = threading.Thread(target=serve, name="p5-loopback-ssh", daemon=True)
        SERVERS[target["port"]] = server
        worker.start()
        try:
            yield server
        finally:
            stop.set()
            worker.join(6)
            SERVERS.pop(target["port"], None)
            if worker.is_alive():
                raise RuntimeError("disposable SSH fixture failed to stop")


@contextmanager
def environment(host_key):
    with runtime_database() as (_, url), TemporaryDirectory() as directory, echo_server(host_key) as ssh:
        packages = Path(directory) / "packages"
        shutil.copytree(ROOT / "plugins" / "ssh_terminal", packages / "ssh_terminal",
                        ignore=shutil.ignore_patterns("__pycache__"))
        fixture = packages / "p5_fixture"
        fixture.mkdir()
        (fixture / "manifest.yaml").write_text(json.dumps(MANIFEST), encoding="utf-8")
        (fixture / "plugin.py").write_text("from tests_control_plane.p5_fixture import Provisioner\n", encoding="utf-8")
        config = deployment(directory, required=["p5_fixture", "ssh_terminal"],
                            capacity=asdict(CapacitySettings(ordinary_workers=2, control_workers=2,
                                session_workers=1, instance_limit=2, shutdown_grace_seconds=.8)))
        settings = RuntimeSettings.from_env({
            "CONTROL_PLANE_DATABASE_URL": url, "CONTROL_PLANE_RUNTIME_CONFIG": config,
            "CONTROL_PLANE_LOCK_POLL_SECONDS": "0.1", "CONTROL_PLANE_LEASE_SECONDS": "60",
        })
        with patch.dict(os.environ, {
            "CONTROL_PLANE_SECRET_KEYRING": json.dumps({"p5": base64.b64encode(os.urandom(32)).decode()}),
            "CONTROL_PLANE_SECRET_ACTIVE_KEY_ID": "p5",
        }):
            runtime = ControlPlaneRuntime(settings)
            runtime.start()
            try:
                with runtime.fenced_transaction() as db:
                    admin = db.scalar(text("""
                        INSERT INTO control_plane.users(username,role,password_hash)
                        VALUES ('admin','admin',:hash) RETURNING id
                    """), {"hash": _hash_password(PASSWORD)})
                identity = runtime.services.identity
                teacher = identity.create_user(admin, "teacher", PASSWORD, role="teacher")
                student = identity.create_user(teacher, "student", PASSWORD)
                other = identity.create_user(admin, "other", PASSWORD, role="teacher")
                runtime.services.business.set_quota(admin, teacher, limits=COST)
                yield runtime, ssh, {k: str(v) for k, v in
                    {"admin": admin, "teacher": teacher, "student": student, "other": other}.items()}
            finally:
                runtime.stop()


def template():
    return json.loads((ROOT / "tests_control_plane/browser/p5_template.json").read_text(encoding="utf-8"))


def browser_server():
    from control_plane.web.server import serve as serve_http

    with environment(paramiko.RSAKey.generate(2048)) as (runtime, ssh, _):
        # Only deployment data is seeded. The browser creates the instances,
        # publishes the template and performs every business mutation.
        origin = os.environ.get("P5_BROWSER_ORIGIN", "http://localhost:18742")
        driver = runtime.services.driver
        driver.settings = replace(driver.settings, lease_seconds=4, heartbeat_seconds=1)
        port = int(origin.rsplit(":", 1)[1])
        path = os.environ["P5_BROWSER_FIXTURE_PATH"]
        Path(path).write_text(json.dumps({"target": ssh.target_ref}), encoding="utf-8")
        previous_term = signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            if not serve_http(runtime, origin, port):
                raise RuntimeError("test HTTP server failed")
        finally:
            signal.signal(signal.SIGTERM, previous_term)
            with suppress(FileNotFoundError):
                Path(path).unlink()
