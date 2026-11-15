"""Real Paramiko handshakes against an isolated, loopback-only test process.

No devices, user's SSH agent, known_hosts, disk keys or production credentials.
"""
import base64
from contextlib import contextmanager
import io
import multiprocessing
import json
from pathlib import Path
import socket
import threading
import time
from types import SimpleNamespace
import unittest

import paramiko
from jsonschema import Draft202012Validator

from control_plane.plugins.sdk import Deadline, PluginError, SecretRef, StorageRef
from control_plane.plugins.registry import PluginRegistry
from control_plane.plugins.ssh import SSHPlugin


def _server(private_key, ready, mode):
    key = paramiko.RSAKey.from_private_key(io.StringIO(private_key))
    class Server(paramiko.ServerInterface):
        def check_auth_password(self, username, password):
            return paramiko.AUTH_SUCCESSFUL if (username, password) == ("test", "test-only-password") else paramiko.AUTH_FAILED
        def get_allowed_auths(self, username):
            return "password"
        def check_channel_request(self, kind, chanid):
            return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        def check_channel_exec_request(self, channel, command):
            self.command = command
            if mode == "exec_ack_timeout":
                # Accept the request but never return: the transport reply
                # thread is held here, so no exec ACK is ever sent back.
                time.sleep(2)
            return True
    listener = socket.socket()
    listener.settimeout(4)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    ready.send(listener.getsockname()[1])
    transport = None
    try:
        connection, _ = listener.accept()
        if mode == "banner_timeout":
            time.sleep(2)
            connection.close()
            return
        connection.settimeout(3)
        transport = paramiko.Transport(connection)
        transport.add_server_key(key)
        server = Server()
        transport.start_server(server=server)
        channel = transport.accept(3)
        if channel is None:
            return
        end = time.monotonic() + 3
        while not hasattr(server, "command") and time.monotonic() < end:
            time.sleep(.005)
        if not hasattr(server, "command"):
            return
        if mode == "disconnect":
            transport.close()
        elif mode == "wait_timeout":
            time.sleep(2)
        elif mode == "exec_ack_timeout":
            # Stay silent longer than the client's total deadline so the
            # client's deadline is what expires, not the connection.
            time.sleep(1)
        else:
            channel.sendall(b"x" * 8192 if mode == "output_limit" else b"test-output\n")
            channel.sendall_stderr(b"test-error\n")
            channel.send_exit_status(7)
            channel.shutdown_write()
            time.sleep(.1)
            channel.close()
    except (EOFError, OSError, paramiko.SSHException):
        pass  # Client rejection/timeout is intentional in negative handshakes.
    finally:
        if transport is not None:
            transport.close()
        listener.close()
        ready.close()


class FakeStorage:
    def __init__(self, host):
        self.host = host
        self.reads = []
        self.ref = StorageRef("instance", "hosts/test", "storage-v1")
    def get(self, key, version=None):
        self.reads.append((key, version))
        if key != self.ref.key or version not in (None, self.ref.version_id):
            raise PluginError("unavailable")
        return SimpleNamespace(value=dict(self.host), ref=self.ref)
    def list(self, **kwargs):
        return SimpleNamespace(items=(SimpleNamespace(value=dict(self.host), ref=self.ref, key=self.ref.key),), cursor=None)


class FakeHandle:
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def reveal(self):
        return b"test-only-password"


class FakeSecrets:
    def __init__(self):
        self.reads = []
    def resolve(self, ref):
        return SecretRef(ref.secret_id, ref.version_id or "secret-v1")
    def get(self, ref):
        self.reads.append(ref)
        if ref != SecretRef("test-secret", "secret-v1"):
            raise PluginError("unavailable")
        return FakeHandle()


class SSHPluginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = paramiko.RSAKey.generate(2048)
        value = io.StringIO()
        cls.key.write_private_key(value)
        cls.private = value.getvalue()

    @contextmanager
    def server(self, mode="success"):
        ctx = multiprocessing.get_context("spawn")
        parent, child = ctx.Pipe(duplex=False)
        process = ctx.Process(target=_server, args=(self.private, child, mode), daemon=True)
        process.start()
        child.close()
        try:
            self.assertTrue(parent.poll(8), "isolated SSH server failed to start")
            port = parent.recv()
            yield port
        finally:
            parent.close()
            process.join(.5)
            if process.is_alive():
                # Process isolation/termination is test infrastructure only.
                process.terminate()
                process.join(3)
            self.assertFalse(process.is_alive())

    def context(self, port=22, *, key=None, seconds=4, limits=None):
        key = key or self.key
        host = {"name": "test", "hostname": "127.0.0.1", "port": port, "username": "test",
                "host_key": {"type": key.get_name(), "base64": base64.b64encode(key.asbytes()).decode()},
                "credential": {"secret_id": "test-secret"}}
        return SimpleNamespace(deadline=Deadline.after(seconds), storage=FakeStorage(host), secrets=FakeSecrets(),
                               configuration={"ssh_limits": limits or {}})

    def test_manifest_declares_no_terminal_idempotency_or_recovery(self):
        plugin = SSHPlugin()
        manifest = plugin.describe()
        registered = PluginRegistry().register(plugin, manifest, code_digest="test-only-ssh")
        self.assertEqual(registered.plugin_key, "ssh")
        self.assertEqual(manifest["api_version"], "1")
        self.assertEqual(manifest["sessions"], {})
        for action in manifest["actions"].values():
            Draft202012Validator.check_schema(action["input_schema"])
            Draft202012Validator.check_schema(action["output_schema"])
        policy = manifest["actions"]["execute_command"]["execution"]
        self.assertEqual(policy, {"effect": "mutating", "idempotency": "unsupported", "recovery": "unsupported", "cancellation": "unsupported"})

    def test_shipped_package_loads_with_digest_covering_real_provider(self):
        from control_plane.plugins.registry import code_digest
        root = Path(__file__).resolve().parents[1]
        loaded = PluginRegistry().load(root / "plugins", required=("ssh",)).get("ssh")
        self.assertEqual(loaded.plugin_key, "ssh")
        self.assertEqual(loaded.code_digest, code_digest(root / "plugins" / "ssh"))
        self.assertEqual(loaded.manifest, SSHPlugin().describe())
        self.assertEqual(loaded.manifest, json.loads((root / "control_plane/plugins/ssh_manifest.json").read_text(encoding="utf-8")))
        self.assertNotIn("from control_plane.plugins.ssh import", (root / "plugins/ssh/plugin.py").read_text(encoding="utf-8"))
        context = self.context()
        prepared = loaded.implementation.prepare("list_host_options", {}, context)
        self.assertEqual(loaded.implementation.execute(prepared, context).output, [{"id": "test", "name": "test"}])

    def test_real_handshake_command_separate_streams_and_fixed_versions(self):
        with self.server() as port:
            context = self.context(port)
            plugin = SSHPlugin()
            prepared = plugin.prepare("execute_command", {"host_id": "test", "command": "opaque-template-command"}, context)
            result = plugin.execute(prepared, context)
            self.assertEqual(result.outcome, "succeeded")
            self.assertEqual(result.output, {"exit_code": 7, "stdout": "test-output\n", "stderr": "test-error\n"})
            self.assertEqual(context.storage.reads, [("hosts/test", None), ("hosts/test", "storage-v1")])
            self.assertEqual(context.secrets.reads, [SecretRef("test-secret", "secret-v1")])
            Draft202012Validator(plugin.describe()["actions"]["execute_command"]["output_schema"]).validate(result.output)

    def test_host_key_mismatch_is_rejected_before_dispatch(self):
        with self.server() as port:
            context = self.context(port, key=paramiko.RSAKey.generate(2048))
            plugin = SSHPlugin()
            prepared = plugin.prepare("execute_command", {"host_id": "test", "command": "never-run"}, context)
            result = plugin.execute(prepared, context)
            self.assertEqual(result.outcome, "failed")
            self.assertEqual(result.error.code, "host_key_mismatch")

    def test_changed_storage_never_retargets_execute(self):
        context = self.context()
        plugin = SSHPlugin()
        prepared = plugin.prepare("execute_command", {"host_id": "test", "command": "test"}, context)
        context.storage.host["hostname"] = "127.0.0.2"
        result = plugin.execute(prepared, context)
        self.assertEqual(result.outcome, "failed")
        self.assertEqual(result.error.code, "unavailable")
        self.assertEqual(context.secrets.reads, [])

    def test_connection_loss_after_exec_is_unknown_not_retryable_failure(self):
        with self.server("disconnect") as port:
            context = self.context(port)
            plugin = SSHPlugin()
            prepared = plugin.prepare("execute_command", {"host_id": "test", "command": "mutate"}, context)
            result = plugin.execute(prepared, context)
            self.assertEqual(result.outcome, "unknown")
            self.assertIsNone(result.output)
            self.assertEqual(result.error.retry_hint, "manual_review")

    def test_total_command_budget_and_output_are_bounded(self):
        for mode, limits in (("wait_timeout", {"wait": .1}), ("output_limit", {"max_output_bytes": 100})):
            with self.subTest(mode=mode), self.server(mode) as port:
                context = self.context(port, limits=limits)
                plugin = SSHPlugin()
                prepared = plugin.prepare("execute_command", {"host_id": "test", "command": "mutate"}, context)
                started = time.monotonic()
                result = plugin.execute(prepared, context)
                self.assertLess(time.monotonic() - started, 3)
                self.assertEqual(result.outcome, "unknown")
                self.assertIsNone(result.output)

    def test_exec_acknowledgement_wait_is_bounded_by_total_deadline(self):
        # The server completes handshake+auth+channel open but never sends the
        # exec request ACK.  execute must return within the total deadline,
        # report unknown (dispatch may have happened, never a safe retry),
        # close its resources, and leave no threads behind.
        with self.server("exec_ack_timeout") as port:
            context = self.context(port, seconds=.3)
            plugin = SSHPlugin()
            prepared = plugin.prepare("execute_command", {"host_id": "test", "command": "mutate"}, context)
            before = threading.enumerate()
            started = time.monotonic()
            result = plugin.execute(prepared, context)
            self.assertLess(time.monotonic() - started, 1.5)
            self.assertEqual(result.outcome, "unknown")
            self.assertIsNone(result.output)
            self.assertEqual(result.error.retry_hint, "manual_review")
            deadline = time.monotonic() + 2
            after = before
            while time.monotonic() < deadline:
                after = threading.enumerate()
                if after == before:
                    break
                time.sleep(.05)
            self.assertEqual(after, before)

    def test_banner_budget_fails_without_claiming_dispatched_command(self):
        with self.server("banner_timeout") as port:
            context = self.context(port, seconds=.2, limits={"banner": .1})
            plugin = SSHPlugin()
            prepared = plugin.prepare("execute_command", {"host_id": "test", "command": "never-run"}, context)
            started = time.monotonic()
            result = plugin.execute(prepared, context)
            self.assertLess(time.monotonic() - started, 1)
            self.assertEqual(result.outcome, "failed")

    def test_listing_is_readonly_bounded_and_has_no_credentials(self):
        context = self.context()
        plugin = SSHPlugin()
        prepared = plugin.prepare("list_host_options", {}, context)
        result = plugin.execute(prepared, context)
        self.assertEqual(result.output, [{"id": "test", "name": "test"}])
        self.assertEqual(prepared.execution_policy.effect, "read_only")
        self.assertNotIn("credential", str(result.output))
        self.assertEqual(context.secrets.reads, [])

    def test_unknown_key_and_unbounded_dns_host_are_not_trusted(self):
        context = self.context()
        context.storage.host["hostname"] = "unbounded-dns.example.invalid"
        with self.assertRaises(PluginError):
            SSHPlugin().prepare("execute_command", {"host_id": "test", "command": "test"}, context)
        context = self.context()
        del context.storage.host["host_key"]
        with self.assertRaises(PluginError):
            SSHPlugin().prepare("execute_command", {"host_id": "test", "command": "test"}, context)


if __name__ == "__main__":
    unittest.main()
