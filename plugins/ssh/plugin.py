"""Trusted SSH management plugin, deliberately not a student terminal provider.

Hosts are private Storage objects at ``hosts/<id>``. They contain a numeric
``hostname`` (bounded DNS is not available in this in-process implementation),
``username``, optional ``port``, an exact ``host_key`` {type, base64}, and a
``credential`` SecretRef. Neither discovery nor execution creates resources.
"""
from __future__ import annotations

import base64
import hmac
import io
import ipaddress
import json
from pathlib import Path
import socket
import time

from control_plane.plugins.sdk import (ExecutionPolicy, ExecutionResult, PluginError, PreparedCall,
                  SafeError, SecretRef, StorageRef, finite_json)


class SSHPlugin:
    def describe(self):
        return json.loads(Path(__file__).with_name("manifest.yaml").read_text(encoding="utf-8"))

    def prepare(self, action_key, input, context):
        context.deadline.check()
        if action_key == "list_host_options":
            if input != {}:
                raise PluginError("invalid_input", "host listing accepts no parameters")
            # Fix the complete bounded selection now, not when execute is called.
            items, refs, cursor = [], [], None
            while True:
                context.deadline.check()
                page = context.storage.list(prefix="hosts/", cursor=cursor, limit=100)
                for item in page.items:
                    host_id = item.key.removeprefix("hosts/")
                    name = item.value.get("name", host_id)
                    if not host_id or len(host_id) > 240 or "/" in host_id or not isinstance(name, str) or not name or len(name) > 255:
                        raise PluginError("invalid_input", "invalid host option")
                    items.append({"id": host_id, "name": name})
                    refs.append(item.ref)
                    if len(items) > 1000:
                        raise PluginError("invalid_input", "host inventory exceeds bounded listing")
                cursor = page.cursor
                if cursor is None:
                    break
            if len({item["id"] for item in items}) != len(items):
                raise PluginError("invalid_input", "duplicate host option")
            return PreparedCall(action_key, {"options": items}, storage_refs=tuple(refs),
                                execution_policy=ExecutionPolicy(effect="read_only"))
        if action_key != "execute_command" or not isinstance(input, dict) or set(input) != {"host_id", "command"}:
            raise PluginError("invalid_input", "invalid SSH action parameters")
        host_id, command = input["host_id"], input["command"]
        if not isinstance(host_id, str) or not host_id or len(host_id) > 240 or "/" in host_id:
            raise PluginError("invalid_input", "invalid host identifier")
        if not isinstance(command, str) or not command or len(command.encode("utf-8")) > 65536 or "\x00" in command:
            raise PluginError("invalid_input", "invalid SSH command")
        entry = context.storage.get("hosts/" + host_id)
        host = self._host(entry.value)
        secret = context.secrets.resolve(SecretRef(**host["credential"]))
        if secret.version_id is None:
            raise PluginError("unavailable", "credential version was not fixed")
        host["credential"] = secret.to_dict()
        return PreparedCall(action_key, {"command": command}, target_ref=host,
                            storage_refs=(entry.ref,), secret_refs=(secret,),
                            execution_policy=ExecutionPolicy())

    @staticmethod
    def _host(value):
        if not isinstance(value, dict):
            raise PluginError("invalid_input", "invalid host configuration")
        try:
            hostname = str(ipaddress.ip_address(value["hostname"]))
            username = value["username"]
            port = value.get("port", 22)
            key = value["host_key"]
            credential = value["credential"]
            if (not isinstance(username, str) or not username or len(username) > 255
                    or isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
                    or not isinstance(key, dict) or set(key) != {"type", "base64"}
                    or not isinstance(key["type"], str) or not key["type"]
                    or not isinstance(key["base64"], str) or len(key["base64"]) > 16384
                    or not isinstance(credential, dict) or not set(credential).issubset({"secret_id", "version_id"})
                    or not isinstance(credential.get("secret_id"), str) or not credential["secret_id"]
                    or ("version_id" in credential and (not isinstance(credential["version_id"], str) or not credential["version_id"]))):
                raise ValueError()
            base64.b64decode(key["base64"], validate=True)
            auth = value.get("auth", "password")
            if auth not in ("password", "private_key"):
                raise ValueError()
            result = {"hostname": hostname, "username": username, "port": port,
                      "host_key": dict(key), "credential": dict(credential), "auth": auth}
            finite_json(result, object_only=True, max_bytes=32768)
            return result
        except (KeyError, TypeError, ValueError):
            raise PluginError("invalid_input", "host requires an IP, pinned host key and credential reference") from None

    def execute(self, prepared_call, context):
        if prepared_call.action_key == "list_host_options":
            context.deadline.check()
            return ExecutionResult("succeeded", output=prepared_call.resolved_input["options"])
        if prepared_call.action_key != "execute_command":
            raise PluginError("invalid_input", "unsupported SSH action")
        import paramiko  # Optional dependency: no network or threads on module import.

        transport = channel = sock = None
        dispatched = False
        try:
            host = self._host(prepared_call.target_ref)
            if len(prepared_call.storage_refs) != 1 or len(prepared_call.secret_refs) != 1:
                raise PluginError("invalid_input", "SSH fixed references are missing")
            fixed_secret = prepared_call.secret_refs[0]
            fixed_secret = fixed_secret if isinstance(fixed_secret, SecretRef) else SecretRef(**fixed_secret)
            if not fixed_secret.version_id or fixed_secret.to_dict() != host["credential"]:
                raise PluginError("invalid_input", "SSH credential does not match fixed target")
            # Reading this exact historical object validates availability; never resolve latest.
            ref = prepared_call.storage_refs[0]
            ref = ref if isinstance(ref, StorageRef) else StorageRef(**ref)
            historical = context.storage.get(ref.key, version=ref.version_id)
            fixed_host = self._host(historical.value)
            configured_secret = SecretRef(**fixed_host["credential"])
            if configured_secret.secret_id != fixed_secret.secret_id or (
                    configured_secret.version_id is not None and configured_secret.version_id != fixed_secret.version_id):
                raise PluginError("unavailable", "fixed SSH credential does not match storage history")
            fixed_host["credential"] = fixed_secret.to_dict()
            if fixed_host != host:
                raise PluginError("unavailable", "fixed SSH target does not match storage history")
            config = getattr(context, "configuration", {}) or {}
            limits = config.get("ssh_limits", {})
            output_limit = self._limit(limits, "max_output_bytes", 262144, 1, 1048576, integer=True)
            phase = {name: self._limit(limits, name, default, 0.001, 300)
                     for name, default in (("connect", 5), ("banner", 5), ("auth", 5), ("readwrite", 1), ("wait", 30))}
            deadline = context.deadline
            with context.secrets.get(fixed_secret) as handle:
                credential = handle.reveal()
                sock = socket.create_connection((host["hostname"], host["port"]),
                                                timeout=min(phase["connect"], deadline.check()))
                sock.settimeout(min(phase["readwrite"], deadline.check()))
                transport = paramiko.Transport(sock)
                transport.banner_timeout = min(phase["banner"], deadline.check())
                transport.auth_timeout = min(phase["auth"], deadline.check())
                transport.start_client(timeout=min(phase["banner"], deadline.check()))
                remote = transport.get_remote_server_key()
                if remote.get_name() != host["host_key"]["type"] or not hmac.compare_digest(
                        remote.asbytes(), base64.b64decode(host["host_key"]["base64"], validate=True)):
                    raise PluginError("host_key_mismatch", "SSH host key is not the configured key")
                transport.auth_timeout = min(phase["auth"], deadline.check())
                if host["auth"] == "password":
                    transport.auth_password(host["username"], credential.decode("utf-8"), fallback=False)
                else:
                    # No filesystem key access: parse only the delivered secret.
                    key = None
                    for key_type in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
                        try:
                            key = key_type.from_private_key(io.StringIO(credential.decode("utf-8")))
                            break
                        except (paramiko.SSHException, ValueError):
                            continue
                    if key is None:
                        raise PluginError("authentication_failed", "invalid SSH private key")
                    transport.auth_publickey(host["username"], key)
            deadline.check()
            channel = transport.open_session(timeout=min(phase["readwrite"], deadline.check()))
            channel.settimeout(min(phase["readwrite"], deadline.check()))
            # The request may have reached the server even if its acknowledgement is lost.
            dispatched = True
            channel.exec_command(prepared_call.resolved_input["command"])
            wait_until = min(time.monotonic() + phase["wait"], time.monotonic() + deadline.check())
            stdout, stderr, size = bytearray(), bytearray(), 0
            while True:
                deadline.check()
                if time.monotonic() >= wait_until:
                    raise PluginError("timeout", "SSH command wait budget exhausted")
                for ready, receive, buffer in ((channel.recv_ready, channel.recv, stdout),
                                               (channel.recv_stderr_ready, channel.recv_stderr, stderr)):
                    if ready():
                        data = receive(min(32768, output_limit - size + 1))
                        size += len(data)
                        if size > output_limit:
                            raise PluginError("output_limit", "SSH output exceeded bounded result")
                        buffer.extend(data)
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    status = channel.recv_exit_status()
                    if status < 0:
                        raise PluginError("connection_lost", "SSH command completion is unknown")
                    return ExecutionResult("succeeded", output={"exit_code": status,
                        "stdout": stdout.decode("utf-8", errors="replace"), "stderr": stderr.decode("utf-8", errors="replace")})
                if not transport.is_active() or channel.closed:
                    raise PluginError("connection_lost", "SSH command completion is unknown")
                time.sleep(min(0.01, deadline.check(), max(0.001, wait_until - time.monotonic())))
        except Exception as exc:
            # Never expose vendor exceptions, command text, credentials or raw output.
            code = exc.code if isinstance(exc, PluginError) else "ssh_unavailable"
            return ExecutionResult("unknown" if dispatched else "failed",
                                   error=SafeError(code, "SSH execution could not be confirmed" if dispatched
                                                   else "SSH connection was not established", retry_hint="manual_review" if dispatched else None))
        finally:
            for resource in (channel, transport, sock):
                if resource is not None:
                    try:
                        resource.close()
                    except Exception:
                        pass

    @staticmethod
    def _limit(config, name, default, low, high, integer=False):
        value = config.get(name, default)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high or (integer and not isinstance(value, int)):
            raise PluginError("invalid_input", "invalid SSH execution budget")
        return value

