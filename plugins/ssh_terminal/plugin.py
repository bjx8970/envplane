"""SSH PTY over an explicitly pinned environment target and password."""

import base64
import binascii
import codecs
from contextlib import contextmanager
from dataclasses import dataclass, field
from hmac import compare_digest
from ipaddress import ip_address
import json
from pathlib import Path
import socket
from threading import Timer
from time import sleep

from control_plane.plugins.sdk import PluginError, PreparedCall, SecretRef, SessionOpenResult
from control_plane.plugins.sessions import OpeningNotEstablished


@dataclass(repr=False)
class Channel:
    sock: socket.socket
    transport: object
    channel: object
    decoder: object = field(default_factory=lambda: codecs.getincrementaldecoder("utf-8")("replace"))


def _interrupt(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


@contextmanager
def _budget(sock, deadline):
    # Paramiko's PTY/shell acknowledgement and packet writes may outlive a
    # channel timeout. Interrupt the socket on expiry and join the watchdog
    # before the caller releases its supervised capacity slot.
    timer = Timer(deadline.check(), _interrupt, args=(sock,))
    timer.daemon = True
    timer.start()
    try:
        yield
        deadline.check()
    finally:
        timer.cancel()
        timer.join()


def _target(value):
    try:
        if set(value) != {"hostname", "port", "username", "host_key"}:
            raise ValueError()
        hostname = str(ip_address(value["hostname"]))
        port, username, host_key = value["port"], value["username"], value["host_key"]
        if (type(port) is not int or not 1 <= port <= 65535 or not isinstance(username, str)
                or not 1 <= len(username) <= 255 or "\x00" in username or set(host_key) != {"type", "base64"}
                or not isinstance(host_key["type"], str) or not 1 <= len(host_key["type"]) <= 100
                or not isinstance(host_key["base64"], str) or not 1 <= len(host_key["base64"]) <= 16384):
            raise ValueError()
        key = base64.b64decode(host_key["base64"], validate=True)
        return hostname, port, username, host_key["type"], key
    except (KeyError, TypeError, ValueError, binascii.Error):
        raise PluginError("invalid_input", "terminal requires a confirmed IP, user and pinned SSH host key") from None


class SSHTerminal:
    def describe(self):
        return json.loads(Path(__file__).with_name("manifest.yaml").read_text(encoding="utf-8"))

    def prepare(self, action_key, input, context):
        raise PluginError("invalid_input", "interactive session capability required")

    def execute(self, prepared_call, context):
        raise PluginError("invalid_input", "interactive session capability required")

    def prepare_session(self, session_type, input, context):
        context.deadline.check()
        if session_type != "terminal" or input["input"] != {}:
            raise PluginError("invalid_input", "invalid terminal request")
        _target(input["target_ref"])
        ref = context.secrets.resolve(SecretRef(**input["credential_ref"]))
        if not ref.version_id:
            raise PluginError("unavailable", "terminal credential is not pinned")
        return PreparedCall(session_type, target_ref=input["target_ref"], secret_refs=(ref,))

    def open_session(self, prepared_call, context):
        import paramiko

        sock = transport = None
        shell_requested = False
        try:
            hostname, port, username, key_type, key = _target(prepared_call.target_ref)
            ref, = prepared_call.secret_refs
            if isinstance(ref, dict):
                ref = SecretRef(**ref)
            deadline = context.deadline
            with context.secrets.get(ref) as secret:
                password = secret.reveal().decode("utf-8")
                sock = socket.create_connection((hostname, port), timeout=min(5, deadline.check()))
                with _budget(sock, deadline):
                    transport = paramiko.Transport(sock)
                    transport.banner_timeout = min(5, deadline.check())
                    transport.auth_timeout = min(5, deadline.check())
                    transport.start_client(timeout=min(5, deadline.check()))
                    remote_key = transport.get_remote_server_key()
                    if key_type != remote_key.get_name() or not compare_digest(key, remote_key.asbytes()):
                        raise PluginError("host_key_mismatch", "SSH host key does not match the confirmed target")
                    transport.auth_password(username, password, fallback=False)
                    channel = transport.open_session(timeout=deadline.check())
                    channel.set_combine_stderr(True)
                    channel.get_pty(term="xterm-256color", width=80, height=24)
                    shell_requested = True
                    channel.invoke_shell()
            return SessionOpenResult(Channel(sock, transport, channel))
        except Exception:
            if sock is not None:
                _interrupt(sock)
            if transport is not None:
                transport.close()
            if sock is not None:
                sock.close()
            if shell_requested:
                raise PluginError("opening_unknown", "remote shell establishment could not be determined") from None
            raise OpeningNotEstablished("ssh_connection_failed", "remote shell was not established") from None

    def send(self, handle, input_frame, *, deadline):
        with _budget(handle.sock, deadline):
            handle.channel.settimeout(deadline.check())
            handle.channel.sendall(input_frame["data"].encode("utf-8"))

    def resize(self, handle, size, *, deadline):
        with _budget(handle.sock, deadline):
            handle.channel.resize_pty(width=size["cols"], height=size["rows"])

    def receive(self, handle, *, deadline):
        while not deadline.expired:
            if handle.channel.recv_ready():
                # JSON control-character escaping can expand each byte sixfold.
                handle.channel.settimeout(deadline.check())
                data = handle.channel.recv(2048)
                if not data:
                    return {"type": "closed"}
                current = handle.decoder.decode(data)
                return {"type": "output", "data": current} if current else None
            if handle.channel.closed or not handle.transport.is_active():
                remainder = handle.decoder.decode(b"", final=True)
                return {"type": "output", "data": remainder} if remainder else {"type": "closed"}
            sleep(min(0.02, deadline.remaining()))
        return None

    def close_session(self, handle, reason, *, deadline):
        _interrupt(handle.sock)
        try:
            handle.transport.close()
        finally:
            handle.sock.close()
        return {"channel_closed": True}
