"""Explicit HTTP startup and initial administrator provisioning."""
from getpass import getpass
import sys

from sqlalchemy import text
import uvicorn

from ..config import RuntimeSettings
from ..identity import _hash_password, _label
from ..runtime import ControlPlaneRuntime
from . import create_app


def serve(runtime, origin, port):
    # The deployment proxy supplies TLS and preserves the configured Host.
    # Hiding vendor paths and tokens is simpler with access logging disabled.
    failed = False

    def fail():
        nonlocal failed
        failed = True
        server.should_exit = True

    server = uvicorn.Server(uvicorn.Config(
        create_app(runtime, origin, poll=True, on_failure=fail),
        host="127.0.0.1", port=port, workers=1, proxy_headers=False, access_log=False,
        limit_concurrency=128, timeout_keep_alive=5, timeout_graceful_shutdown=5,
        ws="websockets", ws_max_size=16384, ws_max_queue=4, ws_per_message_deflate=False,
    ))
    try:
        server.run()
    except SystemExit:
        return False
    return server.started and not failed


def bootstrap_admin(username):
    try:
        settings = RuntimeSettings.from_env()
        username = _label(username)
        password = getpass("Initial administrator password: ")
        if password != getpass("Confirm password: "):
            raise ValueError()
        hashed = _hash_password(password)
        runtime = ControlPlaneRuntime(settings)
        try:
            runtime.start()
            with runtime.fenced_transaction() as db:
                if db.scalar(text("SELECT EXISTS(SELECT FROM control_plane.users)")):
                    raise ValueError()
                user_id = db.scalar(text("""
                    INSERT INTO control_plane.users(username,password_hash,role)
                    VALUES (:name,:hash,'admin') RETURNING id
                """), {"name": username, "hash": hashed})
                db.execute(text("""
                    INSERT INTO control_plane.audit_events(actor_id,action,result)
                    VALUES (:actor,'account.bootstrap','succeeded')
                """), {"actor": user_id})
        finally:
            runtime.stop()
    except Exception:
        print("Initial administrator provisioning failed.", file=sys.stderr)
        return False
    print("Initial administrator created.")
    return True
