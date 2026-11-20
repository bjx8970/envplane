"""Translate same-origin browser WebSockets to the P2 terminal protocol."""
import json

import anyio
from starlette.concurrency import run_in_threadpool
from starlette.responses import Response
from starlette.routing import WebSocketRoute
from starlette.websockets import WebSocketDisconnect

from ..plugins.sdk import AuthorizationDenied, PluginError
from .auth import COOKIE, HttpError

FRAME_LIMIT = 16384
SUBPROTOCOL = "lab-terminal"


def metadata(row, actor):
    return {"type": "control", "state": row["state"], "epoch": row["controller_revision"],
            "can_input": str(row["controller_id"]) == str(actor)}


def terminal_service(api):
    result = api.services.sessions
    if result is None:
        raise HttpError(503, "session_unavailable", "Interactive sessions are unavailable.")
    return result


def route(api):
    async def terminal(socket):
        accepted = reserved = False
        service = client = actor = None
        session_id = str(socket.path_params["session_id"])
        token = socket.cookies.get(COOKIE, "")
        alive = True

        def require_actor():
            current = api.sessions.actor(token)
            if current is None:
                raise AuthorizationDenied()
            return current["id"]

        def connection_valid():
            return alive and api.sessions._get(token) is not None

        def read_output():
            require_actor()
            row = service.store.get(session_id)
            frames = service.poll_output(actor, session_id, client, limit=1)
            return metadata(row, actor), frames

        async def send(frame):
            with anyio.fail_after(2):
                await socket.send_json(frame)

        try:
            api.origin.check(socket.headers, origin_required=True)
            try:
                api.websocket_slots.acquire_nowait()
            except anyio.WouldBlock:
                await socket.send_denial_response(Response(status_code=503, headers={"Retry-After": "2"}))
                return
            reserved = True
            if SUBPROTOCOL not in socket.scope.get("subprotocols", ()):
                raise HttpError(400, "invalid_protocol", "Terminal subprotocol is required.")
            actor = await run_in_threadpool(require_actor)
            service = terminal_service(api)
            after = socket.query_params.get("after")
            sequence = int(after) if after is not None else None
            if sequence is not None and not 0 <= sequence < 2**63:
                raise ValueError()
            client = await run_in_threadpool(service.observe, actor, session_id,
                                             after_seq=sequence, reconnect=after is not None)
            await socket.accept(subprotocol=SUBPROTOCOL)
            accepted = True
            previous = None
            wait = 0.1
            while True:
                message = None
                with anyio.move_on_after(wait):
                    message = await socket.receive()
                if message is not None:
                    if message["type"] == "websocket.disconnect":
                        break
                    raw = message.get("text")
                    if not isinstance(raw, str) or len(raw.encode()) > FRAME_LIMIT:
                        await socket.close(1009)
                        break
                    try:
                        frame = json.loads(raw)
                        await run_in_threadpool(require_actor)
                        await run_in_threadpool(service.frame, actor, session_id, frame,
                                                connection_valid=connection_valid)
                        if isinstance(frame, dict) and frame.get("type") == "close":
                            break
                    except AuthorizationDenied:
                        row = await run_in_threadpool(service.store.get, session_id)
                        # A current observer who tried to write gets a denial;
                        # a revoked observer cannot keep the WebSocket open.
                        await run_in_threadpool(require_actor)
                        await run_in_threadpool(service._authorize, actor, row, "observe")
                        await run_in_threadpool(api.audit_denial, actor, "session_frame")
                        await send({"type": "transport_error", "code": "read_only"})
                    except (ValueError, TypeError, RecursionError, PluginError) as exc:
                        code = getattr(exc, "code", "invalid_frame")
                        safe = code if code in {"backpressure", "conflict", "unsupported"} else "invalid_frame"
                        await send({"type": "transport_error", "code": safe})
                        if safe == "invalid_frame":
                            await socket.close(1008)
                            break
                control, frames = await run_in_threadpool(read_output)
                if control != previous:
                    await send(control)
                    previous = control
                if frames:
                    await run_in_threadpool(require_actor)
                    row = await run_in_threadpool(service.store.get, session_id)
                    await run_in_threadpool(service._authorize, actor, row, "output")
                    await send(frames[0])
                wait = 0.005 if frames else 0.1
        except WebSocketDisconnect:
            pass
        except Exception as exc:
            if isinstance(exc, AuthorizationDenied) and actor is not None:
                try:
                    await run_in_threadpool(api.audit_denial, actor, "session_connect_or_output")
                except Exception:
                    pass  # A persistence failure must still close the WebSocket.
            if accepted:
                # A closed or revoked stream never emits buffered output.
                with anyio.move_on_after(2):
                    await socket.close(1008 if isinstance(exc, AuthorizationDenied) else 1013)
            else:
                await socket.close(1008)
        finally:
            alive = False
            if reserved:
                api.websocket_slots.release()
            if service is not None and client is not None:
                try:
                    await run_in_threadpool(service.detach, actor, session_id, client)
                except PluginError:
                    pass

    return WebSocketRoute("/realtime/sessions/{session_id:uuid}", terminal)
