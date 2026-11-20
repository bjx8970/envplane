"""Browser session and request security for a single control-plane process."""
from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest, digest
from secrets import token_urlsafe, token_bytes
from threading import Lock
from time import monotonic
from urllib.parse import urlsplit

from sqlalchemy import text

from ..identity import verify_password
from ..plugins.capacity import CapacityRejected

COOKIE = "lab_session"
LIFETIME = 8 * 60 * 60
DUMMY_PASSWORD_HASH = "scrypt:32768:8:1$" + "00" * 16 + "$" + "00" * 32


class HttpError(Exception):
    def __init__(self, status, code, message):
        self.status, self.code, self.message = status, code, message


@dataclass(frozen=True)
class BrowserOrigin:
    value: str
    authority: str
    secure: bool

    @classmethod
    def parse(cls, value):
        try:
            url = urlsplit(value)
            port = url.port
            if (url.scheme not in {"http", "https"} or not url.hostname or url.username is not None
                    or url.path or url.query or url.fragment or "*" in value
                    or value != f"{url.scheme}://{url.netloc}" or port == 0
                    or any(ord(char) <= 32 or ord(char) >= 127 for char in value)):
                raise ValueError()
        except (ValueError, TypeError):
            raise ValueError("HTTP origin must be one exact HTTP(S) origin") from None
        return cls(value, url.netloc, url.scheme == "https")

    def check(self, headers, *, origin_required):
        hosts = headers.getlist("host")
        origins = headers.getlist("origin")
        if hosts != [self.authority] or ((origins or origin_required) and origins != [self.value]):
            raise HttpError(403, "origin_denied", "The request origin is not allowed.")


class BrowserSessions:
    """Tokens expire, rotate on login, and are discarded on logout or restart."""

    def __init__(self, runtime, *, limit=4096):
        self.runtime, self.limit = runtime, limit
        self._key, self._lock, self._sessions = token_bytes(32), Lock(), {}

    def _sign(self, usage, value):
        return digest(self._key, (usage + value).encode(), sha256).hex()

    def anonymous(self):
        nonce = "anonymous." + token_urlsafe(32)
        return nonce + "." + self._sign("preauth:", nonce)

    def valid_anonymous(self, token):
        prefix, sep, signature = token.rpartition(".")
        return bool(sep and prefix.startswith("anonymous.") and
                    compare_digest(self._sign("preauth:", prefix), signature))

    def csrf(self, token):
        return self._sign("csrf:", token)

    def check_csrf(self, token, supplied):
        if (not token or len(token) > 128 or not supplied or not supplied.isascii()
                or not compare_digest(self.csrf(token), supplied)
                or (self._get(token) is None and not self.valid_anonymous(token))):
            raise HttpError(403, "csrf_denied", "The request could not be verified.")

    def _get(self, token):
        if not token or len(token) > 128:
            return None
        with self._lock:
            session = self._sessions.get(token)
            if session and session[2] <= monotonic():
                self._sessions.pop(token, None)
                return None
            return session

    def actor(self, token):
        session = self._get(token)
        if session is None:
            return None
        user_id, password_hash, _ = session
        with self.runtime._engine.connect() as db:
            row = db.execute(text("""
                SELECT id,username,role,password_hash FROM control_plane.users
                WHERE id=:id AND active AND deleted_at IS NULL
            """), {"id": user_id}).first()
        if not row or row.password_hash != password_hash:
            self.logout(token)
            return None
        if self._get(token) is not session:
            return None
        return {"id": str(row.id), "username": row.username, "role": row.role}

    def login(self, token, username, password):
        if not isinstance(username, str) or not 1 <= len(username) <= 255 or "\x00" in username:
            raise HttpError(401, "invalid_login", "Invalid username or password.")
        with self.runtime._engine.connect() as db:
            row = db.execute(text("""
                SELECT id,password_hash FROM control_plane.users
                WHERE username=:name AND active AND deleted_at IS NULL
            """), {"name": username.strip()}).first()
        if not verify_password(password, row.password_hash if row else DUMMY_PASSWORD_HASH) or not row:
            raise HttpError(401, "invalid_login", "Invalid username or password.")
        new_token = token_urlsafe(32)
        with self._lock:
            now = monotonic()
            self._sessions = {k: v for k, v in self._sessions.items() if v[2] > now and k != token}
            if len(self._sessions) >= self.limit:
                raise CapacityRejected("browser session capacity is exhausted")
            self._sessions[new_token] = (row.id, row.password_hash, now + LIFETIME)
        return new_token

    def logout(self, token):
        with self._lock:
            self._sessions.pop(token, None)
