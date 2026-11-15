import math
import os
from dataclasses import dataclass, field

from sqlalchemy.engine import make_url

COORDINATOR_LOCK_KEY = 0x4B384C5001
_DEFAULT_CONNECT_TIMEOUT = 5.0
_DEFAULT_LOCK_POLL = 1.0


class ConfigurationError(ValueError):
    """Raised when runtime configuration is missing or invalid."""


def _read_seconds(
    environ, name: str, default: float, minimum: float, maximum: float
) -> float:
    raw = environ.get(name)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        value = float(raw)
    except (TypeError, ValueError):
        raise ConfigurationError(f"{name} must be a number") from None
    if not math.isfinite(value) or not (minimum <= value <= maximum):
        raise ConfigurationError(
            f"{name} must be between {minimum} and {maximum}"
        )
    return value


@dataclass(frozen=True)
class RuntimeSettings:
    database_url: str = field(repr=False)
    connect_timeout_seconds: float = _DEFAULT_CONNECT_TIMEOUT
    lock_poll_seconds: float = _DEFAULT_LOCK_POLL
    lease_seconds: float = 30.0
    deployment_path: str | None = field(default=None, repr=False)

    @classmethod
    def from_env(cls, environ=None) -> "RuntimeSettings":
        env = os.environ if environ is None else environ
        raw_url = (env.get("CONTROL_PLANE_DATABASE_URL") or "").strip()
        if not raw_url:
            raise ConfigurationError("CONTROL_PLANE_DATABASE_URL is required")
        try:
            url = make_url(raw_url)
        except Exception:
            raise ConfigurationError(
                "CONTROL_PLANE_DATABASE_URL is not a valid URL"
            ) from None
        if url.drivername == "postgresql":
            url = url.set(drivername="postgresql+pg8000")
        elif url.drivername != "postgresql+pg8000":
            raise ConfigurationError(
                "CONTROL_PLANE_DATABASE_URL must use PostgreSQL with pg8000"
            )
        if not url.database:
            raise ConfigurationError(
                "CONTROL_PLANE_DATABASE_URL must name a database"
            )
        settings = cls(
            database_url=url.render_as_string(hide_password=False),
            connect_timeout_seconds=_read_seconds(
                env,
                "CONTROL_PLANE_CONNECT_TIMEOUT_SECONDS",
                _DEFAULT_CONNECT_TIMEOUT,
                0.5,
                30.0,
            ),
            lock_poll_seconds=_read_seconds(
                env,
                "CONTROL_PLANE_LOCK_POLL_SECONDS",
                _DEFAULT_LOCK_POLL,
                0.05,
                60.0,
            ),
            lease_seconds=_read_seconds(
                env, "CONTROL_PLANE_LEASE_SECONDS", 30.0, 1.0, 3600.0
            ),
            deployment_path=(env.get("CONTROL_PLANE_RUNTIME_CONFIG") or "").strip() or None,
        )
        if settings.lease_seconds <= 2 * settings.lock_poll_seconds + settings.connect_timeout_seconds:
            raise ConfigurationError("lease duration must exceed two polls and a connection timeout")
        return settings
