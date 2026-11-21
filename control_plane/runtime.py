from sqlalchemy import text

from .config import COORDINATOR_LOCK_KEY
from .coordination import CoordinatorLease
from .database import create_database_engine
from .execution.wakeup import Wakeup
from .migrations import SchemaMismatch, check_schema
from .permissions import RuntimePermissionError, validate_runtime_permissions


class CoordinatorConflict(RuntimeError):
    """Another process already holds the coordinator lock."""


class DatabaseUnavailable(RuntimeError):
    """The database could not be reached or the lock could not be checked."""


class RuntimeInitializationFailed(RuntimeError):
    """Plugin deployment or service composition failed without leaking details."""


class LeadershipLost(RuntimeError):
    """The coordinator lock session is no longer alive."""


class StartupInterrupted(RuntimeError):
    """A stop signal arrived while the coordinator was starting."""


class StartupDeadlineExceeded(RuntimeError):
    """The whole startup connection attempt exceeded its budget."""


class ControlPlaneRuntime:
    def __init__(self, settings, *, driver_factory=None, session_factory=None):
        self.settings = settings
        self.wakeup = Wakeup()
        self._engine = None
        self._lease = None
        self._state = "stopped"
        self._services = None
        self._driver_factory = driver_factory
        self._session_factory = session_factory

    def start(self) -> None:
        if self._state != "stopped":
            raise RuntimeError("control plane runtime is not stopped")
        self._engine = create_database_engine(self.settings)
        self._lease = CoordinatorLease(self._engine, COORDINATOR_LOCK_KEY, self.settings.lease_seconds)
        self._state = "starting"
        try:
            with self._engine.connect() as connection:
                check_schema(connection)
                if not connection.scalar(text("SELECT session_user = current_user")):
                    raise RuntimePermissionError("runtime must connect directly as its least-privilege login role")
                validate_runtime_permissions(connection)
            if not self._lease.acquire():
                raise CoordinatorConflict("another coordinator is active")
            self._state = "running"
            from .services import PluginServices
            self._services = PluginServices(self, driver_factory=self._driver_factory,
                                            session_factory=self._session_factory)
            self._services.start()
        except (StartupInterrupted, StartupDeadlineExceeded, SchemaMismatch,
                RuntimePermissionError, CoordinatorConflict):
            self.stop()
            raise
        except Exception:
            initializing_services = self._state == "running"
            self.stop()
            if initializing_services:
                raise RuntimeInitializationFailed("plugin runtime initialization failed") from None
            raise DatabaseUnavailable("database connection failed") from None
        except BaseException:
            self.stop()
            raise

    def poll(self) -> None:
        if self._state != "running" or self._lease is None:
            raise LeadershipLost("coordinator is not running")
        if not self._lease.verify():
            self._state = "lost"
            raise LeadershipLost("coordinator lock session was lost")
        if self._services is not None:
            self._services.tick()

    @property
    def services(self):
        if self._state != "running" or self._services is None:
            raise LeadershipLost("plugin services are not running")
        return self._services

    def health(self):
        details = self._services.health() if self._services is not None else {}
        degraded = self._state != "running" or details.get("degraded", False)
        return {"ready": not degraded, "degraded": degraded, "coordinator": self._state,
                "services": details}

    def stop(self) -> None:
        if self._state == "stopped":
            return
        lease = self._lease
        engine = self._engine
        services = self._services
        # Revoke new/queued authoritative writes immediately, before any plugin
        # shutdown grace. Remaining dispatch intents are recovery facts, not proof
        # of cancellation. Never delay P1 fencing behind a stuck plugin callback.
        self._state = "stopping"
        self._services = None
        if services is not None and services.driver is not None:
            services.driver.stop()
        if services is not None and services.sessions is not None:
            services.sessions.quiesce()
        self._lease = None
        if lease is not None:
            lease.release()
        try:
            if services is not None:
                services.stop()
        finally:
            self._engine = None
            self._state = "stopped"
            if engine is not None:
                engine.dispose()

    def fenced_transaction(self):
        if self._state != "running" or self._lease is None:
            raise LeadershipLost("coordinator is not running")
        return self._lease.fenced_transaction()

    @property
    def coordinator_identity(self):
        if self._lease is None:
            raise LeadershipLost("coordinator is not running")
        return str(self._lease.owner_id), self._lease.revision

    @property
    def lock_backend_pid(self) -> int:
        if self._lease is None or self._lease.backend_pid is None:
            raise RuntimeError("coordinator is not running")
        return self._lease.backend_pid
