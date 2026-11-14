from .config import COORDINATOR_LOCK_KEY
from .coordination import CoordinatorLease
from .database import create_database_engine
from .migrations import SchemaMismatch


class CoordinatorConflict(RuntimeError):
    """Another process already holds the coordinator lock."""


class DatabaseUnavailable(RuntimeError):
    """The database could not be reached or the lock could not be checked."""


class LeadershipLost(RuntimeError):
    """The coordinator lock session is no longer alive."""


class StartupInterrupted(RuntimeError):
    """A stop signal arrived while the coordinator was starting."""


class StartupDeadlineExceeded(RuntimeError):
    """The whole startup connection attempt exceeded its budget."""


class ControlPlaneRuntime:
    def __init__(self, settings):
        self.settings = settings
        self._engine = None
        self._lease = None
        self._state = "stopped"

    def start(self) -> None:
        if self._state != "stopped":
            raise RuntimeError("control plane runtime is not stopped")
        self._engine = create_database_engine(self.settings)
        self._lease = CoordinatorLease(self._engine, COORDINATOR_LOCK_KEY, self.settings.lease_seconds)
        self._state = "starting"
        try:
            if not self._lease.acquire():
                raise CoordinatorConflict("another coordinator is active")
            self._state = "running"
        except (StartupInterrupted, StartupDeadlineExceeded, SchemaMismatch, CoordinatorConflict):
            self.stop()
            raise
        except Exception:
            self.stop()
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

    def stop(self) -> None:
        if self._state == "stopped":
            return
        lease = self._lease
        engine = self._engine
        self._lease = None
        self._engine = None
        self._state = "stopped"
        if lease is not None:
            lease.release()
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
