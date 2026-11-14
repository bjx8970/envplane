from contextlib import contextmanager
from uuid import uuid4

from sqlalchemy import text

from .migrations import check_schema


class LeaseLost(RuntimeError):
    pass


_LOCK_EXISTS = """
EXISTS (SELECT 1 FROM pg_locks
        WHERE locktype='advisory' AND granted AND pid=:backend_pid
          AND classid=:lock_high AND objid=:lock_low AND objsubid=1)
"""


class CoordinatorLease:
    def __init__(self, engine, lock_key: int, lease_seconds: float = 30):
        self._engine = engine
        self._lock_key = lock_key
        self._lease_seconds = lease_seconds
        self._connection = None
        self._backend_pid = None
        self.owner_id = uuid4()
        self.revision = None

    def _parameters(self):
        return {
            "owner_id": self.owner_id,
            "revision": self.revision,
            "backend_pid": self._backend_pid,
            "seconds": self._lease_seconds,
            "lock_high": self._lock_key >> 32,
            "lock_low": self._lock_key & 0xFFFFFFFF,
        }

    def acquire(self) -> bool:
        if self._connection is not None:
            raise RuntimeError("coordinator lease is already held")
        connection = self._engine.connect().execution_options(isolation_level="AUTOCOMMIT")
        self._connection = connection
        try:
            if not connection.scalar(text("SELECT pg_try_advisory_lock(:key)"), {"key": self._lock_key}):
                self._close()
                return False
            check_schema(connection)
            self._backend_pid = int(connection.scalar(text("SELECT pg_backend_pid()")))
            revision = connection.scalar(text("""
                UPDATE control_plane.coordinator_leases
                SET previous_owner_id=COALESCE(owner_id, previous_owner_id), owner_id=:owner_id,
                    revision=revision+1, backend_pid=:backend_pid,
                    acquired_at=clock_timestamp(), heartbeat_at=clock_timestamp(),
                    expires_at=clock_timestamp()+make_interval(secs=>:seconds)
                WHERE id=1 AND (owner_id IS NULL OR expires_at<=clock_timestamp())
                RETURNING revision
            """), self._parameters())
            if revision is None:
                self._close()
                return False
            self.revision = int(revision)
        except BaseException:
            self._close()
            raise
        return True

    def verify(self) -> bool:
        if self._connection is None:
            return False
        try:
            self._connection.exec_driver_sql("BEGIN")
            self._connection.execute(text("SELECT id FROM control_plane.coordinator_leases WHERE id=1 FOR UPDATE"))
            renewed = self._connection.scalar(text(f"""
                UPDATE control_plane.coordinator_leases
                SET heartbeat_at=clock_timestamp(), expires_at=clock_timestamp()+make_interval(secs=>:seconds)
                WHERE id=1 AND owner_id=:owner_id AND revision=:revision
                  AND expires_at>clock_timestamp() AND pg_backend_pid()=:backend_pid
                  AND {_LOCK_EXISTS}
                RETURNING revision
            """), self._parameters())
            self._connection.exec_driver_sql("COMMIT")
            if renewed is not None:
                return True
        except Exception:
            pass
        self._close()
        return False

    @contextmanager
    def fenced_transaction(self):
        if self._connection is None or self.revision is None:
            raise LeaseLost("coordinator lease is not active")
        with self._engine.begin() as connection:
            timeout = {"timeout": f"{int(self._lease_seconds * 1000)}ms"}
            connection.execute(text("SELECT set_config('lock_timeout', :timeout, true)"), timeout)
            connection.execute(text("SELECT set_config('statement_timeout', :timeout, true)"), timeout)
            self._check_fence(connection)
            yield connection
            self._check_fence(connection)

    def _check_fence(self, connection):
        connection.execute(text("SELECT id FROM control_plane.coordinator_leases WHERE id=1 FOR UPDATE"))
        row = connection.execute(text(f"""
            SELECT id FROM control_plane.coordinator_leases
            WHERE id=1 AND owner_id=:owner_id AND revision=:revision
              AND expires_at>clock_timestamp() AND {_LOCK_EXISTS}
        """), self._parameters()).first()
        if row is None:
            raise LeaseLost("coordinator lease was lost")

    def release(self) -> None:
        connection = self._connection
        self._connection = None
        if connection is None:
            return
        try:
            connection.execute(text("""
                UPDATE control_plane.coordinator_leases
                SET previous_owner_id=owner_id, owner_id=NULL, backend_pid=NULL,
                    heartbeat_at=NULL, expires_at=NULL
                WHERE id=1 AND owner_id=:owner_id AND revision=:revision
            """), self._parameters())
            connection.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": self._lock_key})
        except Exception:
            self._invalidate(connection)
        finally:
            connection.close()
            self._backend_pid = None

    @property
    def backend_pid(self):
        return self._backend_pid

    def _close(self):
        connection = self._connection
        self._connection = None
        self._backend_pid = None
        if connection is not None:
            self._invalidate(connection)
            connection.close()

    @staticmethod
    def _invalidate(connection):
        try:
            connection.invalidate()
        except Exception:
            pass
