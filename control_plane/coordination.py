from contextlib import contextmanager
from threading import get_ident
from uuid import uuid4
import re

from sqlalchemy import text
from sqlalchemy.sql.dml import Delete, Insert, Update
from sqlalchemy.sql.elements import TextClause
from sqlalchemy.sql.selectable import Select

from .migrations import check_schema


class LeaseLost(RuntimeError):
    pass


_LOCK_EXISTS = """
EXISTS (SELECT 1 FROM pg_locks
        WHERE locktype='advisory' AND granted AND pid=:backend_pid
          AND classid=:lock_high AND objid=:lock_low AND objsubid=1)
"""


_FENCE_ISSUER = object()


class _FencedResult:
    """Expose row data, never CursorResult.connection/cursor/context."""

    def __init__(self, result):
        self._result = result

    def __iter__(self):
        yield from self._result

    def first(self):
        return self._result.first()

    def one(self):
        return self._result.one()

    def all(self):
        return self._result.all()

    def scalar_one(self):
        return self._result.scalar_one()

    @property
    def rowcount(self):
        return self._result.rowcount


class FencedConnection:
    """Core-only Unit of Work; no commit/rollback or raw-connection handoff.

    This is an accidental-misuse boundary for trusted core code, not a Python
    sandbox. Plugins must never receive this object or database credentials.
    """

    def __init__(self, connection, lease, *, _issuer=None):
        if _issuer is not _FENCE_ISSUER:
            raise LeaseLost("Unit of Work must be issued by the coordinator")
        self._connection = connection
        self._lease = lease
        self._transaction = connection.get_transaction()
        self._identity = (lease.owner_id, lease.revision, lease.backend_pid)
        self._thread = get_ident()
        self._active = True

    def _validate_scope(self):
        if (not self._active or get_ident() != self._thread
                or self._connection.closed or not self._transaction.is_active
                or self._connection.get_transaction() is not self._transaction
                or self._lease._connection is None
                or self._identity != (self._lease.owner_id, self._lease.revision,
                                      self._lease.backend_pid)):
            raise LeaseLost("fenced transaction is no longer active")

    def check_fence(self):
        self._validate_scope()
        self._lease._check_fence(self._connection)

    def _validate_statement(self, statement):
        self._validate_scope()
        if isinstance(statement, TextClause):
            # Fixed, single core DML/query statements only. Transaction control,
            # DDL, CALL/DO and multi-statement batches belong outside this UoW.
            # Parameters carry arbitrary values, not interpolated SQL text.
            sql = statement.text.strip()
            if ";" in sql or not re.match(
                r"^(SELECT|INSERT|UPDATE|DELETE|WITH)\b|^SET\s+(CONSTRAINTS\b|LOCAL\s+(lock_timeout|statement_timeout)\s*=)",
                sql, re.IGNORECASE,
            ):
                raise LeaseLost("statement is outside the fenced Unit of Work contract")
        elif not isinstance(statement, (Select, Insert, Update, Delete)):
            raise LeaseLost("statement is outside the fenced Unit of Work contract")

    def execute(self, statement, parameters=None):
        self._validate_statement(statement)
        return _FencedResult(self._connection.execute(statement, parameters or {}))

    def scalar(self, statement, parameters=None):
        self._validate_statement(statement)
        return self._connection.scalar(statement, parameters or {})

    def scalars(self, statement, parameters=None):
        self._validate_statement(statement)
        return _FencedResult(self._connection.scalars(statement, parameters or {}))

    @contextmanager
    def begin_nested(self):
        self._validate_scope()
        with self._connection.begin_nested():
            yield
        self._validate_scope()


def require_fenced_connection(connection):
    if not isinstance(connection, FencedConnection):
        raise LeaseLost("authoritative writes require a fenced Unit of Work")
    connection.check_fence()


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

    def _set_timeouts(self, connection, *, local):
        # A row-lock holder must not stall heartbeat or shutdown indefinitely.
        # Keep each database wait well below the lease; session defaults also
        # cover acquisition/release and survive the heartbeat transaction.
        milliseconds = max(1, int(min(1.0, self._lease_seconds / 4) * 1000))
        for setting in ("lock_timeout", "statement_timeout"):
            connection.execute(text("SELECT set_config(:setting, :value, :local)"),
                               {"setting": setting, "value": f"{milliseconds}ms", "local": local})

    def acquire(self) -> bool:
        if self._connection is not None:
            raise RuntimeError("coordinator lease is already held")
        connection = self._engine.connect()
        self._connection = connection
        try:
            # pg8000 pool_pre_ping can open a driver transaction before
            # SQLAlchemy has a RootTransaction. Switching autocommit alone does
            # not end it, so acquisition would retain the lease row lock and
            # deadlock its own fenced writer. Roll back at the DBAPI boundary;
            # Connection.rollback() can be a no-op in this checkout state.
            connection.connection.rollback()
            connection = connection.execution_options(isolation_level="AUTOCOMMIT")
            self._connection = connection
            self._set_timeouts(connection, local=False)
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
            self._set_timeouts(self._connection, local=True)
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
            unit = FencedConnection(connection, self, _issuer=_FENCE_ISSUER)
            try:
                yield unit
                unit.check_fence()
            finally:
                unit._active = False

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
