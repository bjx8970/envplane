from contextlib import contextmanager
from threading import Lock, get_ident
from time import monotonic
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


class _FencedMappingResult:
    """RowMapping rows without exposing CursorResult.connection/cursor/context."""

    def __init__(self, mappings):
        self._mappings = mappings

    def __iter__(self):
        yield from self._mappings

    def first(self):
        return self._mappings.first()

    def one(self):
        return self._mappings.one()

    def all(self):
        return self._mappings.all()


class _FencedResult:
    """Expose row data, never CursorResult.connection/cursor/context."""

    def __init__(self, result):
        self._result = result

    def __iter__(self):
        yield from self._result

    def mappings(self):
        # Mapping access is ordinary read data. The wrapping type deliberately
        # omits CursorResult attributes so a caller cannot reach the connection.
        return _FencedMappingResult(self._result.mappings())

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
        self._identity = lease._snapshot()
        self._thread = get_ident()
        self._active = True

    def _validate_scope(self):
        if (not self._active or get_ident() != self._thread
                or self._connection.closed or not self._transaction.is_active
                or self._connection.get_transaction() is not self._transaction
                or not self._lease._is_current(self._identity)):
            raise LeaseLost("fenced transaction is no longer active")

    def check_fence(self):
        self._validate_scope()
        self._lease._check_fence(self._connection, self._identity)

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
        self._budget = min(1.0, lease_seconds / 4)
        self._connection = None
        self._backend_pid = None
        self.owner_id = uuid4()
        self.revision = None
        # Local scheduling only: PostgreSQL remains the authority. Never wait
        # for the writer gate while owning the dedicated-session gate.
        self._write_gate = Lock()
        self._session_gate = Lock()
        self._state_lock = Lock()
        self._writer_thread = None
        self._generation = 0
        self._active = False
        self._acquiring = False
        self._renew_requested = 0
        self._renew_served = 0

    def _snapshot(self):
        with self._state_lock:
            if not self._active or self._connection is None:
                raise LeaseLost("coordinator lease is not active")
            return (self._generation, self._connection, self.owner_id,
                    self.revision, self._backend_pid)

    def _is_current(self, identity):
        with self._state_lock:
            return self._active and identity == (
                self._generation, self._connection, self.owner_id,
                self.revision, self._backend_pid,
            )

    def _parameters(self, identity=None):
        return {
            "owner_id": self.owner_id if identity is None else identity[2],
            "revision": self.revision if identity is None else identity[3],
            "backend_pid": self._backend_pid if identity is None else identity[4],
            "seconds": self._lease_seconds,
            "lock_high": self._lock_key >> 32,
            "lock_low": self._lock_key & 0xFFFFFFFF,
        }

    def _set_timeouts(self, connection, *, local):
        # Unknown/external row locks retain the original short failure budget.
        milliseconds = max(1, int(self._budget * 1000))
        for setting in ("lock_timeout", "statement_timeout"):
            connection.execute(text("SELECT set_config(:setting, :value, :local)"),
                               {"setting": setting, "value": f"{milliseconds}ms", "local": local})

    def _revoke(self, generation=None):
        # Stop invalidates queued writers/acquisition *before* any bounded wait.
        # Only a session-gate owner may touch or close the dedicated connection.
        with self._state_lock:
            if generation is not None and generation != self._generation:
                return None
            identity = (self._generation, self._connection, self.owner_id,
                        self.revision, self._backend_pid)
            self._active = False
            self._generation += 1
            self._renew_requested = self._renew_served = 0
            return identity

    def _close_revoked_session(self):
        # Caller owns _session_gate; a concurrent stop only changes local state.
        with self._state_lock:
            connection = None if self._active else self._connection
            if connection is not None:
                self._connection = None
                self._backend_pid = None
        if connection is not None:
            self._invalidate(connection)
            connection.close()

    def acquire(self) -> bool:
        with self._state_lock:
            if self._active or self._acquiring:
                raise RuntimeError("coordinator lease is already held or acquiring")
            generation = self._generation
            self._acquiring = True
        held = False
        connection = None
        try:
            held = self._session_gate.acquire(timeout=self._budget)
            if not held:
                raise LeaseLost("coordinator session is busy")
            self._close_revoked_session()
            with self._state_lock:
                if generation != self._generation:
                    return False
            connection = self._engine.connect()
            # pool_pre_ping may leave a DBAPI transaction without a SQLAlchemy
            # RootTransaction; end it before switching to autocommit.
            connection.connection.rollback()
            connection = connection.execution_options(isolation_level="AUTOCOMMIT")
            self._set_timeouts(connection, local=False)
            if not connection.scalar(text("SELECT pg_try_advisory_lock(:key)"), {"key": self._lock_key}):
                return False
            check_schema(connection)
            pid = int(connection.scalar(text("SELECT pg_backend_pid()")))
            parameters = self._parameters()
            parameters["backend_pid"] = pid
            revision = connection.scalar(text("""
                UPDATE control_plane.coordinator_leases
                SET previous_owner_id=COALESCE(owner_id, previous_owner_id), owner_id=:owner_id,
                    revision=revision+1, backend_pid=:backend_pid,
                    acquired_at=clock_timestamp(), heartbeat_at=clock_timestamp(),
                    expires_at=clock_timestamp()+make_interval(secs=>:seconds)
                WHERE id=1 AND (owner_id IS NULL OR expires_at<=clock_timestamp())
                RETURNING revision
            """), parameters)
            if revision is None:
                return False
            with self._state_lock:
                if generation != self._generation:
                    return False
                self._connection = connection
                self._backend_pid = pid
                self.revision = int(revision)
                self._renew_requested = self._renew_served = 0
                self._active = True
                connection = None  # ownership transferred to the lease
            return True
        except BaseException:
            self._revoke(generation)
            raise
        finally:
            try:
                if connection is not None:
                    self._invalidate(connection)
                    connection.close()
                if held:
                    self._close_revoked_session()
            finally:
                with self._state_lock:
                    self._acquiring = False
                if held:
                    self._session_gate.release()

    def _renew(self, identity):
        # Caller owns both gates. SQL time/ownership checks forbid revival of an
        # expired lease, including after waiting on an unknown external writer.
        connection = identity[1]
        connection.exec_driver_sql("BEGIN")
        self._set_timeouts(connection, local=True)
        connection.execute(text("SELECT id FROM control_plane.coordinator_leases WHERE id=1 FOR UPDATE"))
        renewed = connection.scalar(text(f"""
            UPDATE control_plane.coordinator_leases
            SET heartbeat_at=clock_timestamp(), expires_at=clock_timestamp()+make_interval(secs=>:seconds)
            WHERE id=1 AND owner_id=:owner_id AND revision=:revision AND backend_pid=:backend_pid
              AND expires_at>clock_timestamp() AND pg_backend_pid()=:backend_pid
              AND {_LOCK_EXISTS}
            RETURNING revision
        """), self._parameters(identity))
        connection.exec_driver_sql("COMMIT")
        return renewed is not None and self._is_current(identity)

    def verify(self) -> bool:
        try:
            identity = self._snapshot()
        except LeaseLost:
            return False
        if not self._session_gate.acquire(timeout=self._budget):
            self._revoke(identity[0])
            return False
        writing = False
        try:
            if not self._is_current(identity):
                return False
            writing = self._write_gate.acquire(blocking=False)
            if writing:
                with self._state_lock:
                    requested = self._renew_requested
                healthy = self._renew(identity)
                if healthy:
                    healthy = self._mark_renewed(identity, requested)
            else:
                # A known local UoW owns the row lock. MVCC inspection is safe
                # here, but neither this local gate nor that inspection renews
                # the lease or authorises a commit after expiry/advisory loss.
                healthy = identity[1].scalar(text(f"""
                    SELECT id FROM control_plane.coordinator_leases
                    WHERE id=1 AND owner_id=:owner_id AND revision=:revision
                      AND backend_pid=:backend_pid AND pg_backend_pid()=:backend_pid
                      AND expires_at>clock_timestamp() AND {_LOCK_EXISTS}
                """), self._parameters(identity)) is not None
                healthy = healthy and self._is_current(identity)
                if healthy:
                    with self._state_lock:
                        if identity[0] == self._generation and self._active:
                            self._renew_requested += 1
            if healthy:
                return True
            self._revoke(identity[0])
            return False
        except BaseException as error:
            self._revoke(identity[0])
            if not isinstance(error, Exception):
                raise
            return False
        finally:
            try:
                self._close_revoked_session()
            finally:
                if writing:
                    self._write_gate.release()
                self._session_gate.release()

    def _mark_renewed(self, identity, requested):
        with self._state_lock:
            if identity[0] != self._generation or not self._active:
                return False
            self._renew_served = requested
            return True

    def _serve_pending_renewal(self, identity, deadline):
        with self._state_lock:
            requested = self._renew_requested
            pending = requested > self._renew_served
        if not pending:
            return
        remaining = max(0, min(self._budget, deadline - monotonic()))
        if not self._session_gate.acquire(timeout=remaining):
            self._revoke(identity[0])
            raise LeaseLost("coordinator session is busy")
        try:
            if not self._is_current(identity) or not self._renew(identity):
                raise LeaseLost("coordinator lease was lost")
            # Consume only this generation's snapshot; stop may race between
            # the database COMMIT and this local bookkeeping operation.
            if not self._mark_renewed(identity, requested):
                raise LeaseLost("coordinator lease was stopped during renewal")
        except BaseException:
            self._revoke(identity[0])
            raise
        finally:
            try:
                self._close_revoked_session()
            finally:
                self._session_gate.release()

    @contextmanager
    def fenced_transaction(self):
        identity = self._snapshot()
        with self._state_lock:
            if self._writer_thread == get_ident():
                raise LeaseLost("nested fenced transactions are not supported")
        deadline = monotonic() + self._lease_seconds
        if not self._write_gate.acquire(timeout=max(0, deadline - monotonic())):
            raise LeaseLost("fenced transaction wait budget exhausted")
        try:
            if not self._is_current(identity):
                raise LeaseLost("coordinator lease was replaced while waiting")
            with self._state_lock:
                self._writer_thread = get_ident()
            # Busy polls request a bounded renewal at the NEXT transaction
            # boundary, never inside the preceding UoW. This prevents a queue
            # of short writers starving heartbeat renewals indefinitely.
            self._serve_pending_renewal(identity, deadline)
            with self._engine.begin() as connection:
                timeout = {"timeout": f"{int(self._lease_seconds * 1000)}ms"}
                connection.execute(text("SELECT set_config('lock_timeout', :timeout, true)"), timeout)
                connection.execute(text("SELECT set_config('statement_timeout', :timeout, true)"), timeout)
                self._check_fence(connection, identity)
                unit = FencedConnection(connection, self, _issuer=_FENCE_ISSUER)
                try:
                    yield unit
                    unit.check_fence()
                finally:
                    unit._active = False
            # engine.begin() has now actually committed (or, on error, rolled
            # back). Do NOT release the gate in the inner UoW finally block.
        finally:
            with self._state_lock:
                self._writer_thread = None
            self._write_gate.release()

    def _check_fence(self, connection, identity=None):
        identity = self._snapshot() if identity is None else identity
        if not self._is_current(identity):
            raise LeaseLost("coordinator lease is no longer active")
        connection.execute(text("SELECT id FROM control_plane.coordinator_leases WHERE id=1 FOR UPDATE"))
        row = connection.execute(text(f"""
            SELECT id FROM control_plane.coordinator_leases
            WHERE id=1 AND owner_id=:owner_id AND revision=:revision
              AND backend_pid=:backend_pid AND expires_at>clock_timestamp() AND {_LOCK_EXISTS}
        """), self._parameters(identity)).first()
        if row is None or not self._is_current(identity):
            raise LeaseLost("coordinator lease was lost")

    def release(self) -> None:
        identity = self._revoke()
        if identity[1] is None or not self._session_gate.acquire(timeout=self._budget):
            return
        try:
            # An acquire after this stop may already have closed the retired
            # session. Never release or close that acquire's new generation.
            if self._connection is not identity[1]:
                return
            try:
                identity[1].execute(text("""
                    UPDATE control_plane.coordinator_leases
                    SET previous_owner_id=owner_id, owner_id=NULL, backend_pid=NULL,
                        heartbeat_at=NULL, expires_at=NULL
                    WHERE id=1 AND owner_id=:owner_id AND revision=:revision
                """), self._parameters(identity))
                identity[1].execute(text("SELECT pg_advisory_unlock(:key)"), {"key": self._lock_key})
            except Exception:
                pass  # invalidation below also releases the session lock
        finally:
            try:
                self._close_revoked_session()
            finally:
                self._session_gate.release()

    @property
    def backend_pid(self):
        with self._state_lock:
            return self._backend_pid if self._active else None

    def _close(self):
        self._revoke()
        if self._session_gate.acquire(timeout=self._budget):
            try:
                self._close_revoked_session()
            finally:
                self._session_gate.release()

    @staticmethod
    def _invalidate(connection):
        try:
            connection.invalidate()
        except Exception:
            pass
