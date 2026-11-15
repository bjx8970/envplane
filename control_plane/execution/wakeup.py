"""Lossy NOTIFY acceleration; periodic database scans remain authoritative.

The listener owns a dedicated pg8000 DB-API connection. Only documented cursor,
notifications, commit/rollback/close APIs are used: no pool checkout is held, no
private socket/protocol fields are touched and no execution UoW is shared.
"""
from threading import Event, Thread


class Wakeup:
    def __init__(self):
        self._event = Event()

    def notify(self):
        self._event.set()

    def wait(self, seconds):
        if not 0 < seconds <= 60:
            raise ValueError("finite scan interval required")
        signalled = self._event.wait(seconds)
        self._event.clear()
        return signalled


class PostgresWakeupListener:
    CHANNEL = "control_plane_jobs"

    def __init__(self, connect, wakeup, *, poll_seconds=0.5):
        if not 0.01 <= poll_seconds <= 10:
            raise ValueError("bounded listener interval required")
        self._connect, self.wakeup = connect, wakeup
        self.poll_seconds = poll_seconds
        self._stop = Event()
        self._thread = None
        self.failed = False

    def start(self):
        if self._thread is not None:
            raise RuntimeError("listener already started")
        self._stop.clear()
        self._thread = Thread(target=self._run, name="execution-pg-listener", daemon=False)
        self._thread.start()

    def _run(self):
        connection = None
        try:
            # Deployment must configure a finite pg8000 connect/socket timeout.
            connection = self._connect()
            connection.autocommit = True
            cursor = connection.cursor()
            try:
                cursor.execute("LISTEN control_plane_jobs")
                self.wakeup.notify()  # Startup scan closes the LISTEN race.
                while not self._stop.wait(self.poll_seconds):
                    # pg8000 processes asynchronous protocol messages during a
                    # public round trip. A socket timeout bounds this operation.
                    cursor.execute("SELECT 1")
                    cursor.fetchall()
                    while connection.notifications:
                        connection.notifications.popleft()
                        self.wakeup.notify()
            finally:
                cursor.close()
        except Exception:
            self.failed = True
            self.wakeup.notify()  # Fall back to the service's finite periodic scan.
        finally:
            if connection is not None:
                connection.close()

    def stop(self, grace_seconds=2):
        if not 0 <= grace_seconds <= 60:
            raise ValueError("bounded shutdown grace required")
        self._stop.set()
        if self._thread:
            self._thread.join(grace_seconds)
            return not self._thread.is_alive()
        return True


def notify_jobs(uow):
    from sqlalchemy import text
    from ..coordination import require_fenced_connection
    require_fenced_connection(uow)
    # Transactional notification has no job data; recipients always rescan DB.
    uow.execute(text("SELECT pg_notify('control_plane_jobs','')"))
