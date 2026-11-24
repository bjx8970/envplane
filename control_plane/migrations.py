from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import text

from .config import COORDINATOR_LOCK_KEY
from .database import create_database_engine

SCHEMA = "control_plane"
HEAD_REVISION = "0001_v1_initial"


class SchemaMismatch(RuntimeError):
    pass


class MigrationConflict(RuntimeError):
    pass


class MigrationError(RuntimeError):
    pass


def check_schema(connection) -> None:
    if connection.scalar(text("SELECT to_regclass('control_plane.alembic_version')")) is None:
        raise SchemaMismatch("schema is not initialized; run python -m control_plane db upgrade")
    revisions = list(connection.scalars(text("SELECT version_num FROM control_plane.alembic_version")))
    if revisions != [HEAD_REVISION]:
        raise SchemaMismatch("schema revision is incompatible; initialize a new dedicated database")
    required = {
        "users", "courses", "groups", "course_members", "templates", "template_versions",
        "plugin_instances", "plugin_instance_versions", "plugin_storage_heads", "plugin_storage_versions",
        "plugin_storage_snapshots", "teacher_quotas", "quota_reservations", "environments",
        "experiment_resources", "environment_assignments", "execution_groups", "conflict_protections",
        "jobs", "job_steps", "operations", "operation_evidence", "job_logs", "local_resource_items",
        "job_plugin_snapshots", "job_secret_refs", "secrets", "secret_versions", "interactive_sessions",
        "audit_events", "coordinator_leases", "operation_call_attempts",
        "environment_credential_confirmations", "access_revocations", "execution_recovery_requests",
    }
    tables = set(connection.scalars(text("SELECT tablename FROM pg_tables WHERE schemaname='control_plane'")))
    if not required <= tables:
        raise SchemaMismatch("schema is incomplete; restore a validated database")


def _validate_database(connection) -> bool:
    foreign_tables = connection.scalar(text(
        "SELECT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname NOT IN ('pg_catalog','information_schema','control_plane') "
        "AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp_%' "
        "AND c.relkind IN ('r','p','v','m','f','S'))"
    ))
    if foreign_tables:
        raise MigrationError("refusing migration of a database containing unrelated objects")
    version_table = connection.scalar(text("SELECT to_regclass('control_plane.alembic_version')"))
    if version_table is not None:
        check_schema(connection)
        return True
    if connection.scalar(text(
        "SELECT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname='control_plane' AND c.relkind IN ('r','p','v','m','f','S'))"
    )):
        raise MigrationError("refusing an unversioned nonempty schema")
    return False


@contextmanager
def migration_transaction(settings, target="head", *, upgrade=True):
    if target not in (("head", HEAD_REVISION) if upgrade else ("base",)):
        raise MigrationError("unsupported migration target")
    engine = create_database_engine(settings)
    try:
        with engine.begin() as connection:
            timeout_ms = str(int(settings.connect_timeout_seconds * 1000))
            connection.execute(text("SELECT set_config('lock_timeout', :value, true)"), {"value": f"{timeout_ms}ms"})
            connection.execute(text("SELECT set_config('statement_timeout', :value, true)"), {"value": "60s"})
            if not connection.scalar(text("SELECT pg_try_advisory_xact_lock(:key)"), {"key": COORDINATOR_LOCK_KEY}):
                raise MigrationConflict("another migration or coordinator is active")
            initialized = _validate_database(connection)
            if not initialized and not upgrade:
                raise MigrationError("downgrade requires an initialized schema")
            # Require database CREATE privilege even for an idempotent upgrade.
            connection.execute(text("CREATE SCHEMA IF NOT EXISTS control_plane"))
            if not upgrade:
                tables = list(connection.scalars(text(
                    "SELECT tablename FROM pg_tables WHERE schemaname='control_plane' "
                    "AND tablename NOT IN ('alembic_version','coordinator_leases')"
                )))
                for table in tables:
                    quoted = connection.dialect.identifier_preparer.quote(table)
                    if connection.scalar(text(f"SELECT EXISTS (SELECT 1 FROM control_plane.{quoted})")):
                        raise MigrationError("downgrade requires an empty application schema")
            yield connection
            if not upgrade:
                connection.execute(text("DROP TABLE control_plane.alembic_version"))
                connection.execute(text("DROP SCHEMA control_plane"))
    except (MigrationConflict, MigrationError):
        raise
    except Exception:
        raise MigrationError("database migration failed; no changes were committed") from None
    finally:
        engine.dispose()


def run_migrations(settings, target="head", *, upgrade=True) -> None:
    from alembic import command
    from alembic.config import Config

    root = Path(__file__).resolve().parents[1]
    config = Config(str(root / "alembic.ini"))
    with migration_transaction(settings, target, upgrade=upgrade) as connection:
        config.attributes["connection"] = connection
        if upgrade:
            command.upgrade(config, target)
        else:
            command.downgrade(config, target)
