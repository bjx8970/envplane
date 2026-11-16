from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import text

from .config import COORDINATOR_LOCK_KEY
from .database import create_database_engine

SCHEMA = "control_plane"
BASELINE_REVISION = "0001_v1_foundation"
P1_REVISION = "0002_p1_review_guards"
HEAD_REVISION = "0003_p2_runtime_contracts"


class SchemaMismatch(RuntimeError):
    pass


class MigrationConflict(RuntimeError):
    pass


class MigrationError(RuntimeError):
    pass


def check_schema(connection, *, compatible_revisions=(HEAD_REVISION,)) -> None:
    if connection.scalar(text("SELECT to_regclass('control_plane.alembic_version')")) is None:
        raise SchemaMismatch("schema is not initialized; run python -m control_plane db upgrade")
    revisions = list(connection.scalars(text("SELECT version_num FROM control_plane.alembic_version")))
    if len(revisions) != 1 or revisions[0] not in compatible_revisions:
        raise SchemaMismatch("schema revision is incompatible; run python -m control_plane db upgrade")
    required = {
        "users", "courses", "groups", "course_members", "templates", "template_versions",
        "plugin_instances", "plugin_instance_versions", "plugin_storage_heads", "plugin_storage_versions",
        "plugin_storage_snapshots", "teacher_quotas", "quota_reservations", "environments",
        "experiment_resources", "environment_assignments", "execution_groups", "conflict_protections",
        "jobs", "job_steps", "operations", "operation_evidence", "job_logs", "local_resource_items",
        "job_plugin_snapshots", "job_secret_refs", "secrets", "secret_versions", "interactive_sessions",
        "audit_events", "coordinator_leases",
    }
    if revisions[0] == HEAD_REVISION:
        required.add("operation_call_attempts")
    tables = set(connection.scalars(text("SELECT tablename FROM pg_tables WHERE schemaname='control_plane'")))
    if not required <= tables:
        raise SchemaMismatch("schema is incomplete; restore a validated database")


def _validate_database(connection) -> None:
    foreign_tables = connection.scalar(text(
        "SELECT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname NOT IN ('pg_catalog','information_schema','control_plane') "
        "AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp_%' "
        "AND c.relkind IN ('r','p','v','m','f','S'))"
    ))
    if foreign_tables:
        raise MigrationError("refusing migration of a database containing unrelated objects")
    version_table = connection.scalar(text("SELECT to_regclass('control_plane.alembic_version')"))
    if version_table is None and connection.scalar(text(
        "SELECT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname='control_plane' AND c.relkind IN ('r','p','v','m','f','S'))"
    )):
        raise MigrationError("refusing an unversioned nonempty schema")


@contextmanager
def migration_transaction(settings, target="head", *, upgrade=True):
    if target not in ("head", "base", BASELINE_REVISION, P1_REVISION, HEAD_REVISION) or (upgrade and target == "base"):
        raise MigrationError("unsupported migration target")
    engine = create_database_engine(settings)
    try:
        with engine.begin() as connection:
            timeout_ms = str(int(settings.connect_timeout_seconds * 1000))
            connection.execute(text("SELECT set_config('lock_timeout', :value, true)"), {"value": f"{timeout_ms}ms"})
            connection.execute(text("SELECT set_config('statement_timeout', :value, true)"), {"value": "60s"})
            if not connection.scalar(text("SELECT pg_try_advisory_xact_lock(:key)"), {"key": COORDINATOR_LOCK_KEY}):
                raise MigrationConflict("another migration or coordinator is active")
            _validate_database(connection)
            connection.execute(text("CREATE SCHEMA IF NOT EXISTS control_plane"))
            if not upgrade:
                check_schema(connection, compatible_revisions=(BASELINE_REVISION, P1_REVISION, HEAD_REVISION))
                tables = list(connection.scalars(text(
                    "SELECT tablename FROM pg_tables WHERE schemaname='control_plane' "
                    "AND tablename NOT IN ('alembic_version','coordinator_leases')"
                )))
                for table in tables:
                    quoted = connection.dialect.identifier_preparer.quote(table)
                    if connection.scalar(text(f"SELECT EXISTS (SELECT 1 FROM control_plane.{quoted})")):
                        raise MigrationError("downgrade requires an empty application schema")
            yield connection
            if not upgrade and target == "base":
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
