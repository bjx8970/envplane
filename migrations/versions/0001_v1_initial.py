"""Initialize the current control-plane schema in a dedicated database."""
from pathlib import Path

from alembic import op

revision = "0001_v1_initial"
down_revision = None
branch_labels = None
depends_on = None

_TABLES = (
    "users", "courses", "groups", "course_members", "templates", "template_versions",
    "plugin_instances", "plugin_instance_versions", "plugin_storage_heads", "plugin_storage_versions",
    "plugin_storage_snapshots", "teacher_quotas", "quota_reservations", "environments",
    "experiment_resources", "environment_assignments", "execution_groups", "conflict_protections",
    "jobs", "job_steps", "operations", "operation_evidence", "operation_call_attempts",
    "job_logs", "local_resource_items", "job_plugin_snapshots", "job_secret_refs", "secrets",
    "secret_versions", "interactive_sessions", "audit_events", "coordinator_leases",
    "environment_credential_confirmations", "access_revocations", "execution_recovery_requests",
)


def upgrade():
    for file in ("v1_core.sql", "v1_execution.sql", "v1_credentials.sql", "v1_recovery.sql"):
        op.execute(Path(__file__).with_name(file).read_text(encoding="utf-8"))
    for table in (
        "plugin_instance_versions", "plugin_storage_versions", "plugin_storage_snapshots",
        "job_plugin_snapshots", "job_secret_refs", "operation_evidence", "job_logs", "audit_events",
    ):
        op.execute(f"""
            CREATE TRIGGER {table}_no_truncate BEFORE TRUNCATE ON control_plane.{table}
            FOR EACH STATEMENT EXECUTE FUNCTION control_plane.protect_record()
        """)


def downgrade():
    # The runner checks that the application tables are empty. Dropping the
    # tables together handles their foreign keys without cascading to other objects.
    op.execute("DROP TABLE " + ", ".join(f"control_plane.{table}" for table in _TABLES))
    op.execute("DROP FUNCTION " + ", ".join(
        f"control_plane.{signature}" for signature in (
            "check_secret_scope()", "protect_storage_view()", "protect_instance_revision()",
            "protect_template_status()", "protect_record()", "bounded_json(jsonb, text)",
            "protect_storage_head()", "check_storage_head_current()", "check_job_secret_source()",
            "guard_execution_state()", "guard_credential_confirmation()", "guard_access_revocation()",
        )
    ))
