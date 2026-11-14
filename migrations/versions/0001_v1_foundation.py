"""Frozen v1 foundation; the runner owns the schema and transaction."""
from pathlib import Path

from alembic import op

revision = "0001_v1_foundation"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_name("v1_core.sql").read_text(encoding="utf-8"))
    op.execute(Path(__file__).with_name("v1_execution.sql").read_text(encoding="utf-8"))


def downgrade():
    # The runner rejects nonempty application tables. Break only explicit FK cycles.
    op.execute("""
        ALTER TABLE control_plane.secrets DROP CONSTRAINT secrets_environment_fk;
        ALTER TABLE control_plane.job_steps DROP CONSTRAINT job_steps_current_operation_fk;
        ALTER TABLE control_plane.execution_groups DROP CONSTRAINT execution_groups_current_job_fk;
        ALTER TABLE control_plane.plugin_storage_heads DROP CONSTRAINT storage_head_version_fk;
    """)
    tables = (
        "audit_events", "interactive_sessions", "job_secret_refs", "conflict_protections",
        "quota_reservations", "environment_assignments", "experiment_resources",
        "local_resource_items", "job_logs", "operation_evidence", "operations",
        "job_plugin_snapshots", "job_steps", "jobs", "execution_groups", "environments",
        "coordinator_leases", "teacher_quotas", "secret_versions", "secrets",
        "plugin_storage_snapshots", "plugin_storage_versions", "plugin_storage_heads",
        "plugin_instance_versions", "plugin_instances", "template_versions", "templates",
        "course_members", "groups", "courses", "users",
    )
    for table in tables:
        op.execute(f"DROP TABLE control_plane.{table}")
    for function in (
        "check_secret_scope()", "protect_storage_view()", "protect_instance_revision()",
        "protect_template_status()", "protect_record()",
        "bounded_json(jsonb, text)",
    ):
        op.execute(f"DROP FUNCTION control_plane.{function}")
