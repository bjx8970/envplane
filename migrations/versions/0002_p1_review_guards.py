"""P1 review: monotonic Storage heads and statement-level evidence protection."""
from pathlib import Path

from alembic import op

revision = "0002_p1_review_guards"
down_revision = "0001_v1_foundation"
branch_labels = None
depends_on = None

_APPEND_ONLY = (
    "plugin_instance_versions", "plugin_storage_versions", "plugin_storage_snapshots",
    "job_plugin_snapshots", "job_secret_refs", "operation_evidence", "job_logs", "audit_events",
)


def upgrade():
    op.execute(Path(__file__).with_name("v1_storage_head.sql").read_text(encoding="utf-8"))
    for table in _APPEND_ONLY:
        op.execute(f"""
            CREATE TRIGGER {table}_no_truncate
            BEFORE TRUNCATE ON control_plane.{table}
            FOR EACH STATEMENT EXECUTE FUNCTION control_plane.protect_record()
        """)


def downgrade():
    for table in _APPEND_ONLY:
        op.execute(f"DROP TRIGGER {table}_no_truncate ON control_plane.{table}")
    op.execute("""
        DROP TRIGGER storage_head_guard ON control_plane.plugin_storage_heads;
        DROP TRIGGER storage_head_current ON control_plane.plugin_storage_heads;
        DROP TRIGGER storage_history_head_current ON control_plane.plugin_storage_versions;
        DROP FUNCTION control_plane.check_storage_head_current();
        DROP FUNCTION control_plane.protect_storage_head();
    """)
