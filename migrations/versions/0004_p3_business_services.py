"""P3 membership history, stable template instance names and credential facts."""
from pathlib import Path

from alembic import op

revision = "0004_p3_business_services"
down_revision = "0003_p2_runtime_contracts"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        ALTER TABLE control_plane.courses ADD COLUMN deleted_at timestamptz;
        ALTER TABLE control_plane.groups ADD COLUMN deleted_at timestamptz;
        ALTER TABLE control_plane.course_members ADD COLUMN left_at timestamptz;
        ALTER TABLE control_plane.plugin_instances ADD COLUMN instance_alias text UNIQUE
            CHECK (instance_alias ~ '^[A-Za-z0-9_][A-Za-z0-9_-]{0,127}$'
                   AND instance_alias !~* '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$');
        CREATE TRIGGER instance_alias_immutable BEFORE UPDATE ON control_plane.plugin_instances
            FOR EACH ROW WHEN (OLD.instance_alias IS NOT NULL)
            EXECUTE FUNCTION control_plane.protect_record('instance_alias');
    """)
    op.execute(Path(__file__).with_name("p3_credentials.sql").read_text(encoding="utf-8"))


def downgrade():
    op.execute("""
        DO $$ BEGIN
            IF EXISTS (SELECT FROM control_plane.courses WHERE deleted_at IS NOT NULL)
                OR EXISTS (SELECT FROM control_plane.groups WHERE deleted_at IS NOT NULL)
                OR EXISTS (SELECT FROM control_plane.course_members WHERE left_at IS NOT NULL)
                OR EXISTS (SELECT FROM control_plane.plugin_instances WHERE instance_alias IS NOT NULL)
                OR EXISTS (SELECT FROM control_plane.environment_credential_confirmations)
                OR EXISTS (SELECT FROM control_plane.access_revocations)
                OR EXISTS (SELECT FROM control_plane.jobs WHERE execution_snapshot ? 'workflow')
            THEN RAISE EXCEPTION 'P3 downgrade would discard business facts' USING ERRCODE='23514';
            END IF;
        END $$;
        DROP TABLE control_plane.access_revocations, control_plane.environment_credential_confirmations;
        DROP FUNCTION control_plane.guard_access_revocation();
        DROP FUNCTION control_plane.guard_credential_confirmation();
        DROP TRIGGER instance_alias_immutable ON control_plane.plugin_instances;
        ALTER TABLE control_plane.plugin_instances DROP COLUMN instance_alias;
        ALTER TABLE control_plane.course_members DROP COLUMN left_at;
        ALTER TABLE control_plane.groups DROP COLUMN deleted_at;
        ALTER TABLE control_plane.courses DROP COLUMN deleted_at;
    """)
