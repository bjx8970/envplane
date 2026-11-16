"""P2 runtime call provenance, fixed preparation and instance-scoped secrets."""
from pathlib import Path

from alembic import op

revision = "0003_p2_runtime_contracts"
down_revision = "0002_p1_review_guards"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(Path(__file__).with_name("p2_runtime.sql").read_text(encoding="utf-8"))


def downgrade():
    # The managed runner permits downgrade only for an empty application schema.
    # Native Alembic must not collapse two instance-specific grants into one P1
    # grant, discard provenance, or erase any execution fact either.
    op.execute("""
        DO $$ BEGIN
            IF EXISTS (SELECT 1 FROM control_plane.operation_call_attempts)
               OR EXISTS (SELECT 1 FROM control_plane.job_secret_refs)
               OR EXISTS (SELECT 1 FROM control_plane.interactive_sessions)
               OR EXISTS (SELECT 1 FROM control_plane.operation_evidence WHERE
                    call_attempt_id IS NOT NULL OR event_id IS NOT NULL OR
                    event_digest IS NOT NULL OR observed_at IS NOT NULL OR trusted_for_derivation)
               OR EXISTS (SELECT 1 FROM control_plane.job_steps WHERE
                    prepare_started_at IS NOT NULL OR prepare_deadline_at IS NOT NULL OR prepare_error IS NOT NULL)
               OR EXISTS (SELECT 1 FROM control_plane.secrets WHERE derived_spec_digest IS NOT NULL)
            THEN
                RAISE EXCEPTION 'P2 downgrade would discard runtime facts' USING ERRCODE='23514';
            END IF;
        END $$;
        DROP TRIGGER jobs_state_guard ON control_plane.jobs;
        DROP TRIGGER steps_state_guard ON control_plane.job_steps;
        DROP TRIGGER operations_state_guard ON control_plane.operations;
        DROP TRIGGER sessions_state_guard ON control_plane.interactive_sessions;
        DROP FUNCTION control_plane.guard_p2_execution();
        DROP TRIGGER session_identity ON control_plane.interactive_sessions;
        ALTER TABLE control_plane.interactive_sessions
            DROP CONSTRAINT session_secret_instance_fk,
            DROP COLUMN session_type, DROP COLUMN last_activity_at, DROP COLUMN controller_revision;
        DROP TRIGGER secret_derived_spec ON control_plane.secrets;
        ALTER TABLE control_plane.secrets DROP COLUMN derived_spec_digest;
        DROP TRIGGER job_secret_source ON control_plane.job_secret_refs;
        DROP FUNCTION control_plane.check_job_secret_source();
        ALTER TABLE control_plane.job_secret_refs
            DROP CONSTRAINT job_secret_refs_pkey,
            DROP CONSTRAINT job_secret_instance_fk,
            DROP CONSTRAINT job_secret_operation_fk,
            DROP CONSTRAINT job_secret_evidence_fk,
            DROP CONSTRAINT job_secret_provenance,
            DROP COLUMN plugin_instance_id, DROP COLUMN source_operation_id, DROP COLUMN source_evidence_id,
            ADD PRIMARY KEY (job_id, secret_version_id);
        ALTER TABLE control_plane.interactive_sessions
            ADD CONSTRAINT interactive_sessions_job_id_secret_version_id_fkey
            FOREIGN KEY (job_id, secret_version_id)
            REFERENCES control_plane.job_secret_refs(job_id, secret_version_id) ON DELETE RESTRICT;
        ALTER TABLE control_plane.job_steps
            DROP CONSTRAINT step_prepare_budget,
            DROP COLUMN prepare_started_at, DROP COLUMN prepare_deadline_at, DROP COLUMN prepare_error;
        ALTER TABLE control_plane.operation_evidence
            DROP CONSTRAINT evidence_call_fk,
            DROP CONSTRAINT evidence_source_unique,
            DROP CONSTRAINT evidence_event_metadata,
            DROP COLUMN call_attempt_id, DROP COLUMN event_id, DROP COLUMN event_digest,
            DROP COLUMN observed_at, DROP COLUMN trusted_for_derivation;
        DROP TABLE control_plane.operation_call_attempts;
    """)
