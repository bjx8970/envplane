-- P2 is incremental: do not edit or reinterpret the P1 evidence baseline.
-- The runner owns the coordinator lock; table locks also freeze the legacy
-- authorization set throughout preflight/backfill, including direct SQL writers.
LOCK TABLE control_plane.job_secret_refs, control_plane.job_plugin_snapshots,
    control_plane.interactive_sessions IN SHARE ROW EXCLUSIVE MODE;
CREATE TABLE control_plane.operation_call_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_id UUID NOT NULL REFERENCES control_plane.operations(id) ON DELETE RESTRICT,
    method TEXT NOT NULL CHECK (method IN ('execute', 'poll', 'cancel')),
    job_lease_owner TEXT NOT NULL CHECK (length(job_lease_owner) > 0),
    job_lease_token UUID NOT NULL,
    coordinator_owner UUID NOT NULL,
    coordinator_revision BIGINT NOT NULL CHECK (coordinator_revision >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    deadline_at TIMESTAMPTZ NOT NULL,
    retry_of_call_id UUID,
    UNIQUE (id, operation_id),
    CHECK (deadline_at > created_at),
    CHECK (retry_of_call_id IS DISTINCT FROM id),
    FOREIGN KEY (retry_of_call_id, operation_id)
        REFERENCES control_plane.operation_call_attempts(id, operation_id) ON DELETE RESTRICT
);
CREATE INDEX operation_calls_operation_idx
    ON control_plane.operation_call_attempts(operation_id, created_at, id);
CREATE TRIGGER operation_calls_append_only BEFORE UPDATE OR DELETE ON control_plane.operation_call_attempts
    FOR EACH ROW EXECUTE FUNCTION control_plane.protect_record();
CREATE TRIGGER operation_calls_no_truncate BEFORE TRUNCATE ON control_plane.operation_call_attempts
    FOR EACH STATEMENT EXECUTE FUNCTION control_plane.protect_record();

ALTER TABLE control_plane.operation_evidence
    ADD COLUMN call_attempt_id UUID,
    ADD COLUMN event_id TEXT CHECK (event_id IS NULL OR length(event_id) > 0),
    ADD COLUMN event_digest TEXT CHECK (event_digest IS NULL OR length(event_digest) > 0),
    ADD COLUMN observed_at TIMESTAMPTZ,
    -- Only callbacks admitted under the live call fence may authorize derivation.
    -- Legacy and late evidence remain false, without rewriting their payload.
    ADD COLUMN trusted_for_derivation BOOLEAN NOT NULL DEFAULT false,
    ADD CONSTRAINT evidence_call_fk FOREIGN KEY (call_attempt_id, operation_id)
        REFERENCES control_plane.operation_call_attempts(id, operation_id) ON DELETE RESTRICT,
    ADD CONSTRAINT evidence_source_unique UNIQUE (id, operation_id),
    ADD CONSTRAINT evidence_event_metadata CHECK (
        (event_id IS NULL AND event_digest IS NULL) OR
        (event_id IS NOT NULL AND event_digest IS NOT NULL AND call_attempt_id IS NOT NULL AND observed_at IS NOT NULL));
CREATE UNIQUE INDEX operation_evidence_event_idx ON control_plane.operation_evidence(operation_id, event_id)
    WHERE event_id IS NOT NULL;

ALTER TABLE control_plane.job_steps
    ADD COLUMN prepare_started_at TIMESTAMPTZ,
    ADD COLUMN prepare_deadline_at TIMESTAMPTZ,
    ADD COLUMN prepare_error JSONB CHECK (prepare_error IS NULL OR control_plane.bounded_json(prepare_error, 'object')),
    ADD CONSTRAINT step_prepare_budget CHECK (
        (prepare_started_at IS NULL AND prepare_deadline_at IS NULL) OR
        (prepare_started_at IS NOT NULL AND prepare_deadline_at IS NOT NULL AND prepare_deadline_at > prepare_started_at));

-- A legacy grant did not name an instance. Only a unique already-authorized
-- Job snapshot is sufficient evidence. Never infer a grant from arbitrary code,
-- a current instance, or a list of candidate instances.
DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM control_plane.job_secret_refs r
        WHERE r.derived OR (SELECT count(*) FROM control_plane.job_plugin_snapshots s WHERE s.job_id=r.job_id) <> 1
    ) THEN
        RAISE EXCEPTION 'P2 upgrade requires unambiguous instance grants and derived provenance' USING ERRCODE='23514';
    END IF;
END $$;
ALTER TABLE control_plane.job_secret_refs
    ADD COLUMN plugin_instance_id UUID,
    ADD COLUMN source_operation_id UUID,
    ADD COLUMN source_evidence_id UUID;
-- P1 append-only history is retained byte-for-byte except for this proved scope.
ALTER TABLE control_plane.job_secret_refs DISABLE TRIGGER job_secret_refs_append_only;
UPDATE control_plane.job_secret_refs r SET plugin_instance_id=s.instance_id
    FROM control_plane.job_plugin_snapshots s WHERE s.job_id=r.job_id;
ALTER TABLE control_plane.job_secret_refs ENABLE TRIGGER job_secret_refs_append_only;
ALTER TABLE control_plane.interactive_sessions DROP CONSTRAINT interactive_sessions_job_id_secret_version_id_fkey;
ALTER TABLE control_plane.job_secret_refs
    DROP CONSTRAINT job_secret_refs_pkey,
    ALTER COLUMN plugin_instance_id SET NOT NULL,
    ADD PRIMARY KEY (job_id, plugin_instance_id, secret_version_id),
    ADD CONSTRAINT job_secret_instance_fk FOREIGN KEY (job_id, plugin_instance_id)
        REFERENCES control_plane.job_plugin_snapshots(job_id, instance_id) ON DELETE RESTRICT,
    ADD CONSTRAINT job_secret_provenance CHECK (
        (NOT derived AND source_operation_id IS NULL AND source_evidence_id IS NULL) OR
        (derived AND source_operation_id IS NOT NULL));
ALTER TABLE control_plane.job_secret_refs
    ADD CONSTRAINT job_secret_operation_fk FOREIGN KEY (source_operation_id, plugin_instance_id)
        REFERENCES control_plane.operations(id, plugin_instance_id) ON DELETE RESTRICT,
    ADD CONSTRAINT job_secret_evidence_fk FOREIGN KEY (source_evidence_id, source_operation_id)
        REFERENCES control_plane.operation_evidence(id, operation_id) ON DELETE RESTRICT;
ALTER TABLE control_plane.interactive_sessions
    ADD CONSTRAINT session_secret_instance_fk FOREIGN KEY (job_id, plugin_instance_id, secret_version_id)
        REFERENCES control_plane.job_secret_refs(job_id, plugin_instance_id, secret_version_id) ON DELETE RESTRICT;

CREATE FUNCTION control_plane.check_job_secret_source() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE instance_count bigint; authorized_instance uuid;
BEGIN
    -- Compatibility for P1 trusted-core inserts only; P2 APIs require explicit scope.
    IF NEW.plugin_instance_id IS NULL THEN
        SELECT count(*), (array_agg(instance_id))[1] INTO instance_count, authorized_instance
            FROM control_plane.job_plugin_snapshots WHERE job_id=NEW.job_id;
        IF instance_count <> 1 THEN
            RAISE EXCEPTION 'secret grant requires an unambiguous authorized instance' USING ERRCODE='23514';
        END IF;
        NEW.plugin_instance_id := authorized_instance;
    END IF;
    IF NEW.derived THEN
        -- An explicit recovery Job can consume the original exact output or
        -- checkpoint, but an unrelated Job/group cannot manufacture a grant.
        -- Job environment/group identities are immutable under the P1 guards.
        IF NOT EXISTS (
            SELECT 1 FROM control_plane.operations source
            JOIN control_plane.jobs producer ON producer.id=source.job_id
            JOIN control_plane.jobs consumer ON consumer.id=NEW.job_id
            WHERE source.id=NEW.source_operation_id
              AND producer.environment_id=consumer.environment_id
              AND producer.execution_group_id=consumer.execution_group_id
        ) THEN
            RAISE EXCEPTION 'derived secret source must belong to the same environment and execution group' USING ERRCODE='23514';
        END IF;
        IF NEW.source_evidence_id IS NULL THEN
            IF NOT EXISTS (SELECT 1 FROM control_plane.operations WHERE id=NEW.source_operation_id AND state='succeeded') THEN
                RAISE EXCEPTION 'derived secret requires successful output or checkpoint provenance' USING ERRCODE='23514';
            END IF;
        ELSIF NOT EXISTS (SELECT 1 FROM control_plane.operation_evidence
            WHERE id=NEW.source_evidence_id AND operation_id=NEW.source_operation_id
              AND kind='checkpoint' AND trusted_for_derivation) THEN
            RAISE EXCEPTION 'derived secret requires trusted checkpoint provenance' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER job_secret_source BEFORE INSERT ON control_plane.job_secret_refs
    FOR EACH ROW EXECUTE FUNCTION control_plane.check_job_secret_source();

ALTER TABLE control_plane.secrets ADD COLUMN derived_spec_digest TEXT
    CHECK (derived_spec_digest IS NULL OR length(derived_spec_digest) > 0);
CREATE TRIGGER secret_derived_spec BEFORE UPDATE ON control_plane.secrets
    FOR EACH ROW EXECUTE FUNCTION control_plane.protect_record('derived_spec_digest');

ALTER TABLE control_plane.interactive_sessions
    ADD COLUMN session_type TEXT NOT NULL DEFAULT 'terminal' CHECK (length(session_type) > 0),
    ADD COLUMN last_activity_at TIMESTAMPTZ,
    ADD COLUMN controller_revision BIGINT NOT NULL DEFAULT 0 CHECK (controller_revision >= 0);
UPDATE control_plane.interactive_sessions SET last_activity_at=created_at;
ALTER TABLE control_plane.interactive_sessions ALTER COLUMN last_activity_at SET DEFAULT clock_timestamp(),
    ALTER COLUMN last_activity_at SET NOT NULL;
CREATE TRIGGER session_identity BEFORE UPDATE OR DELETE ON control_plane.interactive_sessions
    FOR EACH ROW EXECUTE FUNCTION control_plane.protect_record(
        'id', 'environment_id', 'resource_id', 'job_id', 'open_operation_id', 'actor_id',
        'plugin_instance_id', 'target_ref', 'secret_version_id', 'template_entry', 'session_type', 'created_at');

CREATE FUNCTION control_plane.guard_p2_execution() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE allowed boolean := false; terminal boolean := false; before_row jsonb; after_row jsonb;
BEGIN
    IF TG_TABLE_NAME='jobs' THEN
        terminal := OLD.state IN ('succeeded','failed','cancelled');
        allowed := CASE OLD.state
            WHEN 'queued' THEN NEW.state IN ('running','cancelled','blocked')
            WHEN 'running' THEN NEW.state IN ('succeeded','failed','cancel_requested','blocked')
            WHEN 'cancel_requested' THEN NEW.state IN ('cancelled','blocked','succeeded','failed')
            WHEN 'blocked' THEN NEW.state IN ('running','failed','cancelled') ELSE false END;
        before_row := to_jsonb(OLD) - ARRAY['updated_at','lease_owner','lease_token','lease_expires_at','heartbeat_at'];
        after_row := to_jsonb(NEW) - ARRAY['updated_at','lease_owner','lease_token','lease_expires_at','heartbeat_at'];
    ELSIF TG_TABLE_NAME='job_steps' THEN
        terminal := OLD.state IN ('succeeded','failed','cancelled','skipped');
        allowed := CASE OLD.state
            WHEN 'pending' THEN NEW.state IN ('running','blocked','failed','cancelled','skipped')
            WHEN 'running' THEN NEW.state IN ('waiting_external','blocked','succeeded','failed','cancelled')
            WHEN 'waiting_external' THEN NEW.state IN ('blocked','succeeded','failed','cancelled')
            WHEN 'blocked' THEN NEW.state IN ('running','waiting_external','succeeded','failed','cancelled') ELSE false END;
        IF NEW.input IS DISTINCT FROM OLD.input
           OR (OLD.expansion IS NOT NULL AND NEW.expansion IS DISTINCT FROM OLD.expansion)
           OR (OLD.prepare_started_at IS NOT NULL AND NEW.prepare_started_at IS DISTINCT FROM OLD.prepare_started_at)
           OR (OLD.prepare_deadline_at IS NOT NULL AND NEW.prepare_deadline_at IS DISTINCT FROM OLD.prepare_deadline_at) THEN
            RAISE EXCEPTION 'step input, expansion and prepare budget are fixed' USING ERRCODE='23514';
        END IF;
        before_row := to_jsonb(OLD) - 'updated_at'; after_row := to_jsonb(NEW) - 'updated_at';
    ELSIF TG_TABLE_NAME='operations' THEN
        terminal := OLD.state IN ('succeeded','failed','cancelled');
        allowed := CASE OLD.state
            WHEN 'prepared' THEN NEW.state IN ('running','cancelled')
            WHEN 'running' THEN NEW.state IN ('succeeded','failed','cancelled','pending_external','unknown')
            WHEN 'pending_external' THEN NEW.state IN ('succeeded','failed','cancelled','unknown')
            WHEN 'unknown' THEN NEW.state IN ('pending_external','succeeded','failed','cancelled') ELSE false END;
        IF (OLD.dispatch_intent_at IS NOT NULL AND NEW.dispatch_intent_at IS DISTINCT FROM OLD.dispatch_intent_at)
           OR (OLD.deadline_at IS NOT NULL AND NEW.deadline_at IS DISTINCT FROM OLD.deadline_at) THEN
            RAISE EXCEPTION 'operation dispatch budget is fixed' USING ERRCODE='23514';
        END IF;
        before_row := to_jsonb(OLD) - ARRAY['updated_at','cancel_requested_at','cancellation_result'];
        after_row := to_jsonb(NEW) - ARRAY['updated_at','cancel_requested_at','cancellation_result'];
    ELSIF TG_TABLE_NAME='interactive_sessions' THEN
        terminal := OLD.state IN ('closed','failed','disconnected');
        allowed := CASE OLD.state
            WHEN 'opening' THEN NEW.state IN ('active','failed','disconnected')
            WHEN 'active' THEN NEW.state IN ('closing','disconnected')
            WHEN 'closing' THEN NEW.state IN ('closed','disconnected') ELSE false END;
        IF NEW.last_activity_at < OLD.last_activity_at
           OR (NEW.controller_id IS DISTINCT FROM OLD.controller_id AND NEW.controller_revision <> OLD.controller_revision+1)
           OR (NEW.controller_id IS NOT DISTINCT FROM OLD.controller_id AND NEW.controller_revision <> OLD.controller_revision) THEN
            RAISE EXCEPTION 'session activity and controller revision must be monotonic' USING ERRCODE='23514';
        END IF;
        before_row := to_jsonb(OLD); after_row := to_jsonb(NEW);
    END IF;
    IF NEW.state IS DISTINCT FROM OLD.state AND NOT allowed THEN
        RAISE EXCEPTION 'illegal execution state transition' USING ERRCODE='23514';
    END IF;
    IF terminal AND before_row IS DISTINCT FROM after_row THEN
        RAISE EXCEPTION 'terminal execution fact is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER jobs_state_guard BEFORE UPDATE ON control_plane.jobs
    FOR EACH ROW EXECUTE FUNCTION control_plane.guard_p2_execution();
CREATE TRIGGER steps_state_guard BEFORE UPDATE ON control_plane.job_steps
    FOR EACH ROW EXECUTE FUNCTION control_plane.guard_p2_execution();
CREATE TRIGGER operations_state_guard BEFORE UPDATE ON control_plane.operations
    FOR EACH ROW EXECUTE FUNCTION control_plane.guard_p2_execution();
CREATE TRIGGER sessions_state_guard BEFORE UPDATE ON control_plane.interactive_sessions
    FOR EACH ROW EXECUTE FUNCTION control_plane.guard_p2_execution();
