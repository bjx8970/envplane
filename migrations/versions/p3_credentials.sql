-- Only a projected, confirmed remote install makes an exact environment version viewable.
CREATE TABLE control_plane.environment_credential_confirmations (
    version_id uuid PRIMARY KEY,
    secret_id uuid NOT NULL,
    lineage_version_id uuid NOT NULL,
    predecessor_id uuid REFERENCES control_plane.environment_credential_confirmations(version_id),
    CHECK (predecessor_id IS NOT NULL OR lineage_version_id=version_id),
    FOREIGN KEY (lineage_version_id,secret_id) REFERENCES control_plane.secret_versions(id,secret_id),
    environment_id uuid NOT NULL REFERENCES control_plane.environments(id),
    job_id uuid NOT NULL,
    operation_id uuid NOT NULL UNIQUE,
    confirmed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (version_id, secret_id) REFERENCES control_plane.secret_versions(id, secret_id),
    FOREIGN KEY (job_id, environment_id) REFERENCES control_plane.jobs(id, environment_id),
    FOREIGN KEY (operation_id, job_id) REFERENCES control_plane.operations(id, job_id)
);
CREATE INDEX credential_confirmation_environment ON control_plane.environment_credential_confirmations(environment_id,secret_id);
CREATE TRIGGER credential_confirmation_immutable BEFORE UPDATE OR DELETE ON control_plane.environment_credential_confirmations
    FOR EACH ROW EXECUTE FUNCTION control_plane.protect_record();

CREATE TABLE control_plane.access_revocations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id uuid NOT NULL REFERENCES control_plane.users(id),
    student_id uuid NOT NULL REFERENCES control_plane.users(id),
    environment_id uuid NOT NULL REFERENCES control_plane.environments(id),
    exposed_versions uuid[] NOT NULL,
    action_key text,
    job_id uuid,
    status text NOT NULL CHECK (status IN ('revocation_pending','revocation_failed','confirmed')),
    reason text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    next_check_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (job_id, environment_id) REFERENCES control_plane.jobs(id,environment_id),
    CHECK (status <> 'confirmed' OR job_id IS NOT NULL)
);
CREATE INDEX access_revocations_pending ON control_plane.access_revocations(next_check_at,id)
    WHERE status='revocation_pending';
CREATE TRIGGER access_revocation_identity BEFORE UPDATE OR DELETE ON control_plane.access_revocations
    FOR EACH ROW EXECUTE FUNCTION control_plane.protect_record(
        'id','actor_id','student_id','environment_id','exposed_versions','action_key','created_at');
CREATE FUNCTION control_plane.guard_access_revocation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status <> 'revocation_pending' OR (OLD.job_id IS NOT NULL AND NEW.job_id IS DISTINCT FROM OLD.job_id) THEN
        RAISE EXCEPTION 'revocation disposition is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER access_revocation_disposition BEFORE UPDATE ON control_plane.access_revocations
    FOR EACH ROW EXECUTE FUNCTION control_plane.guard_access_revocation();
CREATE TRIGGER credential_confirmation_no_truncate BEFORE TRUNCATE ON control_plane.environment_credential_confirmations
    FOR EACH STATEMENT EXECUTE FUNCTION control_plane.protect_record();
CREATE TRIGGER access_revocations_no_truncate BEFORE TRUNCATE ON control_plane.access_revocations
    FOR EACH STATEMENT EXECUTE FUNCTION control_plane.protect_record();

CREATE FUNCTION control_plane.guard_credential_confirmation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT FROM control_plane.operations o
        JOIN control_plane.job_secret_refs g ON g.job_id=o.job_id AND g.plugin_instance_id=o.plugin_instance_id
        JOIN control_plane.secret_versions v ON v.id=g.secret_version_id
        JOIN control_plane.secrets s ON s.id=v.secret_id
        WHERE o.id=NEW.operation_id AND o.job_id=NEW.job_id AND o.state='succeeded'
          AND s.id=NEW.secret_id AND v.id=NEW.version_id
          AND s.purpose='environment' AND s.environment_id=NEW.environment_id
          AND v.revoked_at IS NULL AND v.invalidated_at IS NULL
          AND o.output->'confirmed_environment_credential' =
              jsonb_build_object('secret_id',s.id::text,'version_id',v.id::text)
    ) THEN
        RAISE EXCEPTION 'unproven environment credential confirmation' USING ERRCODE='23514';
    END IF;
    IF NEW.predecessor_id IS NOT NULL AND NOT EXISTS (
        SELECT FROM control_plane.environment_credential_confirmations previous
        JOIN control_plane.secret_versions prior ON prior.id=previous.version_id
        JOIN control_plane.secret_versions successor ON successor.id=NEW.version_id
        JOIN control_plane.operations o ON o.id=NEW.operation_id
        JOIN control_plane.access_revocations r ON r.job_id=NEW.job_id
        WHERE previous.version_id=NEW.predecessor_id AND previous.secret_id=NEW.secret_id
          AND previous.environment_id=NEW.environment_id AND previous.lineage_version_id=NEW.lineage_version_id
          AND prior.version<successor.version AND r.status='revocation_pending'
          AND previous.version_id=ANY(r.exposed_versions)
          AND o.output#>'{remote_revocation,replacement_confirmed}'='true'::jsonb
          AND (o.output#>'{remote_revocation,invalidated_versions}') ? previous.version_id::text
    ) THEN
        RAISE EXCEPTION 'unproven credential replacement' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER credential_confirmation_proof BEFORE INSERT ON control_plane.environment_credential_confirmations
    FOR EACH ROW EXECUTE FUNCTION control_plane.guard_credential_confirmation();
