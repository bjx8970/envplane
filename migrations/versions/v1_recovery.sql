CREATE TABLE control_plane.execution_recovery_requests (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id uuid NOT NULL,
    group_id uuid NOT NULL,
    operation_id uuid,
    evidence_id uuid,
    actor_id uuid NOT NULL REFERENCES control_plane.users(id) ON DELETE RESTRICT,
    request_key uuid NOT NULL,
    expected_revision bigint NOT NULL CHECK (expected_revision >= 0),
    queue_revision bigint NOT NULL CHECK (queue_revision >= expected_revision),
    deferred_until timestamptz,
    confirmed_review_id uuid REFERENCES control_plane.execution_recovery_requests(id) ON DELETE RESTRICT,
    verification jsonb CHECK (verification IS NULL OR control_plane.bounded_json(verification,'object')),
    active_revision bigint,
    coordinator_revision bigint,
    call_attempt_id uuid UNIQUE,
    action text NOT NULL CHECK (action IN ('review', 'poll', 'apply_result')),
    reason text NOT NULL CHECK (
        (action='review' AND reason IN ('evidence_reviewed', 'evidence_inconclusive', 'external_success_declared'))
        OR (action='poll' AND reason='check_remote_status')
        OR (action='apply_result' AND reason='apply_verified_result')),
    state text NOT NULL CHECK (state IN ('queued', 'running', 'completed', 'blocked')),
    outcome text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    finished_at timestamptz,
    UNIQUE (actor_id, request_key),
    FOREIGN KEY (job_id, group_id) REFERENCES control_plane.jobs(id, execution_group_id) ON DELETE RESTRICT,
    FOREIGN KEY (operation_id, job_id) REFERENCES control_plane.operations(id, job_id) ON DELETE RESTRICT,
    FOREIGN KEY (evidence_id, operation_id)
        REFERENCES control_plane.operation_evidence(id, operation_id) ON DELETE RESTRICT,
    FOREIGN KEY (call_attempt_id, operation_id)
        REFERENCES control_plane.operation_call_attempts(id, operation_id) ON DELETE RESTRICT,
    CHECK (action='review' OR operation_id IS NOT NULL),
    CHECK (action<>'apply_result' OR evidence_id IS NOT NULL),
    CHECK ((action='apply_result') = (confirmed_review_id IS NOT NULL)),
    CHECK ((reason='external_success_declared') = (verification IS NOT NULL)),
    CHECK (verification IS NULL OR (evidence_id IS NOT NULL AND state='completed')),
    CHECK (evidence_id IS NULL OR operation_id IS NOT NULL),
    CHECK ((state IN ('completed', 'blocked')) = (finished_at IS NOT NULL)),
    CHECK ((state IN ('completed', 'blocked')) = (outcome IS NOT NULL)),
    CHECK ((active_revision IS NULL) = (coordinator_revision IS NULL)),
    CHECK (state<>'running' OR active_revision IS NOT NULL),
    CHECK (state<>'queued' OR active_revision IS NULL),
    CHECK (call_attempt_id IS NULL OR (action='poll' AND active_revision IS NOT NULL))
);
CREATE UNIQUE INDEX recovery_one_active_per_group ON control_plane.execution_recovery_requests(group_id)
    WHERE state IN ('queued','running');
CREATE INDEX recovery_queue ON control_plane.execution_recovery_requests
    ((action='apply_result') DESC,COALESCE(deferred_until,created_at),id) WHERE state='queued';
CREATE INDEX recovery_job_history ON control_plane.execution_recovery_requests(job_id,created_at,id);
CREATE INDEX jobs_blocked_review ON control_plane.jobs(created_at DESC,id DESC) WHERE state='blocked';
CREATE TRIGGER recovery_requests_no_truncate BEFORE TRUNCATE ON control_plane.execution_recovery_requests
    FOR EACH STATEMENT EXECUTE FUNCTION control_plane.protect_record();
CREATE TRIGGER recovery_request_identity BEFORE UPDATE ON control_plane.execution_recovery_requests
    FOR EACH ROW EXECUTE FUNCTION control_plane.protect_record(
        'job_id','group_id','operation_id','evidence_id','actor_id','request_key',
        'expected_revision','confirmed_review_id','verification','action','reason','created_at');
CREATE TRIGGER recovery_request_terminal BEFORE UPDATE ON control_plane.execution_recovery_requests
    FOR EACH ROW WHEN (OLD.state IN ('completed','blocked'))
    EXECUTE FUNCTION control_plane.protect_record();
CREATE TRIGGER recovery_request_claim BEFORE UPDATE ON control_plane.execution_recovery_requests
    FOR EACH ROW WHEN (OLD.active_revision IS NOT NULL AND NEW.state<>'queued')
    EXECUTE FUNCTION control_plane.protect_record('active_revision','coordinator_revision');
CREATE TRIGGER recovery_request_dispatch BEFORE UPDATE ON control_plane.execution_recovery_requests
    FOR EACH ROW WHEN (OLD.call_attempt_id IS NOT NULL AND NEW.state<>'queued')
    EXECUTE FUNCTION control_plane.protect_record('call_attempt_id');
