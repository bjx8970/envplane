CREATE TABLE control_plane.environments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_teacher_id UUID NOT NULL REFERENCES control_plane.users(id) ON DELETE RESTRICT,
    course_id UUID NOT NULL,
    created_by UUID NOT NULL REFERENCES control_plane.users(id) ON DELETE RESTRICT,
    template_version_id UUID NOT NULL REFERENCES control_plane.template_versions(id) ON DELETE RESTRICT,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    parameters JSONB NOT NULL DEFAULT '{}' CHECK (control_plane.bounded_json(parameters, 'object')),
    create_results JSONB NOT NULL DEFAULT '{}' CHECK (control_plane.bounded_json(create_results, 'object')),
    target_ref JSONB CHECK (target_ref IS NULL OR control_plane.bounded_json(target_ref)),
    lifecycle TEXT NOT NULL DEFAULT 'creating' CHECK (lifecycle IN
        ('creating', 'ready', 'create_failed', 'blocked', 'deleting', 'delete_failed', 'deleted')),
    blocked_phase TEXT,
    blocked_reason JSONB CHECK (blocked_reason IS NULL OR control_plane.bounded_json(blocked_reason, 'object')),
    target_lifecycle TEXT CHECK (target_lifecycle IN
        ('creating', 'ready', 'create_failed', 'deleting', 'delete_failed', 'deleted')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ,
    UNIQUE (id, course_id), UNIQUE (id, owner_teacher_id), UNIQUE (id, template_version_id),
    FOREIGN KEY (course_id, owner_teacher_id)
        REFERENCES control_plane.courses(id, owner_teacher_id) ON DELETE RESTRICT
);

CREATE TABLE control_plane.execution_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    environment_id UUID NOT NULL REFERENCES control_plane.environments(id) ON DELETE RESTRICT,
    revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0),
    current_job_id UUID,
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'blocked', 'released')),
    reason JSONB CHECK (reason IS NULL OR control_plane.bounded_json(reason, 'object')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (id, environment_id)
);

CREATE TABLE control_plane.jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    environment_id UUID NOT NULL REFERENCES control_plane.environments(id) ON DELETE RESTRICT,
    execution_group_id UUID NOT NULL,
    actor_id UUID NOT NULL REFERENCES control_plane.users(id) ON DELETE RESTRICT,
    request_key TEXT NOT NULL CHECK (length(request_key) > 0),
    request_digest TEXT NOT NULL CHECK (length(request_digest) > 0),
    logical_invocation_id UUID NOT NULL DEFAULT gen_random_uuid(),
    parent_job_id UUID,
    retry_of UUID,
    kind TEXT NOT NULL CHECK (length(kind) > 0),
    input JSONB NOT NULL CHECK (control_plane.bounded_json(input, 'object')),
    execution_snapshot JSONB NOT NULL CHECK (
        control_plane.bounded_json(execution_snapshot, 'object')
        AND jsonb_typeof(execution_snapshot->'workflow') IS NOT DISTINCT FROM 'object'
        AND COALESCE(execution_snapshot #>> '{workflow,kind}' IN ('create', 'action', 'cleanup', 'session_open'), false)
        AND jsonb_typeof(execution_snapshot #> '{workflow,steps}') IS NOT DISTINCT FROM 'array'
    ),
    state TEXT NOT NULL DEFAULT 'queued' CHECK (state IN
        ('queued', 'running', 'cancel_requested', 'blocked', 'succeeded', 'failed', 'cancelled')),
    priority INTEGER NOT NULL DEFAULT 0,
    available_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts >= 1),
    lease_owner TEXT,
    lease_token UUID,
    lease_expires_at TIMESTAMPTZ,
    heartbeat_at TIMESTAMPTZ,
    cancel_requested_at TIMESTAMPTZ,
    error JSONB CHECK (error IS NULL OR control_plane.bounded_json(error, 'object')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMPTZ,
    UNIQUE (actor_id, request_key), UNIQUE (id, environment_id), UNIQUE (id, execution_group_id),
    UNIQUE (id, environment_id, logical_invocation_id),
    CHECK (parent_job_id IS DISTINCT FROM id AND retry_of IS DISTINCT FROM id),
    CHECK (num_nonnulls(lease_owner, lease_token, lease_expires_at) IN (0, 3)),
    FOREIGN KEY (execution_group_id, environment_id)
        REFERENCES control_plane.execution_groups(id, environment_id) ON DELETE RESTRICT,
    FOREIGN KEY (parent_job_id, execution_group_id)
        REFERENCES control_plane.jobs(id, execution_group_id) ON DELETE RESTRICT,
    FOREIGN KEY (retry_of, execution_group_id)
        REFERENCES control_plane.jobs(id, execution_group_id) ON DELETE RESTRICT
);
ALTER TABLE control_plane.execution_groups ADD CONSTRAINT execution_groups_current_job_fk
    FOREIGN KEY (current_job_id, id) REFERENCES control_plane.jobs(id, execution_group_id)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX jobs_queued_claim_idx ON control_plane.jobs(state, available_at, priority DESC, id)
    WHERE state = 'queued';
CREATE INDEX jobs_lease_expiry_idx ON control_plane.jobs(lease_expires_at)
    WHERE lease_expires_at IS NOT NULL;
CREATE INDEX jobs_environment_idx ON control_plane.jobs(environment_id, created_at);

CREATE TABLE control_plane.job_steps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL REFERENCES control_plane.jobs(id) ON DELETE RESTRICT,
    step_path TEXT NOT NULL CHECK (length(step_path) > 0),
    item_key TEXT NOT NULL DEFAULT '',
    attempt INTEGER NOT NULL DEFAULT 1 CHECK (attempt >= 1),
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN
        ('pending', 'running', 'waiting_external', 'blocked', 'succeeded', 'failed', 'cancelled', 'skipped')),
    input JSONB NOT NULL DEFAULT '{}' CHECK (control_plane.bounded_json(input)),
    output JSONB CHECK (output IS NULL OR control_plane.bounded_json(output)),
    prepare_started_at TIMESTAMPTZ,
    prepare_deadline_at TIMESTAMPTZ,
    prepare_error JSONB CHECK (prepare_error IS NULL OR control_plane.bounded_json(prepare_error, 'object')),
    expansion JSONB CHECK (expansion IS NULL OR control_plane.bounded_json(expansion)),
    error JSONB CHECK (error IS NULL OR control_plane.bounded_json(error, 'object')),
    current_operation_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMPTZ,
    CONSTRAINT step_prepare_budget CHECK (
        (prepare_started_at IS NULL AND prepare_deadline_at IS NULL) OR
        (prepare_started_at IS NOT NULL AND prepare_deadline_at IS NOT NULL AND prepare_deadline_at > prepare_started_at)),
    UNIQUE (job_id, step_path, item_key), UNIQUE (id, job_id),
    CHECK (state NOT IN ('running', 'waiting_external', 'succeeded') OR current_operation_id IS NOT NULL)
);

CREATE TABLE control_plane.job_plugin_snapshots (
    job_id UUID NOT NULL REFERENCES control_plane.jobs(id) ON DELETE RESTRICT,
    instance_id UUID NOT NULL REFERENCES control_plane.plugin_instances(id) ON DELETE RESTRICT,
    configuration_revision BIGINT NOT NULL CHECK (configuration_revision >= 0),
    storage_snapshot_id UUID NOT NULL,
    plugin_version TEXT NOT NULL CHECK (length(plugin_version) > 0),
    code_digest TEXT NOT NULL CHECK (length(code_digest) > 0),
    PRIMARY KEY (job_id, instance_id),
    UNIQUE (job_id, instance_id, plugin_version, code_digest),
    FOREIGN KEY (instance_id, configuration_revision, plugin_version, code_digest)
        REFERENCES control_plane.plugin_instance_versions(instance_id, revision, plugin_version, code_digest) ON DELETE RESTRICT,
    FOREIGN KEY (storage_snapshot_id, instance_id)
        REFERENCES control_plane.plugin_storage_snapshots(id, instance_id) ON DELETE RESTRICT
);

CREATE TABLE control_plane.operations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL REFERENCES control_plane.jobs(id) ON DELETE RESTRICT,
    step_id UUID NOT NULL,
    attempt INTEGER NOT NULL CHECK (attempt >= 1),
    invocation_key TEXT NOT NULL CHECK (length(invocation_key) > 0),
    plugin_instance_id UUID NOT NULL,
    plugin_version TEXT NOT NULL CHECK (length(plugin_version) > 0),
    code_digest TEXT NOT NULL CHECK (length(code_digest) > 0),
    prepared_call JSONB NOT NULL CHECK (control_plane.bounded_json(prepared_call, 'object')),
    state TEXT NOT NULL DEFAULT 'prepared' CHECK (state IN
        ('prepared', 'running', 'pending_external', 'succeeded', 'failed', 'cancelled', 'unknown')),
    external_execution_ref JSONB CHECK (external_execution_ref IS NULL OR control_plane.bounded_json(external_execution_ref)),
    output JSONB CHECK (output IS NULL OR control_plane.bounded_json(output)),
    protocol_error JSONB CHECK (protocol_error IS NULL OR control_plane.bounded_json(protocol_error, 'object')),
    error JSONB CHECK (error IS NULL OR control_plane.bounded_json(error, 'object')),
    cancellation_result TEXT CHECK (cancellation_result IN
        ('unsupported', 'requested', 'confirmed_cancelled', 'too_late', 'unknown')),
    cancel_requested_at TIMESTAMPTZ,
    dispatch_intent_at TIMESTAMPTZ,
    deadline_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMPTZ,
    UNIQUE (step_id, attempt), UNIQUE (id, step_id), UNIQUE (id, job_id), UNIQUE (id, plugin_instance_id),
    FOREIGN KEY (step_id, job_id) REFERENCES control_plane.job_steps(id, job_id) ON DELETE RESTRICT,
    FOREIGN KEY (job_id, plugin_instance_id, plugin_version, code_digest)
        REFERENCES control_plane.job_plugin_snapshots(job_id, instance_id, plugin_version, code_digest) ON DELETE RESTRICT
);
ALTER TABLE control_plane.job_steps ADD CONSTRAINT job_steps_current_operation_fk
    FOREIGN KEY (current_operation_id, id) REFERENCES control_plane.operations(id, step_id)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

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

CREATE TABLE control_plane.operation_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_id UUID NOT NULL REFERENCES control_plane.operations(id) ON DELETE RESTRICT,
    kind TEXT NOT NULL CHECK (kind IN ('external_ref', 'checkpoint', 'late_result')),
    ref_key TEXT NOT NULL CHECK (length(ref_key) > 0),
    revision BIGINT NOT NULL CHECK (revision > 0),
    data JSONB NOT NULL CHECK (control_plane.bounded_json(data)),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    call_attempt_id UUID NOT NULL,
    event_id TEXT NOT NULL CHECK (length(event_id) > 0),
    event_digest TEXT NOT NULL CHECK (length(event_digest) > 0),
    observed_at TIMESTAMPTZ NOT NULL,
    trusted_for_derivation BOOLEAN NOT NULL DEFAULT false,
    CONSTRAINT evidence_call_fk FOREIGN KEY (call_attempt_id, operation_id)
        REFERENCES control_plane.operation_call_attempts(id, operation_id) ON DELETE RESTRICT,
    CONSTRAINT evidence_source_unique UNIQUE (id, operation_id),
    UNIQUE (operation_id, kind, ref_key, revision)
);
CREATE UNIQUE INDEX operation_evidence_event_idx ON control_plane.operation_evidence(operation_id, event_id);
CREATE INDEX operation_evidence_read_idx ON control_plane.operation_evidence(operation_id, created_at, id);

CREATE TABLE control_plane.job_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL REFERENCES control_plane.jobs(id) ON DELETE RESTRICT,
    sequence BIGINT NOT NULL CHECK (sequence >= 0),
    data JSONB NOT NULL CHECK (control_plane.bounded_json(data)),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (job_id, sequence)
);

CREATE TABLE control_plane.local_resource_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    environment_id UUID NOT NULL REFERENCES control_plane.environments(id) ON DELETE RESTRICT,
    logical_invocation_id UUID NOT NULL,
    resource_slot TEXT NOT NULL CHECK (length(resource_slot) > 0),
    item_key TEXT NOT NULL DEFAULT '',
    source_job_id UUID NOT NULL,
    source_operation_id UUID NOT NULL,
    confirmed_input_refs JSONB NOT NULL CHECK (control_plane.bounded_json(confirmed_input_refs, 'object')),
    data JSONB NOT NULL DEFAULT '{}' CHECK (control_plane.bounded_json(data, 'object')),
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'completed', 'blocked', 'failed')),
    error JSONB CHECK (error IS NULL OR control_plane.bounded_json(error, 'object')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (environment_id, logical_invocation_id, resource_slot, item_key),
    UNIQUE (id, environment_id, logical_invocation_id, resource_slot, item_key),
    FOREIGN KEY (source_job_id, environment_id, logical_invocation_id)
        REFERENCES control_plane.jobs(id, environment_id, logical_invocation_id) ON DELETE RESTRICT,
    FOREIGN KEY (source_operation_id, source_job_id)
        REFERENCES control_plane.operations(id, job_id) ON DELETE RESTRICT
);

CREATE TABLE control_plane.experiment_resources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    environment_id UUID NOT NULL REFERENCES control_plane.environments(id) ON DELETE RESTRICT,
    logical_invocation_id UUID NOT NULL,
    resource_slot TEXT NOT NULL CHECK (length(resource_slot) > 0),
    item_key TEXT NOT NULL DEFAULT '',
    source_job_id UUID NOT NULL,
    source_operation_id UUID NOT NULL,
    local_resource_item_id UUID,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    type_label TEXT NOT NULL CHECK (length(type_label) BETWEEN 1 AND 255),
    display JSONB NOT NULL DEFAULT '{}' CHECK (control_plane.bounded_json(display, 'object')),
    data JSONB NOT NULL CHECK (control_plane.bounded_json(data, 'object')),
    target_ref JSONB CHECK (target_ref IS NULL OR control_plane.bounded_json(target_ref)),
    action_snapshot JSONB NOT NULL CHECK (control_plane.bounded_json(action_snapshot, 'object')),
    access_snapshot JSONB NOT NULL CHECK (control_plane.bounded_json(access_snapshot, 'object')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (environment_id, logical_invocation_id, resource_slot, item_key), UNIQUE (id, environment_id),
    FOREIGN KEY (source_job_id, environment_id, logical_invocation_id)
        REFERENCES control_plane.jobs(id, environment_id, logical_invocation_id) ON DELETE RESTRICT,
    FOREIGN KEY (source_operation_id, source_job_id)
        REFERENCES control_plane.operations(id, job_id) ON DELETE RESTRICT,
    FOREIGN KEY (local_resource_item_id, environment_id, logical_invocation_id, resource_slot, item_key)
        REFERENCES control_plane.local_resource_items(id, environment_id, logical_invocation_id, resource_slot, item_key) ON DELETE RESTRICT
);

CREATE TABLE control_plane.environment_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    environment_id UUID NOT NULL,
    course_id UUID NOT NULL,
    group_id UUID,
    student_id UUID,
    assigned_by UUID NOT NULL REFERENCES control_plane.users(id) ON DELETE RESTRICT,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMPTZ,
    CHECK (num_nonnulls(group_id, student_id) = 1),
    FOREIGN KEY (environment_id, course_id) REFERENCES control_plane.environments(id, course_id) ON DELETE RESTRICT,
    FOREIGN KEY (group_id, course_id) REFERENCES control_plane.groups(id, course_id) ON DELETE RESTRICT,
    FOREIGN KEY (course_id, student_id) REFERENCES control_plane.course_members(course_id, student_id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX environment_assignments_active_group_idx
    ON control_plane.environment_assignments(environment_id, group_id) WHERE revoked_at IS NULL AND group_id IS NOT NULL;
CREATE UNIQUE INDEX environment_assignments_active_student_idx
    ON control_plane.environment_assignments(environment_id, student_id) WHERE revoked_at IS NULL AND student_id IS NOT NULL;

CREATE TABLE control_plane.quota_reservations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL UNIQUE,
    environment_id UUID NOT NULL,
    teacher_id UUID NOT NULL REFERENCES control_plane.teacher_quotas(teacher_id) ON DELETE RESTRICT,
    environments BIGINT NOT NULL CHECK (environments >= 0),
    vms BIGINT NOT NULL CHECK (vms >= 0),
    vcpu BIGINT NOT NULL CHECK (vcpu >= 0),
    memory_mb BIGINT NOT NULL CHECK (memory_mb >= 0),
    state TEXT NOT NULL DEFAULT 'reserved' CHECK (state IN ('reserved', 'allocated', 'quarantined', 'released')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    released_at TIMESTAMPTZ,
    CHECK ((state = 'released') = (released_at IS NOT NULL)),
    FOREIGN KEY (job_id, environment_id) REFERENCES control_plane.jobs(id, environment_id) ON DELETE RESTRICT,
    FOREIGN KEY (environment_id, teacher_id) REFERENCES control_plane.environments(id, owner_teacher_id) ON DELETE RESTRICT
);
CREATE INDEX quota_reservations_teacher_idx ON control_plane.quota_reservations(teacher_id, state);

CREATE TABLE control_plane.conflict_protections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_key TEXT NOT NULL CHECK (length(scope_key) > 0),
    execution_group_id UUID NOT NULL REFERENCES control_plane.execution_groups(id) ON DELETE RESTRICT,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision >= 1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    released_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX conflict_protections_active_scope_idx
    ON control_plane.conflict_protections(scope_key) WHERE released_at IS NULL;
CREATE INDEX conflict_protections_group_idx ON control_plane.conflict_protections(execution_group_id);

ALTER TABLE control_plane.secrets ADD CONSTRAINT secrets_environment_fk
    FOREIGN KEY (environment_id) REFERENCES control_plane.environments(id) ON DELETE RESTRICT;
CREATE TABLE control_plane.job_secret_refs (
    job_id UUID NOT NULL REFERENCES control_plane.jobs(id) ON DELETE RESTRICT,
    secret_version_id UUID NOT NULL REFERENCES control_plane.secret_versions(id) ON DELETE RESTRICT,
    derived BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    plugin_instance_id UUID NOT NULL,
    source_operation_id UUID,
    source_evidence_id UUID,
    PRIMARY KEY (job_id, plugin_instance_id, secret_version_id),
    CONSTRAINT job_secret_instance_fk FOREIGN KEY (job_id, plugin_instance_id)
        REFERENCES control_plane.job_plugin_snapshots(job_id, instance_id) ON DELETE RESTRICT,
    CONSTRAINT job_secret_provenance CHECK (
        (NOT derived AND source_operation_id IS NULL AND source_evidence_id IS NULL) OR
        (derived AND source_operation_id IS NOT NULL)),
    CONSTRAINT job_secret_operation_fk FOREIGN KEY (source_operation_id, plugin_instance_id)
        REFERENCES control_plane.operations(id, plugin_instance_id) ON DELETE RESTRICT,
    CONSTRAINT job_secret_evidence_fk FOREIGN KEY (source_evidence_id, source_operation_id)
        REFERENCES control_plane.operation_evidence(id, operation_id) ON DELETE RESTRICT
);

CREATE TABLE control_plane.interactive_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    environment_id UUID NOT NULL REFERENCES control_plane.environments(id) ON DELETE RESTRICT,
    resource_id UUID,
    job_id UUID NOT NULL,
    open_operation_id UUID NOT NULL,
    actor_id UUID NOT NULL REFERENCES control_plane.users(id) ON DELETE RESTRICT,
    plugin_instance_id UUID NOT NULL,
    target_ref JSONB NOT NULL CHECK (control_plane.bounded_json(target_ref)),
    secret_version_id UUID NOT NULL,
    template_entry TEXT NOT NULL CHECK (length(template_entry) > 0),
    state TEXT NOT NULL DEFAULT 'opening' CHECK (state IN ('opening', 'active', 'closing', 'closed', 'failed', 'disconnected')),
    controller_id UUID REFERENCES control_plane.users(id) ON DELETE RESTRICT,
    session_type TEXT NOT NULL DEFAULT 'terminal' CHECK (length(session_type) > 0),
    last_activity_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    controller_revision BIGINT NOT NULL DEFAULT 0 CHECK (controller_revision >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    opened_at TIMESTAMPTZ,
    closed_at TIMESTAMPTZ,
    reason JSONB CHECK (reason IS NULL OR control_plane.bounded_json(reason, 'object')),
    FOREIGN KEY (resource_id, environment_id) REFERENCES control_plane.experiment_resources(id, environment_id) ON DELETE RESTRICT,
    FOREIGN KEY (job_id, environment_id) REFERENCES control_plane.jobs(id, environment_id) ON DELETE RESTRICT,
    FOREIGN KEY (open_operation_id, job_id) REFERENCES control_plane.operations(id, job_id) ON DELETE RESTRICT,
    FOREIGN KEY (open_operation_id, plugin_instance_id) REFERENCES control_plane.operations(id, plugin_instance_id) ON DELETE RESTRICT,
    CONSTRAINT session_secret_instance_fk FOREIGN KEY (job_id, plugin_instance_id, secret_version_id)
        REFERENCES control_plane.job_secret_refs(job_id, plugin_instance_id, secret_version_id) ON DELETE RESTRICT
);
CREATE INDEX interactive_sessions_environment_idx ON control_plane.interactive_sessions(environment_id, state);

CREATE TABLE control_plane.audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id UUID REFERENCES control_plane.users(id) ON DELETE RESTRICT,
    environment_id UUID REFERENCES control_plane.environments(id) ON DELETE RESTRICT,
    resource_id UUID REFERENCES control_plane.experiment_resources(id) ON DELETE RESTRICT,
    job_id UUID REFERENCES control_plane.jobs(id) ON DELETE RESTRICT,
    operation_id UUID REFERENCES control_plane.operations(id) ON DELETE RESTRICT,
    template_version_id UUID REFERENCES control_plane.template_versions(id) ON DELETE RESTRICT,
    action TEXT NOT NULL CHECK (length(action) > 0),
    result TEXT NOT NULL CHECK (length(result) > 0),
    data JSONB NOT NULL DEFAULT '{}' CHECK (control_plane.bounded_json(data, 'object')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (operation_id IS NULL OR job_id IS NOT NULL),
    CHECK ((resource_id IS NULL AND job_id IS NULL) OR environment_id IS NOT NULL),
    FOREIGN KEY (resource_id, environment_id) REFERENCES control_plane.experiment_resources(id, environment_id) ON DELETE RESTRICT,
    FOREIGN KEY (job_id, environment_id) REFERENCES control_plane.jobs(id, environment_id) ON DELETE RESTRICT,
    FOREIGN KEY (operation_id, job_id) REFERENCES control_plane.operations(id, job_id) ON DELETE RESTRICT,
    FOREIGN KEY (environment_id, template_version_id) REFERENCES control_plane.environments(id, template_version_id) ON DELETE RESTRICT
);
CREATE INDEX audit_events_environment_idx ON control_plane.audit_events(environment_id, created_at, id);

CREATE FUNCTION control_plane.check_secret_scope() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE secret_purpose text; secret_environment uuid; job_environment uuid;
BEGIN
    SELECT s.purpose, s.environment_id INTO secret_purpose, secret_environment
        FROM control_plane.secrets s JOIN control_plane.secret_versions v ON v.secret_id=s.id
        WHERE v.id=NEW.secret_version_id;
    SELECT environment_id INTO job_environment FROM control_plane.jobs WHERE id=NEW.job_id;
    IF secret_purpose='environment' AND secret_environment IS DISTINCT FROM job_environment THEN
        RAISE EXCEPTION 'secret belongs to another environment' USING ERRCODE='23514';
    END IF;
    IF TG_TABLE_NAME='interactive_sessions' THEN
        IF secret_purpose IS DISTINCT FROM 'environment' OR secret_environment IS DISTINCT FROM NEW.environment_id THEN
            RAISE EXCEPTION 'session requires an environment-use credential' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER job_secret_scope BEFORE INSERT OR UPDATE ON control_plane.job_secret_refs
    FOR EACH ROW EXECUTE FUNCTION control_plane.check_secret_scope();
CREATE TRIGGER session_secret_scope BEFORE INSERT OR UPDATE ON control_plane.interactive_sessions
    FOR EACH ROW EXECUTE FUNCTION control_plane.check_secret_scope();

CREATE TRIGGER environments_protect BEFORE UPDATE OR DELETE ON control_plane.environments
    FOR EACH ROW EXECUTE FUNCTION control_plane.protect_record(
        'id', 'owner_teacher_id', 'course_id', 'created_by', 'template_version_id', 'parameters', 'created_at');
CREATE TRIGGER execution_groups_protect BEFORE UPDATE OR DELETE ON control_plane.execution_groups
    FOR EACH ROW EXECUTE FUNCTION control_plane.protect_record('id', 'environment_id', 'created_at');
CREATE TRIGGER job_steps_protect BEFORE UPDATE OR DELETE ON control_plane.job_steps
    FOR EACH ROW EXECUTE FUNCTION control_plane.protect_record('id', 'job_id', 'step_path', 'item_key', 'created_at');
CREATE TRIGGER local_resource_items_protect BEFORE UPDATE OR DELETE ON control_plane.local_resource_items
    FOR EACH ROW EXECUTE FUNCTION control_plane.protect_record(
        'id', 'environment_id', 'logical_invocation_id', 'resource_slot', 'item_key',
        'source_job_id', 'source_operation_id', 'confirmed_input_refs', 'created_at');
CREATE TRIGGER experiment_resources_protect BEFORE UPDATE OR DELETE ON control_plane.experiment_resources
    FOR EACH ROW EXECUTE FUNCTION control_plane.protect_record(
        'id', 'environment_id', 'logical_invocation_id', 'resource_slot', 'item_key', 'source_job_id',
        'source_operation_id', 'local_resource_item_id', 'name', 'type_label', 'display', 'data',
        'target_ref', 'action_snapshot', 'access_snapshot', 'created_at');
CREATE TRIGGER jobs_protect BEFORE UPDATE OR DELETE ON control_plane.jobs
    FOR EACH ROW EXECUTE FUNCTION control_plane.protect_record(
        'id', 'environment_id', 'execution_group_id', 'actor_id', 'request_key', 'request_digest',
        'logical_invocation_id', 'parent_job_id', 'retry_of', 'kind', 'input', 'execution_snapshot', 'created_at');
CREATE TRIGGER operations_protect BEFORE UPDATE OR DELETE ON control_plane.operations
    FOR EACH ROW EXECUTE FUNCTION control_plane.protect_record(
        'id', 'job_id', 'step_id', 'attempt', 'invocation_key', 'plugin_instance_id',
        'plugin_version', 'code_digest', 'prepared_call', 'created_at');
CREATE TRIGGER job_plugin_snapshots_append_only BEFORE UPDATE OR DELETE ON control_plane.job_plugin_snapshots
    FOR EACH ROW EXECUTE FUNCTION control_plane.protect_record();
CREATE TRIGGER job_secret_refs_append_only BEFORE UPDATE OR DELETE ON control_plane.job_secret_refs
    FOR EACH ROW EXECUTE FUNCTION control_plane.protect_record();
CREATE TRIGGER operation_evidence_append_only BEFORE UPDATE OR DELETE ON control_plane.operation_evidence
    FOR EACH ROW EXECUTE FUNCTION control_plane.protect_record();
CREATE TRIGGER job_logs_append_only BEFORE UPDATE OR DELETE ON control_plane.job_logs
    FOR EACH ROW EXECUTE FUNCTION control_plane.protect_record();
CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON control_plane.audit_events
    FOR EACH ROW EXECUTE FUNCTION control_plane.protect_record();

CREATE FUNCTION control_plane.check_job_secret_source() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.derived THEN
        -- An explicit recovery Job can consume the original exact output or
        -- checkpoint, but an unrelated Job/group cannot manufacture a grant.
        -- Job environment/group identities are immutable under the database guards.
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

CREATE TRIGGER session_identity BEFORE UPDATE OR DELETE ON control_plane.interactive_sessions
    FOR EACH ROW EXECUTE FUNCTION control_plane.protect_record(
        'id', 'environment_id', 'resource_id', 'job_id', 'open_operation_id', 'actor_id',
        'plugin_instance_id', 'target_ref', 'secret_version_id', 'template_entry', 'session_type', 'created_at');

CREATE FUNCTION control_plane.guard_execution_state() RETURNS trigger LANGUAGE plpgsql AS $$
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
    FOR EACH ROW EXECUTE FUNCTION control_plane.guard_execution_state();
CREATE TRIGGER steps_state_guard BEFORE UPDATE ON control_plane.job_steps
    FOR EACH ROW EXECUTE FUNCTION control_plane.guard_execution_state();
CREATE TRIGGER operations_state_guard BEFORE UPDATE ON control_plane.operations
    FOR EACH ROW EXECUTE FUNCTION control_plane.guard_execution_state();
CREATE TRIGGER sessions_state_guard BEFORE UPDATE ON control_plane.interactive_sessions
    FOR EACH ROW EXECUTE FUNCTION control_plane.guard_execution_state();
