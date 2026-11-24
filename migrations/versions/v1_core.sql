CREATE FUNCTION control_plane.bounded_json(document jsonb, expected_type text DEFAULT 'any')
RETURNS boolean LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE AS $$
BEGIN
    IF document IS NULL OR expected_type IS NULL OR expected_type NOT IN
       ('any','object','array','string','number','boolean','null') THEN RETURN false; END IF;
    IF expected_type <> 'any' AND jsonb_typeof(document) <> expected_type THEN RETURN false; END IF;
    -- Reject oversized roots before expanding the tree; never recursively serialize subtrees.
    IF octet_length(document::text) > 1048576 THEN RETURN false; END IF;
    RETURN NOT EXISTS (
        WITH RECURSIVE nodes(value, depth) AS (
            SELECT document, 1
            UNION ALL
            SELECT child.value, parent.depth + 1 FROM nodes parent
            CROSS JOIN LATERAL (
                SELECT value FROM jsonb_each(CASE WHEN jsonb_typeof(parent.value) = 'object'
                    THEN parent.value ELSE '{}'::jsonb END)
                UNION ALL
                SELECT value FROM jsonb_array_elements(CASE WHEN jsonb_typeof(parent.value) = 'array'
                    THEN parent.value ELSE '[]'::jsonb END)
            ) child WHERE parent.depth <= 32
        )
        SELECT 1 FROM nodes WHERE depth > 32
           OR CASE jsonb_typeof(value)
                WHEN 'array' THEN jsonb_array_length(value) > 1000
                WHEN 'object' THEN (SELECT count(*) FROM
                    (SELECT 1 FROM jsonb_object_keys(value) LIMIT 1001) keys) > 1000
                ELSE false END
    );
END $$;

CREATE FUNCTION control_plane.protect_record() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE field text; before_row jsonb; after_row jsonb;
BEGIN
    IF TG_OP = 'DELETE' OR TG_NARGS = 0 THEN
        RAISE EXCEPTION 'record is immutable' USING ERRCODE = '23514';
    END IF;
    before_row := to_jsonb(OLD); after_row := to_jsonb(NEW);
    FOREACH field IN ARRAY TG_ARGV LOOP
        IF NOT (before_row ? field) OR before_row -> field IS DISTINCT FROM after_row -> field THEN
            RAISE EXCEPTION 'immutable field: %', field USING ERRCODE = '23514';
        END IF;
    END LOOP;
    RETURN NEW;
END $$;

CREATE TABLE control_plane.users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(), username text NOT NULL UNIQUE,
    password_hash text NOT NULL, role text NOT NULL CHECK (role IN ('admin','teacher','student')),
    created_by uuid REFERENCES control_plane.users(id) ON DELETE RESTRICT,
    exclusive_management boolean NOT NULL DEFAULT false, active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(), deleted_at timestamptz,
    CHECK (NOT exclusive_management OR (role = 'student' AND created_by IS NOT NULL))
);
CREATE TRIGGER users_history BEFORE UPDATE OR DELETE ON control_plane.users
FOR EACH ROW EXECUTE FUNCTION control_plane.protect_record('id','created_by','created_at');
CREATE TABLE control_plane.courses (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_teacher_id uuid NOT NULL REFERENCES control_plane.users(id) ON DELETE RESTRICT,
    name text NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    deleted_at timestamptz, UNIQUE (id, owner_teacher_id)
);
CREATE TABLE control_plane.groups (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    course_id uuid NOT NULL REFERENCES control_plane.courses(id) ON DELETE RESTRICT,
    name text NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    deleted_at timestamptz, UNIQUE (id, course_id)
);
CREATE TABLE control_plane.course_members (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    course_id uuid NOT NULL REFERENCES control_plane.courses(id) ON DELETE RESTRICT,
    student_id uuid NOT NULL REFERENCES control_plane.users(id) ON DELETE RESTRICT, group_id uuid,
    added_by uuid NOT NULL REFERENCES control_plane.users(id) ON DELETE RESTRICT,
    joined_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    left_at timestamptz, UNIQUE (course_id, student_id),
    FOREIGN KEY (group_id, course_id) REFERENCES control_plane.groups(id, course_id) ON DELETE RESTRICT
);
CREATE TABLE control_plane.templates (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL,
    created_by uuid NOT NULL REFERENCES control_plane.users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(), deleted_at timestamptz
);
CREATE TABLE control_plane.template_versions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    template_id uuid NOT NULL REFERENCES control_plane.templates(id) ON DELETE RESTRICT,
    version bigint NOT NULL CHECK (version > 0), definition jsonb NOT NULL,
    content_digest text NOT NULL, status text NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft','published','disabled')),
    created_by uuid NOT NULL REFERENCES control_plane.users(id) ON DELETE RESTRICT,
    published_by uuid REFERENCES control_plane.users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(), published_at timestamptz,
    UNIQUE (template_id, version), CHECK (control_plane.bounded_json(definition, 'object')),
    CHECK ((status = 'draft' AND published_by IS NULL AND published_at IS NULL)
        OR (status <> 'draft' AND published_by IS NOT NULL AND published_at IS NOT NULL))
);
CREATE TRIGGER template_version_identity BEFORE UPDATE OR DELETE ON control_plane.template_versions
FOR EACH ROW EXECUTE FUNCTION control_plane.protect_record('id','template_id','version','created_by','created_at');
CREATE TRIGGER template_version_payload BEFORE UPDATE ON control_plane.template_versions
FOR EACH ROW WHEN (OLD.status <> 'draft') EXECUTE FUNCTION control_plane.protect_record(
    'definition','content_digest','published_by','published_at');
CREATE FUNCTION control_plane.protect_template_status() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (OLD.status <> 'draft' AND NEW.status = 'draft')
       OR (OLD.status = 'disabled' AND NEW.status <> 'disabled') THEN
        RAISE EXCEPTION 'template publication is irreversible' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER template_version_status BEFORE UPDATE ON control_plane.template_versions
FOR EACH ROW EXECUTE FUNCTION control_plane.protect_template_status();

CREATE TABLE control_plane.plugin_instances (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(), plugin_key text NOT NULL,
    instance_alias text NOT NULL UNIQUE
        CHECK (instance_alias ~ '^[A-Za-z0-9_][A-Za-z0-9_-]{0,127}$'
               AND instance_alias !~* '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'),
    enabled boolean NOT NULL DEFAULT true,
    namespace_revision bigint NOT NULL DEFAULT 0 CHECK (namespace_revision >= 0),
    configuration_revision bigint NOT NULL DEFAULT 0 CHECK (configuration_revision >= 0),
    created_by uuid REFERENCES control_plane.users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER plugin_instance_identity BEFORE UPDATE OR DELETE ON control_plane.plugin_instances
FOR EACH ROW EXECUTE FUNCTION control_plane.protect_record('id','plugin_key','instance_alias','created_at');
CREATE FUNCTION control_plane.protect_instance_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.namespace_revision < OLD.namespace_revision OR NEW.configuration_revision < OLD.configuration_revision THEN
        RAISE EXCEPTION 'instance revision cannot decrease' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER plugin_instance_revision BEFORE UPDATE ON control_plane.plugin_instances
FOR EACH ROW EXECUTE FUNCTION control_plane.protect_instance_revision();
CREATE TABLE control_plane.plugin_instance_versions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_id uuid NOT NULL REFERENCES control_plane.plugin_instances(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0), configuration jsonb NOT NULL,
    plugin_version text NOT NULL, code_digest text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(), UNIQUE (instance_id, revision),
    UNIQUE (instance_id, revision, plugin_version, code_digest), UNIQUE (id, instance_id), CHECK (control_plane.bounded_json(configuration, 'object'))
);
CREATE TRIGGER plugin_configuration_history BEFORE UPDATE OR DELETE ON control_plane.plugin_instance_versions
FOR EACH ROW EXECUTE FUNCTION control_plane.protect_record();
CREATE TABLE control_plane.plugin_storage_heads (
    instance_id uuid NOT NULL REFERENCES control_plane.plugin_instances(id) ON DELETE RESTRICT,
    key text NOT NULL, version_id uuid NOT NULL, PRIMARY KEY (instance_id, key)
);
CREATE TABLE control_plane.plugin_storage_versions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_id uuid NOT NULL REFERENCES control_plane.plugin_instances(id) ON DELETE RESTRICT,
    key text NOT NULL, version bigint NOT NULL CHECK (version > 0),
    namespace_revision bigint NOT NULL CHECK (namespace_revision > 0), value jsonb,
    is_tombstone boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (instance_id, key, version), UNIQUE (instance_id, namespace_revision), UNIQUE (id, instance_id, key),
    CHECK ((is_tombstone AND value IS NULL)
        OR (NOT is_tombstone AND value IS NOT NULL AND control_plane.bounded_json(value, 'object')))
);
ALTER TABLE control_plane.plugin_storage_heads ADD CONSTRAINT storage_head_version_fk
FOREIGN KEY (version_id, instance_id, key)
REFERENCES control_plane.plugin_storage_versions(id, instance_id, key) ON DELETE RESTRICT
DEFERRABLE INITIALLY DEFERRED;
CREATE TRIGGER plugin_storage_history BEFORE UPDATE OR DELETE ON control_plane.plugin_storage_versions
FOR EACH ROW EXECUTE FUNCTION control_plane.protect_record();
CREATE TABLE control_plane.plugin_storage_snapshots (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_id uuid NOT NULL REFERENCES control_plane.plugin_instances(id) ON DELETE RESTRICT,
    namespace_revision bigint NOT NULL CHECK (namespace_revision >= 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(), UNIQUE (id, instance_id)
);
CREATE TRIGGER plugin_snapshot_history BEFORE UPDATE OR DELETE ON control_plane.plugin_storage_snapshots
FOR EACH ROW EXECUTE FUNCTION control_plane.protect_record();
-- Serialize snapshot capture with history writes; late inserts cannot alter an existing historical view.
CREATE FUNCTION control_plane.protect_storage_view() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE current_revision bigint;
BEGIN
    SELECT namespace_revision INTO current_revision FROM control_plane.plugin_instances
        WHERE id = NEW.instance_id FOR UPDATE;
    IF TG_TABLE_NAME = 'plugin_storage_snapshots' THEN
        IF NEW.namespace_revision > current_revision THEN
            RAISE EXCEPTION 'snapshot exceeds namespace revision' USING ERRCODE = '23514';
        END IF;
    ELSIF NEW.namespace_revision <> current_revision THEN
        RAISE EXCEPTION 'storage revision must match the namespace head' USING ERRCODE = '23514';
    ELSIF EXISTS (SELECT 1 FROM control_plane.plugin_storage_snapshots
        WHERE instance_id = NEW.instance_id AND namespace_revision >= NEW.namespace_revision) THEN
        RAISE EXCEPTION 'storage insert would change a frozen snapshot' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER plugin_storage_insert BEFORE INSERT ON control_plane.plugin_storage_versions
FOR EACH ROW EXECUTE FUNCTION control_plane.protect_storage_view();
CREATE TRIGGER plugin_snapshot_insert BEFORE INSERT ON control_plane.plugin_storage_snapshots
FOR EACH ROW EXECUTE FUNCTION control_plane.protect_storage_view();

CREATE TABLE control_plane.secrets (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    purpose text NOT NULL CHECK (purpose IN ('admin_connection','environment')),
    environment_id uuid, derived_key text UNIQUE,
    derived_spec_digest text CHECK (derived_spec_digest IS NULL OR length(derived_spec_digest) > 0),
    created_by uuid REFERENCES control_plane.users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((purpose = 'admin_connection' AND environment_id IS NULL)
        OR (purpose = 'environment' AND environment_id IS NOT NULL))
);
CREATE TRIGGER secret_identity BEFORE UPDATE OR DELETE ON control_plane.secrets
FOR EACH ROW EXECUTE FUNCTION control_plane.protect_record('id','purpose','environment_id','derived_key','created_at');
CREATE TRIGGER secret_derived_spec BEFORE UPDATE ON control_plane.secrets
FOR EACH ROW EXECUTE FUNCTION control_plane.protect_record('derived_spec_digest');
CREATE TABLE control_plane.secret_versions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id uuid NOT NULL REFERENCES control_plane.secrets(id) ON DELETE RESTRICT,
    version bigint NOT NULL CHECK (version > 0), ciphertext bytea NOT NULL,
    encryption_key_id text NOT NULL, revoked_at timestamptz, invalidated_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(), UNIQUE (secret_id, version),
    UNIQUE (id, secret_id), CHECK (octet_length(ciphertext) BETWEEN 1 AND 1048576)
);
CREATE TRIGGER secret_version_payload BEFORE UPDATE OR DELETE ON control_plane.secret_versions
FOR EACH ROW EXECUTE FUNCTION control_plane.protect_record(
    'id','secret_id','version','ciphertext','encryption_key_id','created_at');
CREATE TRIGGER secret_version_revoked BEFORE UPDATE ON control_plane.secret_versions
FOR EACH ROW WHEN (OLD.revoked_at IS NOT NULL)
EXECUTE FUNCTION control_plane.protect_record('revoked_at');
CREATE TRIGGER secret_version_invalidated BEFORE UPDATE ON control_plane.secret_versions
FOR EACH ROW WHEN (OLD.invalidated_at IS NOT NULL)
EXECUTE FUNCTION control_plane.protect_record('invalidated_at');
CREATE TABLE control_plane.teacher_quotas (
    teacher_id uuid PRIMARY KEY REFERENCES control_plane.users(id) ON DELETE RESTRICT,
    environments bigint NOT NULL DEFAULT 0 CHECK (environments >= 0),
    vms bigint NOT NULL DEFAULT 0 CHECK (vms >= 0), vcpu bigint NOT NULL DEFAULT 0 CHECK (vcpu >= 0),
    memory_mb bigint NOT NULL DEFAULT 0 CHECK (memory_mb >= 0),
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0)
);
CREATE TABLE control_plane.coordinator_leases (
    id integer PRIMARY KEY CHECK (id = 1), owner_id uuid, previous_owner_id uuid,
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0), backend_pid integer,
    acquired_at timestamptz, heartbeat_at timestamptz, expires_at timestamptz,
    CHECK ((owner_id IS NULL AND expires_at IS NULL AND backend_pid IS NULL)
        OR (owner_id IS NOT NULL AND expires_at IS NOT NULL AND backend_pid IS NOT NULL))
);
INSERT INTO control_plane.coordinator_leases (id, revision) VALUES (1, 0);

CREATE FUNCTION control_plane.protect_storage_head() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    target_version bigint;
    target_revision bigint;
    previous_version bigint;
    previous_revision bigint;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'storage heads cannot be deleted; append a tombstone instead'
            USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'UPDATE' AND
       (NEW.instance_id IS DISTINCT FROM OLD.instance_id OR NEW.key IS DISTINCT FROM OLD.key) THEN
        RAISE EXCEPTION 'storage head identity is immutable' USING ERRCODE = '23514';
    END IF;

    SELECT version, namespace_revision INTO target_version, target_revision
      FROM control_plane.plugin_storage_versions
      WHERE id = NEW.version_id AND instance_id = NEW.instance_id AND key = NEW.key;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'storage head must reference matching history' USING ERRCODE = '23514';
    END IF;
    IF EXISTS (
        SELECT 1 FROM control_plane.plugin_storage_versions
        WHERE instance_id = NEW.instance_id AND key = NEW.key
          AND (version > target_version OR namespace_revision > target_revision)
    ) THEN
        RAISE EXCEPTION 'storage head must reference the newest history' USING ERRCODE = '23514';
    END IF;

    IF TG_OP = 'UPDATE' AND NEW.version_id IS DISTINCT FROM OLD.version_id THEN
        SELECT version, namespace_revision INTO previous_version, previous_revision
          FROM control_plane.plugin_storage_versions
          WHERE id = OLD.version_id AND instance_id = OLD.instance_id AND key = OLD.key;
        IF NOT FOUND OR target_version <= previous_version OR target_revision <= previous_revision THEN
            RAISE EXCEPTION 'storage head can only advance' USING ERRCODE = '23514';
        END IF;
    END IF;
    -- UPDATE already serializes the head row. Do not take the instance lock here:
    -- write_storage locks instance -> head, so head -> instance would deadlock.
    RETURN NEW;
END $$;
CREATE TRIGGER storage_head_guard
    BEFORE INSERT OR UPDATE OR DELETE ON control_plane.plugin_storage_heads
    FOR EACH ROW EXECUTE FUNCTION control_plane.protect_storage_head();

-- History and its head are written together, but history is inserted first.
-- Check completeness at transaction end rather than rejecting that valid window.
CREATE FUNCTION control_plane.check_storage_head_current() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM control_plane.plugin_storage_heads h
        JOIN control_plane.plugin_storage_versions v
          ON (v.id, v.instance_id, v.key) = (h.version_id, h.instance_id, h.key)
        WHERE h.instance_id = NEW.instance_id AND h.key = NEW.key
          AND NOT EXISTS (
              SELECT 1 FROM control_plane.plugin_storage_versions newer
              WHERE newer.instance_id = h.instance_id AND newer.key = h.key
                AND (newer.version > v.version OR newer.namespace_revision > v.namespace_revision)
          )
    ) THEN
        RAISE EXCEPTION 'storage history requires its newest current head'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER storage_history_head_current
    AFTER INSERT ON control_plane.plugin_storage_versions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION control_plane.check_storage_head_current();
CREATE CONSTRAINT TRIGGER storage_head_current
    AFTER INSERT OR UPDATE ON control_plane.plugin_storage_heads
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION control_plane.check_storage_head_current();
