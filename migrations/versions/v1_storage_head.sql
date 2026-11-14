-- Refuse to reinterpret already-corrupt current pointers as valid history.
-- Migration locking also prevents direct SQL writers changing the inspected set.
LOCK TABLE control_plane.plugin_instances, control_plane.plugin_storage_versions,
    control_plane.plugin_storage_heads IN SHARE ROW EXCLUSIVE MODE;
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM control_plane.plugin_storage_heads h
        LEFT JOIN control_plane.plugin_storage_versions v
          ON (v.id, v.instance_id, v.key) = (h.version_id, h.instance_id, h.key)
        WHERE v.id IS NULL OR EXISTS (
            SELECT 1 FROM control_plane.plugin_storage_versions newer
            WHERE newer.instance_id = h.instance_id AND newer.key = h.key
              AND (newer.version > v.version OR newer.namespace_revision > v.namespace_revision)
        )
    ) OR EXISTS (
        SELECT 1 FROM control_plane.plugin_storage_versions v
        WHERE NOT EXISTS (
            SELECT 1 FROM control_plane.plugin_storage_heads h
            WHERE h.instance_id = v.instance_id AND h.key = v.key
        )
    ) THEN
        RAISE EXCEPTION 'storage history has an invalid or missing current head'
            USING ERRCODE = '23514';
    END IF;
END $$;

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
