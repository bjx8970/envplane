from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import unittest
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from control_plane.config import COORDINATOR_LOCK_KEY
from control_plane.coordination import CoordinatorLease
from control_plane.persistence import RequestConflict, StorageConflict, admit_job, write_storage
from tests_control_plane.p1_harness import migrated_database
from tests_control_plane.pg_harness import engine_for


def insert(connection, table, **values):
    columns = ",".join(f'"{key}"' for key in values)
    parameters = ",".join(f"CAST(:{key} AS jsonb)" if isinstance(value, (dict, list)) else f":{key}" for key, value in values.items())
    encoded = {key: json.dumps(value) if isinstance(value, (dict, list)) else value for key, value in values.items()}
    return connection.scalar(text(f'INSERT INTO control_plane."{table}" ({columns}) VALUES ({parameters}) RETURNING id'), encoded)


def graph(connection):
    actor = insert(connection, "users", username=f"teacher-{uuid4().hex}", role="teacher", password_hash="not-a-real-password")
    course = insert(connection, "courses", name="course", owner_teacher_id=actor)
    template = insert(connection, "templates", name="template", created_by=actor)
    version = insert(connection, "template_versions", template_id=template, version=1,
                     definition={}, content_digest="a" * 64, status="published", created_by=actor,
                     published_by=actor, published_at=datetime.now(timezone.utc))
    env = insert(connection, "environments", owner_teacher_id=actor, course_id=course,
                 created_by=actor, template_version_id=version, name="environment", parameters={})
    group = insert(connection, "execution_groups", environment_id=env)
    return actor, course, version, env, group


def job_arguments(connection):
    actor, course, version, environment, group = graph(connection)
    return dict(actor_id=actor, request_key=uuid4().hex, request_digest="b" * 64,
                environment_id=environment, execution_group_id=group,
                logical_invocation_id=uuid4(), kind="create", input={}, execution_snapshot={})


def operation_arguments(connection, job, step):
    plugin = insert(connection, "plugin_instances", plugin_key="fake")
    insert(connection, "plugin_instance_versions", instance_id=plugin, revision=1,
           configuration={}, plugin_version="1", code_digest="e" * 64)
    snapshot = insert(connection, "plugin_storage_snapshots", instance_id=plugin, namespace_revision=0)
    connection.execute(text("""
        INSERT INTO control_plane.job_plugin_snapshots
          (job_id,instance_id,configuration_revision,storage_snapshot_id,plugin_version,code_digest)
        VALUES (:job,:instance,1,:snapshot,'1',:digest)
    """), {"job": job, "instance": plugin, "snapshot": snapshot, "digest": "e" * 64})
    return dict(job_id=job, step_id=step, attempt=1, invocation_key=uuid4().hex,
                plugin_instance_id=plugin, plugin_version="1", code_digest="e" * 64, prepared_call={})


class SchemaConstraintTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.url = cls.enterClassContext(migrated_database())
        cls.engine = engine_for(cls.url)
        cls.addClassCleanup(cls.engine.dispose)

    def setUp(self):
        lease = CoordinatorLease(self.engine, COORDINATOR_LOCK_KEY)
        self.addCleanup(lease.release)
        self.assertTrue(lease.acquire())
        context = lease.fenced_transaction()
        self.conn = context.__enter__()
        self.addCleanup(context.__exit__, RuntimeError, RuntimeError("test rollback"), None)

    def rejects(self, sql, params=None):
        with self.assertRaises(DBAPIError):
            with self.conn.begin_nested():
                self.conn.execute(text(sql), params or {})

    def test_all_domain_responsibilities_exist(self):
        required = {"users", "courses", "groups", "course_members", "templates", "template_versions",
                    "plugin_instances", "plugin_instance_versions", "plugin_storage_heads", "plugin_storage_versions",
                    "plugin_storage_snapshots", "environments", "experiment_resources", "environment_assignments",
                    "teacher_quotas", "quota_reservations", "jobs", "job_steps", "operations", "operation_evidence",
                    "execution_groups", "conflict_protections", "secrets", "secret_versions", "interactive_sessions",
                    "audit_events", "job_plugin_snapshots", "job_secret_refs", "local_resource_items", "coordinator_leases"}
        actual = set(self.conn.scalars(text("SELECT tablename FROM pg_tables WHERE schemaname='control_plane'")))
        self.assertLessEqual(required, actual)

    def test_timestamps_and_foreign_key_deletion_are_explicit(self):
        naive = self.conn.scalar(text("SELECT count(*) FROM information_schema.columns WHERE table_schema='control_plane' AND data_type='timestamp without time zone'"))
        self.assertEqual(naive, 0)
        cascades = self.conn.scalar(text("SELECT count(*) FROM information_schema.referential_constraints WHERE constraint_schema='control_plane' AND delete_rule='CASCADE'"))
        self.assertEqual(cascades, 0)

    def test_json_limits_reject_depth_size_collection_and_wrong_root(self):
        nested = {}
        for _ in range(35):
            nested = {"next": nested}
        for value in (nested, {"large": "x" * 1048577}, {"items": list(range(1001))}, []):
            self.assertFalse(self.conn.scalar(text("SELECT control_plane.bounded_json(CAST(:value AS jsonb),'object')"), {"value": json.dumps(value)}))
        self.assertTrue(self.conn.scalar(text("SELECT control_plane.bounded_json('{\"ok\":[]}'::jsonb,'object')")))

    def test_idempotent_job_replay_and_digest_conflict(self):
        args = job_arguments(self.conn)
        first, replay = admit_job(self.conn, **args)
        self.assertFalse(replay)
        second, replay = admit_job(self.conn, **args)
        self.assertTrue(replay)
        self.assertEqual(first, second)
        with self.assertRaises(RequestConflict):
            admit_job(self.conn, **{**args, "request_digest": "c" * 64})

    def test_job_request_and_snapshot_are_immutable(self):
        job, _ = admit_job(self.conn, **job_arguments(self.conn))
        self.rejects("UPDATE control_plane.jobs SET request_digest=:digest WHERE id=:id", {"id": job, "digest": "d" * 64})
        self.rejects("UPDATE control_plane.jobs SET execution_snapshot=CAST(:value AS jsonb) WHERE id=:id", {"id": job, "value": '{"changed":true}'})
        self.rejects("DELETE FROM control_plane.jobs WHERE id=:id", {"id": job})

    def test_step_item_and_initial_operation_are_unique(self):
        job, _ = admit_job(self.conn, **job_arguments(self.conn))
        step = insert(self.conn, "job_steps", job_id=job, step_path="create.inspect", item_key="host-1")
        with self.assertRaises(DBAPIError):
            with self.conn.begin_nested():
                insert(self.conn, "job_steps", job_id=job, step_path="create.inspect", item_key="host-1")
        self.rejects("UPDATE control_plane.job_steps SET state='running' WHERE id=:id", {"id": step})
        operation = operation_arguments(self.conn, job, step)
        insert(self.conn, "operations", **operation)
        with self.assertRaises(DBAPIError):
            with self.conn.begin_nested():
                insert(self.conn, "operations", **{**operation, "invocation_key": uuid4().hex})

    def test_resource_logical_identity_is_not_operation_identity(self):
        args = job_arguments(self.conn)
        job, _ = admit_job(self.conn, **args)
        step = insert(self.conn, "job_steps", job_id=job, step_path="inspect", item_key="host-1")
        op = insert(self.conn, "operations", **operation_arguments(self.conn, job, step))
        resource = dict(environment_id=args["environment_id"], logical_invocation_id=args["logical_invocation_id"],
                        resource_slot="report", item_key="host-1", source_job_id=job,
                        source_operation_id=op, name="report", type_label="report", data={},
                        action_snapshot={}, access_snapshot={})
        insert(self.conn, "experiment_resources", **resource)
        with self.assertRaises(DBAPIError):
            with self.conn.begin_nested():
                insert(self.conn, "experiment_resources", **resource)

    def test_conflict_scope_has_one_unreleased_owner(self):
        _, _, _, environment, group = graph(self.conn)
        scope = f"environment:{environment}"
        insert(self.conn, "conflict_protections", scope_key=scope, execution_group_id=group, revision=1)
        with self.assertRaises(DBAPIError):
            with self.conn.begin_nested():
                insert(self.conn, "conflict_protections", scope_key=scope, execution_group_id=group, revision=2)

    def test_course_group_cannot_reference_another_course(self):
        actor, course, _, _, _ = graph(self.conn)
        other_course = insert(self.conn, "courses", name="other", owner_teacher_id=actor)
        group = insert(self.conn, "groups", course_id=other_course, name="foreign")
        student = insert(self.conn, "users", username=uuid4().hex, password_hash="hash", role="student")
        with self.assertRaises(DBAPIError):
            with self.conn.begin_nested():
                insert(self.conn, "course_members", course_id=course, student_id=student, group_id=group, added_by=actor)

    def test_assignments_require_exactly_one_same_course_target(self):
        actor, course, _, env, _ = graph(self.conn)
        student = insert(self.conn, "users", username=uuid4().hex, password_hash="hash", role="student")
        group = insert(self.conn, "groups", course_id=course, name="group")
        with self.assertRaises(DBAPIError):
            with self.conn.begin_nested():
                insert(self.conn, "environment_assignments", environment_id=env, course_id=course,
                       student_id=student, group_id=group, assigned_by=actor)
        with self.assertRaises(DBAPIError):
            with self.conn.begin_nested():
                insert(self.conn, "environment_assignments", environment_id=env, course_id=course,
                       student_id=student, assigned_by=actor)

    def test_quota_scope_and_nonnegative_units(self):
        actor, _, _, _, _ = graph(self.conn)
        self.conn.execute(text("INSERT INTO control_plane.teacher_quotas(teacher_id,environments,vms,vcpu,memory_mb) VALUES (:id,1,2,4,2048)"), {"id": actor})
        self.rejects("INSERT INTO control_plane.teacher_quotas(teacher_id,environments,vms,vcpu,memory_mb) VALUES (:id,1,2,4,2048)", {"id": actor})
        self.rejects("UPDATE control_plane.teacher_quotas SET memory_mb=-1 WHERE teacher_id=:id", {"id": actor})

    def test_storage_cas_history_and_tombstones(self):
        instance = insert(self.conn, "plugin_instances", plugin_key="fake")
        first = write_storage(self.conn, instance, "hosts", {"host": "original"})
        with self.assertRaises(StorageConflict):
            write_storage(self.conn, instance, "hosts", {"host": "overwrite"})
        second = write_storage(self.conn, instance, "hosts", {"host": "updated"}, expected_version=first.id)
        tombstone = write_storage(self.conn, instance, "hosts", None, expected_version=second.id, delete=True)
        self.assertEqual((first.version, second.version, tombstone.version), (1, 2, 3))
        value = self.conn.scalar(text("SELECT value FROM control_plane.plugin_storage_versions WHERE id=:id"), {"id": first.id})
        self.assertEqual(value, {"host": "original"})
        self.rejects("UPDATE control_plane.plugin_storage_versions SET value='{}'::jsonb WHERE id=:id", {"id": first.id})
        self.rejects("DELETE FROM control_plane.plugin_storage_versions WHERE id=:id", {"id": first.id})

    def test_storage_snapshots_preserve_old_view_and_reject_backfill(self):
        instance = insert(self.conn, "plugin_instances", plugin_key="fake")
        first = write_storage(self.conn, instance, "hosts", {"host": "original"})
        snapshot = insert(self.conn, "plugin_storage_snapshots", instance_id=instance,
                          namespace_revision=first.namespace_revision)
        write_storage(self.conn, instance, "hosts", {"host": "new"}, expected_version=first.id)
        value = self.conn.scalar(text("""
            SELECT v.value FROM control_plane.plugin_storage_versions v
            JOIN control_plane.plugin_storage_snapshots s ON s.instance_id=v.instance_id
            WHERE s.id=:snapshot AND v.key='hosts' AND v.namespace_revision<=s.namespace_revision
            ORDER BY v.namespace_revision DESC LIMIT 1
        """), {"snapshot": snapshot})
        self.assertEqual(value, {"host": "original"})
        self.rejects("UPDATE control_plane.plugin_instances SET namespace_revision=0 WHERE id=:id", {"id": instance})
        with self.assertRaises(DBAPIError):
            with self.conn.begin_nested():
                insert(self.conn, "plugin_storage_versions", instance_id=instance, key="late", version=1,
                       namespace_revision=first.namespace_revision, value={})
        with self.assertRaises(DBAPIError):
            with self.conn.begin_nested():
                insert(self.conn, "plugin_storage_snapshots", instance_id=instance, namespace_revision=99)

    def test_storage_head_cannot_cross_instances(self):
        first_instance = insert(self.conn, "plugin_instances", plugin_key="fake")
        second_instance = insert(self.conn, "plugin_instances", plugin_key="fake")
        write_storage(self.conn, first_instance, "hosts", {})
        foreign = write_storage(self.conn, second_instance, "hosts", {})
        with self.assertRaises(DBAPIError):
            with self.conn.begin_nested():
                self.conn.execute(text("UPDATE control_plane.plugin_storage_heads SET version_id=:version WHERE instance_id=:instance"),
                                  {"version": foreign.id, "instance": first_instance})
                self.conn.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))

    def test_execution_state_values_and_snapshot_dependencies(self):
        job, _ = admit_job(self.conn, **job_arguments(self.conn))
        self.rejects("UPDATE control_plane.jobs SET state='not-a-state' WHERE id=:id", {"id": job})
        step = insert(self.conn, "job_steps", job_id=job, step_path="inspect")
        operation = operation_arguments(self.conn, job, step)
        op = insert(self.conn, "operations", **operation)
        self.rejects("UPDATE control_plane.operations SET state='retryable' WHERE id=:id", {"id": op})
        evidence = insert(self.conn, "operation_evidence", operation_id=op, kind="external_ref",
                          ref_key="remote", revision=1, data={"reference": "opaque"})
        self.rejects("DELETE FROM control_plane.operation_evidence WHERE id=:id", {"id": evidence})
        self.rejects("UPDATE control_plane.job_plugin_snapshots SET configuration_revision=2 WHERE job_id=:id", {"id": job})
        self.rejects("DELETE FROM control_plane.plugin_instance_versions WHERE instance_id=:id", {"id": operation["plugin_instance_id"]})

    def test_job_cannot_reference_another_environments_secret(self):
        args = job_arguments(self.conn)
        job, _ = admit_job(self.conn, **args)
        _, _, _, other_env, _ = graph(self.conn)
        secret = insert(self.conn, "secrets", purpose="environment", environment_id=other_env)
        version = insert(self.conn, "secret_versions", secret_id=secret, version=1,
                         ciphertext=b"encrypted", encryption_key_id="test-key")
        self.rejects("INSERT INTO control_plane.job_secret_refs(job_id,secret_version_id) VALUES (:job,:secret)",
                     {"job": job, "secret": version})

    def test_session_cannot_use_management_secret(self):
        args = job_arguments(self.conn)
        job, _ = admit_job(self.conn, **args)
        step = insert(self.conn, "job_steps", job_id=job, step_path="open")
        operation = operation_arguments(self.conn, job, step)
        op = insert(self.conn, "operations", **operation)
        secret = insert(self.conn, "secrets", purpose="admin_connection")
        version = insert(self.conn, "secret_versions", secret_id=secret, version=1,
                         ciphertext=b"encrypted", encryption_key_id="test-key")
        self.conn.execute(text("INSERT INTO control_plane.job_secret_refs(job_id,secret_version_id) VALUES (:job,:secret)"),
                          {"job": job, "secret": version})
        with self.assertRaises(DBAPIError):
            with self.conn.begin_nested():
                insert(self.conn, "interactive_sessions", environment_id=args["environment_id"],
                       job_id=job, open_operation_id=op, actor_id=args["actor_id"],
                       plugin_instance_id=operation["plugin_instance_id"], target_ref={},
                       secret_version_id=version, template_entry="terminal")
        environment_secret = insert(self.conn, "secrets", purpose="environment", environment_id=args["environment_id"])
        environment_version = insert(self.conn, "secret_versions", secret_id=environment_secret, version=1,
                                     ciphertext=b"encrypted", encryption_key_id="test-key")
        self.conn.execute(text("INSERT INTO control_plane.job_secret_refs(job_id,secret_version_id) VALUES (:job,:secret)"),
                          {"job": job, "secret": environment_version})
        insert(self.conn, "interactive_sessions", environment_id=args["environment_id"],
               job_id=job, open_operation_id=op, actor_id=args["actor_id"],
               plugin_instance_id=operation["plugin_instance_id"], target_ref={},
               secret_version_id=environment_version, template_entry="terminal")

    def test_job_plugin_code_matches_configuration_identity(self):
        args = job_arguments(self.conn)
        job, _ = admit_job(self.conn, **args)
        step = insert(self.conn, "job_steps", job_id=job, step_path="inspect")
        operation = operation_arguments(self.conn, job, step)
        new_job, _ = admit_job(self.conn, **{**args, "request_key": uuid4().hex})
        snapshot = self.conn.scalar(text("SELECT storage_snapshot_id FROM control_plane.job_plugin_snapshots WHERE job_id=:job"), {"job": job})
        self.rejects("""
            INSERT INTO control_plane.job_plugin_snapshots
              (job_id,instance_id,configuration_revision,storage_snapshot_id,plugin_version,code_digest)
            VALUES (:job,:instance,1,:snapshot,'different',:digest)
        """, {"job": new_job, "instance": operation["plugin_instance_id"], "snapshot": snapshot, "digest": "f" * 64})

    def test_role_changes_do_not_rewrite_historical_creator(self):
        actor, _, _, _, _ = graph(self.conn)
        self.conn.execute(text("UPDATE control_plane.users SET role='admin' WHERE id=:id"), {"id": actor})
        self.rejects("UPDATE control_plane.users SET created_by=:creator WHERE id=:id", {"id": actor, "creator": actor})

    def test_append_only_audit_and_identity_delete_protection(self):
        actor, _, _, _, _ = graph(self.conn)
        event = insert(self.conn, "audit_events", actor_id=actor, action="test", result="succeeded", data={})
        self.rejects("UPDATE control_plane.audit_events SET result='changed' WHERE id=:id", {"id": event})
        self.rejects("DELETE FROM control_plane.audit_events WHERE id=:id", {"id": event})
        self.rejects("DELETE FROM control_plane.users WHERE id=:id", {"id": actor})

    def test_published_template_cannot_be_edited(self):
        _, _, version, _, _ = graph(self.conn)
        self.rejects("UPDATE control_plane.template_versions SET definition=CAST(:value AS jsonb) WHERE id=:id", {"id": version, "value": '{"changed":true}'})
        self.conn.execute(text("UPDATE control_plane.template_versions SET status='disabled' WHERE id=:id"), {"id": version})
        self.rejects("UPDATE control_plane.template_versions SET status='draft' WHERE id=:id", {"id": version})

    def test_secret_payload_immutable_but_revocable(self):
        secret = insert(self.conn, "secrets", purpose="admin_connection")
        version = insert(self.conn, "secret_versions", secret_id=secret, version=1,
                         ciphertext=b"encrypted-test-sentinel", encryption_key_id="test-key")
        self.rejects("UPDATE control_plane.secret_versions SET ciphertext=decode('00','hex') WHERE id=:id", {"id": version})
        self.conn.execute(text("UPDATE control_plane.secret_versions SET revoked_at=clock_timestamp() WHERE id=:id"), {"id": version})
        self.rejects("UPDATE control_plane.secret_versions SET revoked_at=NULL WHERE id=:id", {"id": version})
        self.rejects("DELETE FROM control_plane.secret_versions WHERE id=:id", {"id": version})


class CoordinatorConnectionReuseTests(unittest.TestCase):
    def test_pre_ping_reuse_does_not_retain_lease_locks_or_test_writes(self):
        class RollbackProbe(Exception):
            pass

        with migrated_database() as url:
            engine = engine_for(url)
            probe_engine = engine_for(url)
            try:
                # Ensure acquire checks out an already-used connection, so the
                # pg8000 pre_ping SELECT has run with autocommit initially off.
                with engine.connect() as connection:
                    connection.scalar(text("SELECT 1"))
                for _ in range(3):
                    lease = CoordinatorLease(engine, COORDINATOR_LOCK_KEY)
                    try:
                        self.assertTrue(lease.acquire())
                        with probe_engine.begin() as probe:
                            self.assertEqual(probe.scalar(text("""
                                SELECT state FROM pg_stat_activity WHERE pid=:pid
                            """), {"pid": lease.backend_pid}), "idle")
                            probe.execute(text("""
                                SELECT id FROM control_plane.coordinator_leases
                                WHERE id=1 FOR UPDATE NOWAIT
                            """))
                        marker = f"rollback-probe-{uuid4().hex}"
                        with self.assertRaises(RollbackProbe):
                            with lease.fenced_transaction() as connection:
                                insert(connection, "users", username=marker,
                                       password_hash="test-hash", role="teacher")
                                raise RollbackProbe()
                        with probe_engine.begin() as probe:
                            # Independent backend: neither leaked locks nor an
                            # accidentally committed fixture can hide in reuse.
                            probe.execute(text("""
                                SELECT id FROM control_plane.coordinator_leases
                                WHERE id=1 FOR UPDATE NOWAIT
                            """))
                            self.assertEqual(probe.scalar(text("""
                                SELECT count(*) FROM control_plane.users WHERE username=:marker
                            """), {"marker": marker}), 0)
                    finally:
                        lease.release()
                    with probe_engine.begin() as probe:
                        acquired = probe.scalar(text("SELECT pg_try_advisory_lock(:key)"),
                                                {"key": COORDINATOR_LOCK_KEY})
                        try:
                            self.assertTrue(acquired, "released coordinator retained its advisory lock")
                        finally:
                            if acquired:
                                probe.execute(text("SELECT pg_advisory_unlock(:key)"),
                                              {"key": COORDINATOR_LOCK_KEY})
            finally:
                engine.dispose()
                probe_engine.dispose()


class PersistenceConcurrencyTests(unittest.TestCase):
    def test_concurrent_storage_cas_has_one_winner(self):
        with migrated_database() as url:
            engine = engine_for(url)
            lease = CoordinatorLease(engine, COORDINATOR_LOCK_KEY)
            try:
                self.assertTrue(lease.acquire())
                with lease.fenced_transaction() as conn:
                    instance = insert(conn, "plugin_instances", plugin_key="fake")
                    original = write_storage(conn, instance, "hosts", {"initial": True})
                def write(index):
                    try:
                        with lease.fenced_transaction() as conn:
                            write_storage(conn, instance, "hosts", {"writer": index}, expected_version=original.id)
                        return "ok"
                    except StorageConflict:
                        return "conflict"
                with ThreadPoolExecutor(max_workers=2) as pool:
                    results = list(pool.map(write, (1, 2)))
                self.assertEqual(sorted(results), ["conflict", "ok"])
                with engine.connect() as conn:
                    self.assertEqual(conn.scalar(text("SELECT count(*) FROM control_plane.plugin_storage_versions WHERE instance_id=:id"), {"id": instance}), 2)
            finally:
                lease.release()
                engine.dispose()

    def test_concurrent_identical_requests_share_one_job(self):
        with migrated_database() as url:
            engine = engine_for(url)
            lease = CoordinatorLease(engine, COORDINATOR_LOCK_KEY)
            try:
                self.assertTrue(lease.acquire())
                with lease.fenced_transaction() as conn:
                    args = job_arguments(conn)
                def submit(_):
                    with lease.fenced_transaction() as conn:
                        return admit_job(conn, **args)
                with ThreadPoolExecutor(max_workers=2) as pool:
                    results = list(pool.map(submit, (1, 2)))
                self.assertEqual(results[0][0], results[1][0])
                self.assertEqual(sorted(item[1] for item in results), [False, True])
            finally:
                lease.release()
                engine.dispose()
