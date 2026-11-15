"""P2 PostgreSQL contracts. Run only through the disposable-database harness."""
from datetime import datetime, timedelta, timezone
import unittest
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from control_plane.config import RuntimeSettings
from control_plane.migrations import (
    BASELINE_REVISION, HEAD_REVISION, P1_REVISION, MigrationError,
    SchemaMismatch, check_schema, run_migrations,
)
from control_plane.permissions import grant_runtime_permissions, validate_runtime_permissions
from tests_control_plane.p1_harness import fresh_database, migrated_database
from tests_control_plane.pg_harness import engine_for
from tests_control_plane.test_p1_schema import insert, job_arguments, operation_arguments


def runtime_graph(connection):
    args = job_arguments(connection)
    job = insert(connection, "jobs", **args)
    step = insert(connection, "job_steps", job_id=job, step_path="test")
    operation = operation_arguments(connection, job, step)
    op = insert(connection, "operations", **operation)
    return args, job, step, op, operation["plugin_instance_id"]


def call_arguments(operation, **changes):
    now = datetime.now(timezone.utc)
    return dict(operation_id=operation, method="execute", job_lease_owner="test-worker",
                job_lease_token=uuid4(), coordinator_owner=uuid4(), coordinator_revision=1,
                created_at=now, deadline_at=now + timedelta(seconds=30), **changes)


class P2SchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.url = cls.enterClassContext(migrated_database())
        cls.engine = engine_for(cls.url)
        cls.addClassCleanup(cls.engine.dispose)

    def setUp(self):
        self.conn = self.engine.connect()
        self.addCleanup(self.conn.close)
        transaction = self.conn.begin()
        self.addCleanup(transaction.rollback)
        self.args, self.job, self.step, self.op, self.instance = runtime_graph(self.conn)

    def rejects(self, sql, parameters=None, code="23514"):
        with self.assertRaises(DBAPIError) as raised:
            with self.conn.begin_nested():
                self.conn.execute(text(sql), parameters or {})
        if code:
            self.assertEqual(raised.exception.orig.args[0]["C"], code)

    def attempt(self, **changes):
        values = call_arguments(self.op)
        values.update(changes)
        return insert(self.conn, "operation_call_attempts", **values)

    def evidence(self, call=None, **changes):
        values = dict(operation_id=self.op, kind="checkpoint", ref_key=uuid4().hex,
                      revision=1, data={})
        if call is not None:
            values.update(call_attempt_id=call, event_id=uuid4().hex, event_digest="a" * 64,
                          observed_at=datetime.now(timezone.utc))
        values.update(changes)
        return insert(self.conn, "operation_evidence", **values)

    def secret(self):
        secret = insert(self.conn, "secrets", purpose="environment", environment_id=self.args["environment_id"])
        return insert(self.conn, "secret_versions", secret_id=secret, version=1,
                      ciphertext=b"isolated-test-ciphertext", encryption_key_id="test")

    def session(self):
        secret = self.secret()
        self.conn.execute(text("""INSERT INTO control_plane.job_secret_refs
            (job_id,plugin_instance_id,secret_version_id) VALUES (:job,:instance,:secret)"""),
            {"job": self.job, "instance": self.instance, "secret": secret})
        return insert(self.conn, "interactive_sessions", environment_id=self.args["environment_id"],
                      job_id=self.job, open_operation_id=self.op, actor_id=self.args["actor_id"],
                      plugin_instance_id=self.instance, target_ref={}, secret_version_id=secret,
                      template_entry="terminal")

    def test_call_attempts_are_narrow_append_only_and_truncate_protected(self):
        call = self.attempt()
        expected = {"id", "operation_id", "method", "job_lease_owner", "job_lease_token",
                    "coordinator_owner", "coordinator_revision", "created_at", "deadline_at", "retry_of_call_id"}
        actual = set(self.conn.scalars(text("""SELECT column_name FROM information_schema.columns
            WHERE table_schema='control_plane' AND table_name='operation_call_attempts'""")))
        self.assertEqual(actual, expected)
        self.rejects("UPDATE control_plane.operation_call_attempts SET method='poll' WHERE id=:id", {"id": call})
        self.rejects("DELETE FROM control_plane.operation_call_attempts WHERE id=:id", {"id": call})
        self.rejects("TRUNCATE control_plane.operation_call_attempts CASCADE")

    def test_call_attempt_budget_and_method_are_checked(self):
        for changes in ({"method": "prepare"}, {"job_lease_owner": ""}, {"coordinator_revision": -1},
                        {"deadline_at": datetime.now(timezone.utc) - timedelta(seconds=1)}):
            with self.subTest(changes=tuple(changes)), self.assertRaises(DBAPIError):
                with self.conn.begin_nested():
                    self.attempt(**changes)

    def test_call_retry_fk_cannot_cross_operations(self):
        call = self.attempt()
        self.attempt(method="poll", retry_of_call_id=call)
        _, _, _, other, _ = runtime_graph(self.conn)
        with self.assertRaises(DBAPIError):
            with self.conn.begin_nested():
                insert(self.conn, "operation_call_attempts", **call_arguments(other, retry_of_call_id=call))

    def test_evidence_legacy_nulls_and_new_event_deduplication(self):
        self.evidence()
        call = self.attempt()
        self.evidence(call, event_id="stable-event")
        with self.assertRaises(DBAPIError):
            with self.conn.begin_nested():
                self.evidence(call, event_id="stable-event", event_digest="changed")
        self.assertEqual(self.conn.scalar(text("SELECT count(*) FROM control_plane.operation_evidence")), 2)

    def test_evidence_call_fk_cannot_cross_operations(self):
        _, _, _, other, _ = runtime_graph(self.conn)
        other_call = insert(self.conn, "operation_call_attempts", **call_arguments(other))
        with self.assertRaises(DBAPIError):
            with self.conn.begin_nested():
                self.evidence(other_call)

    def test_evidence_event_metadata_is_not_partially_accepted(self):
        with self.assertRaises(DBAPIError):
            with self.conn.begin_nested():
                self.evidence(event_id="orphan-event", event_digest="digest")

    def test_step_input_expansion_and_prepare_budget_are_fixed(self):
        self.rejects("UPDATE control_plane.job_steps SET input='1'::jsonb WHERE id=:id", {"id": self.step})
        self.conn.execute(text("""UPDATE control_plane.job_steps SET expansion='[]'::jsonb,
            prepare_started_at=clock_timestamp(), prepare_deadline_at=clock_timestamp()+interval '5 seconds'
            WHERE id=:id"""), {"id": self.step})
        self.rejects("UPDATE control_plane.job_steps SET expansion=NULL WHERE id=:id", {"id": self.step})
        self.rejects("UPDATE control_plane.job_steps SET expansion='[1]'::jsonb WHERE id=:id", {"id": self.step})
        self.rejects("UPDATE control_plane.job_steps SET prepare_deadline_at=prepare_deadline_at+interval '1 second' WHERE id=:id", {"id": self.step})
        self.rejects("UPDATE control_plane.job_steps SET prepare_started_at=NULL WHERE id=:id", {"id": self.step})

    def test_prepare_budget_pair_and_error_shape_are_checked(self):
        self.rejects("UPDATE control_plane.job_steps SET prepare_started_at=clock_timestamp() WHERE id=:id", {"id": self.step})
        self.rejects("UPDATE control_plane.job_steps SET prepare_error='[]'::jsonb WHERE id=:id", {"id": self.step})
        self.conn.execute(text("UPDATE control_plane.job_steps SET prepare_error='{}'::jsonb WHERE id=:id"), {"id": self.step})

    def test_job_blocked_recovery_and_terminal_protection_need_no_business_payload(self):
        for state in ("blocked", "running", "cancel_requested", "succeeded"):
            self.conn.execute(text("UPDATE control_plane.jobs SET state=:state WHERE id=:id"), {"id": self.job, "state": state})
        self.rejects("UPDATE control_plane.jobs SET state='running' WHERE id=:id", {"id": self.job})
        self.rejects("UPDATE control_plane.jobs SET error='{}'::jsonb WHERE id=:id", {"id": self.job})
        self.conn.execute(text("UPDATE control_plane.jobs SET lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE id=:id"), {"id": self.job})

    def test_illegal_job_transition_does_not_masquerade_as_missing_field_failure(self):
        self.rejects("UPDATE control_plane.jobs SET state='succeeded' WHERE id=:id", {"id": self.job})
        self.conn.execute(text("UPDATE control_plane.jobs SET state='running' WHERE id=:id"), {"id": self.job})
        self.rejects("UPDATE control_plane.jobs SET state='queued' WHERE id=:id", {"id": self.job})

    def test_operation_unknown_can_recover_but_not_blindly_restart(self):
        for state in ("running", "unknown"):
            self.conn.execute(text("UPDATE control_plane.operations SET state=:state WHERE id=:id"), {"id": self.op, "state": state})
        self.rejects("UPDATE control_plane.operations SET state='running' WHERE id=:id", {"id": self.op})
        for state in ("pending_external", "succeeded"):
            self.conn.execute(text("UPDATE control_plane.operations SET state=:state WHERE id=:id"), {"id": self.op, "state": state})
        self.rejects("UPDATE control_plane.operations SET output='{}'::jsonb WHERE id=:id", {"id": self.op})
        self.conn.execute(text("UPDATE control_plane.operations SET cancellation_result='too_late' WHERE id=:id"), {"id": self.op})

    def test_step_terminal_cannot_be_reopened_or_rewritten(self):
        self.conn.execute(text("UPDATE control_plane.job_steps SET state='running',current_operation_id=:op WHERE id=:id"), {"op": self.op, "id": self.step})
        self.conn.execute(text("UPDATE control_plane.job_steps SET state='succeeded' WHERE id=:id"), {"id": self.step})
        self.rejects("UPDATE control_plane.job_steps SET state='pending' WHERE id=:id", {"id": self.step})
        self.rejects("UPDATE control_plane.job_steps SET output='{}'::jsonb WHERE id=:id", {"id": self.step})

    def test_secret_grants_are_instance_scoped_with_unique_legacy_fill(self):
        secret = self.secret()
        self.conn.execute(text("INSERT INTO control_plane.job_secret_refs(job_id,secret_version_id) VALUES (:job,:secret)"), {"job": self.job, "secret": secret})
        self.assertEqual(self.conn.scalar(text("SELECT plugin_instance_id FROM control_plane.job_secret_refs WHERE job_id=:id"), {"id": self.job}), self.instance)
        # Same secret can be authorized independently to a second snapshot.
        other_step = insert(self.conn, "job_steps", job_id=self.job, step_path="second")
        second = operation_arguments(self.conn, self.job, other_step)["plugin_instance_id"]
        self.conn.execute(text("INSERT INTO control_plane.job_secret_refs(job_id,plugin_instance_id,secret_version_id) VALUES (:job,:instance,:secret)"), {"job": self.job, "instance": second, "secret": secret})
        self.rejects("INSERT INTO control_plane.job_secret_refs(job_id,secret_version_id) VALUES (:job,:secret)", {"job": self.job, "secret": self.secret()})
        self.assertEqual(self.conn.scalar(text("SELECT count(*) FROM control_plane.job_secret_refs")), 2)

    def test_secret_grant_rejects_unbound_instance_and_cross_instance_session(self):
        secret = self.secret()
        self.rejects("INSERT INTO control_plane.job_secret_refs(job_id,plugin_instance_id,secret_version_id) VALUES (:job,:instance,:secret)", {"job": self.job, "instance": uuid4(), "secret": secret}, code="23503")
        second_step = insert(self.conn, "job_steps", job_id=self.job, step_path="other")
        second = operation_arguments(self.conn, self.job, second_step)["plugin_instance_id"]
        self.conn.execute(text("INSERT INTO control_plane.job_secret_refs(job_id,plugin_instance_id,secret_version_id) VALUES (:job,:instance,:secret)"), {"job": self.job, "instance": second, "secret": secret})
        with self.assertRaises(DBAPIError):
            with self.conn.begin_nested():
                insert(self.conn, "interactive_sessions", environment_id=self.args["environment_id"],
                       job_id=self.job, open_operation_id=self.op, actor_id=self.args["actor_id"],
                       plugin_instance_id=self.instance, target_ref={}, secret_version_id=secret, template_entry="terminal")

    def test_derived_secret_provenance_requires_success_or_checkpoint_same_scope(self):
        secret = self.secret()
        values = {"job": self.job, "instance": self.instance, "secret": secret, "op": self.op}
        sql = """INSERT INTO control_plane.job_secret_refs
            (job_id,plugin_instance_id,secret_version_id,derived,source_operation_id)
            VALUES (:job,:instance,:secret,true,:op)"""
        self.rejects(sql, values)
        evidence = self.evidence(self.attempt(), trusted_for_derivation=True)
        self.conn.execute(text("""INSERT INTO control_plane.job_secret_refs
            (job_id,plugin_instance_id,secret_version_id,derived,source_operation_id,source_evidence_id)
            VALUES (:job,:instance,:secret,true,:op,:evidence)"""), {**values, "evidence": evidence})
        _, other_job, _, other_op, _ = runtime_graph(self.conn)
        self.rejects(sql, {**values, "secret": self.secret(), "op": other_op})

    def test_successful_output_can_authorize_derived_secret(self):
        for state in ("running", "succeeded"):
            self.conn.execute(text("UPDATE control_plane.operations SET state=:state WHERE id=:id"), {"id": self.op, "state": state})
        self.conn.execute(text("""INSERT INTO control_plane.job_secret_refs
            (job_id,plugin_instance_id,secret_version_id,derived,source_operation_id)
            VALUES (:job,:instance,:secret,true,:op)"""),
            {"job": self.job, "instance": self.instance, "secret": self.secret(), "op": self.op})

    def recovery_job(self, *, group=None):
        values = {**self.args, "request_key": uuid4().hex,
                  "execution_group_id": group or self.args["execution_group_id"]}
        if group is None:
            values["parent_job_id"] = self.job
        recovery = insert(self.conn, "jobs", **values)
        self.copy_snapshot(recovery)
        return recovery

    def copy_snapshot(self, consumer):
        self.conn.execute(text("""INSERT INTO control_plane.job_plugin_snapshots
            (job_id,instance_id,configuration_revision,storage_snapshot_id,plugin_version,code_digest)
            SELECT :consumer,instance_id,configuration_revision,storage_snapshot_id,plugin_version,code_digest
            FROM control_plane.job_plugin_snapshots WHERE job_id=:producer AND instance_id=:instance"""),
            {"consumer": consumer, "producer": self.job, "instance": self.instance})

    def publish_secret(self, consumer, *, evidence=None, instance=None, secret=None):
        self.conn.execute(text("""INSERT INTO control_plane.job_secret_refs
            (job_id,plugin_instance_id,secret_version_id,derived,source_operation_id,source_evidence_id)
            VALUES (:job,:instance,:secret,true,:op,:evidence)"""),
            {"job": consumer, "instance": instance or self.instance, "secret": secret or self.secret(),
             "op": self.op, "evidence": evidence})

    def succeed_source(self):
        for state in ("running", "succeeded"):
            self.conn.execute(text("UPDATE control_plane.operations SET state=:state WHERE id=:id"),
                              {"id": self.op, "state": state})

    def test_recovery_job_can_publish_exact_successful_output_from_same_group(self):
        self.succeed_source()
        recovery = self.recovery_job()
        self.publish_secret(recovery)
        row = self.conn.execute(text("""SELECT source_operation_id,source_evidence_id,plugin_instance_id
            FROM control_plane.job_secret_refs WHERE job_id=:job"""), {"job": recovery}).one()
        self.assertEqual((row.source_operation_id, row.plugin_instance_id), (self.op, self.instance))
        self.assertIsNone(row.source_evidence_id)

    def test_recovery_job_can_publish_exact_checkpoint_from_same_group(self):
        evidence = self.evidence(self.attempt(), trusted_for_derivation=True)
        recovery = self.recovery_job()
        self.publish_secret(recovery, evidence=evidence)
        self.assertEqual(self.conn.scalar(text("""SELECT source_evidence_id FROM control_plane.job_secret_refs
            WHERE job_id=:job"""), {"job": recovery}), evidence)
        # Publishing the precise reference does not rewrite either Job snapshot.
        self.assertEqual(self.conn.scalar(text("SELECT count(*) FROM control_plane.job_plugin_snapshots")), 2)

    def test_derived_secret_rejects_same_environment_different_group(self):
        self.succeed_source()
        group = insert(self.conn, "execution_groups", environment_id=self.args["environment_id"])
        consumer = self.recovery_job(group=group)
        with self.assertRaises(DBAPIError) as raised:
            with self.conn.begin_nested():
                self.publish_secret(consumer)
        self.assertEqual(raised.exception.orig.args[0]["C"], "23514")
        self.assertEqual(self.conn.scalar(text("SELECT count(*) FROM control_plane.job_secret_refs")), 0)

    def test_derived_secret_rejects_different_environment_even_with_instance_authorized(self):
        self.succeed_source()
        other_args, consumer, _, _, _ = runtime_graph(self.conn)
        self.copy_snapshot(consumer)
        secret = insert(self.conn, "secrets", purpose="environment", environment_id=other_args["environment_id"])
        version = insert(self.conn, "secret_versions", secret_id=secret, version=1,
                         ciphertext=b"isolated-test-ciphertext", encryption_key_id="test")
        with self.assertRaises(DBAPIError) as raised:
            with self.conn.begin_nested():
                self.publish_secret(consumer, secret=version)
        self.assertEqual(raised.exception.orig.args[0]["C"], "23514")

    def test_derived_secret_recovery_cannot_switch_instance_or_checkpoint_operation(self):
        self.succeed_source()
        recovery = self.recovery_job()
        step = insert(self.conn, "job_steps", job_id=recovery, step_path="other-instance")
        other = operation_arguments(self.conn, recovery, step)
        other_op = insert(self.conn, "operations", **other)
        other_evidence = insert(self.conn, "operation_evidence", operation_id=other_op,
                                kind="checkpoint", ref_key="different-operation", revision=1, data={})
        for values, expected_code in (({"instance": other["plugin_instance_id"]}, "23503"),
                                      ({"evidence": other_evidence}, "23514")):
            with self.subTest(values=tuple(values)), self.assertRaises(DBAPIError) as raised:
                with self.conn.begin_nested():
                    self.publish_secret(recovery, **values)
            self.assertEqual(raised.exception.orig.args[0]["C"], expected_code)

    def test_untrusted_checkpoint_cannot_authorize_derivation_or_be_promoted(self):
        self.succeed_source()
        evidence = self.evidence(self.attempt())
        self.assertFalse(self.conn.scalar(text("""SELECT trusted_for_derivation
            FROM control_plane.operation_evidence WHERE id=:id"""), {"id": evidence}))
        recovery = self.recovery_job()
        with self.assertRaises(DBAPIError) as raised:
            with self.conn.begin_nested():
                self.publish_secret(recovery, evidence=evidence)
        self.assertEqual(raised.exception.orig.args[0]["C"], "23514")
        self.rejects("""UPDATE control_plane.operation_evidence SET trusted_for_derivation=true
            WHERE id=:id""", {"id": evidence})
        trusted = self.evidence(self.attempt(), trusted_for_derivation=True)
        self.publish_secret(recovery, evidence=trusted)

    def test_derived_spec_digest_is_immutable(self):
        secret = insert(self.conn, "secrets", purpose="environment", environment_id=self.args["environment_id"],
                        derived_key=uuid4().hex, derived_spec_digest="a" * 64)
        self.rejects("UPDATE control_plane.secrets SET derived_spec_digest='changed' WHERE id=:id", {"id": secret})

    def test_session_defaults_control_revision_activity_and_terminal_guard(self):
        session = self.session()
        row = self.conn.execute(text("SELECT session_type,last_activity_at,controller_revision FROM control_plane.interactive_sessions WHERE id=:id"), {"id": session}).one()
        self.assertEqual((row.session_type, row.controller_revision), ("terminal", 0))
        self.assertIsNotNone(row.last_activity_at)
        self.rejects("UPDATE control_plane.interactive_sessions SET controller_id=:actor WHERE id=:id", {"id": session, "actor": self.args["actor_id"]})
        self.conn.execute(text("UPDATE control_plane.interactive_sessions SET controller_id=:actor,controller_revision=1 WHERE id=:id"), {"id": session, "actor": self.args["actor_id"]})
        self.rejects("UPDATE control_plane.interactive_sessions SET last_activity_at=last_activity_at-interval '1 second' WHERE id=:id", {"id": session})
        for state in ("active", "closing", "closed"):
            self.conn.execute(text("UPDATE control_plane.interactive_sessions SET state=:state WHERE id=:id"), {"id": session, "state": state})
        self.rejects("UPDATE control_plane.interactive_sessions SET state='active' WHERE id=:id", {"id": session})
        self.rejects("UPDATE control_plane.interactive_sessions SET reason='{}'::jsonb WHERE id=:id", {"id": session})

    def test_low_privilege_can_append_calls_but_cannot_mutate_or_truncate(self):
        role = "p2_acl_" + uuid4().hex
        self.conn.execute(text(f'CREATE ROLE "{role}" NOLOGIN'))
        grant_runtime_permissions(self.conn, role)
        self.conn.execute(text(f'SET LOCAL ROLE "{role}"'))
        try:
            validate_runtime_permissions(self.conn)
            call = self.attempt()
            self.evidence(call)
            for sql in ("UPDATE control_plane.operation_call_attempts SET method='poll'",
                        "DELETE FROM control_plane.operation_call_attempts", "TRUNCATE control_plane.operation_call_attempts CASCADE"):
                self.rejects(sql, code="42501")
        finally:
            self.conn.execute(text("RESET ROLE"))
        # Role creation, ACLs and fixtures are rolled back with this test.


class P2MigrationTests(unittest.TestCase):
    def settings(self, url):
        return RuntimeSettings.from_env({"CONTROL_PLANE_DATABASE_URL": url})

    def test_p1_unique_authorized_instance_is_backfilled_without_rewriting_evidence(self):
        with fresh_database() as url:
            settings = self.settings(url)
            run_migrations(settings, P1_REVISION)
            engine = engine_for(url)
            try:
                with engine.begin() as conn:
                    args, job, step, op, instance = runtime_graph(conn)
                    secret = insert(conn, "secrets", purpose="environment", environment_id=args["environment_id"])
                    version = insert(conn, "secret_versions", secret_id=secret, version=1, ciphertext=b"test", encryption_key_id="test")
                    conn.execute(text("INSERT INTO control_plane.job_secret_refs(job_id,secret_version_id) VALUES (:job,:secret)"), {"job": job, "secret": version})
                    evidence = insert(conn, "operation_evidence", operation_id=op, kind="checkpoint", ref_key="original", revision=1, data={})
                run_migrations(settings)
                with engine.connect() as conn:
                    check_schema(conn)
                    self.assertEqual(conn.scalar(text("SELECT plugin_instance_id FROM control_plane.job_secret_refs")), instance)
                    row = conn.execute(text("SELECT id,call_attempt_id,event_id,trusted_for_derivation FROM control_plane.operation_evidence")).one()
                    self.assertEqual(row.id, evidence)
                    self.assertIsNone(row.call_attempt_id)
                    self.assertIsNone(row.event_id)
                    self.assertFalse(row.trusted_for_derivation)
            finally:
                engine.dispose()

    def test_ambiguous_missing_or_unproven_legacy_grants_roll_back_entire_upgrade(self):
        for mode in ("ambiguous", "missing", "derived"):
            with self.subTest(mode=mode), fresh_database() as url:
                settings = self.settings(url)
                run_migrations(settings, P1_REVISION)
                engine = engine_for(url)
                try:
                    with engine.begin() as conn:
                        args = job_arguments(conn)
                        job = insert(conn, "jobs", **args)
                        if mode != "missing":
                            step = insert(conn, "job_steps", job_id=job, step_path="first")
                            operation_arguments(conn, job, step)
                        if mode == "ambiguous":
                            step = insert(conn, "job_steps", job_id=job, step_path="second")
                            operation_arguments(conn, job, step)
                        secret = insert(conn, "secrets", purpose="environment", environment_id=args["environment_id"])
                        version = insert(conn, "secret_versions", secret_id=secret, version=1, ciphertext=b"test", encryption_key_id="test")
                        conn.execute(text("INSERT INTO control_plane.job_secret_refs(job_id,secret_version_id,derived) VALUES (:job,:secret,:derived)"), {"job": job, "secret": version, "derived": mode == "derived"})
                    with self.assertRaises(MigrationError):
                        run_migrations(settings)
                    with engine.begin() as conn:
                        self.assertEqual(conn.scalar(text("SELECT version_num FROM control_plane.alembic_version")), P1_REVISION)
                        self.assertIsNone(conn.scalar(text("SELECT to_regclass('control_plane.operation_call_attempts')")))
                        self.assertEqual(conn.scalar(text("SELECT count(*) FROM control_plane.job_secret_refs")), 1)
                        self.assertEqual(conn.scalar(text("""SELECT count(*) FROM pg_trigger WHERE
                            tgrelid='control_plane.job_secret_refs'::regclass AND tgname='job_secret_refs_append_only' AND tgenabled='O'""")), 1)
                finally:
                    engine.dispose()

    def test_empty_baseline_p1_head_roundtrip_preserves_incremental_path(self):
        with fresh_database() as url:
            settings = self.settings(url)
            for target in (BASELINE_REVISION, P1_REVISION, HEAD_REVISION):
                run_migrations(settings, target)
            run_migrations(settings, P1_REVISION, upgrade=False)
            run_migrations(settings)
            run_migrations(settings, "base", upgrade=False)
            engine = engine_for(url)
            try:
                with engine.connect() as conn:
                    self.assertIsNone(conn.scalar(text("SELECT to_regnamespace('control_plane')")))
            finally:
                engine.dispose()

    def test_nonempty_downgrade_rejected_without_losing_call_history(self):
        with migrated_database() as url:
            engine = engine_for(url)
            try:
                with engine.begin() as conn:
                    _, _, _, op, _ = runtime_graph(conn)
                    call = insert(conn, "operation_call_attempts", **call_arguments(op))
                with self.assertRaises(MigrationError):
                    run_migrations(self.settings(url), P1_REVISION, upgrade=False)
                with engine.connect() as conn:
                    self.assertEqual(conn.scalar(text("SELECT version_num FROM control_plane.alembic_version")), HEAD_REVISION)
                    self.assertEqual(conn.scalar(text("SELECT id FROM control_plane.operation_call_attempts")), call)
            finally:
                engine.dispose()

    def test_head_requires_call_attempt_table_and_p1_is_not_runtime_compatible(self):
        with fresh_database() as url:
            settings = self.settings(url)
            run_migrations(settings, P1_REVISION)
            engine = engine_for(url)
            try:
                with engine.connect() as conn:
                    with self.assertRaises(SchemaMismatch):
                        check_schema(conn)
                run_migrations(settings)
                with engine.begin() as conn:
                    conn.execute(text("ALTER TABLE control_plane.operation_call_attempts RENAME TO missing_calls"))
                    with self.assertRaises(SchemaMismatch):
                        check_schema(conn)
                    conn.execute(text("ALTER TABLE control_plane.missing_calls RENAME TO operation_call_attempts"))
            finally:
                engine.dispose()


if __name__ == "__main__":
    unittest.main()
