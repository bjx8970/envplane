"""Real transaction, ownership and membership boundaries for P3 identity."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Event
from time import monotonic, sleep
import unittest
from unittest.mock import patch
from uuid import uuid4

from sqlalchemy import event, text

from control_plane.config import RuntimeSettings
from control_plane.identity import IdentityService, can_access_environment, verify_password
from control_plane.plugins.sdk import AuthorizationDenied
from control_plane.runtime import ControlPlaneRuntime
from tests_control_plane.p1_harness import runtime_database
from tests_control_plane.pg_harness import engine_for
from tests_control_plane.test_p1_schema import graph, insert, operation_arguments


class IdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        admin_url, cls.runtime_url = cls.enterClassContext(runtime_database())
        cls.db = engine_for(admin_url)
        cls.addClassCleanup(cls.db.dispose)

    def setUp(self):
        self.runtime = ControlPlaneRuntime(RuntimeSettings.from_env(
            {"CONTROL_PLANE_DATABASE_URL": self.runtime_url}))
        self.runtime.start()
        self.addCleanup(self.runtime.stop)
        self.identity = IdentityService(self.runtime)
        with self.db.begin() as db:
            self.admin = insert(db, "users", username=uuid4().hex, role="admin", password_hash="fixture")
            self.teacher, self.course, _, self.env, self.execution_group = graph(db)
            self.other, self.foreign_course, _, self.foreign_env, _ = graph(db)
        self.student = self.identity.create_user(self.teacher, uuid4().hex, "secret value")

    def access(self, actor, env=None, **options):
        with self.db.connect() as db:
            return can_access_environment(db, actor, env or self.env, **options)

    def test_cross_teacher_enrollment_permanently_removes_all_four_management_rights(self):
        self.assertTrue(self.identity.get_user(self.teacher, self.student)["exclusive_management"])
        self.identity.enroll(self.teacher, self.course, self.student)
        self.identity.rename_user(self.teacher, self.student, uuid4().hex)
        self.identity.enroll(self.admin, self.foreign_course, self.student)
        self.identity.leave_course(self.other, self.foreign_course, self.student)
        account = self.identity.get_user(self.admin, self.student)
        self.assertEqual(account["created_by"], self.teacher)
        self.assertFalse(account["exclusive_management"])
        for operation, args in [
            (self.identity.rename_user, (uuid4().hex,)), (self.identity.reset_password, ("new password",)),
            (self.identity.set_active, (False,)), (self.identity.delete_user, ())]:
            with self.subTest(operation=operation.__name__), self.assertRaises(AuthorizationDenied):
                operation(self.teacher, self.student, *args)
        self.identity.assign(self.teacher, self.env, student_id=self.student)
        self.assertTrue(self.access(self.student))
        self.assertFalse(self.access(self.student, manage=True))
        self.assertFalse(self.access(self.student, roles=["teacher", "admin"]))

    def test_failed_or_rolled_back_enrollment_preserves_original_management(self):
        group = self.identity.create_group(self.teacher, self.course, "group")
        with self.assertRaises(ValueError):
            self.identity.enroll(self.other, self.foreign_course, self.student, group_id=group)
        with patch("control_plane.identity._audit", side_effect=ValueError("rollback")):
            with self.assertRaises(ValueError):
                self.identity.enroll(self.other, self.foreign_course, self.student)
        self.assertTrue(self.identity.get_user(self.teacher, self.student)["exclusive_management"])
        with self.db.connect() as db:
            self.assertEqual(db.scalar(text("""SELECT count(*) FROM control_plane.course_members
                                             WHERE student_id=:id"""), {"id": self.student}), 0)

    def test_waiting_teacher_edit_rechecks_locked_account_after_concurrent_downgrade(self):
        # Hold the account row in a second PostgreSQL transaction. Release it after
        # the manager's SELECT FOR UPDATE is issued. The manager must see the new
        # version even though it began its statement while the old row was visible.
        selecting = Event()
        def before_select(conn, cursor, statement, params, context, executemany):
            if "FROM control_plane.users WHERE id=" in statement and "FOR UPDATE" in statement:
                selecting.set()
        event.listen(self.runtime._engine, "before_cursor_execute", before_select)
        self.addCleanup(event.remove, self.runtime._engine, "before_cursor_execute", before_select)
        with ThreadPoolExecutor(max_workers=1) as pool:
            with self.db.begin() as db:
                db.execute(text("""UPDATE control_plane.users SET exclusive_management=false WHERE id=:id"""),
                           {"id": self.student})
                db.execute(text("""
                    INSERT INTO control_plane.course_members(course_id,student_id,added_by)
                    VALUES (:course,:student,:actor)
                """), {"course": self.foreign_course, "student": self.student, "actor": self.other})
                change = pool.submit(self.identity.set_active, self.teacher, self.student, False)
                self.assertTrue(selecting.wait(5))
            with self.assertRaises(AuthorizationDenied):
                change.result(timeout=5)
        self.assertTrue(self.identity.get_user(self.admin, self.student)["active"])

    def test_effective_assignment_union_revokes_only_last_path(self):
        group = self.identity.create_group(self.teacher, self.course, "group")
        self.identity.enroll(self.teacher, self.course, self.student, group_id=group)
        direct = self.identity.assign(self.teacher, self.env, student_id=self.student)
        indirect = self.identity.assign(self.teacher, self.env, group_id=group)
        self.assertEqual(direct, self.identity.assign(self.teacher, self.env, student_id=self.student))
        self.identity.revoke_assignment(self.teacher, direct)
        self.assertTrue(self.access(self.student))
        with self.db.connect() as db:
            self.assertEqual(db.scalar(text("""SELECT count(*) FROM control_plane.access_revocations
                                              WHERE student_id=:id"""), {"id": self.student}), 0)
        self.identity.revoke_assignment(self.teacher, indirect)
        self.assertFalse(self.access(self.student))
        self.identity.revoke_assignment(self.teacher, indirect)
        with self.db.connect() as db:
            self.assertEqual(db.scalar(text("""SELECT count(*) FROM control_plane.access_revocations
                                              WHERE student_id=:id"""), {"id": self.student}), 1)

    def test_group_removal_retains_membership_and_direct_path_leaving_prevents_reactivation(self):
        group = self.identity.create_group(self.teacher, self.course, "group")
        self.identity.enroll(self.teacher, self.course, self.student, group_id=group)
        self.identity.assign(self.teacher, self.env, student_id=self.student)
        self.identity.assign(self.teacher, self.env, group_id=group)
        self.identity.delete_group(self.teacher, self.course, group)
        self.assertTrue(self.access(self.student))
        self.identity.leave_course(self.teacher, self.course, self.student)
        self.assertFalse(self.access(self.student))
        self.identity.enroll(self.teacher, self.course, self.student)
        self.assertFalse(self.access(self.student))
        with self.assertRaises(ValueError):
            self.identity.move_student(self.teacher, self.course, self.student, group)

    def test_course_ownership_controls_assignment_and_course_deletion_preserves_history(self):
        self.assertTrue(self.access(self.admin, self.foreign_env, manage=True))
        self.assertFalse(self.access(self.teacher, self.foreign_env))
        self.identity.enroll(self.other, self.foreign_course, self.student)
        with self.assertRaises(ValueError):
            self.identity.assign(self.teacher, self.env, student_id=self.student)
        with self.assertRaises(AuthorizationDenied):
            self.identity.assign(self.teacher, self.foreign_env, student_id=self.student)
        with self.assertRaises(ValueError):
            self.identity.delete_course(self.teacher, self.course)
        course = self.identity.create_course(self.admin, self.teacher, "empty")
        self.identity.delete_course(self.teacher, course)
        with self.assertRaises(AuthorizationDenied):
            self.identity.create_group(self.teacher, course, "closed")

    def test_status_checks_resource_and_job_ownership_before_exposing_fresh_observations(self):
        with self.db.begin() as db:
            invocation = uuid4()
            job = insert(db, "jobs", actor_id=self.teacher, environment_id=self.env,
                         execution_group_id=self.execution_group, logical_invocation_id=invocation,
                         request_key=uuid4().hex, request_digest="digest", kind="create",
                         input={}, execution_snapshot={})
            step = insert(db, "job_steps", job_id=job, step_path="observe")
            op = insert(db, "operations", **operation_arguments(db, job, step))
            resource = insert(db, "experiment_resources", environment_id=self.env, logical_invocation_id=invocation,
                              source_job_id=job, source_operation_id=op, name="report", type_label="report",
                              resource_slot="report", action_snapshot={}, access_snapshot={}, data={})
            observation = dict(resource_id=resource, environment_id=self.env, job_id=job,
                               action="resource.state_observed", result="confirmed")
            insert(db, "audit_events", **observation, data={"state": "on", "ttl_seconds": 60},
                   created_at=datetime.now(timezone.utc) - timedelta(minutes=10))
        readers = [(self.identity.resource_status, resource), (self.identity.job_status, job),
                   (self.identity.environment_status, self.env)]
        for reader, obj in readers:
            with self.assertRaises(AuthorizationDenied):
                reader(self.other, obj)
            with self.assertRaises(AuthorizationDenied):
                reader(self.student, obj)
            with self.assertRaises(AuthorizationDenied):
                reader(self.teacher, uuid4())
        self.identity.enroll(self.teacher, self.course, self.student)
        direct = self.identity.assign(self.teacher, self.env, student_id=self.student)
        self.assertNotIn("execution_snapshot", self.identity.job_status(self.student, job))
        self.assertNotIn("parameters", self.identity.environment_status(self.student, self.env))
        stale = self.identity.resource_status(self.student, resource)
        self.assertEqual(stale["state"], "unknown")
        self.assertIsNotNone(stale["observed_at"])
        with self.db.begin() as db:
            insert(db, "audit_events", **observation, data={"state": "off", "ttl_seconds": 60})
        self.assertEqual(self.identity.resource_status(self.student, resource)["state"], "off")
        self.identity.revoke_assignment(self.teacher, direct)
        for reader, obj in readers:
            with self.assertRaises(AuthorizationDenied):
                reader(self.student, obj)
        with self.db.begin() as db:
            db.execute(text("""UPDATE control_plane.environments SET lifecycle='deleted',deleted_at=clock_timestamp()
                             WHERE id=:env"""), {"env": self.env})
        self.assertFalse(self.access(self.teacher))
        self.assertEqual(self.identity.job_status(self.teacher, job)["job_id"], job)
        self.assertEqual(self.identity.environment_status(self.admin, self.env)["lifecycle"], "deleted")
        for reader, obj in readers:
            with self.assertRaises(AuthorizationDenied):
                reader(self.other, obj)

    def test_teacher_deletion_waits_for_course_and_student_responsibilities_to_end(self):
        teacher = self.identity.create_user(self.admin, uuid4().hex, uuid4().hex, role="teacher")
        course = self.identity.create_course(self.admin, teacher, "retiring course")
        with self.assertRaisesRegex(ValueError, "owns courses"):
            self.identity.delete_user(self.admin, teacher)
        self.identity.delete_course(self.admin, course)
        student = self.identity.create_user(teacher, uuid4().hex, "fixture password")
        self.identity.set_active(self.admin, student, False)
        with self.assertRaisesRegex(ValueError, "exclusively manages students"):
            self.identity.delete_user(self.admin, teacher)
        with self.assertRaisesRegex(ValueError, "exclusively manages students"):
            self.identity.set_role(self.admin, teacher, "student")
        self.assertTrue(self.identity.get_user(self.admin, teacher)["active"])
        self.identity.set_active(self.admin, student, True)
        self.identity.enroll(self.admin, self.foreign_course, student)
        self.identity.delete_user(self.admin, teacher)
        history = self.identity.get_user(self.admin, student)
        self.assertEqual(history["created_by"], teacher)
        self.assertFalse(history["exclusive_management"])
        with self.db.connect() as db:
            self.assertIsNotNone(db.scalar(text("SELECT deleted_at FROM control_plane.users WHERE id=:id"),
                                           {"id": teacher}))

    def test_losing_creation_race_cannot_attach_student_to_retired_teacher(self):
        teacher = self.identity.create_user(self.admin, uuid4().hex, uuid4().hex, role="teacher")
        checking_owner = Event()

        def before_select(conn, cursor, statement, params, context, executemany):
            if "SELECT role FROM control_plane.users" in statement:
                checking_owner.set()
        event.listen(self.runtime._engine, "before_cursor_execute", before_select)
        self.addCleanup(event.remove, self.runtime._engine, "before_cursor_execute", before_select)
        with ThreadPoolExecutor(max_workers=1) as pool:
            with self.db.begin() as db:
                db.execute(text("""
                    UPDATE control_plane.users SET active=false,deleted_at=clock_timestamp() WHERE id=:id
                """), {"id": teacher})
                creating = pool.submit(self.identity.create_user, teacher, uuid4().hex, "student fixture")
                self.assertTrue(checking_owner.wait(5))
                # Release the retiring account only after PostgreSQL reports the
                # competing transaction waiting on this connection's row lock.
                deadline = monotonic() + 0.8
                while not db.scalar(text("""
                    SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database()
                                  AND pg_backend_pid()=ANY(pg_blocking_pids(pid)))
                """)):
                    self.assertFalse(creating.done(), "creation skipped the owner lock")
                    self.assertLess(monotonic(), deadline, "creation did not lock the teacher")
                    sleep(0.005)
            with self.assertRaises(AuthorizationDenied):
                creating.result(timeout=5)
        with self.db.connect() as db:
            self.assertFalse(db.scalar(text("SELECT EXISTS(SELECT FROM control_plane.users WHERE created_by=:id)"),
                                       {"id": teacher}))

    def test_role_changes_are_admin_only_and_preserve_active_domain_relationships(self):
        with self.assertRaises(AuthorizationDenied):
            self.identity.set_role(self.teacher, self.student, "admin")
        with self.assertRaises(AuthorizationDenied):
            self.identity.set_role(self.student, self.student, "teacher")
        self.identity.enroll(self.teacher, self.course, self.student)
        with self.assertRaises(ValueError):
            self.identity.set_role(self.admin, self.student, "teacher")
        with self.assertRaises(ValueError):
            self.identity.set_role(self.admin, self.teacher, "admin")
        self.identity.leave_course(self.teacher, self.course, self.student)
        self.identity.set_role(self.admin, self.student, "teacher")
        self.identity.set_role(self.admin, self.student, "student")
        self.assertFalse(self.identity.get_user(self.admin, self.student)["exclusive_management"])
        with self.assertRaises(AuthorizationDenied):
            self.identity.set_active(self.teacher, self.student, False)

    def test_group_reassignment_does_not_grant_foreign_group_or_restore_revoked_path(self):
        group = self.identity.create_group(self.teacher, self.course, "first")
        second = self.identity.create_group(self.teacher, self.course, "second")
        foreign = self.identity.create_group(self.other, self.foreign_course, "foreign")
        self.identity.enroll(self.teacher, self.course, self.student, group_id=group)
        self.identity.assign(self.teacher, self.env, group_id=group)
        with self.assertRaises(ValueError):
            self.identity.move_student(self.teacher, self.course, self.student, foreign)
        self.assertTrue(self.access(self.student))
        self.identity.move_student(self.teacher, self.course, self.student, second)
        self.assertFalse(self.access(self.student))
        self.identity.move_student(self.teacher, self.course, self.student, None)
        direct = self.identity.assign(self.teacher, self.env, student_id=self.student)
        self.assertTrue(self.access(self.student))
        self.identity.set_active(self.teacher, self.student, False)
        self.assertFalse(self.access(self.student))
        self.identity.revoke_assignment(self.teacher, direct)
        self.identity.set_active(self.teacher, self.student, True)
        self.assertFalse(self.access(self.student))

    def test_account_tombstone_and_self_service_protect_secrets_and_audit(self):
        admin_created = self.identity.create_user(self.admin, uuid4().hex, "admin set secret")
        self.assertFalse(self.identity.get_user(self.admin, admin_created)["exclusive_management"])
        with self.assertRaises(AuthorizationDenied):
            self.identity.create_user(self.teacher, uuid4().hex, "not allowed", role="admin")
        with self.assertRaises(AuthorizationDenied):
            self.identity.change_password(self.student, "wrong", "another secret")
        self.identity.change_password(self.student, "secret value", "another secret")
        self.assertNotIn("password_hash", self.identity.get_user(self.student, self.student))
        self.identity.enroll(self.teacher, self.course, self.student)
        self.identity.assign(self.teacher, self.env, student_id=self.student)
        self.identity.delete_user(self.teacher, self.student)
        self.assertFalse(self.access(self.student))
        with self.assertRaises(AuthorizationDenied):
            self.identity.set_active(self.admin, self.student, True)
        with self.db.connect() as db:
            account = db.execute(text("SELECT * FROM control_plane.users WHERE id=:id"), {"id": self.student}).one()
            self.assertFalse(account.active)
            self.assertIsNotNone(account.deleted_at)
            self.assertTrue(verify_password("another secret", account.password_hash))
            self.assertTrue(db.scalar(text("SELECT EXISTS(SELECT FROM control_plane.environments WHERE id=:e)"),
                                      {"e": self.env}))
            events = db.execute(text("""SELECT data FROM control_plane.audit_events WHERE data->>'user_id'=:id"""),
                                {"id": str(self.student)}).all()
            self.assertTrue(events)
            self.assertNotIn("secret", repr(events))
