from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from threading import Event
from time import monotonic, sleep
import unittest
from unittest.mock import patch
from uuid import uuid4

from sqlalchemy import text

from control_plane.credentials import CredentialService, confirmed_session_ref_in, confirm_from_operation, is_ready_in
from control_plane.identity import IdentityService
from control_plane.plugins.sdk import AuthorizationDenied
from tests_control_plane.test_p2_storage import ServicesFixture


class EnvironmentCredentialTests(ServicesFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.credentials = CredentialService(self.lease, self.secrets)
        self.identities = IdentityService(self.lease)
        with self.lease.fenced_transaction() as uow:
            uow.execute(text("UPDATE control_plane.environments SET lifecycle='ready' WHERE id=:id"),
                        {"id": self.environment})
            self.course = uow.scalar(text("SELECT course_id FROM control_plane.environments WHERE id=:id"),
                                     {"id": self.environment})

    def student(self):
        student = self.identities.create_user(self.teacher, uuid4().hex, uuid4().hex)
        self.identities.enroll(self.teacher, self.course, student)
        assignment = self.identities.assign(self.teacher, self.environment, student_id=student)
        return student, assignment

    def remote_result(self, ref, extra=None, *, confirm=True):
        config = self.configurations.get(self.instance)
        self.configurations.put(self.instance, {"data": {}, "allowed_secret_refs": [ref.to_dict()]},
                                expected_revision=config.revision)
        job, step = self.job()
        op, _ = self.source(job, step, {"confirmed_environment_credential": ref.to_dict(), **(extra or {})})
        if confirm:
            with self.lease.fenced_transaction() as uow:
                self.assertTrue(confirm_from_operation(uow, op))
        return job, op

    def test_audit_no_cache_readiness_and_revocation(self):
        ref = self.secrets.create(b"known-secret-fixture", purpose="environment", environment_id=self.environment)
        student, _ = self.student()
        with self.assertRaises(AuthorizationDenied):
            self.credentials.view(student, self.environment, ref.secret_id)
        self.remote_result(ref)
        view = self.credentials.view(student, self.environment, ref.secret_id)
        self.assertEqual(view.value, b"known-secret-fixture")
        self.assertEqual(view.headers["Cache-Control"], "no-store")
        self.assertNotIn("known-secret-fixture", repr(view))
        self.secrets.revoke(ref)
        with self.assertRaises(AuthorizationDenied):
            self.credentials.view(student, self.environment, ref.secret_id)
        with self.lease.fenced_transaction() as uow:
            events = uow.execute(text("""
                SELECT result,data FROM control_plane.audit_events WHERE actor_id=:student
                AND action='credential.view' ORDER BY created_at
            """), {"student": student}).all()
            self.assertEqual([e.result for e in events], ["denied", "delivered", "denied"])
            self.assertNotIn("known-secret-fixture", str(events))
            self.assertFalse(is_ready_in(uow, self.environment, ref.to_dict()))

    def test_confirmed_credential_remains_hidden_outside_ready_lifecycle(self):
        ref = self.secrets.create(b"confirmed-fixture", purpose="environment", environment_id=self.environment)
        student, _ = self.student()
        self.remote_result(ref)
        for state in ("creating", "create_failed", "blocked", "deleting", "delete_failed"):
            with self.subTest(lifecycle=state):
                with self.lease.fenced_transaction() as uow:
                    uow.execute(text("UPDATE control_plane.environments SET lifecycle=:state WHERE id=:env"),
                                {"state": state, "env": self.environment})
                with self.assertRaises(AuthorizationDenied):
                    self.credentials.view(student, self.environment, ref.secret_id)
        with self.lease.fenced_transaction() as uow:
            uow.execute(text("UPDATE control_plane.environments SET lifecycle='ready' WHERE id=:env"),
                        {"env": self.environment})
        self.assertEqual(self.credentials.view(student, self.environment, ref.secret_id).value, b"confirmed-fixture")

    def test_credential_read_serializes_with_last_assignment_revocation(self):
        ref = self.secrets.create(b"concurrent-fixture", purpose="environment", environment_id=self.environment)
        student, assignment = self.student()
        self.remote_result(ref)
        authorized = Event()
        continue_read = Event()
        writer_pid = Queue()
        decrypt = self.secrets._decrypt

        def pause_after_authorization(row):
            authorized.set()
            if not continue_read.wait(10):
                raise RuntimeError("credential reader was not released")
            return decrypt(row)

        def revoke_in_independent_transaction():
            # Use the production revocation lock order on an independent
            # connection so the coordinator's write gate cannot mask a race.
            with self.engine.begin() as tx:
                writer_pid.put(tx.scalar(text("SELECT pg_backend_pid()")))
                tx.execute(text("SELECT id FROM control_plane.courses WHERE id=:course FOR UPDATE"),
                           {"course": self.course})
                tx.execute(text("""UPDATE control_plane.environment_assignments
                    SET revoked_at=clock_timestamp() WHERE id=:id"""), {"id": assignment})

        with ThreadPoolExecutor(max_workers=2) as pool:
            with patch.object(self.secrets, "_decrypt", side_effect=pause_after_authorization):
                reader = pool.submit(self.credentials.view, student, self.environment, ref.secret_id)
                try:
                    self.assertTrue(authorized.wait(5), "reader did not reach decryption")
                    writer = pool.submit(revoke_in_independent_transaction)
                    pid = writer_pid.get(timeout=5)
                    deadline = monotonic() + 5
                    with self.engine.connect() as observer:
                        while not observer.scalar(text("SELECT cardinality(pg_blocking_pids(:pid)) > 0"),
                                                  {"pid": pid}):
                            self.assertFalse(writer.done(), "revocation committed before delivery")
                            self.assertLess(monotonic(), deadline, "revocation did not wait for the course lock")
                            sleep(.02)
                finally:
                    continue_read.set()
                self.assertEqual(reader.result(5).value, b"concurrent-fixture")
                writer.result(5)
        with patch.object(self.secrets, "_decrypt", side_effect=AssertionError("revoked credential decrypted")):
            with self.assertRaises(AuthorizationDenied):
                self.credentials.view(student, self.environment, ref.secret_id)

    def test_management_credential_cannot_be_confirmed_or_viewed_even_by_owner(self):
        ref = self.secrets.create(b"fixture-management-connection")
        _, op = self.remote_result(ref, confirm=False)
        with self.lease.fenced_transaction() as uow, self.assertRaises(AuthorizationDenied):
            confirm_from_operation(uow, op)
        with self.assertRaises(AuthorizationDenied):
            self.credentials.view(self.teacher, self.environment, ref.secret_id)

    def test_ungranted_reference_in_successful_output_is_not_confirmation(self):
        ref = self.secrets.create(b"ungranted", purpose="environment", environment_id=self.environment)
        job, step = self.job()
        op, _ = self.source(job, step, {"confirmed_environment_credential": ref.to_dict()})
        with self.lease.fenced_transaction() as uow, self.assertRaises(AuthorizationDenied):
            confirm_from_operation(uow, op)

    def test_shared_remote_rotation_keeps_other_students_access_and_expires_old_version(self):
        with self.lease.fenced_transaction() as uow:
            uow.execute(text("""
                UPDATE control_plane.template_versions SET definition='{"revocation_action":"rotate"}'
                WHERE id=(SELECT template_version_id FROM control_plane.environments WHERE id=:env)
            """), {"env": self.environment})
        old = self.secrets.create(b"old-shared-password", purpose="environment", environment_id=self.environment)
        self.remote_result(old)
        student, assignment = self.student()
        remaining, _ = self.student()
        self.credentials.view(student, self.environment, old.secret_id)
        self.identities.revoke_assignment(self.teacher, assignment)
        with self.assertRaises(AuthorizationDenied):
            self.credentials.view(student, self.environment, old.secret_id)
        replacement = self.secrets.rotate(old.secret_id, b"new-shared-password")
        job, _ = self.remote_result(replacement, {"remote_revocation": {"remote_sessions_terminated": True,
             "invalidated_versions": [old.version_id], "replacement_confirmed": True}}, confirm=False)
        calls = []

        def submit(actor_id, **kwargs):
            calls.append(kwargs)
            return job, True

        self.credentials.run_action = submit
        self.assertEqual(self.credentials.poll_revocations(), 1)
        with self.lease.fenced_transaction() as uow:
            rid = uow.scalar(text("SELECT id FROM control_plane.access_revocations WHERE job_id=:job"), {"job": job})
            uow.execute(text("UPDATE control_plane.jobs SET state='running' WHERE id=:job"), {"job": job})
            uow.execute(text("UPDATE control_plane.jobs SET state='succeeded' WHERE id=:job"), {"job": job})
            uow.execute(text("UPDATE control_plane.access_revocations SET next_check_at=clock_timestamp() WHERE id=:id"),
                        {"id": rid})
        self.assertEqual(calls[0]["request_key"], "revocation/" + str(rid))
        self.assertEqual(calls[0]["action_key"], "rotate")
        self.assertEqual(self.credentials.poll_revocations(), 1)
        self.assertEqual(self.credentials.revocation_status(self.teacher, rid)["status"], "confirmed")
        self.assertEqual(self.credentials.view(remaining, self.environment, old.secret_id).value, b"new-shared-password")
        with self.assertRaises(AuthorizationDenied):
            self.credentials.view(student, self.environment, old.secret_id)
        with self.lease.fenced_transaction() as uow:
            self.assertFalse(is_ready_in(uow, self.environment, old.to_dict()))
            self.assertTrue(is_ready_in(uow, self.environment, replacement.to_dict()))
            self.assertEqual(confirmed_session_ref_in(uow, self.environment, old.to_dict()), replacement.to_dict())

    def test_unsupported_remote_revocation_preserves_history_on_regrant(self):
        student, assignment = self.student()
        self.identities.revoke_assignment(self.teacher, assignment)
        self.identities.assign(self.teacher, self.environment, student_id=student)
        with self.lease.fenced_transaction() as uow:
            row = uow.execute(text("""
                SELECT status,reason FROM control_plane.access_revocations
                WHERE student_id=:student AND environment_id=:env
            """), {"student": student, "env": self.environment}).one()
            self.assertEqual((row.status, row.reason), ("revocation_failed", "unsupported"))

    def test_revocation_history_survives_cleanup_for_current_owners_and_admins(self):
        student, assignment = self.student()
        self.identities.revoke_assignment(self.teacher, assignment)
        with self.lease.fenced_transaction() as uow:
            rid = uow.scalar(text("""
                SELECT id FROM control_plane.access_revocations WHERE student_id=:id AND environment_id=:env
            """), {"id": student, "env": self.environment})
            admin = uow.scalar(text("""
                INSERT INTO control_plane.users(username,password_hash,role)
                VALUES (:name,'test-only','admin') RETURNING id
            """), {"name": uuid4().hex})
            uow.execute(text("""
                UPDATE control_plane.environments SET lifecycle='deleted',deleted_at=clock_timestamp() WHERE id=:env
            """), {"env": self.environment})
        other_teacher = self.identities.create_user(admin, uuid4().hex, uuid4().hex, role="teacher")
        for actor in (admin, self.teacher):
            status = self.credentials.revocation_status(actor, rid)
            self.assertEqual((status["status"], status["environment_id"]), ("revocation_failed", self.environment))
        for actor in (student, other_teacher):
            with self.assertRaises(AuthorizationDenied):
                self.credentials.revocation_status(actor, rid)
        self.identities.set_active(admin, self.teacher, False)
        with self.assertRaises(AuthorizationDenied):
            self.credentials.revocation_status(self.teacher, rid)

    def test_confirmed_secret_cannot_be_read_through_another_owned_environment(self):
        ref = self.secrets.create(b"only-for-first-environment", purpose="environment", environment_id=self.environment)
        self.remote_result(ref)
        self.assertEqual(self.credentials.view(self.teacher, self.environment, ref.secret_id).value,
                         b"only-for-first-environment")
        with self.lease.fenced_transaction() as uow:
            other = uow.scalar(text("""
                INSERT INTO control_plane.environments(owner_teacher_id,course_id,created_by,template_version_id,name)
                SELECT owner_teacher_id,course_id,created_by,template_version_id,'second' FROM control_plane.environments
                WHERE id=:env RETURNING id
            """), {"env": self.environment})
        with self.assertRaises(AuthorizationDenied):
            self.credentials.view(self.teacher, other, ref.secret_id)

    def test_live_terminal_ownership_controller_and_last_path_revocation(self):
        from types import SimpleNamespace
        from control_plane.plugins.sdk import canonical_json

        # Only the transport implementation is stubbed. The fixed entry, grants,
        # session binding, assignments and current input controller live in PostgreSQL.
        terminal = SimpleNamespace(manifest={"sessions": {"terminal": {}}},
                                   validate_input=lambda name, data: None)
        registry = SimpleNamespace(get=lambda key: terminal)
        service = CredentialService(self.lease, self.secrets, registry=registry)
        student, assignment = self.student()
        peer, _ = self.student()
        ref = self.secrets.create(b"terminal-use", purpose="environment", environment_id=self.environment)
        job, operation = self.remote_result(ref)
        target = {"host": "loopback-fixture"}
        definition = {"access": {"entry": {"roles": ["student"], "session_type": "terminal",
            "plugin_instance": str(self.instance), "target_ref": target, "credential_ref": ref.to_dict()}}}
        with self.lease.fenced_transaction() as uow:
            uow.execute(text("""
                UPDATE control_plane.template_versions SET status='published',published_by=:teacher,
                    published_at=clock_timestamp(),definition=CAST(:definition AS jsonb)
                WHERE id=(SELECT template_version_id FROM control_plane.environments WHERE id=:env)
            """), {"teacher": self.teacher, "env": self.environment, "definition": canonical_json(definition)})
            uow.execute(text("UPDATE control_plane.environments SET lifecycle='ready' WHERE id=:env"),
                        {"env": self.environment})
            sid = uow.scalar(text("""
                INSERT INTO control_plane.interactive_sessions
                  (environment_id,job_id,open_operation_id,actor_id,plugin_instance_id,target_ref,
                   secret_version_id,template_entry,controller_id,state)
                VALUES (:env,:job,:op,:student,:instance,CAST(:target AS jsonb),:version,'entry',:student,'active')
                RETURNING id
            """), {"env": self.environment,"job": job,"op": operation,"student": student,
                   "instance": self.instance, "target":canonical_json(target),"version":ref.version_id})
        def allowed(actor, action, **extra):
            return service.session_authorizer(actor, self.environment, "session." + action,
                        session_id=sid, template_entry="entry", **extra)

        self.assertTrue(allowed(student, "input"))
        replacement = self.secrets.rotate(ref.secret_id, b"terminal-rotated")
        self.remote_result(replacement)
        with self.lease.fenced_transaction() as uow:
            self.assertFalse(is_ready_in(uow, self.environment, ref.to_dict()))
            self.assertEqual(confirmed_session_ref_in(uow, self.environment, replacement.to_dict()),
                             replacement.to_dict())
        self.assertTrue(allowed(student, "output"))
        self.assertTrue(allowed(self.teacher, "observe"))
        self.assertFalse(allowed(peer, "output"))
        self.assertFalse(allowed(student, "takeover"))
        with self.lease.fenced_transaction() as uow:
            uow.execute(text("""
                UPDATE control_plane.interactive_sessions SET controller_id=:teacher,
                    controller_revision=controller_revision+1 WHERE id=:id
            """), {"teacher": self.teacher,"id": sid})
        self.assertFalse(allowed(student, "input"))
        self.assertFalse(allowed(student, "resize"))
        self.assertTrue(allowed(self.teacher, "input"))
        self.assertTrue(allowed(student, "resume_input"))
        self.identities.revoke_assignment(self.teacher, assignment)
        self.assertFalse(allowed(student, "replay"))
        self.assertFalse(allowed(self.teacher, "output"))
        self.identities.assign(self.teacher, self.environment, student_id=student)
        self.assertFalse(allowed(student, "reconnect"))
        self.secrets.revoke(ref)
        with self.lease.fenced_transaction() as uow, self.assertRaises(AuthorizationDenied):
            confirmed_session_ref_in(uow, self.environment, ref.to_dict(), pinned_version_id=ref.version_id)
