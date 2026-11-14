"""Real PostgreSQL ACL tests; SET ROLE uses random, password-free roles."""

from contextlib import contextmanager
import unittest
from unittest.mock import MagicMock, patch
from types import SimpleNamespace
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from control_plane.permissions import (
    RuntimePermissionError,
    grant_runtime_permissions,
    validate_runtime_permissions,
)
from tests_control_plane.p1_harness import migrated_database
from tests_control_plane.pg_harness import engine_for


class RuntimePermissionSignalTests(unittest.TestCase):
    def test_lifecycle_interruptions_are_not_reported_as_permission_failures(self):
        from control_plane.runtime import StartupDeadlineExceeded, StartupInterrupted
        connection = MagicMock()
        connection.dialect.name = 'postgresql'
        role = SimpleNamespace(oid=1, rolname='unused')
        for exception_type in (StartupInterrupted, StartupDeadlineExceeded):
            for call in (lambda: validate_runtime_permissions(connection),
                         lambda: grant_runtime_permissions(connection, 'unused')):
                with self.subTest(exception=exception_type.__name__):
                    interruption = exception_type('startup interrupted')
                    with patch('control_plane.permissions._role', return_value=role):
                        with patch('control_plane.permissions._check', side_effect=interruption):
                            with self.assertRaises(exception_type) as raised:
                                call()
                    self.assertIs(raised.exception, interruption)


class RuntimePermissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.url = cls.enterClassContext(migrated_database())
        cls.engine = engine_for(cls.url)
        cls.addClassCleanup(cls.engine.dispose)

    def setUp(self):
        self.connection = self.engine.connect()
        self.transaction = self.connection.begin()
        self.roles = []
        self.addCleanup(self._cleanup)
        self.role = self.new_role()

    def _cleanup(self):
        # Tests do not know, create or log any login password. Role/ACL changes
        # are transactional; DROP OWNED precedes DROP ROLE on successful paths.
        try:
            if self.transaction.is_active:
                self.connection.execute(text("RESET ROLE"))
                for role in reversed(self.roles):
                    self.connection.execute(text(f'DROP OWNED BY "{role}"'))
                    self.connection.execute(text(f'DROP ROLE "{role}"'))
        finally:
            self.transaction.rollback()
            self.connection.close()

    def new_role(self, attributes=""):
        role = "cp_test_role_" + uuid4().hex
        self.connection.execute(text(f'CREATE ROLE "{role}" NOLOGIN {attributes}'))
        self.roles.append(role)
        return role

    @contextmanager
    def as_role(self, role=None):
        self.connection.execute(text(f'SET LOCAL ROLE "{role or self.role}"'))
        try:
            yield
        finally:
            self.connection.execute(text("RESET ROLE"))

    def provision(self):
        grant_runtime_permissions(self.connection, self.role)

    def rejects_sql(self, sql):
        with self.assertRaises(DBAPIError) as raised:
            with self.connection.begin_nested():
                self.connection.execute(text(sql))
        # Not a trigger/check failure disguised as an ACL assertion.
        self.assertEqual(raised.exception.orig.args[0].get("C"), "42501")

    def rejects_validation(self):
        with self.as_role():
            with self.assertRaises(RuntimePermissionError):
                validate_runtime_permissions(self.connection)

    def test_provision_is_explicit_and_idempotent_and_runtime_role_validates(self):
        with self.as_role():
            with self.assertRaises(RuntimePermissionError):
                validate_runtime_permissions(self.connection)
        self.provision()
        self.provision()
        with self.as_role():
            validate_runtime_permissions(self.connection)
            self.connection.execute(text("SELECT * FROM control_plane.alembic_version"))
            self.connection.execute(text("UPDATE control_plane.coordinator_leases SET revision=revision WHERE id=1"))
            self.connection.execute(text("INSERT INTO control_plane.audit_events(action,result) VALUES ('test','allowed')"))
            self.connection.execute(text("INSERT INTO control_plane.users(username,password_hash,role) VALUES ('acl-test','not-a-secret','teacher')"))
            self.connection.execute(text("UPDATE control_plane.users SET active=false WHERE username='acl-test'"))

    def test_missing_needed_privilege_fails_closed_and_provision_repairs(self):
        self.provision()
        self.connection.execute(text(f'REVOKE INSERT ON control_plane.audit_events FROM "{self.role}"'))
        self.rejects_validation()
        self.provision()
        with self.as_role():
            validate_runtime_permissions(self.connection)

    def test_truncate_delete_ddl_and_unneeded_dml_are_acl_denied(self):
        self.provision()
        statements = (
            "TRUNCATE control_plane.audit_events",
            "TRUNCATE control_plane.jobs CASCADE",
            "DELETE FROM control_plane.jobs",
            "UPDATE control_plane.audit_events SET action='changed'",
            "UPDATE control_plane.plugin_storage_versions SET value='{}'",
            "UPDATE control_plane.plugin_storage_snapshots SET namespace_revision=0",
            "UPDATE control_plane.plugin_instance_versions SET configuration='{}'",
            "UPDATE control_plane.operation_evidence SET data='{}'",
            "UPDATE control_plane.job_logs SET data='{}'",
            "UPDATE control_plane.job_plugin_snapshots SET code_digest='changed'",
            "UPDATE control_plane.job_secret_refs SET derived=true",
            "INSERT INTO control_plane.coordinator_leases(id) VALUES (2)",
            "UPDATE control_plane.alembic_version SET version_num='changed'",
            "CREATE TABLE control_plane.acl_forbidden(id integer)",
            "CREATE TABLE public.acl_forbidden(id integer)",
            "ALTER TABLE control_plane.jobs DISABLE TRIGGER ALL",
            "DROP TABLE control_plane.audit_events",
            "ALTER TABLE control_plane.jobs ADD COLUMN forbidden integer",
            "CREATE SCHEMA acl_forbidden",
        )
        with self.as_role():
            for statement in statements:
                with self.subTest(statement=statement):
                    self.rejects_sql(statement)

    def test_owner_and_superuser_are_rejected_with_safe_message(self):
        with self.assertRaises(RuntimePermissionError) as raised:
            validate_runtime_permissions(self.connection)
        self.assertNotIn(self.url, str(raised.exception))
        current = self.connection.scalar(text("SELECT current_user"))
        with self.assertRaises(RuntimePermissionError):
            grant_runtime_permissions(self.connection, current)
        elevated = self.new_role("SUPERUSER")
        with self.assertRaises(RuntimePermissionError):
            grant_runtime_permissions(self.connection, elevated)

    def test_missing_role_is_not_created_and_bad_identifier_is_safe(self):
        absent = "cp_missing_" + uuid4().hex
        for name in (absent, "not-a-role\"; DROP SCHEMA control_plane; --", "", None):
            with self.subTest(name=name):
                with self.assertRaises(RuntimePermissionError) as raised:
                    grant_runtime_permissions(self.connection, name)
                self.assertNotIn(absent, str(raised.exception))
        self.assertIsNone(self.connection.scalar(text("SELECT oid FROM pg_roles WHERE rolname=:name"), {"name": absent}))

    def test_database_and_schema_create_are_rejected_including_public(self):
        self.provision()
        database = self.connection.dialect.identifier_preparer.quote_identifier(
            self.connection.scalar(text("SELECT current_database()")))
        for grant, revoke in (
            (f'GRANT CREATE ON DATABASE {database} TO "{self.role}"', f'REVOKE CREATE ON DATABASE {database} FROM "{self.role}"'),
            (f'GRANT CREATE ON SCHEMA control_plane TO "{self.role}"', f'REVOKE CREATE ON SCHEMA control_plane FROM "{self.role}"'),
            ("GRANT CREATE ON SCHEMA public TO PUBLIC", "REVOKE CREATE ON SCHEMA public FROM PUBLIC"),
        ):
            self.connection.execute(text(grant))
            self.rejects_validation()
            with self.assertRaises(RuntimePermissionError):
                self.provision()
            self.connection.execute(text(revoke))

    def test_public_table_and_column_privileges_are_not_missed(self):
        self.provision()
        for grant, revoke in (
            ("GRANT TRUNCATE ON control_plane.audit_events TO PUBLIC", "REVOKE TRUNCATE ON control_plane.audit_events FROM PUBLIC"),
            ("GRANT UPDATE(action) ON control_plane.audit_events TO PUBLIC", "REVOKE UPDATE(action) ON control_plane.audit_events FROM PUBLIC"),
            ("GRANT INSERT(id) ON control_plane.coordinator_leases TO PUBLIC", "REVOKE INSERT(id) ON control_plane.coordinator_leases FROM PUBLIC"),
            ("GRANT REFERENCES(id) ON control_plane.audit_events TO PUBLIC", "REVOKE REFERENCES(id) ON control_plane.audit_events FROM PUBLIC"),
        ):
            self.connection.execute(text(grant))
            self.rejects_validation()
            self.connection.execute(text(revoke))
        with self.as_role():
            validate_runtime_permissions(self.connection)

    def test_direct_column_privilege_and_grant_option_are_rejected(self):
        self.provision()
        self.connection.execute(text(f'GRANT UPDATE(action) ON control_plane.audit_events TO "{self.role}"'))
        self.rejects_validation()
        self.connection.execute(text(f'REVOKE UPDATE(action) ON control_plane.audit_events FROM "{self.role}"'))
        self.connection.execute(text(f'GRANT SELECT ON control_plane.audit_events TO "{self.role}" WITH GRANT OPTION'))
        self.rejects_validation()

    def test_inherited_privilege_escalation_is_rejected(self):
        self.provision()
        helper = self.new_role()
        self.connection.execute(text(f'GRANT DELETE ON control_plane.jobs TO "{helper}"'))
        self.connection.execute(text(f'GRANT "{helper}" TO "{self.role}" WITH INHERIT TRUE, SET FALSE'))
        self.rejects_validation()

    def test_set_role_escalation_is_rejected_without_inheritance(self):
        self.provision()
        helper = self.new_role()
        self.connection.execute(text(f'GRANT UPDATE(action) ON control_plane.audit_events TO "{helper}"'))
        self.connection.execute(text(f'GRANT "{helper}" TO "{self.role}" WITH INHERIT FALSE, SET TRUE'))
        self.rejects_validation()
        with self.assertRaises(RuntimePermissionError):
            self.provision()

    def test_indirect_set_role_to_owner_is_rejected(self):
        self.provision()
        middle = self.new_role()
        owner = self.connection.scalar(text("SELECT current_user"))
        self.connection.execute(text(f'GRANT "{owner}" TO "{middle}" WITH INHERIT FALSE, SET TRUE'))
        self.connection.execute(text(f'GRANT "{middle}" TO "{self.role}" WITH INHERIT FALSE, SET TRUE'))
        self.rejects_validation()

    def test_inherited_ownership_even_after_acl_revocation_is_rejected(self):
        self.provision()
        owner = self.new_role()
        self.connection.execute(text(f'ALTER TABLE control_plane.audit_events OWNER TO "{owner}"'))
        self.connection.execute(text(f'REVOKE ALL ON control_plane.audit_events FROM "{owner}"'))
        self.connection.execute(text(f'GRANT "{owner}" TO "{self.role}" WITH INHERIT TRUE, SET FALSE'))
        self.rejects_validation()

    def test_harmless_membership_is_not_an_approval_gate(self):
        helper = self.new_role()
        self.connection.execute(text(f'GRANT SELECT ON control_plane.alembic_version TO "{helper}"'))
        self.connection.execute(text(f'GRANT "{helper}" TO "{self.role}" WITH INHERIT FALSE, SET TRUE'))
        self.provision()
        with self.as_role():
            validate_runtime_permissions(self.connection)

    def test_admin_option_can_restore_escalating_membership_and_is_rejected(self):
        self.provision()
        elevated = self.new_role("CREATEROLE")
        self.connection.execute(text(f'GRANT "{elevated}" TO "{self.role}" WITH ADMIN TRUE, INHERIT FALSE, SET FALSE'))
        self.rejects_validation()

    def test_security_definer_entrypoint_in_managed_schema_is_rejected(self):
        self.provision()
        self.connection.execute(text("""
            CREATE FUNCTION control_plane.acl_security_definer() RETURNS integer
            LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'
        """))
        self.rejects_validation()

    def test_unknown_managed_table_is_not_automatically_granted(self):
        self.connection.execute(text("CREATE TABLE control_plane.acl_unexpected(id integer)"))
        with self.assertRaises(RuntimePermissionError):
            self.provision()
        self.connection.execute(text("DROP TABLE control_plane.acl_unexpected"))


if __name__ == "__main__":
    unittest.main()
