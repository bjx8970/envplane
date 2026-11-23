"""Upgrade populated P2 schemas without assigning arbitrary template aliases."""
import unittest
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from control_plane.config import RuntimeSettings
from control_plane.migrations import P2_REVISION, P3_REVISION, check_schema, run_migrations
from tests_control_plane.p1_harness import fresh_database
from tests_control_plane.pg_harness import engine_for


class BusinessMigrationTests(unittest.TestCase):
    def test_admin_recovery_migration_preserves_existing_ssh_configuration(self):
        with fresh_database() as url:
            settings = RuntimeSettings.from_env({"CONTROL_PLANE_DATABASE_URL": url})
            run_migrations(settings, P3_REVISION)
            db = engine_for(url)
            self.addCleanup(db.dispose)
            with db.begin() as connection:
                instance = connection.scalar(text("""
                    INSERT INTO control_plane.plugin_instances(plugin_key,instance_alias)
                    VALUES ('ssh','old-ssh') RETURNING id
                """))
                connection.execute(text("""
                    INSERT INTO control_plane.plugin_instance_versions
                        (instance_id,revision,configuration,plugin_version,code_digest)
                    VALUES (:instance,1,'{"data":{"marker":"old"},"allowed_secret_refs":[]}'::jsonb,
                            '1.0.0',repeat('a',64))
                """), {"instance": instance})
                connection.execute(text("""
                    UPDATE control_plane.plugin_instances SET configuration_revision=1 WHERE id=:instance
                """), {"instance": instance})
            run_migrations(settings)
            with db.connect() as connection:
                check_schema(connection)
                version = connection.execute(text("""
                    SELECT i.configuration_revision,v.configuration,v.plugin_version,v.code_digest
                    FROM control_plane.plugin_instances i
                    JOIN control_plane.plugin_instance_versions v
                      ON v.instance_id=i.id AND v.revision=i.configuration_revision
                    WHERE i.id=:instance
                """), {"instance": instance}).one()
                self.assertEqual(tuple(version), (1, {"data": {"marker": "old"}, "allowed_secret_refs": []},
                                                  "1.0.0", "a" * 64))

    def test_upgrade_keeps_legacy_instance_and_fixes_alias_on_first_bind(self):
        with fresh_database() as url:
            settings = RuntimeSettings.from_env({'CONTROL_PLANE_DATABASE_URL': url})
            run_migrations(settings, P2_REVISION)
            db = engine_for(url)
            self.addCleanup(db.dispose)
            with db.begin() as connection:
                identity = connection.scalar(text(
                    "INSERT INTO control_plane.plugin_instances(plugin_key) VALUES ('ssh') RETURNING id"))
            run_migrations(settings)
            with db.begin() as connection:
                check_schema(connection)
                self.assertIsNone(connection.scalar(text(
                    "SELECT instance_alias FROM control_plane.plugin_instances WHERE id=:id"), {'id': identity}))
                connection.execute(text(
                    "UPDATE control_plane.plugin_instances SET instance_alias='ssh-lab' WHERE id=:id"), {'id': identity})
            for sql, args in (
                    ("UPDATE control_plane.plugin_instances SET instance_alias=NULL WHERE id=:id", {'id': identity}),
                    ("INSERT INTO control_plane.plugin_instances(plugin_key,instance_alias) VALUES ('ssh',:alias)",
                     {'alias': 'ssh-lab'}),
                    ("INSERT INTO control_plane.plugin_instances(plugin_key,instance_alias) VALUES ('ssh',:alias)",
                     {'alias': str(uuid4())})):
                with self.subTest(args=args), self.assertRaises(DBAPIError), db.begin() as connection:
                    connection.execute(text(sql), args)
