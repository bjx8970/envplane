"""The initial schema requires stable plugin aliases."""
import unittest
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from control_plane.business import instance_binding
from control_plane.plugins.sdk import ReferenceUnavailable
from tests_control_plane.p1_harness import migrated_database
from tests_control_plane.pg_harness import engine_for


class PluginAliasTests(unittest.TestCase):
    def test_alias_is_required_immutable_unique_and_used_for_template_binding(self):
        with migrated_database() as url:
            db = engine_for(url)
            self.addCleanup(db.dispose)
            with db.begin() as connection:
                identity = connection.scalar(text("""
                    INSERT INTO control_plane.plugin_instances(plugin_key,instance_alias)
                    VALUES ('ssh','ssh-lab') RETURNING id
                """))
                self.assertEqual(instance_binding(connection, "ssh-lab"), (str(identity), "ssh"))
                with self.assertRaises(ReferenceUnavailable):
                    instance_binding(connection, str(identity))
            for sql, args in (
                    ("INSERT INTO control_plane.plugin_instances(plugin_key) VALUES ('ssh')", {}),
                    ("UPDATE control_plane.plugin_instances SET instance_alias='renamed' WHERE id=:id", {'id': identity}),
                    ("INSERT INTO control_plane.plugin_instances(plugin_key,instance_alias) VALUES ('ssh',:alias)",
                     {'alias': 'ssh-lab'}),
                    ("INSERT INTO control_plane.plugin_instances(plugin_key,instance_alias) VALUES ('ssh',:alias)",
                     {'alias': str(uuid4())})):
                with self.subTest(args=args), self.assertRaises(DBAPIError), db.begin() as connection:
                    connection.execute(text(sql), args)
