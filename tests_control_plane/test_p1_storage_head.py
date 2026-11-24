from concurrent.futures import ThreadPoolExecutor
import threading
import unittest
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from control_plane.config import COORDINATOR_LOCK_KEY, RuntimeSettings
from control_plane.coordination import CoordinatorLease
from control_plane.persistence import StorageConflict, write_storage
from tests_control_plane.p1_harness import migrated_database
from tests_control_plane.pg_harness import engine_for


def instance(connection):
    return connection.scalar(text(
        "INSERT INTO control_plane.plugin_instances(plugin_key,instance_alias) VALUES ('fake',:alias) RETURNING id"
    ), {"alias": "test-" + uuid4().hex})


def history(connection, instance_id, key="hosts", *, version=1, tombstone=False):
    revision = connection.scalar(text("""
        UPDATE control_plane.plugin_instances SET namespace_revision=namespace_revision+1
        WHERE id=:instance RETURNING namespace_revision
    """), {"instance": instance_id})
    return connection.scalar(text("""
        INSERT INTO control_plane.plugin_storage_versions
          (instance_id,key,version,namespace_revision,value,is_tombstone)
        VALUES (:instance,:key,:version,:revision,
                CASE WHEN :deleted THEN NULL ELSE '{}'::jsonb END,:deleted)
        RETURNING id
    """), {"instance": instance_id, "key": key, "version": version,
           "revision": revision, "deleted": tombstone})


def set_head(connection, instance_id, version_id, key="hosts"):
    connection.execute(text("""
        INSERT INTO control_plane.plugin_storage_heads(instance_id,key,version_id)
        VALUES (:instance,:key,:version)
        ON CONFLICT(instance_id,key) DO UPDATE SET version_id=EXCLUDED.version_id
    """), {"instance": instance_id, "key": key, "version": version_id})


class StorageHeadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.url = cls.enterClassContext(migrated_database())
        cls.engine = engine_for(cls.url)
        cls.addClassCleanup(cls.engine.dispose)
        cls.lease = CoordinatorLease(cls.engine, COORDINATOR_LOCK_KEY, lease_seconds=300)
        if not cls.lease.acquire():
            raise AssertionError("isolated test coordinator was not acquired")
        cls.addClassCleanup(cls.lease.release)

    def setUp(self):
        self.assertTrue(self.lease.verify())

    def rejects(self, connection, sql, parameters=None):
        with self.assertRaises(DBAPIError):
            with connection.begin_nested():
                connection.execute(text(sql), parameters or {})
                connection.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))

    def test_direct_update_cannot_roll_head_back(self):
        with self.lease.fenced_transaction() as conn:
            plugin = instance(conn)
            first = write_storage(conn, plugin, "hosts", {"version": 1})
            second = write_storage(conn, plugin, "hosts", {"version": 2}, expected_version=first.id)
            self.rejects(conn, """
                UPDATE control_plane.plugin_storage_heads SET version_id=:version
                WHERE instance_id=:instance AND key='hosts'
            """, {"instance": plugin, "version": first.id})
            self.assertEqual(conn.scalar(text("""
                SELECT version_id FROM control_plane.plugin_storage_heads WHERE instance_id=:instance
            """), {"instance": plugin}), second.id)

    def test_delete_and_reinsert_cannot_reset_head_or_cas(self):
        with self.lease.fenced_transaction() as conn:
            plugin = instance(conn)
            original = write_storage(conn, plugin, "hosts", {})
            self.rejects(conn, """
                DELETE FROM control_plane.plugin_storage_heads WHERE instance_id=:instance
            """, {"instance": plugin})
            with self.assertRaises(StorageConflict):
                write_storage(conn, plugin, "hosts", {"reset": True})
            self.rejects(conn, """
                WITH removed AS (
                    DELETE FROM control_plane.plugin_storage_heads
                    WHERE instance_id=:instance RETURNING instance_id,key
                )
                INSERT INTO control_plane.plugin_storage_heads(instance_id,key,version_id)
                SELECT instance_id,key,:version FROM removed
            """, {"instance": plugin, "version": original.id})

    def test_head_instance_and_key_are_immutable_even_with_matching_history(self):
        with self.lease.fenced_transaction() as conn:
            plugin = instance(conn)
            other = instance(conn)
            write_storage(conn, plugin, "hosts", {})
            other_history = history(conn, other)
            self.rejects(conn, """
                UPDATE control_plane.plugin_storage_heads
                SET instance_id=:other,version_id=:version WHERE instance_id=:instance
            """, {"instance": plugin, "other": other, "version": other_history})
            # Complete the other valid history before transaction end.
            set_head(conn, other, other_history)
            renamed_history = history(conn, plugin, "renamed")
            self.rejects(conn, """
                UPDATE control_plane.plugin_storage_heads
                SET key='renamed',version_id=:version WHERE instance_id=:instance AND key='hosts'
            """, {"instance": plugin, "version": renamed_history})
            set_head(conn, plugin, renamed_history, "renamed")

    def test_first_insert_cannot_select_an_old_history_version(self):
        with self.lease.fenced_transaction() as conn:
            plugin = instance(conn)
            first = history(conn, plugin)
            latest = history(conn, plugin, version=2)
            self.rejects(conn, """
                INSERT INTO control_plane.plugin_storage_heads(instance_id,key,version_id)
                VALUES (:instance,'hosts',:version)
            """, {"instance": plugin, "version": first})
            set_head(conn, plugin, latest)

    def test_head_must_match_history_scope(self):
        with self.lease.fenced_transaction() as conn:
            plugin = instance(conn)
            other = instance(conn)
            foreign = write_storage(conn, other, "hosts", {})
            self.rejects(conn, """
                INSERT INTO control_plane.plugin_storage_heads(instance_id,key,version_id)
                VALUES (:instance,'hosts',:version)
            """, {"instance": plugin, "version": foreign.id})

    def test_same_pointer_is_idempotent_and_tombstone_recreation_advances(self):
        with self.lease.fenced_transaction() as conn:
            plugin = instance(conn)
            first = write_storage(conn, plugin, "hosts", {"value": "first"})
            set_head(conn, plugin, first.id)
            tombstone = write_storage(conn, plugin, "hosts", None,
                                      expected_version=first.id, delete=True)
            recreated = write_storage(conn, plugin, "hosts", {"value": "recreated"},
                                      expected_version=tombstone.id)
            self.assertEqual((first.version, tombstone.version, recreated.version), (1, 2, 3))
            self.rejects(conn, """
                UPDATE control_plane.plugin_storage_heads SET version_id=:version
                WHERE instance_id=:instance
            """, {"instance": plugin, "version": tombstone.id})
            self.assertEqual(conn.scalar(text("""
                SELECT count(*) FROM control_plane.plugin_storage_versions WHERE instance_id=:instance
            """), {"instance": plugin}), 3)

    def test_history_without_a_head_cannot_commit(self):
        with self.assertRaises(DBAPIError):
            with self.lease.fenced_transaction() as conn:
                plugin = instance(conn)
                history(conn, plugin)
        with self.engine.connect() as conn:
            self.assertIsNone(conn.scalar(text("""
                SELECT id FROM control_plane.plugin_instances WHERE id=:instance
            """), {"instance": plugin}))

    def test_new_history_cannot_commit_with_the_previous_head(self):
        with self.lease.fenced_transaction() as conn:
            plugin = instance(conn)
            original = write_storage(conn, plugin, "hosts", {})
        with self.assertRaises(DBAPIError):
            with self.lease.fenced_transaction() as conn:
                history(conn, plugin, version=2)
        with self.engine.connect() as conn:
            self.assertEqual(conn.scalar(text("""
                SELECT version_id FROM control_plane.plugin_storage_heads WHERE instance_id=:instance
            """), {"instance": plugin}), original.id)
            self.assertEqual(conn.scalar(text("""
                SELECT count(*) FROM control_plane.plugin_storage_versions WHERE instance_id=:instance
            """), {"instance": plugin}), 1)

    def test_concurrent_cas_has_one_winner_and_then_advances_normally(self):
        with self.lease.fenced_transaction() as conn:
            plugin = instance(conn)
            original = write_storage(conn, plugin, "hosts", {})
        start = threading.Barrier(2)

        def write(index):
            start.wait(timeout=5)
            try:
                with self.lease.fenced_transaction() as conn:
                    result = write_storage(conn, plugin, "hosts", {"writer": index},
                                           expected_version=original.id)
                return result
            except StorageConflict:
                return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(write, (1, 2)))
        winners = [result for result in results if result is not None]
        self.assertEqual(len(winners), 1)
        self.assertEqual(winners[0].version, 2)
        with self.lease.fenced_transaction() as conn:
            following = write_storage(conn, plugin, "hosts", {}, expected_version=winners[0].id)
            self.assertEqual(following.version, 3)

    def test_head_update_does_not_take_instance_lock_in_reverse_order(self):
        with self.lease.fenced_transaction() as conn:
            plugin = instance(conn)
            original = write_storage(conn, plugin, "hosts", {})
        head_locked = threading.Event()
        history_inserted = threading.Event()

        def hold_head():
            with self.engine.begin() as conn:
                conn.execute(text("SET LOCAL lock_timeout='4s'"))
                conn.execute(text("""
                    SELECT version_id FROM control_plane.plugin_storage_heads
                    WHERE instance_id=:instance FOR UPDATE
                """), {"instance": plugin})
                head_locked.set()
                if not history_inserted.wait(5):
                    raise AssertionError("writer did not reach history insert")
                # The writer now owns the instance row and needs this head row.
                # This idempotent direct UPDATE must not request that instance row.
                conn.execute(text("""
                    UPDATE control_plane.plugin_storage_heads SET version_id=:version
                    WHERE instance_id=:instance
                """), {"instance": plugin, "version": original.id})

        def advance():
            if not head_locked.wait(5):
                raise AssertionError("head holder did not acquire its row")
            with self.lease.fenced_transaction() as conn:
                conn.execute(text("SET LOCAL lock_timeout='4s'"))
                newest = history(conn, plugin, version=2)
                history_inserted.set()
                set_head(conn, plugin, newest)
            return newest

        with ThreadPoolExecutor(max_workers=2) as pool:
            holder = pool.submit(hold_head)
            writer = pool.submit(advance)
            holder.result(timeout=10)
            newest = writer.result(timeout=10)
        with self.engine.connect() as conn:
            self.assertEqual(conn.scalar(text("""
                SELECT version_id FROM control_plane.plugin_storage_heads WHERE instance_id=:instance
            """), {"instance": plugin}), newest)
