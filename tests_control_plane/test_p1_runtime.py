from concurrent.futures import ThreadPoolExecutor
import os
import subprocess
import sys
import time
import unittest
from unittest import mock
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.engine import make_url

from control_plane.config import COORDINATOR_LOCK_KEY, ConfigurationError, RuntimeSettings
from control_plane.coordination import CoordinatorLease, LeaseLost
from control_plane.migrations import (
    HEAD_REVISION, MigrationConflict, MigrationError, check_schema, run_migrations,
)
from tests_control_plane.p1_harness import fresh_database, migrated_database
from tests_control_plane.pg_harness import ROOT, engine_for, run_cli_once, terminate_backend


def settings_for(url):
    return RuntimeSettings.from_env({"CONTROL_PLANE_DATABASE_URL": url})


def database_command(url, *args):
    return subprocess.run(
        [sys.executable, "-B", "-m", "control_plane", "db", *args],
        cwd=ROOT, env={**os.environ, "CONTROL_PLANE_DATABASE_URL": url},
        capture_output=True, text=True, timeout=130,
    )


class MigrationTests(unittest.TestCase):
    def test_empty_database_refuses_start_without_creating_schema(self):
        with fresh_database() as url:
            code, out, err = run_cli_once(url)
            self.assertEqual(code, 4, out + err)
            self.assertNotIn('"event": "ready"', out)
            self.assertIn("db upgrade", err)
            engine = engine_for(url)
            try:
                with engine.connect() as conn:
                    self.assertIsNone(conn.scalar(text("SELECT to_regnamespace('control_plane')")))
            finally:
                engine.dispose()

    def test_upgrade_repeat_downgrade_and_upgrade(self):
        with fresh_database() as url:
            settings = settings_for(url)
            run_migrations(settings)
            run_migrations(settings)
            engine = engine_for(url)
            try:
                with engine.connect() as conn:
                    check_schema(conn)
                run_migrations(settings, "base", upgrade=False)
                with engine.connect() as conn:
                    self.assertIsNone(conn.scalar(text("SELECT to_regnamespace('control_plane')")))
                run_migrations(settings)
                with engine.connect() as conn:
                    check_schema(conn)
            finally:
                engine.dispose()

    def test_standard_alembic_command_uses_guarded_runner(self):
        with fresh_database() as url:
            result = subprocess.run(
                [sys.executable, "-B", "-m", "alembic", "upgrade", "head"], cwd=ROOT,
                env={**os.environ, "CONTROL_PLANE_DATABASE_URL": url},
                capture_output=True, text=True, timeout=130,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            engine = engine_for(url)
            try:
                with engine.connect() as conn:
                    check_schema(conn)
                result = subprocess.run(
                    [sys.executable, "-B", "-m", "alembic", "downgrade", "base"], cwd=ROOT,
                    env={**os.environ, "CONTROL_PLANE_DATABASE_URL": url},
                    capture_output=True, text=True, timeout=130,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                with engine.connect() as conn:
                    self.assertIsNone(conn.scalar(text("SELECT to_regnamespace('control_plane')")))
            finally:
                engine.dispose()

    def test_failure_rolls_back_schema_ddl_and_version(self):
        with fresh_database() as url:
            def fail(config, target):
                config.attributes["connection"].execute(text("CREATE TABLE control_plane.partial_failure(id int)"))
                raise RuntimeError("sentinel-migration-password")
            with mock.patch("alembic.command.upgrade", side_effect=fail):
                with self.assertRaises(MigrationError) as raised:
                    run_migrations(settings_for(url))
            self.assertNotIn("sentinel", str(raised.exception))
            engine = engine_for(url)
            try:
                with engine.connect() as conn:
                    self.assertIsNone(conn.scalar(text("SELECT to_regnamespace('control_plane')")))
            finally:
                engine.dispose()

    def test_interruption_rolls_back(self):
        with fresh_database() as url:
            def interrupt(config, target):
                config.attributes["connection"].execute(text("CREATE TABLE control_plane.partial_failure(id int)"))
                raise KeyboardInterrupt()
            with mock.patch("alembic.command.upgrade", side_effect=interrupt):
                with self.assertRaises(KeyboardInterrupt):
                    run_migrations(settings_for(url))
            engine = engine_for(url)
            try:
                with engine.connect() as conn:
                    self.assertIsNone(conn.scalar(text("SELECT to_regnamespace('control_plane')")))
            finally:
                engine.dispose()

    def test_unrelated_database_is_rejected_without_modification(self):
        with fresh_database() as url:
            engine = engine_for(url)
            try:
                with engine.begin() as conn:
                    conn.execute(text("CREATE TABLE public.legacy_sentinel(id int)"))
                with self.assertRaises(MigrationError):
                    run_migrations(settings_for(url))
                with engine.connect() as conn:
                    self.assertIsNotNone(conn.scalar(text("SELECT to_regclass('public.legacy_sentinel')")))
                    self.assertIsNone(conn.scalar(text("SELECT to_regnamespace('control_plane')")))
            finally:
                engine.dispose()

    def test_unknown_revision_refuses_start(self):
        with migrated_database() as url:
            engine = engine_for(url)
            try:
                with engine.begin() as conn:
                    conn.execute(text("UPDATE control_plane.alembic_version SET version_num='future_revision'"))
                code, out, err = run_cli_once(url)
                self.assertEqual(code, 4, out + err)
                self.assertIn("revision", err)
                self.assertNotIn('"event": "ready"', out)
            finally:
                engine.dispose()

    def test_missing_domain_table_refuses_start(self):
        with migrated_database() as url:
            engine = engine_for(url)
            try:
                with engine.begin() as conn:
                    conn.execute(text("DROP TABLE control_plane.audit_events"))
                code, out, err = run_cli_once(url)
                self.assertEqual(code, 4, out + err)
                self.assertIn("incomplete", err)
                self.assertNotIn('"event": "ready"', out)
            finally:
                engine.dispose()

    def test_migration_is_mutually_exclusive_with_coordinator(self):
        with migrated_database() as url:
            engine = engine_for(url)
            lease = CoordinatorLease(engine, COORDINATOR_LOCK_KEY)
            try:
                self.assertTrue(lease.acquire())
                with self.assertRaises(MigrationConflict):
                    run_migrations(settings_for(url))
                self.assertTrue(lease.verify())
            finally:
                lease.release()
                engine.dispose()

    def test_parallel_upgrades_are_serialized(self):
        with fresh_database() as url:
            def upgrade(_):
                try:
                    run_migrations(settings_for(url))
                    return "ok"
                except MigrationConflict:
                    return "busy"
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(upgrade, range(2)))
            self.assertIn("ok", results)
            self.assertTrue(set(results) <= {"ok", "busy"})
            engine = engine_for(url)
            try:
                with engine.connect() as conn:
                    check_schema(conn)
            finally:
                engine.dispose()

    def test_cli_upgrade_and_nonempty_downgrade_rejection(self):
        with fresh_database() as url:
            result = database_command(url, "upgrade")
            self.assertEqual(result.returncode, 0, result.stderr)
            engine = engine_for(url)
            try:
                with engine.begin() as conn:
                    conn.execute(text("INSERT INTO control_plane.users(username,password_hash,role) VALUES ('keep','hash','admin')"))
                result = database_command(url, "downgrade")
                self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
                with engine.connect() as conn:
                    check_schema(conn)
                    self.assertEqual(conn.scalar(text("SELECT count(*) FROM control_plane.users")), 1)
            finally:
                engine.dispose()

    def test_cli_bad_url_does_not_leak_secrets(self):
        sentinel = "p1-password-sentinel"
        result = database_command(f"postgresql://user:{sentinel}@127.0.0.1:1/control_plane_test_bad", "upgrade")
        self.assertEqual(result.returncode, 4)
        self.assertNotIn(sentinel, result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertNotIn("postgresql://", result.stderr)

    def test_migration_without_create_permission_is_atomic(self):
        with fresh_database() as url:
            role = f"p1_role_{uuid4().hex}"
            engine = engine_for(url)
            try:
                with engine.begin() as conn:
                    conn.execute(text(f'CREATE ROLE "{role}" LOGIN'))
                restricted = make_url(url).set(username=role).render_as_string(hide_password=False)
                with self.assertRaises(MigrationError):
                    run_migrations(settings_for(restricted))
                with engine.connect() as conn:
                    self.assertIsNone(conn.scalar(text("SELECT to_regnamespace('control_plane')")))
            finally:
                with engine.begin() as conn:
                    conn.execute(text(f'DROP ROLE "{role}"'))
                engine.dispose()


class PersistentLeaseTests(unittest.TestCase):
    def setUp(self):
        self.url = self.enterContext(migrated_database())
        self.engine = engine_for(self.url)
        self.addCleanup(self.engine.dispose)

    def lease(self, seconds=30):
        lease = CoordinatorLease(self.engine, COORDINATOR_LOCK_KEY, seconds)
        self.addCleanup(lease.release)
        return lease

    def expire(self):
        with self.engine.begin() as conn:
            conn.execute(text("UPDATE control_plane.coordinator_leases SET expires_at=clock_timestamp()-interval '1 second' WHERE id=1"))

    def test_owner_and_revision_survive_clean_restart(self):
        first = self.lease()
        self.assertTrue(first.acquire())
        revision = first.revision
        first.release()
        first.release()
        second = self.lease()
        self.assertTrue(second.acquire())
        self.assertNotEqual(first.owner_id, second.owner_id)
        self.assertEqual(second.revision, revision + 1)
        with self.engine.connect() as conn:
            previous = conn.scalar(text("SELECT previous_owner_id FROM control_plane.coordinator_leases WHERE id=1"))
            self.assertEqual(str(previous), str(first.owner_id))

    def test_expired_lease_cannot_be_renewed(self):
        first = self.lease()
        self.assertTrue(first.acquire())
        self.expire()
        self.assertFalse(first.verify())
        with self.assertRaises(LeaseLost):
            with first.fenced_transaction():
                self.fail("expired owner entered transaction")

    def test_waiting_renewal_cannot_revive_expired_lease(self):
        first = self.lease(seconds=1)
        self.assertTrue(first.acquire())
        pid = first.backend_pid
        with ThreadPoolExecutor(max_workers=1) as pool:
            gate = self.engine.connect()
            transaction = gate.begin()
            try:
                gate.execute(text("SELECT id FROM control_plane.coordinator_leases WHERE id=1 FOR UPDATE"))
                future = pool.submit(first.verify)
                deadline = time.monotonic() + 0.7
                observed_wait = False
                while time.monotonic() < deadline:
                    with self.engine.connect() as monitor:
                        observed_wait = monitor.scalar(text("SELECT wait_event_type='Lock' FROM pg_stat_activity WHERE pid=:pid"), {"pid": pid})
                    if observed_wait:
                        break
                    time.sleep(0.01)
                self.assertTrue(observed_wait, "renewal did not wait on the held row")
                gate.execute(text("SELECT pg_sleep(GREATEST(0,EXTRACT(EPOCH FROM expires_at-clock_timestamp()))+0.1) FROM control_plane.coordinator_leases WHERE id=1"))
            finally:
                transaction.rollback()
                gate.close()
            self.assertFalse(future.result(timeout=5))

    def test_heartbeat_checks_actual_advisory_ownership(self):
        first = self.lease()
        self.assertTrue(first.acquire())
        first._connection.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": COORDINATOR_LOCK_KEY})
        self.assertFalse(first.verify())

    def test_terminated_backend_loses_lease(self):
        first = self.lease()
        self.assertTrue(first.acquire())
        terminate_backend(self.url, first.backend_pid)
        self.assertFalse(first.verify())

    def test_live_durable_lease_prevents_early_takeover(self):
        first = self.lease()
        self.assertTrue(first.acquire())
        revision = first.revision
        first._close()
        second = self.lease()
        self.assertFalse(second.acquire())
        self.expire()
        self.assertTrue(second.acquire())
        self.assertEqual(second.revision, revision + 1)
        first.release()
        self.assertTrue(second.verify())

    def test_fence_checks_before_and_after_write(self):
        first = self.lease()
        self.assertTrue(first.acquire())
        with self.assertRaises(LeaseLost):
            with first.fenced_transaction() as conn:
                conn.execute(text("UPDATE control_plane.coordinator_leases SET revision=revision+1 WHERE id=1"))
        with self.engine.connect() as conn:
            self.assertEqual(conn.scalar(text("SELECT revision FROM control_plane.coordinator_leases WHERE id=1")), first.revision)
        self.assertTrue(first.verify())

    def test_expiry_during_transaction_rolls_back(self):
        first = self.lease()
        self.assertTrue(first.acquire())
        with self.assertRaises(LeaseLost):
            with first.fenced_transaction() as conn:
                conn.execute(text("UPDATE control_plane.coordinator_leases SET expires_at=clock_timestamp()-interval '1 second' WHERE id=1"))
        self.assertTrue(first.verify())

    def test_advisory_loss_during_transaction_rolls_back(self):
        first = self.lease()
        self.assertTrue(first.acquire())
        with self.assertRaises(LeaseLost):
            with first.fenced_transaction() as conn:
                conn.execute(text("UPDATE control_plane.coordinator_leases SET previous_owner_id=:id WHERE id=1"), {"id": uuid4()})
                first._connection.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": COORDINATOR_LOCK_KEY})
        with self.engine.connect() as conn:
            self.assertIsNone(conn.scalar(text("SELECT previous_owner_id FROM control_plane.coordinator_leases WHERE id=1")))

    def test_concurrent_acquisition_has_one_owner(self):
        leases = [self.lease(), self.lease(), self.lease()]
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(lambda lease: lease.acquire(), leases))
        self.assertEqual(results.count(True), 1)


class LeaseConfigurationTests(unittest.TestCase):
    def test_invalid_and_inconsistent_lease_budget_rejected(self):
        for value in ("nan", "0", "3601", "5"):
            with self.subTest(value=value), self.assertRaises(ConfigurationError):
                RuntimeSettings.from_env({
                    "CONTROL_PLANE_DATABASE_URL": "postgresql://u:p@127.0.0.1/control_plane_test_config",
                    "CONTROL_PLANE_LEASE_SECONDS": value,
                })
