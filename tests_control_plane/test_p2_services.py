"""Service composition, deployment failure and explicit lifecycle regression."""
import base64
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from control_plane.config import ConfigurationError, RuntimeSettings
from control_plane.plugins.capacity import CapacitySettings
from control_plane.plugins.sdk import Deadline
from control_plane.runtime import ControlPlaneRuntime, LeadershipLost, RuntimeInitializationFailed
from control_plane.services import load_deployment
from tests_control_plane.p1_harness import runtime_database


def deployment(directory, **changes):
    data = {'schema_version': 1, 'plugin_directory': 'packages', 'required': [], 'optional': [], 'max_pending_jobs': 100,
            'capacity': asdict(CapacitySettings(ordinary_workers=1, control_workers=1,
                              session_workers=1, queue_limit=2, instance_limit=1,
                              shutdown_grace_seconds=0.1))}
    data.update(changes)
    path = Path(directory) / 'runtime.json'
    path.write_text(json.dumps(data), encoding='utf-8')
    return str(path)


class DeploymentTests(unittest.TestCase):
    def test_explicit_finite_deployment_and_relative_package_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = deployment(directory)
            data, root, limits = load_deployment(path)
            self.assertEqual(root, Path(directory).resolve() / 'packages')
            self.assertEqual(limits.queue_limit, 2)
            self.assertEqual(data['required'], [])

    def test_rejects_unknown_duplicate_unbounded_and_overlapping_config(self):
        with tempfile.TemporaryDirectory() as directory:
            values = [dict(unexpected=True), dict(required=['a'], optional=['a']),
                      dict(required=['a', 'a']), dict(capacity={}), dict(schema_version=999),
                      dict(capacity={**asdict(CapacitySettings()), 'ordinary_workers': 0})]
            for changes in values:
                with self.subTest(changes=changes):
                    with self.assertRaises(ConfigurationError):
                        load_deployment(deployment(directory, **changes))

    def test_config_load_errors_do_not_include_file_content(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bad.yaml'
            path.write_text('password: sentinel-secret\npassword: duplicate', encoding='utf-8')
            with self.assertRaises(ConfigurationError) as raised:
                load_deployment(path)
            self.assertNotIn('sentinel-secret', str(raised.exception))


class ServiceLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, cls.url = cls.enterClassContext(runtime_database())

    def settings(self, path=None):
        return RuntimeSettings.from_env({'CONTROL_PLANE_DATABASE_URL': self.url,
                'CONTROL_PLANE_RUNTIME_CONFIG': path or ''})

    def environment(self):
        return patch.dict(os.environ, {'CONTROL_PLANE_SECRET_KEYRING': json.dumps({'test': base64.b64encode(os.urandom(32)).decode()}),
                                      'CONTROL_PLANE_SECRET_ACTIVE_KEY_ID': 'test'})

    def test_foundation_only_does_not_invent_secret_keys_or_enable_business(self):
        runtime = ControlPlaneRuntime(self.settings())
        self.addCleanup(runtime.stop)
        with patch.dict(os.environ, {'CONTROL_PLANE_SECRET_KEYRING': '', 'CONTROL_PLANE_SECRET_ACTIVE_KEY_ID': ''}):
            runtime.start()
        self.assertIsNone(runtime.services.secrets)
        self.assertIsNone(runtime.services.capacity)
        self.assertFalse(runtime.health()['services']['execution_enabled'])
        self.assertEqual(runtime.health()['services']['mode'], 'foundation_only')
        runtime.poll()

    def test_explicit_services_start_tick_stop_and_revoke_before_grace(self):
        with tempfile.TemporaryDirectory() as directory, self.environment():
            events = []
            class Driver:
                def start(self): events.append('start')
                def tick(self): events.append('tick')
                def stop(self): events.append('stop')
            runtime = ControlPlaneRuntime(self.settings(deployment(directory)), driver_factory=lambda _: Driver())
            self.addCleanup(runtime.stop)
            runtime.start()
            self.assertTrue(runtime.services.capacity.snapshot()['ready'])
            runtime.poll()
            self.assertEqual(events[:2], ['start', 'tick'])
            services = runtime.services
            original = services.capacity.stop
            def verify_stop(*args, **kwargs):
                with self.assertRaises(LeadershipLost):
                    runtime.fenced_transaction()
                return original(*args, **kwargs)
            with patch.object(services.capacity, 'stop', side_effect=verify_stop):
                runtime.stop()
            self.assertIn('stop', events)
            self.assertFalse(runtime.health()['ready'])
            self.assertEqual(services.capacity.snapshot()['retained_calls'], 0)

    def test_required_failure_releases_coordinator_and_is_sanitized(self):
        with tempfile.TemporaryDirectory() as directory, self.environment():
            runtime = ControlPlaneRuntime(self.settings(deployment(directory, required=['missing'])))
            with self.assertRaises(RuntimeInitializationFailed) as raised:
                runtime.start()
            self.assertNotIn(self.url, str(raised.exception))
            replacement = ControlPlaneRuntime(self.settings())
            self.addCleanup(replacement.stop)
            replacement.start()

    def test_optional_failure_reports_degraded_without_discarding_data(self):
        with tempfile.TemporaryDirectory() as directory, self.environment():
            runtime = ControlPlaneRuntime(self.settings(deployment(directory, optional=['missing'])))
            self.addCleanup(runtime.stop)
            runtime.start()
            self.assertTrue(runtime.health()['degraded'])
            self.assertIn('missing', runtime.health()['services']['optional_plugins'])
            self.assertTrue(runtime.health()['services']['execution_enabled'])
            runtime.poll()

    def test_no_keyring_fails_closed_without_starting_threads(self):
        with tempfile.TemporaryDirectory() as directory:
            before = {v.ident for v in threading.enumerate()}
            runtime = ControlPlaneRuntime(self.settings(deployment(directory)))
            with patch.dict(os.environ, {'CONTROL_PLANE_SECRET_KEYRING': '', 'CONTROL_PLANE_SECRET_ACTIVE_KEY_ID': ''}):
                with self.assertRaises(RuntimeInitializationFailed):
                    runtime.start()
            self.assertEqual(before, {v.ident for v in threading.enumerate()})
