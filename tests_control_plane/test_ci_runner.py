import io
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import MagicMock, Mock, patch

from scripts import run_ci_tests as runner


class StrictResultTests(unittest.TestCase):
    def run_inner(self, case):
        output = io.StringIO()
        suite = unittest.TestSuite([unittest.FunctionTestCase(case)])
        return runner.run_suite(suite, stream=output), output.getvalue()

    def test_passed_test_succeeds(self):
        code, output = self.run_inner(lambda: None)
        self.assertEqual(code, 0)
        self.assertIn("1 tests, no skips", output)

    def test_zero_discovered_tests_fails(self):
        output = io.StringIO()
        self.assertEqual(runner.run_suite(unittest.TestSuite(), stream=output), 1)
        self.assertIn("no tests discovered", output.getvalue())

    def test_skipped_test_fails(self):
        def skipped():
            raise unittest.SkipTest("synthetic skip")

        code, output = self.run_inner(skipped)
        self.assertEqual(code, 1)
        self.assertIn("skipped=1", output)

    def test_skipped_subtest_fails(self):
        class WithSubtest(unittest.TestCase):
            def runTest(self):
                with self.subTest(part="skipped"):
                    self.skipTest("synthetic skip")

        output = io.StringIO()
        self.assertEqual(
            runner.run_suite(unittest.TestSuite([WithSubtest()]), stream=output), 1
        )
        self.assertIn("skipped=1", output.getvalue())

    def test_class_fixture_skip_fails(self):
        class WithSkippedFixture(unittest.TestCase):
            @classmethod
            def setUpClass(cls):
                raise unittest.SkipTest("synthetic class skip")

            def runTest(self):
                raise AssertionError("must not run")

        output = io.StringIO()
        self.assertEqual(
            runner.run_suite(
                unittest.TestSuite([WithSkippedFixture()]), stream=output
            ),
            1,
        )
        self.assertIn("started=0", output.getvalue())

    def test_failure_and_error_fail(self):
        for exception in (AssertionError("synthetic failure"), ValueError("error")):
            with self.subTest(exception=type(exception).__name__):
                def failing():
                    raise exception

                code, _ = self.run_inner(failing)
                self.assertEqual(code, 1)

    def test_nonzero_system_exit_in_test_fails(self):
        def exits():
            sys.exit(7)

        code, _ = self.run_inner(exits)
        self.assertEqual(code, 1)

    def test_expected_failure_is_not_a_passing_test(self):
        class WithExpectedFailure(unittest.TestCase):
            @unittest.expectedFailure
            def runTest(self):
                self.fail("synthetic expected failure")

        output = io.StringIO()
        self.assertEqual(
            runner.run_suite(
                unittest.TestSuite([WithExpectedFailure()]), stream=output
            ),
            1,
        )
        self.assertIn("expected_failures=1", output.getvalue())

    def test_unexecuted_discovered_test_fails(self):
        class NotExecuted(unittest.TestSuite):
            def run(self, result, debug=False):
                return result

        output = io.StringIO()
        suite = NotExecuted([unittest.FunctionTestCase(lambda: None)])
        self.assertEqual(runner.run_suite(suite, stream=output), 1)
        self.assertIn("discovered=1, started=0, completed=0", output.getvalue())

    def test_started_but_unfinished_test_fails(self):
        class NotCompleted(unittest.TestCase):
            def run(self, result=None):
                result.startTest(self)
                result.addSuccess(self)
                return result

        output = io.StringIO()
        self.assertEqual(
            runner.run_suite(unittest.TestSuite([NotCompleted()]), stream=output), 1
        )
        self.assertIn("started=1, completed=0", output.getvalue())


class DiscoveryTests(unittest.TestCase):
    def test_discovers_control_plane_suite_once(self):
        with patch.object(runner.unittest, "TestLoader") as loader_class:
            loader = loader_class.return_value
            loader.errors = []
            loader.discover.return_value = unittest.TestSuite()
            self.assertIs(runner.discover_tests(), loader.discover.return_value)
        loader.discover.assert_called_once_with(
            start_dir=str(runner.ROOT / "tests_control_plane"),
            pattern="test*.py",
            top_level_dir=str(runner.ROOT),
        )

    def test_discovery_import_error_fails(self):
        with patch.object(runner.unittest, "TestLoader") as loader_class:
            loader = loader_class.return_value
            loader.errors = ["synthetic import error"]
            loader.discover.return_value = unittest.TestSuite()
            with self.assertRaises(RuntimeError):
                runner.discover_tests()

    def test_premature_discovery_exit_fails_including_exit_zero(self):
        for code in (0, 3):
            with self.subTest(code=code), patch.object(
                runner, "preflight_database"
            ), patch.object(runner, "discover_tests", side_effect=SystemExit(code)):
                self.assertEqual(runner.main([], stream=io.StringIO()), 1)

    def test_preflight_failure_prevents_discovery(self):
        with patch.object(
            runner, "preflight_database", side_effect=runner.PreflightError("safe")
        ), patch.object(runner, "discover_tests") as discover:
            self.assertEqual(runner.main([], stream=io.StringIO()), 2)
        discover.assert_not_called()


class DatabasePreflightTests(unittest.TestCase):
    URL = (
        "postgresql+pg8000://postgres:ci-secret-sentinel@127.0.0.1/"
        "control_plane_test_runner"
    )

    def preflight(self, url=None, *, version="170001", error=None, dialect="postgresql"):
        engine = MagicMock()
        engine.dialect.name = dialect
        connection = engine.connect.return_value.__enter__.return_value = Mock()
        connection.execute.return_value.scalar_one.return_value = version
        if error is not None:
            engine.connect.side_effect = error
        env = {} if url is None else {"CONTROL_PLANE_TEST_DATABASE_URL": url}
        with patch.dict(os.environ, env, clear=True), patch(
            "tests_control_plane.pg_harness.engine_for", return_value=engine
        ) as factory:
            try:
                runner.preflight_database()
            finally:
                self.assertEqual(os.environ["CONTROL_PLANE_REQUIRE_TEST_DATABASE"], "1")
        return engine, factory

    def test_reachable_postgresql_17_succeeds_and_disposes(self):
        engine, factory = self.preflight(self.URL)
        factory.assert_called_once_with(self.URL)
        engine.dispose.assert_called_once_with()

    def test_newer_postgresql_is_supported(self):
        self.preflight(self.URL, version="180000")

    def test_bare_postgresql_driver_is_normalized(self):
        _, factory = self.preflight(self.URL.replace("postgresql+pg8000:", "postgresql:"))
        factory.assert_called_once_with(self.URL)

    def test_missing_unsafe_or_unsupported_urls_fail_before_connect(self):
        invalid = (
            None,
            "invalid-ci-secret-sentinel",
            "sqlite:///control_plane_test_runner",
            self.URL.replace("127.0.0.1", "db.example.com"),
            self.URL.replace("control_plane_test_runner", "production"),
            self.URL + "?host=192.0.2.1",
            self.URL.replace("postgresql+pg8000:", "postgresql+psycopg:"),
            "postgresql+pg8000:///control_plane_test_runner",
        )
        for url in invalid:
            with self.subTest(url_index=invalid.index(url)), patch(
                "tests_control_plane.pg_harness.engine_for"
            ) as factory, patch.dict(
                os.environ,
                {} if url is None else {"CONTROL_PLANE_TEST_DATABASE_URL": url},
                clear=True,
            ):
                with self.assertRaises(runner.PreflightError) as caught:
                    runner.preflight_database()
                self.assertNotIn("ci-secret-sentinel", str(caught.exception))
                factory.assert_not_called()

    def test_postgresql_16_and_non_postgresql_dialect_are_rejected(self):
        for kwargs in ({"version": "160010"}, {"dialect": "sqlite"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(runner.PreflightError):
                self.preflight(self.URL, **kwargs)

    def test_connection_exception_and_url_are_not_reported(self):
        engine = Mock()
        engine.dialect.name = "postgresql"
        engine.connect.side_effect = RuntimeError("connection failed: " + self.URL)
        output = io.StringIO()
        with patch.dict(
            os.environ, {"CONTROL_PLANE_TEST_DATABASE_URL": self.URL}, clear=True
        ), patch("tests_control_plane.pg_harness.engine_for", return_value=engine):
            self.assertEqual(runner.main([], stream=output), 2)
        self.assertNotIn("ci-secret-sentinel", output.getvalue())
        self.assertNotIn(self.URL, output.getvalue())
        self.assertIn("reachable PostgreSQL >=17", output.getvalue())
        engine.dispose.assert_called_once_with()

    def test_command_line_missing_database_exits_nonzero_without_skip(self):
        env = os.environ.copy()
        env.pop("CONTROL_PLANE_TEST_DATABASE_URL", None)
        result = subprocess.run(
            [sys.executable, "-B", str(Path(runner.__file__).resolve())],
            cwd=str(runner.ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("skipped", result.stderr.lower())
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
