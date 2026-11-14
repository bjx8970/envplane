#!/usr/bin/env python3
"""Strict control-plane CI; legacy tests are included only with --legacy."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class PreflightError(RuntimeError):
    """A safe, credential-free preflight diagnostic."""


def preflight_database() -> None:
    """Fail before discovery unless the disposable local PostgreSQL is usable."""
    os.environ["CONTROL_PLANE_REQUIRE_TEST_DATABASE"] = "1"
    engine = None
    try:
        from sqlalchemy import text
        from sqlalchemy.engine import make_url
        from tests_control_plane.pg_harness import (
            engine_for,
            require_disposable_database_url,
        )

        raw = require_disposable_database_url()
        url = make_url(raw)
        # The shared harness supplies the database-prefix and query guards.
        # CI additionally requires an explicit loopback host and known driver.
        if url.drivername != "postgresql+pg8000" or url.host not in {
            "127.0.0.1", "localhost", "::1"
        }:
            raise PreflightError()
        engine = engine_for(raw)
        if engine.dialect.name != "postgresql":
            raise PreflightError()
        with engine.connect() as connection:
            version = int(
                connection.execute(text("SHOW server_version_num")).scalar_one()
            )
            if version < 170000:
                raise PreflightError()
    except Exception:
        # Driver errors can contain passwords, full URLs or server diagnostics.
        raise PreflightError(
            "CI requires a reachable PostgreSQL >=17 test database: set "
            "CONTROL_PLANE_TEST_DATABASE_URL to a loopback pg8000 URL with "
            "a control_plane_test_ database name and no query parameters."
        ) from None
    finally:
        if engine is not None:
            try:
                engine.dispose()
            except Exception:
                raise PreflightError("CI test database cleanup failed.") from None


class StrictTestResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.testsCompleted = 0

    def stopTest(self, test):
        self.testsCompleted += 1
        super().stopTest(test)

    def wasSuccessful(self):
        return (
            super().wasSuccessful()
            and not self.skipped
            and not self.expectedFailures
        )


def discover_tests(include_legacy: bool = False) -> unittest.TestSuite:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    # Never discover from the repository root: that can rediscover nested tests.
    directories = ["tests_control_plane"]
    if include_legacy:
        directories.append("tests")
    for directory in directories:
        suite.addTests(
            loader.discover(
                start_dir=str(ROOT / directory),
                pattern="test*.py",
                top_level_dir=str(ROOT),
            )
        )
    if loader.errors:
        raise RuntimeError("test discovery failed")
    return suite


def run_suite(suite: unittest.TestSuite, *, stream) -> int:
    discovered = suite.countTestCases()
    if discovered == 0:
        print("STRICT CI FAILED: no tests discovered.", file=stream)
        return 1
    result = unittest.TextTestRunner(
        stream=stream, verbosity=2, resultclass=StrictTestResult
    ).run(suite)
    if (
        not result.wasSuccessful()
        or result.testsRun != discovered
        or result.testsCompleted != discovered
    ):
        print(
            "STRICT CI FAILED: "
            f"discovered={discovered}, started={result.testsRun}, "
            f"completed={result.testsCompleted}, skipped={len(result.skipped)}, "
            f"expected_failures={len(result.expectedFailures)}. "
            "All discovered tests must run and pass without skips.",
            file=stream,
        )
        return 1
    print(f"STRICT CI PASSED: {discovered} tests, no skips.", file=stream)
    return 0


def main(argv=None, *, stream=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--legacy",
        action="store_true",
        help="also discover tests/ (requires its dependencies; no relaxed checks)",
    )
    args = parser.parse_args(argv)
    stream = sys.stderr if stream is None else stream
    try:
        preflight_database()
    except PreflightError as exc:
        print(str(exc), file=stream)
        return 2
    print(
        "Strict CI scope: tests_control_plane"
        + (" + tests (legacy)" if args.legacy else " (legacy tests/ not included)"),
        file=stream,
    )
    try:
        return run_suite(discover_tests(args.legacy), stream=stream)
    except (Exception, SystemExit):
        print(
            "STRICT CI FAILED: test discovery or execution terminated unexpectedly.",
            file=stream,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
