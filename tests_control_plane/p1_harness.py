from contextlib import contextmanager
from uuid import uuid4

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool

from control_plane.config import RuntimeSettings
from control_plane.migrations import run_migrations
from tests_control_plane.pg_harness import (
    engine_for,
    require_disposable_database_url,
    validate_disposable_database_url,
)


@contextmanager
def fresh_database():
    base = require_disposable_database_url()
    name = f"control_plane_test_p1_{uuid4().hex}"
    url = validate_disposable_database_url(
        make_url(base).set(database=name).render_as_string(hide_password=False)
    )
    admin = create_engine(base, poolclass=NullPool, hide_parameters=True,
                          connect_args={"timeout": 3})
    created = False
    try:
        with admin.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
            if int(connection.scalar(text("SHOW server_version_num"))) < 170000:
                raise RuntimeError("P1 tests require PostgreSQL 17 or later")
            connection.execute(text(f'CREATE DATABASE "{name}"'))
            created = True
        yield url
    finally:
        try:
            if created:
                with admin.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
                    connection.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        finally:
            admin.dispose()


@contextmanager
def migrated_database():
    with fresh_database() as url:
        settings = RuntimeSettings.from_env({"CONTROL_PLANE_DATABASE_URL": url})
        run_migrations(settings)
        yield url
