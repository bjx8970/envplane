from contextlib import contextmanager
import secrets
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


@contextmanager
def runtime_role(url):
    """Provision a disposable login role; keep migration credentials separate."""
    from control_plane.permissions import grant_runtime_permissions

    validate_disposable_database_url(url)
    role = f"p1_runtime_{uuid4().hex}"
    password = secrets.token_hex(24)
    engine = engine_for(url)
    created = False
    try:
        with engine.begin() as connection:
            # Both identifiers and password are generated hexadecimal test data.
            connection.execute(text(f"CREATE ROLE {role} LOGIN PASSWORD '{password}'"))
            grant_runtime_permissions(connection, role)
        created = True
        yield make_url(url).set(username=role, password=password).render_as_string(hide_password=False)
    finally:
        try:
            if created:
                with engine.begin() as connection:
                    connection.execute(text(f"DROP OWNED BY {role}"))
                    connection.execute(text(f"DROP ROLE {role}"))
        finally:
            engine.dispose()


@contextmanager
def runtime_database():
    with migrated_database() as url:
        with runtime_role(url) as runtime_url:
            yield url, runtime_url
