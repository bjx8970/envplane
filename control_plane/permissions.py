"""Explicit runtime-role provisioning and effective PostgreSQL privilege checks.

Run provisioning as the migration owner in a transaction, after migrating. Neither
entry point creates roles, changes memberships, revokes PUBLIC grants, or commits.
Runtime validation uses current_user so SET ROLE has the same semantics as login.
"""

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError


class RuntimePermissionError(RuntimeError):
    """The database role does not satisfy the runtime least-privilege boundary."""


_APPEND_ONLY = frozenset({
    "plugin_storage_versions", "plugin_storage_snapshots", "plugin_instance_versions",
    "audit_events", "operation_evidence", "job_logs", "job_plugin_snapshots", "job_secret_refs",
    "operation_call_attempts", "environment_credential_confirmations",
})
_MUTABLE = frozenset({
    "users", "courses", "groups", "course_members", "templates", "template_versions",
    "plugin_instances", "plugin_storage_heads", "teacher_quotas", "quota_reservations",
    "environments", "experiment_resources", "environment_assignments", "execution_groups",
    "conflict_protections", "jobs", "job_steps", "operations", "local_resource_items",
    "secrets", "secret_versions", "interactive_sessions", "access_revocations", "execution_recovery_requests",
})
_TABLE_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER", "MAINTAIN")
_COLUMN_PRIVILEGES = frozenset({"SELECT", "INSERT", "UPDATE", "REFERENCES"})
_POLICY = {name: frozenset({"SELECT", "INSERT"}) for name in _APPEND_ONLY}
_POLICY.update({name: frozenset({"SELECT", "INSERT", "UPDATE"}) for name in _MUTABLE})
_POLICY.update({"coordinator_leases": frozenset({"SELECT", "UPDATE"}),
                "alembic_version": frozenset({"SELECT"})})
_ERROR = "runtime database permissions are unsafe or incomplete; use a dedicated least-privilege role"


def _reject():
    raise RuntimePermissionError(_ERROR)


def _role(connection, name):
    row = connection.execute(text("SELECT oid, rolname FROM pg_roles WHERE rolname=:name"),
                             {"name": name}).first()
    if row is None:
        _reject()
    return row


def _effective_roles(connection, role_oid):
    # SET uses the complete PostgreSQL SET-option path, not mere MEMBER status.
    return connection.execute(text("""
        SELECT oid, rolname, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls
        FROM pg_roles WHERE oid=:role OR pg_has_role(CAST(:role AS oid), oid, 'SET')
    """), {"role": role_oid}).all()


def _check(connection, role_oid, *, require_complete):
    if connection.dialect.name != "postgresql":
        _reject()
    tables = connection.execute(text("""
        SELECT c.oid, c.relname, c.relowner, c.relkind FROM pg_class c
        JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='control_plane' AND c.relkind IN ('r','p','v','m','f','S')
    """)).all()
    if {row.relname for row in tables} != set(_POLICY) or any(row.relkind not in ('r', 'p') for row in tables):
        _reject()
    for role in _effective_roles(connection, role_oid):
        parameters = {"role": role.oid}
        if any((role.rolsuper, role.rolcreaterole, role.rolcreatedb, role.rolreplication, role.rolbypassrls)):
            _reject()
        if connection.scalar(text("""
            SELECT has_database_privilege(CAST(:role AS oid), oid, 'CREATE')
                OR pg_has_role(CAST(:role AS oid), datdba, 'USAGE')
            FROM pg_database WHERE datname=current_database()
        """), parameters):
            _reject()
        # Include PUBLIC and inheritance. Ownership still permits ALTER/DROP even
        # when the owner has explicitly revoked its own ordinary ACL privileges.
        if connection.scalar(text("""
            SELECT EXISTS (SELECT 1 FROM pg_namespace
                WHERE nspname NOT LIKE 'pg\\_%' ESCAPE '\\' AND nspname <> 'information_schema'
                AND (has_schema_privilege(CAST(:role AS oid), oid, 'CREATE') OR pg_has_role(CAST(:role AS oid), nspowner, 'USAGE')))
        """), parameters):
            _reject()
        if connection.scalar(text("""
            SELECT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\' AND n.nspname <> 'information_schema'
                  AND pg_has_role(CAST(:role AS oid), c.relowner, 'USAGE'))
            OR EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                WHERE n.nspname='control_plane'
                  AND (pg_has_role(CAST(:role AS oid), p.proowner, 'USAGE')
                    OR (p.prosecdef AND has_function_privilege(CAST(:role AS oid), p.oid, 'EXECUTE'))))
            OR EXISTS (SELECT 1 FROM pg_auth_members m
                WHERE m.admin_option AND pg_has_role(CAST(:role AS oid), m.member, 'USAGE'))
            OR EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname IN
                ('pg_read_server_files','pg_write_server_files','pg_execute_server_program',
                 'pg_signal_backend','pg_checkpoint','pg_create_subscription')
                AND pg_has_role(CAST(:role AS oid), r.oid, 'USAGE'))
        """), parameters):
            _reject()
        if require_complete and role.oid == role_oid and not connection.scalar(text(
            "SELECT has_schema_privilege(CAST(:role AS oid), 'control_plane', 'USAGE')"), parameters):
            _reject()
        # PostgreSQL evaluates inheritance and PUBLIC itself. Batched inspection
        # avoids a network round trip per table/privilege during startup.
        permissions = connection.execute(text("""
            SELECT c.relname, p.privilege,
                has_table_privilege(CAST(:role AS oid), c.oid, p.privilege) AS effective,
                CASE WHEN p.privilege IN ('SELECT','INSERT','UPDATE','REFERENCES')
                    THEN has_any_column_privilege(CAST(:role AS oid), c.oid, p.privilege) ELSE false END AS column_effective,
                has_table_privilege(CAST(:role AS oid), c.oid, p.privilege || ' WITH GRANT OPTION') AS grantable,
                CASE WHEN p.privilege IN ('SELECT','INSERT','UPDATE','REFERENCES')
                    THEN has_any_column_privilege(CAST(:role AS oid), c.oid, p.privilege || ' WITH GRANT OPTION')
                    ELSE false END AS column_grantable
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),('TRUNCATE'),
                               ('REFERENCES'),('TRIGGER'),('MAINTAIN')) AS p(privilege)
            WHERE n.nspname='control_plane' AND c.relkind IN ('r','p')
        """), parameters).all()
        for permission in permissions:
            allowed = _POLICY[permission.relname]
            if permission.privilege not in allowed and (permission.effective or permission.column_effective):
                _reject()
            if (require_complete and role.oid == role_oid and permission.privilege in allowed
                    and not permission.effective):
                _reject()
            if permission.grantable or permission.column_grantable:
                _reject()


def grant_runtime_permissions(connection, role_name) -> None:
    """Grant the fixed runtime policy to an existing safe role, without committing.

    Unsafe pre-existing effective permissions are rejected rather than silently
    changing database-wide PUBLIC ACLs or other roles' membership/privileges.
    """
    try:
        if (connection.dialect.name != "postgresql" or not connection.in_transaction()
                or not isinstance(role_name, str) or not role_name or "\x00" in role_name
                or len(role_name.encode("utf-8")) > 63):
            _reject()
        role = _role(connection, role_name)
        _check(connection, role.oid, require_complete=False)
        quoted_role = connection.dialect.identifier_preparer.quote_identifier(role.rolname)
        connection.execute(text(f"GRANT USAGE ON SCHEMA control_plane TO {quoted_role}"))
        for table, allowed in sorted(_POLICY.items()):
            quoted_table = connection.dialect.identifier_preparer.quote_identifier(table)
            privileges = ", ".join(sorted(allowed))
            connection.execute(text(f"GRANT {privileges} ON TABLE control_plane.{quoted_table} TO {quoted_role}"))
        _check(connection, role.oid, require_complete=True)
    except RuntimePermissionError:
        raise
    except (SQLAlchemyError, UnicodeError):
        raise RuntimePermissionError(_ERROR) from None


def validate_runtime_permissions(connection) -> None:
    """Fail closed on missing or excessive effective current-role privileges."""
    try:
        if connection.dialect.name != "postgresql":
            _reject()
        current = connection.scalar(text("SELECT current_user"))
        _check(connection, _role(connection, current).oid, require_complete=True)
    except RuntimePermissionError:
        raise
    except (SQLAlchemyError, UnicodeError):
        raise RuntimePermissionError(_ERROR) from None
