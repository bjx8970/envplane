"""Alembic bridge: the migration runner owns connections and advisory locking."""
from alembic import context


def run_with_connection(connection):
    if connection.dialect.name != "postgresql":
        raise RuntimeError("control_plane migrations require PostgreSQL")
    context.configure(
        connection=connection,
        target_metadata=None,
        version_table_schema="control_plane",
        transactional_ddl=True,
        transaction_per_migration=False,
    )
    with context.begin_transaction():
        context.run_migrations()


connection = context.config.attributes.get("connection")
if connection is not None:
    run_with_connection(connection)
else:
    if context.is_offline_mode():
        raise RuntimeError("offline migrations are not supported")
    from control_plane.config import RuntimeSettings
    from control_plane.migrations import migration_transaction

    options = context.config.cmd_opts
    command_name = getattr(getattr(options, "cmd", (None,))[0], "__name__", "")
    if command_name not in {"upgrade", "downgrade"}:
        raise RuntimeError("use the control-plane migration runner for this command")
    with migration_transaction(
        RuntimeSettings.from_env(),
        target=getattr(options, "revision", "head"),
        upgrade=command_name == "upgrade",
    ) as connection:
        run_with_connection(connection)
