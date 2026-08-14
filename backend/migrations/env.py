from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from gameframework.config import get_settings
from gameframework.db import models  # noqa: F401 (registers tables on Base.metadata)
from gameframework.db.base import Base

config = context.config

if config.config_file_name is not None:
    # disable_existing_loggers defaults to True, which would silently
    # switch off every application logger already instantiated at the
    # time migrations run — alembic.ini's [loggers] section names only
    # root/sqlalchemy/alembic, so anything under `gameframework.*` goes
    # dark (M2-Task-Plan.md Task 3 Step 3).
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def _database_url() -> str:
    return config.get_main_option("sqlalchemy.url") or get_settings().database_url


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = _database_url()
    connectable = engine_from_config(configuration, prefix="sqlalchemy.", poolclass=pool.NullPool)

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
