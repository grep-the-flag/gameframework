"""Alembic migration chain: upgrade, downgrade, and idempotency.

DDL over a whole schema cannot run inside a wrapping transaction, so these
tests do not use Task 1a's shared, rollback-based fixtures — each test
creates and drops a real PostgreSQL database of its own.
"""

import os
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import URL, make_url

BACKEND_DIR = Path(__file__).resolve().parents[2]
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"

ADMIN_DATABASE_URL = os.environ.get(
    "GF_DATABASE_URL",
    "postgresql+psycopg://gameframework:gameframework@localhost:5432/gameframework",
)


def _table_names(database_url: URL) -> set[str]:
    engine = create_engine(database_url)
    try:
        return set(inspect(engine).get_table_names(schema="public"))
    finally:
        engine.dispose()


def _enum_type_names(database_url: URL) -> set[str]:
    """Postgres enum types in the public schema.

    A separate catalog object (pg_type) from the tables that reference
    them — dropping those tables does not drop the enum type itself.
    """
    engine = create_engine(database_url)
    try:
        with engine.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT t.typname FROM pg_type t "
                    "JOIN pg_namespace n ON n.oid = t.typnamespace "
                    "WHERE t.typtype = 'e' AND n.nspname = 'public'"
                )
            )
            return {row[0] for row in rows}
    finally:
        engine.dispose()


def _alembic_config(database_url: URL) -> Config:
    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("sqlalchemy.url", database_url.render_as_string(hide_password=False))
    return cfg


@pytest.fixture
def fresh_database_url() -> Iterator[URL]:
    """Yield the URL of a brand-new, empty PostgreSQL database; drop it after."""
    admin_url = make_url(ADMIN_DATABASE_URL)
    db_name = f"test_migrations_{uuid.uuid4().hex}"
    admin_engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    try:
        with admin_engine.connect() as conn:
            conn.execute(text(f'CREATE DATABASE "{db_name}"'))
        try:
            yield admin_url.set(database=db_name)
        finally:
            with admin_engine.connect() as conn:
                # A live connection (e.g. left by alembic's env.py) blocks DROP DATABASE.
                conn.execute(
                    text(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                        "WHERE datname = :db AND pid <> pg_backend_pid()"
                    ),
                    {"db": db_name},
                )
                conn.execute(text(f'DROP DATABASE IF EXISTS "{db_name}"'))
    finally:
        admin_engine.dispose()


def test_upgrade_head_succeeds_on_empty_database(fresh_database_url: URL) -> None:
    assert _table_names(fresh_database_url) == set()

    command.upgrade(_alembic_config(fresh_database_url), "head")

    # data-model.md §3 defines 26 tables (3.1 through 3.26); Alembic adds its
    # own bookkeeping table on top.
    assert len(_table_names(fresh_database_url)) == 27


def test_downgrade_base_returns_to_empty(fresh_database_url: URL) -> None:
    assert _table_names(fresh_database_url) == set()
    assert _enum_type_names(fresh_database_url) == set()
    cfg = _alembic_config(fresh_database_url)

    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")

    # Alembic creates its own bookkeeping table on the first upgrade and
    # never drops it on downgrade to base, so "empty" here means no
    # application tables and no leftover enum types — not a literally
    # empty schema.
    assert _table_names(fresh_database_url) == {"alembic_version"}
    assert _enum_type_names(fresh_database_url) == set()


def test_upgrade_head_is_idempotent(fresh_database_url: URL) -> None:
    cfg = _alembic_config(fresh_database_url)

    command.upgrade(cfg, "head")
    first_tables = _table_names(fresh_database_url)
    first_enums = _enum_type_names(fresh_database_url)

    command.upgrade(cfg, "head")

    assert _table_names(fresh_database_url) == first_tables
    assert _enum_type_names(fresh_database_url) == first_enums
