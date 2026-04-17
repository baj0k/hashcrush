"""Helpers for provisioning isolated PostgreSQL databases for automated tests."""

from __future__ import annotations

import atexit
import os
import secrets
import threading

from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.pool import NullPool

TEST_POSTGRES_URI_ENV = "HASHCRUSH_TEST_POSTGRES_URI"
TEST_POSTGRES_ADMIN_URI_ENV = "HASHCRUSH_TEST_POSTGRES_ADMIN_URI"
DEFAULT_LOCAL_TEST_POSTGRES_URI = URL.create(
    "postgresql+psycopg",
    username="hashcrush",
    password="hashcrush",
    host="127.0.0.1",
    port=5432,
    database="hashcrush",
).render_as_string(hide_password=False)

_state_lock = threading.Lock()
_managed_postgres_databases: set[tuple[str, str]] = set()
_managed_postgres_schemas: set[tuple[str, str]] = set()
_cleanup_registered = False


def sqlalchemy_engine_options() -> dict:
    """Return engine options for isolated PostgreSQL-backed test apps."""
    return {"poolclass": NullPool}


def _postgres_admin_uri() -> str:
    uri = (os.getenv(TEST_POSTGRES_ADMIN_URI_ENV) or "").strip()
    if not uri:
        raise RuntimeError("No PostgreSQL admin URI configured for test database mode.")
    return uri


def _database_uri_for_name(admin_uri: str, db_name: str) -> str:
    return make_url(admin_uri).set(database=db_name).render_as_string(hide_password=False)


def _database_uri_for_schema(base_uri: str, schema_name: str) -> str:
    return (
        make_url(base_uri)
        .update_query_dict({"options": f"-csearch_path={schema_name}"})
        .render_as_string(hide_password=False)
    )


def _postgres_identifier(value: str) -> str:
    return value.replace('"', '""')


def _postgres_base_uri() -> str:
    explicit_uri = (os.getenv(TEST_POSTGRES_URI_ENV) or "").strip()
    if explicit_uri:
        return explicit_uri

    runtime_uri = (os.getenv("HASHCRUSH_DATABASE_URI") or "").strip()
    if runtime_uri:
        return runtime_uri

    return DEFAULT_LOCAL_TEST_POSTGRES_URI


def _drop_postgres_database(admin_uri: str, db_name: str) -> None:
    escaped_db_name = _postgres_identifier(db_name)
    engine = create_engine(admin_uri, isolation_level="AUTOCOMMIT", poolclass=NullPool)
    try:
        with engine.connect() as connection:
            connection.execute(
                text(
                    "SELECT pg_terminate_backend(pid) "
                    "FROM pg_stat_activity "
                    "WHERE datname = :db_name AND pid <> pg_backend_pid()"
                ),
                {"db_name": db_name},
            )
            connection.execute(text(f'DROP DATABASE IF EXISTS "{escaped_db_name}"'))
    finally:
        engine.dispose()


def _drop_postgres_schema(base_uri: str, schema_name: str) -> None:
    escaped_schema_name = _postgres_identifier(schema_name)
    engine = create_engine(base_uri, isolation_level="AUTOCOMMIT", poolclass=NullPool)
    try:
        with engine.connect() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{escaped_schema_name}" CASCADE'))
    finally:
        engine.dispose()


def _cleanup_managed_postgres_databases() -> None:
    with _state_lock:
        databases = list(_managed_postgres_databases)
        _managed_postgres_databases.clear()
    for admin_uri, db_name in databases:
        try:
            _drop_postgres_database(admin_uri, db_name)
        except Exception:
            pass


def _cleanup_managed_postgres_schemas() -> None:
    with _state_lock:
        schemas = list(_managed_postgres_schemas)
        _managed_postgres_schemas.clear()
    for base_uri, schema_name in schemas:
        try:
            _drop_postgres_schema(base_uri, schema_name)
        except Exception:
            pass


def _register_cleanup_once() -> None:
    global _cleanup_registered

    with _state_lock:
        if _cleanup_registered:
            return
        atexit.register(_cleanup_managed_postgres_schemas)
        atexit.register(_cleanup_managed_postgres_databases)
        _cleanup_registered = True


def create_managed_postgres_database() -> str:
    """Create an isolated PostgreSQL test target for one app instance.

    Preferred mode:
    - create a fresh temporary schema inside the configured app database
    - requires only normal app credentials with CREATE on the database

    Fallback mode:
    - if HASHCRUSH_TEST_POSTGRES_ADMIN_URI is set and the schema path is unusable,
      create a fresh temporary database
    """
    _register_cleanup_once()

    base_uri = _postgres_base_uri()
    schema_name = f"hashcrush_test_{os.getpid()}_{secrets.token_hex(4)}"
    escaped_schema_name = _postgres_identifier(schema_name)
    schema_engine = create_engine(
        base_uri, isolation_level="AUTOCOMMIT", poolclass=NullPool
    )
    try:
        with schema_engine.connect() as connection:
            connection.execute(text(f'CREATE SCHEMA "{escaped_schema_name}"'))
        with _state_lock:
            _managed_postgres_schemas.add((base_uri, schema_name))
        return _database_uri_for_schema(base_uri, schema_name)
    except Exception:
        schema_engine.dispose()
        admin_uri = _postgres_admin_uri()
        db_name = f"hashcrush_test_{os.getpid()}_{secrets.token_hex(4)}"
        escaped_db_name = _postgres_identifier(db_name)
        admin_url: URL = make_url(admin_uri)
        owner_name = admin_url.username

        engine = create_engine(
            admin_uri, isolation_level="AUTOCOMMIT", poolclass=NullPool
        )
        try:
            with engine.connect() as connection:
                if owner_name:
                    escaped_owner = _postgres_identifier(owner_name)
                    connection.execute(
                        text(
                            f'CREATE DATABASE "{escaped_db_name}" '
                            f'OWNER "{escaped_owner}"'
                        )
                    )
                else:
                    connection.execute(text(f'CREATE DATABASE "{escaped_db_name}"'))
        finally:
            engine.dispose()

        with _state_lock:
            _managed_postgres_databases.add((admin_uri, db_name))
        return _database_uri_for_name(admin_uri, db_name)
    finally:
        schema_engine.dispose()
