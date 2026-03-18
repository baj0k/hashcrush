"""Container bootstrap helpers for one-command local deployments."""

from __future__ import annotations

import os
import time
from pathlib import Path

from sqlalchemy import select, text
from sqlalchemy import create_engine

from hashcrush import create_app
from hashcrush.db_upgrade import upgrade_database
from hashcrush.models import Settings, Users, db
from hashcrush.setup import add_default_tasks, default_tasks_need_added
from hashcrush.users.routes import bcrypt
from hashcrush.utils.utils import migrate_sensitive_storage_rows

DEFAULT_DB_WAIT_SECONDS = 60.0
DEFAULT_DB_POLL_SECONDS = 1.0


def ensure_runtime_and_storage_dirs(runtime_path: str, storage_path: str) -> None:
    """Create the runtime and persistent storage tree expected by the app."""
    runtime_root = Path(runtime_path).expanduser().resolve()
    storage_root = Path(storage_path).expanduser().resolve()

    for relative_path in (
        ("tmp",),
        ("hashes",),
        ("outfiles",),
    ):
        (runtime_root.joinpath(*relative_path)).mkdir(parents=True, exist_ok=True)

    for relative_path in (
        ("wordlists",),
        ("rules",),
    ):
        (storage_root.joinpath(*relative_path)).mkdir(parents=True, exist_ok=True)


def wait_for_database(
    database_uri: str,
    *,
    timeout_seconds: float = DEFAULT_DB_WAIT_SECONDS,
    poll_interval_seconds: float = DEFAULT_DB_POLL_SECONDS,
) -> None:
    """Wait until the configured database accepts connections."""
    deadline = time.monotonic() + max(1.0, float(timeout_seconds))
    poll_interval = max(0.1, float(poll_interval_seconds))
    last_error: Exception | None = None

    while time.monotonic() < deadline:
        engine = create_engine(database_uri, pool_pre_ping=True)
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            return
        except Exception as exc:  # pragma: no cover - exercised via timeout path
            last_error = exc
            time.sleep(poll_interval)
        finally:
            engine.dispose()

    raise RuntimeError(
        "Database did not become ready before timeout."
        + (f" Last error: {last_error}" if last_error else "")
    )


def ensure_seed_data(admin_username: str, admin_password: str) -> None:
    """Seed the minimum runtime rows needed for a usable instance."""
    if len(admin_password) < 14:
        raise RuntimeError(
            "HASHCRUSH_INITIAL_ADMIN_PASSWORD must be at least 14 characters long."
        )

    if db.session.execute(select(Settings)).scalars().first() is None:
        db.session.add(Settings())
        db.session.commit()

    has_admin = db.session.execute(
        select(Users).where(Users.admin.is_(True)).limit(1)
    ).scalars().first()
    if not has_admin:
        db.session.add(
            Users(
                username=admin_username,
                password=bcrypt.generate_password_hash(admin_password).decode("utf-8"),
                admin=True,
            )
        )
        db.session.commit()

    if default_tasks_need_added(db):
        add_default_tasks(db)


def bootstrap_instance(app, admin_username: str, admin_password: str) -> tuple[int, int]:
    """Upgrade schema, migrate sensitive rows, and seed runtime state."""
    with app.app_context():
        result = upgrade_database(dry_run=False)
        migrated_rows = migrate_sensitive_storage_rows()
        ensure_seed_data(admin_username, admin_password)
    return result.target_version, migrated_rows


def build_bootstrap_app():
    return create_app(
        config_overrides={
            "ENABLE_LOCAL_EXECUTOR": False,
            "SKIP_RUNTIME_BOOTSTRAP": True,
        }
    )


def main() -> int:
    database_uri = str(os.getenv("HASHCRUSH_DATABASE_URI") or "").strip()
    if not database_uri:
        raise RuntimeError("HASHCRUSH_DATABASE_URI is required for container bootstrap.")

    runtime_path = str(
        os.getenv("HASHCRUSH_RUNTIME_PATH") or "/tmp/hashcrush-runtime"
    ).strip()
    storage_path = str(
        os.getenv("HASHCRUSH_STORAGE_PATH") or "/var/lib/hashcrush"
    ).strip()
    admin_username = (
        str(os.getenv("HASHCRUSH_INITIAL_ADMIN_USERNAME") or "admin").strip() or "admin"
    )
    admin_password = str(os.getenv("HASHCRUSH_INITIAL_ADMIN_PASSWORD") or "").strip()
    if not admin_password:
        raise RuntimeError("HASHCRUSH_INITIAL_ADMIN_PASSWORD is required.")

    timeout_seconds = float(
        os.getenv("HASHCRUSH_BOOTSTRAP_DB_WAIT_SECONDS") or DEFAULT_DB_WAIT_SECONDS
    )

    print("Ensuring runtime and storage directories exist.")
    ensure_runtime_and_storage_dirs(runtime_path, storage_path)

    print("Waiting for PostgreSQL to accept connections.")
    wait_for_database(database_uri, timeout_seconds=timeout_seconds)

    print("Bootstrapping schema and seed data.")
    target_version, migrated_rows = bootstrap_instance(
        build_bootstrap_app(),
        admin_username,
        admin_password,
    )
    print(f"Schema version is now {target_version}.")
    if migrated_rows:
        print(f"Migrated {migrated_rows} sensitive storage row(s).")
    print("Container bootstrap completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
