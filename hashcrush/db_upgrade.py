"""In-place schema upgrade support for production deployments."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import inspect

import hashcrush
from hashcrush.models import SchemaVersion, db, utc_now_naive

CURRENT_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class MigrationStep:
    """Single idempotent schema migration step."""

    version: int
    name: str
    summary: str
    upgrade: callable


@dataclass(frozen=True)
class UpgradeResult:
    """Outcome of planning or applying schema upgrades."""

    starting_version: int
    target_version: int
    applied_steps: tuple[MigrationStep, ...]
    adopted_unversioned_schema: bool
    initialized_empty_schema: bool
    dry_run: bool


def _migration_001_adopt_current_schema() -> None:
    """Baseline current schema and begin version tracking."""
    db.create_all()


MIGRATIONS: tuple[MigrationStep, ...] = (
    MigrationStep(
        version=1,
        name="baseline_current_schema",
        summary="Adopt the current schema and start tracking in-place upgrades.",
        upgrade=_migration_001_adopt_current_schema,
    ),
)


def _current_table_names() -> set[str]:
    return set(inspect(db.engine).get_table_names())


def _non_versioned_table_names() -> set[str]:
    return _current_table_names() - {SchemaVersion.__tablename__}


def get_current_schema_version() -> int | None:
    if SchemaVersion.__tablename__ not in _current_table_names():
        return None
    state = db.session.get(SchemaVersion, 1)
    if not state:
        return None
    return int(state.version)


def _record_schema_version(version: int) -> None:
    state = db.session.get(SchemaVersion, 1)
    if state is None:
        state = SchemaVersion(id=1, version=version, app_version=hashcrush.__version__)
        db.session.add(state)
    state.version = version
    state.app_version = hashcrush.__version__
    state.updated_at = utc_now_naive()
    db.session.commit()


def _pending_migrations(starting_version: int) -> tuple[MigrationStep, ...]:
    return tuple(
        step
        for step in MIGRATIONS
        if starting_version < step.version <= CURRENT_SCHEMA_VERSION
    )


def upgrade_database(*, dry_run: bool = False) -> UpgradeResult:
    """Apply all pending schema migrations without dropping application data."""
    current_version = get_current_schema_version()
    starting_version = current_version or 0
    existing_user_tables = _non_versioned_table_names()
    adopted_unversioned_schema = current_version is None and bool(existing_user_tables)
    initialized_empty_schema = current_version is None and (not existing_user_tables)

    if starting_version > CURRENT_SCHEMA_VERSION:
        raise RuntimeError(
            f"Database schema version {starting_version} is newer than this code "
            f"supports ({CURRENT_SCHEMA_VERSION})."
        )

    pending_steps = _pending_migrations(starting_version)
    if dry_run:
        return UpgradeResult(
            starting_version=starting_version,
            target_version=CURRENT_SCHEMA_VERSION,
            applied_steps=pending_steps,
            adopted_unversioned_schema=adopted_unversioned_schema,
            initialized_empty_schema=initialized_empty_schema,
            dry_run=True,
        )

    for step in pending_steps:
        step.upgrade()
        _record_schema_version(step.version)

    return UpgradeResult(
        starting_version=starting_version,
        target_version=CURRENT_SCHEMA_VERSION,
        applied_steps=pending_steps,
        adopted_unversioned_schema=adopted_unversioned_schema,
        initialized_empty_schema=initialized_empty_schema,
        dry_run=False,
    )


def get_schema_status() -> dict[str, object]:
    """Return current schema tracking status for CLI/UI checks."""
    current_version = get_current_schema_version()
    has_non_version_tables = bool(_non_versioned_table_names())
    if current_version is None:
        if has_non_version_tables:
            mode = "Unversioned schema"
            detail = (
                "Run `hashcrush.py upgrade` once to adopt schema tracking without "
                "dropping existing data."
            )
        else:
            mode = "Uninitialized schema"
            detail = (
                "Run `hashcrush.py setup` for a destructive bootstrap or "
                "`hashcrush.py upgrade` to initialize the tracked schema."
            )
    else:
        mode = f"Managed upgrades (schema {current_version}/{CURRENT_SCHEMA_VERSION})"
        if current_version < CURRENT_SCHEMA_VERSION:
            detail = "Pending schema upgrades detected. Run `hashcrush.py upgrade`."
        else:
            detail = "Schema history is tracked in-app. Use `hashcrush.py upgrade` for future releases."

    return {
        "current_version": current_version,
        "target_version": CURRENT_SCHEMA_VERSION,
        "mode": mode,
        "detail": detail,
        "tracked": current_version is not None,
        "has_user_tables": has_non_version_tables,
    }

