"""In-place schema upgrade support for production deployments."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import inspect, text

import hashcrush
from hashcrush.models import AuditLog, SchemaVersion, db, utc_now_naive

CURRENT_SCHEMA_VERSION = 3


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
    initialized_empty_schema: bool
    dry_run: bool


def _migration_001_adopt_current_schema() -> None:
    """Baseline current schema and begin version tracking."""
    db.create_all()


def _migration_002_create_audit_log_table() -> None:
    """Add immutable audit-log storage for sensitive application actions."""
    AuditLog.__table__.create(bind=db.engine, checkfirst=True)


def _drop_column_if_exists(table_name: str, column_name: str) -> None:
    inspector = inspect(db.engine)
    if table_name not in inspector.get_table_names():
        return

    column_names = {column["name"] for column in inspector.get_columns(table_name)}
    if column_name not in column_names:
        return

    db.session.execute(
        text(f'ALTER TABLE "{table_name}" DROP COLUMN "{column_name}"')
    )
    db.session.commit()


def _migration_003_remove_obsolete_settings_fields() -> None:
    """Drop obsolete retention/job-weight settings columns."""
    _drop_column_if_exists("settings", "retention_period")
    _drop_column_if_exists("settings", "enabled_job_weights")


MIGRATIONS: tuple[MigrationStep, ...] = (
    MigrationStep(
        version=1,
        name="baseline_current_schema",
        summary="Adopt the current schema and start tracking in-place upgrades.",
        upgrade=_migration_001_adopt_current_schema,
    ),
    MigrationStep(
        version=2,
        name="create_audit_log_table",
        summary="Add immutable audit logging for sensitive actions.",
        upgrade=_migration_002_create_audit_log_table,
    ),
    MigrationStep(
        version=3,
        name="remove_obsolete_settings_fields",
        summary="Remove obsolete retention and job-weight settings fields.",
        upgrade=_migration_003_remove_obsolete_settings_fields,
    ),
)


def _current_table_names() -> set[str]:
    return set(inspect(db.engine).get_table_names())


def _non_versioned_table_names() -> set[str]:
    return _current_table_names() - {SchemaVersion.__tablename__}


def _unsupported_legacy_schema_message() -> str:
    return (
        "Detected a non-empty database without schema version tracking. "
        "In-place upgrades are supported only for tracked schemas created from this "
        "release onward. Rebuild with `hashcrush.py setup` or migrate the database "
        "manually before using `hashcrush.py upgrade`."
    )


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
    initialized_empty_schema = current_version is None and (not existing_user_tables)

    if current_version is None and existing_user_tables:
        raise RuntimeError(_unsupported_legacy_schema_message())

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
        initialized_empty_schema=initialized_empty_schema,
        dry_run=False,
    )


def get_schema_status() -> dict[str, object]:
    """Return current schema tracking status for CLI/UI checks."""
    current_version = get_current_schema_version()
    has_non_version_tables = bool(_non_versioned_table_names())
    if current_version is None:
        if has_non_version_tables:
            mode = "Unsupported legacy schema"
            detail = _unsupported_legacy_schema_message()
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
