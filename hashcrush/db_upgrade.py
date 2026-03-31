"""In-place schema upgrade support for production deployments."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import inspect, text

import hashcrush
from hashcrush.models import AuditLog, SchemaVersion, UploadOperations, db, utc_now_naive

CURRENT_SCHEMA_VERSION = 8


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


def _index_names(table_name: str) -> set[str]:
    inspector = inspect(db.engine)
    if table_name not in inspector.get_table_names():
        return set()
    return {index["name"] for index in inspector.get_indexes(table_name)}


def _unique_constraint_names(table_name: str) -> set[str]:
    inspector = inspect(db.engine)
    if table_name not in inspector.get_table_names():
        return set()
    return {
        constraint["name"]
        for constraint in inspector.get_unique_constraints(table_name)
        if constraint.get("name")
    }


def _drop_index_if_exists(index_name: str) -> None:
    if index_name not in {
        *(_index_names("hashes")),
        *(_index_names("hashfile_hashes")),
    }:
        return
    db.session.execute(text(f'DROP INDEX IF EXISTS "{index_name}"'))
    db.session.commit()


def _migration_003_remove_obsolete_settings_fields() -> None:
    """Drop obsolete retention/job-weight settings columns."""
    _drop_column_if_exists("settings", "retention_period")
    _drop_column_if_exists("settings", "enabled_job_weights")


def _migration_004_add_job_task_position() -> None:
    """Persist job task ordering without delete-and-recreate writes."""
    inspector = inspect(db.engine)
    if "job_tasks" not in inspector.get_table_names():
        return

    column_names = {column["name"] for column in inspector.get_columns("job_tasks")}
    column_added = False
    if "position" not in column_names:
        db.session.execute(
            text(
                "ALTER TABLE job_tasks "
                "ADD COLUMN position INTEGER NOT NULL DEFAULT 0"
            )
        )
        db.session.commit()
        column_added = True

    has_nonzero_positions = bool(
        db.session.scalar(text("SELECT 1 FROM job_tasks WHERE position <> 0 LIMIT 1"))
    )
    if column_added or not has_nonzero_positions:
        job_ids = db.session.scalars(
            text("SELECT DISTINCT job_id FROM job_tasks ORDER BY job_id ASC")
        ).all()
        for job_id in job_ids:
            row_ids = db.session.scalars(
                text(
                    "SELECT id FROM job_tasks "
                    "WHERE job_id = :job_id "
                    "ORDER BY id ASC"
                ),
                {"job_id": job_id},
            ).all()
            for position, row_id in enumerate(row_ids):
                db.session.execute(
                    text(
                        "UPDATE job_tasks "
                        "SET position = :position "
                        "WHERE id = :row_id"
                    ),
                    {"position": position, "row_id": row_id},
                )
        db.session.commit()

    if "ix_job_tasks_job_id_position" not in _index_names("job_tasks"):
        db.session.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_job_tasks_job_id_position "
                "ON job_tasks (job_id, position)"
            )
        )
        db.session.commit()


def _migration_005_encrypt_sensitive_hash_material() -> None:
    """Encrypt persisted hash material and add blind-index lookup columns."""
    inspector = inspect(db.engine)
    table_names = inspector.get_table_names()
    if "hashes" not in table_names or "hashfile_hashes" not in table_names:
        return

    hash_columns = {column["name"] for column in inspector.get_columns("hashes")}
    if "plaintext_digest" not in hash_columns:
        db.session.execute(
            text("ALTER TABLE hashes ADD COLUMN plaintext_digest VARCHAR(64)")
        )
        db.session.commit()
    db.session.execute(text("ALTER TABLE hashes ALTER COLUMN plaintext TYPE TEXT"))
    db.session.commit()
    _drop_index_if_exists("ix_hashes_plaintext")
    if "ix_hashes_plaintext_digest" not in _index_names("hashes"):
        db.session.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_hashes_plaintext_digest "
                "ON hashes (plaintext_digest)"
            )
        )
        db.session.commit()

    association_columns = {
        column["name"] for column in inspector.get_columns("hashfile_hashes")
    }
    if "username_digest" not in association_columns:
        db.session.execute(
            text(
                "ALTER TABLE hashfile_hashes "
                "ADD COLUMN username_digest VARCHAR(64) NOT NULL DEFAULT ''"
            )
        )
        db.session.commit()
    db.session.execute(
        text("ALTER TABLE hashfile_hashes ALTER COLUMN username TYPE TEXT")
    )
    db.session.commit()
    db.session.execute(
        text(
            'ALTER TABLE hashfile_hashes '
            'DROP CONSTRAINT IF EXISTS "uq_hashfile_hashes_hashfile_hash_username"'
        )
    )
    db.session.commit()
    _drop_index_if_exists("ix_hashfile_hashes_username")
    if (
        "uq_hashfile_hashes_hashfile_hash_username_digest"
        not in _unique_constraint_names("hashfile_hashes")
    ):
        db.session.execute(
            text(
                "ALTER TABLE hashfile_hashes "
                "ADD CONSTRAINT uq_hashfile_hashes_hashfile_hash_username_digest "
                "UNIQUE (hashfile_id, hash_id, username_digest)"
            )
        )
        db.session.commit()
    if "ix_hashfile_hashes_username_digest" not in _index_names("hashfile_hashes"):
        db.session.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_hashfile_hashes_username_digest "
                "ON hashfile_hashes (username_digest)"
            )
        )
        db.session.commit()

    from hashcrush.utils.secret_storage import migrate_sensitive_storage_rows

    migrate_sensitive_storage_rows()


def _migration_006_add_audit_filter_indexes() -> None:
    """Add indexes for actor/target filtered audit log views."""
    inspector = inspect(db.engine)
    if "audit_logs" not in inspector.get_table_names():
        return

    index_names = _index_names("audit_logs")
    if "ix_audit_logs_actor_username_created_at" not in index_names:
        db.session.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_audit_logs_actor_username_created_at "
                "ON audit_logs (actor_username, created_at)"
            )
        )
        db.session.commit()
    if "ix_audit_logs_target_type_created_at" not in index_names:
        db.session.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_audit_logs_target_type_created_at "
                "ON audit_logs (target_type, created_at)"
            )
        )
        db.session.commit()


def _migration_007_replace_settings_with_upload_operations() -> None:
    """Drop the legacy settings singleton and add persistent upload tracking."""
    UploadOperations.__table__.create(bind=db.engine, checkfirst=True)
    if "settings" in inspect(db.engine).get_table_names():
        db.session.execute(text("DROP TABLE IF EXISTS settings"))
        db.session.commit()


def _add_column_if_missing(
    table_name: str, column_name: str, definition_sql: str
) -> None:
    inspector = inspect(db.engine)
    if table_name not in inspector.get_table_names():
        return
    column_names = {column["name"] for column in inspector.get_columns(table_name)}
    if column_name in column_names:
        return
    db.session.execute(
        text(
            f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition_sql}"
        )
    )
    db.session.commit()


def _migration_008_expand_upload_operations_queue_metadata() -> None:
    """Add queue metadata for the dedicated upload worker."""
    inspector = inspect(db.engine)
    if "upload_operations" not in inspector.get_table_names():
        UploadOperations.__table__.create(bind=db.engine, checkfirst=True)
        return

    _add_column_if_missing(
        "upload_operations",
        "operation_type",
        "VARCHAR(64) NOT NULL DEFAULT 'legacy_inline'",
    )
    _add_column_if_missing(
        "upload_operations",
        "payload_json",
        "TEXT NOT NULL DEFAULT '{}'",
    )
    _add_column_if_missing(
        "upload_operations",
        "lease_expires_at",
        "TIMESTAMP NULL",
    )
    _add_column_if_missing(
        "upload_operations",
        "attempt_count",
        "INTEGER NOT NULL DEFAULT 0",
    )
    if "ix_upload_operations_state_lease_created_at" not in _index_names(
        "upload_operations"
    ):
        db.session.execute(
            text(
                "CREATE INDEX IF NOT EXISTS "
                "ix_upload_operations_state_lease_created_at "
                "ON upload_operations (state, lease_expires_at, created_at)"
            )
        )
        db.session.commit()


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
    MigrationStep(
        version=4,
        name="add_job_task_position",
        summary="Persist job task ordering without recreating rows on reorder.",
        upgrade=_migration_004_add_job_task_position,
    ),
    MigrationStep(
        version=5,
        name="encrypt_sensitive_hash_material",
        summary="Encrypt persisted hashes, cracked plaintexts, and usernames with blind-index lookups.",
        upgrade=_migration_005_encrypt_sensitive_hash_material,
    ),
    MigrationStep(
        version=6,
        name="add_audit_filter_indexes",
        summary="Add audit-log indexes for actor and target filtering.",
        upgrade=_migration_006_add_audit_filter_indexes,
    ),
    MigrationStep(
        version=7,
        name="replace_settings_with_upload_operations",
        summary="Drop the legacy settings singleton and persist async upload state.",
        upgrade=_migration_007_replace_settings_with_upload_operations,
    ),
    MigrationStep(
        version=8,
        name="expand_upload_operations_queue_metadata",
        summary="Add queue metadata for the dedicated upload worker.",
        upgrade=_migration_008_expand_upload_operations_queue_metadata,
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
