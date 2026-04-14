"""In-place schema upgrade support for production deployments."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from sqlalchemy import delete, inspect, select, text

import hashcrush
from hashcrush.models import (
    AuditLog,
    Domains,
    HashSearchTokens,
    HashfileHashSearchTokens,
    HashfileHashes,
    Hashfiles,
    HashPublicExposure,
    ReferenceDatasets,
    SchemaVersion,
    TaskGroups,
    Tasks,
    UploadOperations,
    db,
    utc_now_naive,
)
from hashcrush.utils.secret_storage import (
    decode_username_from_storage,
    get_account_identity_digest,
)

CURRENT_SCHEMA_VERSION = 13


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


def _foreign_keys(table_name: str) -> list[dict]:
    inspector = inspect(db.engine)
    if table_name not in inspector.get_table_names():
        return []
    return inspector.get_foreign_keys(table_name)


def _migration_009_make_domains_optional_and_per_account() -> None:
    """Allow optional hashfile/job domains and persist inferred domains per account."""

    inspector = inspect(db.engine)
    table_names = inspector.get_table_names()
    if "jobs" in table_names:
        db.session.execute(text("ALTER TABLE jobs ALTER COLUMN domain_id DROP NOT NULL"))
        db.session.commit()
    if "hashfiles" in table_names:
        db.session.execute(
            text("ALTER TABLE hashfiles ALTER COLUMN domain_id DROP NOT NULL")
        )
        db.session.commit()
    if "hashfile_hashes" not in table_names:
        return

    _add_column_if_missing("hashfile_hashes", "domain_id", "INTEGER NULL")

    has_domain_fk = any(
        fk.get("referred_table") == "domains"
        and fk.get("constrained_columns") == ["domain_id"]
        for fk in _foreign_keys("hashfile_hashes")
    )
    if not has_domain_fk:
        db.session.execute(
            text(
                "ALTER TABLE hashfile_hashes "
                "ADD CONSTRAINT fk_hashfile_hashes_domain_id_domains "
                "FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE RESTRICT"
            )
        )
        db.session.commit()

    if "ix_hashfile_hashes_domain_id" not in _index_names("hashfile_hashes"):
        db.session.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_hashfile_hashes_domain_id "
                "ON hashfile_hashes (domain_id)"
            )
        )
        db.session.commit()

    db.session.execute(
        text(
            "UPDATE hashfile_hashes "
            "SET domain_id = hashfiles.domain_id "
            "FROM hashfiles "
            "WHERE hashfile_hashes.hashfile_id = hashfiles.id "
            "AND hashfile_hashes.domain_id IS NULL "
            "AND hashfiles.domain_id IS NOT NULL"
        )
    )
    db.session.commit()


def _migration_010_rename_default_mask_tasks() -> None:
    """Rename legacy seeded mask tasks and group to clearer All Characters labels."""
    from hashcrush.setup import default_mask_task_group_name, default_mask_task_name

    legacy_group_name = "maskmode 1-10"

    for length in range(1, 11):
        mask = "?a" * length
        legacy_name = f"{mask} [{length}]"
        task = db.session.scalar(
            select(Tasks).where(
                Tasks.hc_attackmode == "maskmode",
                Tasks.hc_mask == mask,
                Tasks.name == legacy_name,
            )
        )
        if task is not None:
            task.name = default_mask_task_name(length)

    task_group = db.session.scalar(
        select(TaskGroups).where(TaskGroups.name == legacy_group_name)
    )
    if task_group is not None:
        task_group.name = default_mask_task_group_name()

    db.session.commit()


def _migration_011_add_offline_reference_datasets() -> None:
    """Add offline breach-intelligence dataset metadata and exposure cache tables."""

    ReferenceDatasets.__table__.create(bind=db.engine, checkfirst=True)
    HashPublicExposure.__table__.create(bind=db.engine, checkfirst=True)


def _migration_012_add_partial_search_token_indexes() -> None:
    """Add blind-indexed trigram token tables for scalable partial search."""

    HashSearchTokens.__table__.create(bind=db.engine, checkfirst=True)
    HashfileHashSearchTokens.__table__.create(bind=db.engine, checkfirst=True)

    from hashcrush.searches.token_index import migrate_search_token_rows

    migrate_search_token_rows()


def _migration_013_replace_duplicate_account_rows_with_latest_import() -> None:
    """Track per-account identity and collapse duplicate imported account rows."""

    inspector = inspect(db.engine)
    if "hashfile_hashes" not in inspector.get_table_names():
        return

    association_columns = {
        column["name"] for column in inspector.get_columns("hashfile_hashes")
    }
    if "account_digest" not in association_columns:
        db.session.execute(
            text(
                "ALTER TABLE hashfile_hashes "
                "ADD COLUMN account_digest VARCHAR(64)"
            )
        )
        db.session.commit()

    domain_names_by_id = {
        int(domain_id): str(domain_name)
        for domain_id, domain_name in db.session.execute(
            select(Domains.id, Domains.name)
        ).all()
    }
    hashfiles_by_id = {
        int(hashfile_id): {
            "domain_id": domain_id,
            "uploaded_at": uploaded_at,
        }
        for hashfile_id, domain_id, uploaded_at in db.session.execute(
            select(Hashfiles.id, Hashfiles.domain_id, Hashfiles.uploaded_at)
        ).all()
    }

    association_rows = db.session.execute(
        select(HashfileHashes).order_by(HashfileHashes.id.asc())
    ).scalars().all()
    for row in association_rows:
        if not row.username_digest:
            row.account_digest = None
            continue

        hashfile_info = hashfiles_by_id.get(int(row.hashfile_id), {})
        effective_domain_id = row.domain_id or hashfile_info.get("domain_id")
        effective_domain_name = (
            domain_names_by_id.get(int(effective_domain_id))
            if effective_domain_id is not None
            else None
        )
        decoded_username = decode_username_from_storage(row.username)
        row.account_digest = get_account_identity_digest(
            effective_domain_name,
            decoded_username,
        )
        if row.domain_id is None and effective_domain_id is not None:
            row.domain_id = int(effective_domain_id)
    db.session.commit()

    duplicate_rows = db.session.execute(
        select(
            HashfileHashes.id,
            HashfileHashes.account_digest,
            HashfileHashes.hashfile_id,
        )
        .where(HashfileHashes.account_digest.is_not(None))
        .order_by(HashfileHashes.account_digest.asc(), HashfileHashes.id.desc())
    ).all()

    ranked_rows_by_digest: dict[str, list[tuple[int, object, int]]] = defaultdict(list)
    for row_id, account_digest, hashfile_id in duplicate_rows:
        hashfile_info = hashfiles_by_id.get(int(hashfile_id), {})
        ranked_rows_by_digest[str(account_digest)].append(
            (
                int(row_id),
                hashfile_info.get("uploaded_at") or utc_now_naive(),
                int(hashfile_id),
            )
        )

    delete_ids: list[int] = []
    for ranked_rows in ranked_rows_by_digest.values():
        if len(ranked_rows) <= 1:
            continue
        ranked_rows.sort(key=lambda item: (item[1], item[0]), reverse=True)
        delete_ids.extend(row_id for row_id, _, _ in ranked_rows[1:])

    if delete_ids:
        db.session.execute(
            delete(HashfileHashes).where(HashfileHashes.id.in_(delete_ids))
        )
        db.session.commit()

    if "ix_hashfile_hashes_account_digest" not in _index_names("hashfile_hashes"):
        db.session.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS ix_hashfile_hashes_account_digest "
                "ON hashfile_hashes (account_digest)"
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
    MigrationStep(
        version=9,
        name="make_domains_optional_and_per_account",
        summary="Allow optional hashfile/job domains and persist inferred domains per imported account.",
        upgrade=_migration_009_make_domains_optional_and_per_account,
    ),
    MigrationStep(
        version=10,
        name="rename_default_mask_tasks",
        summary="Rename default mask tasks and task group to clearer All Characters labels.",
        upgrade=_migration_010_rename_default_mask_tasks,
    ),
    MigrationStep(
        version=11,
        name="add_offline_reference_datasets",
        summary="Track offline breach-intelligence datasets and cached exposure matches.",
        upgrade=_migration_011_add_offline_reference_datasets,
    ),
    MigrationStep(
        version=12,
        name="add_partial_search_token_indexes",
        summary="Add blind-indexed trigram token tables for scalable partial search.",
        upgrade=_migration_012_add_partial_search_token_indexes,
    ),
    MigrationStep(
        version=13,
        name="replace_duplicate_account_rows_with_latest_import",
        summary="Track imported account identity and keep only the latest row per domain and username.",
        upgrade=_migration_013_replace_duplicate_account_rows_with_latest_import,
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
