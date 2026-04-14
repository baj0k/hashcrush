"""Shared helpers for search exports and domain-scoped background exports."""

from __future__ import annotations

import csv
import os
import re
from datetime import UTC, datetime

from sqlalchemy import and_, func, or_, select

from hashcrush.models import Hashes, HashfileHashes, Hashfiles, db
from hashcrush.utils.secret_storage import (
    decode_ciphertext_from_storage,
    decode_plaintext_from_storage,
    decode_username_from_storage,
)
from hashcrush.utils.storage_paths import get_runtime_subdir

SEARCH_DOMAIN_EXPORT_OPERATION_TYPE = "search_domain_export"


def _domain_scope_predicate(domain_id: int):
    return or_(
        HashfileHashes.domain_id == domain_id,
        and_(
            HashfileHashes.domain_id.is_(None),
            Hashfiles.domain_id == domain_id,
        ),
    )


def domain_export_stmt(domain_id: int):
    """Return the shared domain-scope statement used by browse and export flows."""

    return (
        select(Hashes, HashfileHashes)
        .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
        .join(Hashfiles, Hashfiles.id == HashfileHashes.hashfile_id)
        .where(_domain_scope_predicate(domain_id))
        .order_by(HashfileHashes.id.asc())
    )


def count_domain_export_rows(domain_id: int) -> int:
    """Return the number of rows included in a domain-scoped export."""

    return int(
        db.session.scalar(
            select(func.count(HashfileHashes.id))
            .select_from(HashfileHashes)
            .join(Hashfiles, Hashfiles.id == HashfileHashes.hashfile_id)
            .where(_domain_scope_predicate(domain_id))
        )
        or 0
    )


def iter_domain_export_rows(domain_id: int):
    """Iterate domain-scoped export rows in stable ID order without one long cursor."""

    batch_size = 1000
    last_seen_id = 0
    while True:
        rows = (
            db.session.execute(
                domain_export_stmt(domain_id)
                .where(HashfileHashes.id > last_seen_id)
                .limit(batch_size)
            )
            .tuples()
            .all()
        )
        if not rows:
            return
        for row in rows:
            yield row
        last_seen_id = int(rows[-1][1].id)


def export_separator_from_label(separator_label: str | None) -> str:
    """Normalize a user-facing separator label to a concrete delimiter."""

    return "," if str(separator_label or "").strip().lower() == "comma" else ":"


def write_search_export_row(
    writer: csv.writer,
    *,
    domain_name: str | None,
    hash_row: Hashes,
    link_row: HashfileHashes,
) -> None:
    """Write one exported search row using decoded display values."""

    username = decode_username_from_storage(link_row.username) or "None"
    ciphertext = decode_ciphertext_from_storage(hash_row.ciphertext) or ""
    plaintext = (
        decode_plaintext_from_storage(hash_row.plaintext) or ""
        if hash_row.cracked
        else "unrecovered"
    )
    writer.writerow(
        [
            domain_name or "None",
            username,
            ciphertext,
            plaintext,
        ]
    )


def domain_export_artifact_path(operation_id: str) -> str:
    """Return the runtime path for a completed domain export artifact."""

    exports_dir = get_runtime_subdir("exports")
    os.makedirs(exports_dir, exist_ok=True)
    return os.path.join(exports_dir, f"search-domain-export-{operation_id}.txt")


def remove_domain_export_artifact(operation_id: str) -> None:
    """Best-effort cleanup for a domain export artifact."""

    artifact_path = domain_export_artifact_path(operation_id)
    try:
        if os.path.isfile(artifact_path):
            os.remove(artifact_path)
    except OSError:
        pass


def build_domain_export_download_name(
    domain_name: str | None,
    *,
    separator_label: str | None,
    exported_at: datetime | None = None,
) -> str:
    """Build a stable human-readable filename for a domain export download."""

    timestamp = (exported_at or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
    slug_source = (domain_name or "none").strip().lower()
    slug = re.sub(r"[^a-z0-9]+", "_", slug_source).strip("_") or "none"
    extension = "csv" if export_separator_from_label(separator_label) == "," else "txt"
    return f"domain_entries_{slug}_{timestamp}.{extension}"
