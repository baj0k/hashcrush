"""Offline HIBP NTLM dataset loading and exposure matching."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
from array import array
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable

from flask import current_app
import lmdb
from sqlalchemy import delete, func, select

from hashcrush.hibp.lmdb_builder import build_db_from_file
from hashcrush.models import (
    HashPublicExposure,
    Hashes,
    HashfileHashes,
    ReferenceDatasets,
    db,
    utc_now_naive,
)
from hashcrush.utils.secret_storage import decode_ciphertext_from_storage
from hashcrush.utils.storage_paths import get_storage_subdir

HIBP_NTLM_KIND = "hibp_ntlm"
HIBP_NTLM_NAME = "Have I Been Pwned NTLM"
NTLM_HASH_TYPE = 1000
_LOAD_BATCH_SIZE = 5000
_SCAN_BATCH_SIZE = 500
_PREFIX_WIDTH = 5
_PREFIX_SPACE = 16**_PREFIX_WIDTH
_PREFIX_OFFSET_VERSION = 1
_LMDB_DATASET_VERSION = 1


def _natural_sort_key(value: str) -> list[object]:
    return [
        int(chunk) if chunk.isdigit() else chunk.lower()
        for chunk in re.split(r"(\d+)", str(value or ""))
    ]


def _normalize_path(value: str | None) -> str:
    return os.path.realpath(
        os.path.abspath(os.path.expanduser(str(value or "").strip()))
    )


def _is_path_within_root(path: str | None, root: str | None) -> bool:
    normalized_path = _normalize_path(path)
    normalized_root = _normalize_path(root)
    if not normalized_path or not normalized_root:
        return False
    try:
        return os.path.commonpath([normalized_path, normalized_root]) == normalized_root
    except ValueError:
        return False


def get_hibp_ntlm_dataset_mount_root() -> str:
    """Return the configured container-visible root for mounted HIBP datasets."""

    return _normalize_path(
        current_app.config.get("HIBP_DATASETS_PATH") or "/mnt/hashcrush-hibp"
    )


def list_mounted_hibp_ntlm_dataset_files() -> list[str]:
    """Return readable mounted HIBP dataset files under the configured root."""

    root = get_hibp_ntlm_dataset_mount_root()
    if not root or not os.path.isdir(root):
        return []

    results: list[str] = []
    for current_root, dirnames, filenames in os.walk(root):
        dirnames.sort(key=_natural_sort_key)
        for filename in sorted(filenames, key=_natural_sort_key):
            candidate = _normalize_path(os.path.join(current_root, filename))
            if not _is_path_within_root(candidate, root):
                continue
            if not os.path.isfile(candidate):
                continue
            if not os.access(candidate, os.R_OK):
                continue
            results.append(candidate)
    return results


def validate_mounted_hibp_ntlm_dataset_path(
    selected_path: str | None,
) -> tuple[str | None, str | None]:
    """Validate a mounted offline HIBP dataset path against the configured root."""

    raw_value = str(selected_path or "").strip()
    if not raw_value:
        return None, "Mounted dataset path is required."
    if not os.path.isabs(raw_value):
        return None, "Mounted dataset paths must be absolute container paths."

    normalized_path = _normalize_path(raw_value)
    mounted_root = get_hibp_ntlm_dataset_mount_root()
    if not mounted_root:
        return None, "No mounted HIBP dataset path is configured for this deployment."
    if not _is_path_within_root(normalized_path, mounted_root):
        return None, f"Mounted dataset path must live under: {mounted_root}."
    if not os.path.isfile(normalized_path):
        return None, "Mounted dataset file does not exist at that path."
    if not os.access(normalized_path, os.R_OK):
        return None, "Mounted dataset file is not readable by the application."
    return normalized_path, None


@dataclass(frozen=True)
class HIBPNTLMDatasetSummary:
    """Loaded offline HIBP NTLM dataset metadata."""

    loaded: bool
    version_label: str | None = None
    source_filename: str | None = None
    record_count: int = 0
    checksum: str | None = None
    loaded_at: datetime | None = None
    path: str | None = None


@dataclass(frozen=True)
class HIBPNTLMLoadResult:
    """Result details for a newly loaded HIBP NTLM dataset."""

    version_label: str
    source_filename: str | None
    checksum: str
    record_count: int
    dataset_path: str
    matched_hash_count: int
    matched_account_count: int


@dataclass(frozen=True)
class PublicExposureScanResult:
    """Result details for a public exposure scan."""

    scanned_hash_count: int
    matched_hash_count: int
    matched_account_count: int


@dataclass(frozen=True)
class PublicExposureSummary:
    """Aggregated exposure counts for a scope."""

    dataset_loaded: bool
    dataset_version_label: str | None
    dataset_loaded_at: datetime | None
    eligible_hash_count: int
    exposed_hash_count: int
    eligible_account_count: int
    exposed_account_count: int
    last_checked_at: datetime | None


@dataclass(frozen=True)
class HIBPNTLMPrefixIndex:
    """Resolved paths for the compact offline HIBP prefix index."""

    manifest_path: str
    source_path: str
    offsets_path: str


@dataclass(frozen=True)
class HIBPNTLMLmdbDataset:
    """Resolved paths for an LMDB-backed offline HIBP dataset."""

    manifest_path: str
    db_path: str


def _reference_storage_root() -> str:
    root = os.path.join(get_storage_subdir("reference-datasets"), "hibp-ntlm")
    os.makedirs(root, exist_ok=True)
    return root


def _normalize_ntlm_hash(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip().upper()
    if len(normalized) != 32:
        return None
    if any(char not in "0123456789ABCDEF" for char in normalized):
        return None
    return normalized


def _active_dataset_record() -> ReferenceDatasets | None:
    return db.session.scalar(
        select(ReferenceDatasets).where(ReferenceDatasets.kind == HIBP_NTLM_KIND)
    )


def get_hibp_ntlm_dataset_summary() -> HIBPNTLMDatasetSummary:
    """Return metadata about the currently loaded offline NTLM dataset."""

    dataset = _active_dataset_record()
    if dataset is None:
        return HIBPNTLMDatasetSummary(loaded=False)
    return HIBPNTLMDatasetSummary(
        loaded=True,
        version_label=dataset.version_label,
        source_filename=dataset.source_filename,
        record_count=int(dataset.record_count or 0),
        checksum=dataset.checksum,
        loaded_at=dataset.loaded_at,
        path=dataset.path,
    )


def _sqlite_connect(path: str, *, writable: bool) -> sqlite3.Connection:
    if writable:
        connection = sqlite3.connect(path)
    else:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def _dataset_lookup_path(dataset_path: str | None = None) -> str | None:
    selected_path = dataset_path
    if not selected_path:
        dataset = _active_dataset_record()
        if dataset is None:
            return None
        selected_path = dataset.path
    resolved = os.path.abspath(os.path.expanduser(str(selected_path)))
    return resolved if os.path.isfile(resolved) else None


def _is_legacy_sqlite_dataset(path: str) -> bool:
    if not os.path.isfile(path):
        return False
    try:
        with open(path, "rb") as handle:
            return handle.read(16) == b"SQLite format 3\x00"
    except OSError:
        return False


def _recommended_lmdb_map_size_gb(source_path: str) -> int:
    source_size = max(1, os.path.getsize(source_path))
    gib = 1 << 30
    estimated = (source_size * 3 + (2 * gib) - 1) // (2 * gib)
    return max(4, min(256, int(estimated)))


def _hibp_map_size_gb(source_path: str) -> int:
    recommended = _recommended_lmdb_map_size_gb(source_path)
    minimum = max(
        4,
        int(current_app.config.get("HIBP_DATASET_MIN_MAP_SIZE_GB", 128) or 128),
    )
    return max(recommended, minimum)


def _prefix_to_int(prefix: str) -> int:
    return int(prefix, 16)


def _write_prefix_offset_index(
    source_path: str,
    offsets_path: str,
    *,
    progress_callback: Callable[[int, int], None] | None = None,
) -> tuple[str, int]:
    checksum = hashlib.sha256()
    total_size = os.path.getsize(source_path)
    processed_bytes = 0
    record_count = 0
    previous_hash: str | None = None
    next_fill_index = 0
    prefix_offsets = [0] * (_PREFIX_SPACE + 1)

    with open(source_path, "rb") as source_handle:
        while True:
            line_start = processed_bytes
            raw_line = source_handle.readline()
            if not raw_line:
                break

            processed_bytes += len(raw_line)
            checksum.update(raw_line)
            if progress_callback is not None:
                progress_callback(processed_bytes, total_size)

            line = raw_line.decode("utf-8", errors="ignore").strip()
            if not line:
                continue

            ntlm_hash, separator, count_text = line.partition(":")
            normalized_hash = _normalize_ntlm_hash(ntlm_hash if separator else line)
            if normalized_hash is None or (separator and not count_text.isdigit()):
                raise ValueError(
                    "Offline HIBP NTLM dataset must contain one NTLM hash per line "
                    "in HASH or HASH:COUNT format."
                )
            if previous_hash is not None and normalized_hash < previous_hash:
                raise ValueError(
                    "Offline HIBP NTLM dataset must be sorted by NTLM hash for fast offline indexing."
                )
            previous_hash = normalized_hash
            prefix_index = _prefix_to_int(normalized_hash[:_PREFIX_WIDTH])
            while next_fill_index <= prefix_index:
                prefix_offsets[next_fill_index] = line_start
                next_fill_index += 1
            record_count += 1

    while next_fill_index <= _PREFIX_SPACE:
        prefix_offsets[next_fill_index] = processed_bytes
        next_fill_index += 1

    with open(offsets_path, "wb") as offsets_handle:
        array("Q", prefix_offsets).tofile(offsets_handle)

    if progress_callback is not None:
        progress_callback(total_size, total_size)
    return checksum.hexdigest(), record_count


def _write_prefix_index_manifest(
    manifest_path: str,
    *,
    source_path: str,
    offsets_path: str,
) -> None:
    payload = {
        "format": "hibp_ntlm_prefix_offsets",
        "version": _PREFIX_OFFSET_VERSION,
        "source_path": source_path,
        "offsets_path": offsets_path,
    }
    with open(manifest_path, "w", encoding="utf-8") as manifest_handle:
        json.dump(payload, manifest_handle, sort_keys=True)


def _write_lmdb_manifest(
    manifest_path: str,
    *,
    db_path: str,
) -> None:
    payload = {
        "format": "hibp_ntlm_lmdb",
        "version": _LMDB_DATASET_VERSION,
        "db_path": db_path,
    }
    with open(manifest_path, "w", encoding="utf-8") as manifest_handle:
        json.dump(payload, manifest_handle, sort_keys=True)


def _load_prefix_index_dataset(manifest_path: str) -> HIBPNTLMPrefixIndex:
    with open(manifest_path, "r", encoding="utf-8") as manifest_handle:
        payload = json.load(manifest_handle)
    if (
        not isinstance(payload, dict)
        or payload.get("format") != "hibp_ntlm_prefix_offsets"
        or int(payload.get("version") or 0) != _PREFIX_OFFSET_VERSION
    ):
        raise ValueError("Unsupported HIBP NTLM dataset index format.")

    source_path = _normalize_path(payload.get("source_path"))
    offsets_path = _normalize_path(payload.get("offsets_path"))
    if not os.path.isfile(source_path):
        raise FileNotFoundError(f"Offline HIBP NTLM source file is missing: {source_path}")
    if not os.path.isfile(offsets_path):
        raise FileNotFoundError(f"Offline HIBP NTLM offsets file is missing: {offsets_path}")
    return HIBPNTLMPrefixIndex(
        manifest_path=_normalize_path(manifest_path),
        source_path=source_path,
        offsets_path=offsets_path,
    )


def _load_lmdb_dataset(manifest_path: str) -> HIBPNTLMLmdbDataset:
    with open(manifest_path, "r", encoding="utf-8") as manifest_handle:
        payload = json.load(manifest_handle)
    if (
        not isinstance(payload, dict)
        or payload.get("format") != "hibp_ntlm_lmdb"
        or int(payload.get("version") or 0) != _LMDB_DATASET_VERSION
    ):
        raise ValueError("Unsupported HIBP NTLM LMDB dataset format.")

    db_path = _normalize_path(payload.get("db_path"))
    if not os.path.isdir(db_path):
        raise FileNotFoundError(f"Offline HIBP NTLM LMDB path is missing: {db_path}")
    return HIBPNTLMLmdbDataset(
        manifest_path=_normalize_path(manifest_path),
        db_path=db_path,
    )


def _read_prefix_offsets(offsets_path: str) -> array:
    expected_entries = _PREFIX_SPACE + 1
    offsets = array("Q")
    with open(offsets_path, "rb") as offsets_handle:
        offsets.fromfile(offsets_handle, expected_entries)
    if len(offsets) != expected_entries:
        raise ValueError("Offline HIBP NTLM offsets file is truncated or invalid.")
    return offsets


def _existing_exposure_rows(hash_ids: list[int]) -> dict[int, HashPublicExposure]:
    if not hash_ids:
        return {}
    rows = db.session.execute(
        select(HashPublicExposure).where(
            HashPublicExposure.hash_id.in_(hash_ids),
            HashPublicExposure.source_kind == HIBP_NTLM_KIND,
        )
    ).scalars().all()
    return {int(row.hash_id): row for row in rows}


def _iter_ntlm_hash_records(hashfile_id: int | None = None) -> list[tuple[int, str | None]]:
    stmt = select(Hashes.id, Hashes.ciphertext).where(Hashes.hash_type == NTLM_HASH_TYPE)
    if hashfile_id is not None:
        stmt = (
            stmt.join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
            .where(HashfileHashes.hashfile_id == hashfile_id)
            .distinct()
        )
    return [
        (int(hash_id), ciphertext)
        for hash_id, ciphertext in db.session.execute(stmt).all()
    ]


def _count_matched_accounts_for_scope(hashfile_id: int | None = None) -> int:
    stmt = (
        select(func.count(HashfileHashes.id))
        .select_from(HashfileHashes)
        .join(Hashes, Hashes.id == HashfileHashes.hash_id)
        .join(
            HashPublicExposure,
            HashPublicExposure.hash_id == Hashes.id,
        )
        .where(Hashes.hash_type == NTLM_HASH_TYPE)
        .where(HashPublicExposure.source_kind == HIBP_NTLM_KIND)
        .where(HashPublicExposure.matched.is_(True))
    )
    if hashfile_id is not None:
        stmt = stmt.where(HashfileHashes.hashfile_id == hashfile_id)
    return int(db.session.scalar(stmt) or 0)


def _lookup_match_counts_legacy_sqlite(
    connection: sqlite3.Connection,
    ntlm_hashes: list[str],
) -> dict[str, int]:
    if not ntlm_hashes:
        return {}
    placeholders = ",".join("?" for _ in ntlm_hashes)
    cursor = connection.execute(
        f"SELECT ntlm_hash, prevalence_count FROM ntlm_hashes WHERE ntlm_hash IN ({placeholders})",
        ntlm_hashes,
    )
    return {str(row["ntlm_hash"]): int(row["prevalence_count"]) for row in cursor.fetchall()}


def _lookup_match_counts_prefix_index(
    dataset: HIBPNTLMPrefixIndex,
    ntlm_hashes: list[str],
    *,
    offsets: array | None = None,
) -> dict[str, int]:
    if not ntlm_hashes:
        return {}

    resolved_offsets = offsets if offsets is not None else _read_prefix_offsets(dataset.offsets_path)
    hashes_by_prefix: dict[str, set[str]] = {}
    for ntlm_hash in ntlm_hashes:
        if not ntlm_hash:
            continue
        prefix = ntlm_hash[:_PREFIX_WIDTH]
        hashes_by_prefix.setdefault(prefix, set()).add(ntlm_hash)

    matches: dict[str, int] = {}
    with open(dataset.source_path, "rb") as source_handle:
        for prefix, target_hashes in hashes_by_prefix.items():
            prefix_index = _prefix_to_int(prefix)
            start_offset = int(resolved_offsets[prefix_index])
            end_offset = int(resolved_offsets[prefix_index + 1])
            if end_offset <= start_offset:
                continue

            source_handle.seek(start_offset)
            while source_handle.tell() < end_offset:
                raw_line = source_handle.readline()
                if not raw_line:
                    break
                line = raw_line.decode("utf-8", errors="ignore").strip()
                if not line:
                    continue
                ntlm_hash, separator, _count_text = line.partition(":")
                normalized_hash = _normalize_ntlm_hash(ntlm_hash if separator else line)
                if normalized_hash is None or normalized_hash not in target_hashes:
                    continue
                matches[normalized_hash] = 0
                if len(matches) >= len(ntlm_hashes):
                    return matches
    return matches


def _lookup_match_counts_lmdb(
    transaction,
    ntlm_hashes: list[str],
) -> dict[str, int]:
    if not ntlm_hashes:
        return {}

    matches: dict[str, int] = {}
    get = transaction.get
    for ntlm_hash in dict.fromkeys(ntlm_hashes):
        try:
            key = bytes.fromhex(ntlm_hash)
        except ValueError:
            continue
        if get(key) is not None:
            matches[ntlm_hash] = 0
    return matches


def _batched(sequence: list[tuple[int, str | None]], size: int):
    for index in range(0, len(sequence), size):
        yield sequence[index : index + size]


def _scan_hash_records(
    hash_records: list[tuple[int, str | None]],
    *,
    dataset_path: str,
    progress_callback: Callable[[int, int], None] | None = None,
    hashfile_id: int | None = None,
) -> PublicExposureScanResult:
    total = len(hash_records)
    if total <= 0:
        return PublicExposureScanResult(
            scanned_hash_count=0,
            matched_hash_count=0,
            matched_account_count=0,
        )

    matched_hash_count = 0
    processed = 0
    lmdb_env = None
    lmdb_txn = None
    lmdb_dataset: HIBPNTLMLmdbDataset | None = None
    prefix_index_dataset: HIBPNTLMPrefixIndex | None = None
    prefix_offsets: array | None = None
    sqlite_connection: sqlite3.Connection | None = None
    try:
        if _is_legacy_sqlite_dataset(dataset_path):
            sqlite_connection = _sqlite_connect(dataset_path, writable=False)
        else:
            with open(dataset_path, "r", encoding="utf-8") as manifest_handle:
                manifest_payload = json.load(manifest_handle)
            manifest_format = (
                manifest_payload.get("format")
                if isinstance(manifest_payload, dict)
                else None
            )
            if manifest_format == "hibp_ntlm_lmdb":
                lmdb_dataset = _load_lmdb_dataset(dataset_path)
                lmdb_env = lmdb.open(
                    lmdb_dataset.db_path,
                    readonly=True,
                    lock=False,
                    max_readers=126,
                )
                lmdb_txn = lmdb_env.begin(write=False)
            else:
                prefix_index_dataset = _load_prefix_index_dataset(dataset_path)
                prefix_offsets = _read_prefix_offsets(prefix_index_dataset.offsets_path)

        for batch in _batched(hash_records, _SCAN_BATCH_SIZE):
            batch_ids = [int(hash_id) for hash_id, _ in batch]
            existing_rows = _existing_exposure_rows(batch_ids)
            normalized_by_hash_id: dict[int, str] = {}
            for hash_id, ciphertext in batch:
                normalized_hash = _normalize_ntlm_hash(
                    decode_ciphertext_from_storage(ciphertext)
                )
                if normalized_hash:
                    normalized_by_hash_id[int(hash_id)] = normalized_hash

            if sqlite_connection is not None:
                match_counts = _lookup_match_counts_legacy_sqlite(
                    sqlite_connection, list(normalized_by_hash_id.values())
                )
            elif lmdb_txn is not None:
                match_counts = _lookup_match_counts_lmdb(
                    lmdb_txn,
                    list(normalized_by_hash_id.values()),
                )
            else:
                assert prefix_index_dataset is not None
                match_counts = _lookup_match_counts_prefix_index(
                    prefix_index_dataset,
                    list(normalized_by_hash_id.values()),
                    offsets=prefix_offsets,
                )

            for hash_id in batch_ids:
                normalized_hash = normalized_by_hash_id.get(hash_id)
                matched = bool(normalized_hash) and normalized_hash in match_counts
                prevalence_count = int(match_counts.get(normalized_hash or "", 0)) if matched else 0
                exposure = existing_rows.get(hash_id)
                if exposure is None:
                    exposure = HashPublicExposure(
                        hash_id=hash_id,
                        source_kind=HIBP_NTLM_KIND,
                    )
                    db.session.add(exposure)
                exposure.matched = matched
                exposure.prevalence_count = prevalence_count
                exposure.checked_at = utc_now_naive()
                if matched:
                    matched_hash_count += 1

            db.session.commit()
            processed += len(batch)
            if progress_callback is not None:
                progress_callback(processed, total)
    finally:
        if sqlite_connection is not None:
            sqlite_connection.close()
        if lmdb_env is not None:
            lmdb_env.close()

    if progress_callback is not None:
        progress_callback(total, total)

    return PublicExposureScanResult(
        scanned_hash_count=total,
        matched_hash_count=matched_hash_count,
        matched_account_count=_count_matched_accounts_for_scope(hashfile_id),
    )


def scan_hashfile_against_hibp_dataset(
    hashfile_id: int,
    *,
    dataset_path: str | None = None,
    progress_callback: Callable[[int, int], None] | None = None,
) -> PublicExposureScanResult:
    """Check one hashfile's NTLM hashes against the active offline dataset."""

    resolved_dataset_path = _dataset_lookup_path(dataset_path)
    if resolved_dataset_path is None:
        return PublicExposureScanResult(0, 0, 0)
    hash_records = _iter_ntlm_hash_records(hashfile_id)
    return _scan_hash_records(
        hash_records,
        dataset_path=resolved_dataset_path,
        progress_callback=progress_callback,
        hashfile_id=hashfile_id,
    )


def scan_all_ntlm_hashes_against_hibp_dataset(
    *,
    dataset_path: str | None = None,
    progress_callback: Callable[[int, int], None] | None = None,
) -> PublicExposureScanResult:
    """Check every stored NTLM hash against the active offline dataset."""

    resolved_dataset_path = _dataset_lookup_path(dataset_path)
    if resolved_dataset_path is None:
        return PublicExposureScanResult(0, 0, 0)
    hash_records = _iter_ntlm_hash_records()
    return _scan_hash_records(
        hash_records,
        dataset_path=resolved_dataset_path,
        progress_callback=progress_callback,
        hashfile_id=None,
    )


def load_hibp_ntlm_dataset_from_source(
    source_path: str,
    *,
    version_label: str | None = None,
    source_filename: str | None = None,
    progress_callback: Callable[[str, int, int], None] | None = None,
    persist_source_copy: bool = False,
) -> HIBPNTLMLoadResult:
    """Build and activate an offline HIBP NTLM lookup dataset from a source file."""

    resolved_source_path = os.path.abspath(os.path.expanduser(source_path))
    if not os.path.isfile(resolved_source_path):
        raise FileNotFoundError(f"Offline HIBP NTLM source file is missing: {source_path}")

    dataset_token = secrets.token_hex(8)
    timestamp_label = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    dataset_dir = os.path.join(_reference_storage_root(), f"dataset-{timestamp_label}-{dataset_token}")
    os.makedirs(dataset_dir, exist_ok=True)
    manifest_path = os.path.join(dataset_dir, "hibp_ntlm_dataset.json")
    lmdb_path = os.path.join(dataset_dir, "lmdb")
    indexed_source_path = resolved_source_path

    try:
        if persist_source_copy:
            retained_filename = source_filename or Path(resolved_source_path).name or "hibp-ntlm.txt"
            retained_source_path = os.path.join(dataset_dir, retained_filename)
            if os.path.abspath(retained_source_path) != os.path.abspath(resolved_source_path):
                shutil.move(resolved_source_path, retained_source_path)
            indexed_source_path = retained_source_path

        build_result = build_db_from_file(
            indexed_source_path,
            db_path=lmdb_path,
            map_size_gb=_hibp_map_size_gb(indexed_source_path),
            progress_callback=(
                (lambda stage, current, total: progress_callback(stage, current, total))
                if progress_callback is not None
                else None
            ),
        )
        _write_lmdb_manifest(
            manifest_path,
            db_path=lmdb_path,
        )
    except Exception:
        shutil.rmtree(dataset_dir, ignore_errors=True)
        raise

    previous_dataset = _active_dataset_record()
    previous_path = previous_dataset.path if previous_dataset is not None else None
    selected_version_label = (
        str(version_label).strip()
        if str(version_label or "").strip()
        else str(source_filename or Path(resolved_source_path).name)
    )

    if previous_dataset is None:
        previous_dataset = ReferenceDatasets(
            kind=HIBP_NTLM_KIND,
            name=HIBP_NTLM_NAME,
            version_label=selected_version_label,
            source_filename=source_filename or Path(indexed_source_path).name,
            path=manifest_path,
            checksum=build_result.checksum,
            record_count=build_result.input_record_count,
            loaded_at=utc_now_naive(),
        )
        db.session.add(previous_dataset)
    else:
        previous_dataset.name = HIBP_NTLM_NAME
        previous_dataset.version_label = selected_version_label
        previous_dataset.source_filename = source_filename or Path(indexed_source_path).name
        previous_dataset.path = manifest_path
        previous_dataset.checksum = build_result.checksum
        previous_dataset.record_count = build_result.input_record_count
        previous_dataset.loaded_at = utc_now_naive()
    db.session.execute(
        delete(HashPublicExposure).where(
            HashPublicExposure.source_kind == HIBP_NTLM_KIND
        )
    )
    db.session.commit()

    if previous_path and os.path.abspath(previous_path) != os.path.abspath(manifest_path):
        try:
            shutil.rmtree(os.path.dirname(previous_path), ignore_errors=True)
        except OSError:
            pass

    return HIBPNTLMLoadResult(
        version_label=selected_version_label,
        source_filename=source_filename or Path(indexed_source_path).name,
        checksum=build_result.checksum,
        record_count=build_result.input_record_count,
        dataset_path=manifest_path,
        matched_hash_count=0,
        matched_account_count=0,
    )


def public_exposure_summary_for_hashfile_ids(
    scoped_hashfile_ids: list[int],
) -> PublicExposureSummary:
    """Return aggregate public-exposure counts for analytics/hashfile detail views."""

    dataset = _active_dataset_record()
    if not scoped_hashfile_ids:
        return PublicExposureSummary(
            dataset_loaded=dataset is not None,
            dataset_version_label=dataset.version_label if dataset else None,
            dataset_loaded_at=dataset.loaded_at if dataset else None,
            eligible_hash_count=0,
            exposed_hash_count=0,
            eligible_account_count=0,
            exposed_account_count=0,
            last_checked_at=None,
        )

    eligible_hash_count = int(
        db.session.scalar(
            select(func.count(func.distinct(Hashes.id)))
            .select_from(Hashes)
            .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
            .where(HashfileHashes.hashfile_id.in_(scoped_hashfile_ids))
            .where(Hashes.hash_type == NTLM_HASH_TYPE)
        )
        or 0
    )
    eligible_account_count = int(
        db.session.scalar(
            select(func.count(HashfileHashes.id))
            .select_from(HashfileHashes)
            .join(Hashes, Hashes.id == HashfileHashes.hash_id)
            .where(HashfileHashes.hashfile_id.in_(scoped_hashfile_ids))
            .where(Hashes.hash_type == NTLM_HASH_TYPE)
        )
        or 0
    )

    if dataset is None:
        return PublicExposureSummary(
            dataset_loaded=False,
            dataset_version_label=None,
            dataset_loaded_at=None,
            eligible_hash_count=eligible_hash_count,
            exposed_hash_count=0,
            eligible_account_count=eligible_account_count,
            exposed_account_count=0,
            last_checked_at=None,
        )

    exposed_hash_count = int(
        db.session.scalar(
            select(func.count(func.distinct(Hashes.id)))
            .select_from(Hashes)
            .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
            .join(HashPublicExposure, HashPublicExposure.hash_id == Hashes.id)
            .where(HashfileHashes.hashfile_id.in_(scoped_hashfile_ids))
            .where(Hashes.hash_type == NTLM_HASH_TYPE)
            .where(HashPublicExposure.source_kind == HIBP_NTLM_KIND)
            .where(HashPublicExposure.matched.is_(True))
        )
        or 0
    )
    exposed_account_count = int(
        db.session.scalar(
            select(func.count(HashfileHashes.id))
            .select_from(HashfileHashes)
            .join(Hashes, Hashes.id == HashfileHashes.hash_id)
            .join(HashPublicExposure, HashPublicExposure.hash_id == Hashes.id)
            .where(HashfileHashes.hashfile_id.in_(scoped_hashfile_ids))
            .where(Hashes.hash_type == NTLM_HASH_TYPE)
            .where(HashPublicExposure.source_kind == HIBP_NTLM_KIND)
            .where(HashPublicExposure.matched.is_(True))
        )
        or 0
    )
    last_checked_at = db.session.scalar(
        select(func.max(HashPublicExposure.checked_at))
        .select_from(HashPublicExposure)
        .join(Hashes, Hashes.id == HashPublicExposure.hash_id)
        .join(HashfileHashes, HashfileHashes.hash_id == Hashes.id)
        .where(HashfileHashes.hashfile_id.in_(scoped_hashfile_ids))
        .where(Hashes.hash_type == NTLM_HASH_TYPE)
        .where(HashPublicExposure.source_kind == HIBP_NTLM_KIND)
    )

    return PublicExposureSummary(
        dataset_loaded=True,
        dataset_version_label=dataset.version_label,
        dataset_loaded_at=dataset.loaded_at,
        eligible_hash_count=eligible_hash_count,
        exposed_hash_count=exposed_hash_count,
        eligible_account_count=eligible_account_count,
        exposed_account_count=exposed_account_count,
        last_checked_at=last_checked_at,
    )
