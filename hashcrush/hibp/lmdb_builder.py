"""Shared LMDB builder for large offline NTLM datasets."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterator

import binascii
import hashlib
import lmdb
import pathlib
import sys
import time

MAP_SIZE_GB = 256
KEY_LEN_BYTES = 16
HEX_LEN = KEY_LEN_BYTES * 2
DEFAULT_STREAM_TRANSACTION_KEYS = 100_000


@dataclass(frozen=True)
class BuildDbResult:
    """Summary information from building an LMDB hash database."""

    checksum: str
    input_record_count: int
    inserted_record_count: int


def human(n: int) -> str:
    """Render a large integer with compact binary suffixes."""

    for unit in ["", "K", "M", "G", "T"]:
        if abs(n) < 1024:
            return f"{n}{unit}"
        n //= 1024
    return f"{n}P"


def _open_lmdb_env(db_path: str, *, map_size_gb: int) -> lmdb.Environment:
    return lmdb.open(
        str(db_path),
        map_size=map_size_gb * (1 << 30),
        writemap=False,
        sync=False,
        metasync=False,
        map_async=True,
        meminit=False,
    )


def iter_lines(
    path: str,
    *,
    progress_callback: Callable[[int, int], None] | None = None,
    checksum: hashlib._Hash | None = None,
) -> Iterator[bytes]:
    """Yield 16-byte NTLM keys from lines of `HEX32` or `HEX32:COUNT`."""

    dataset_path = pathlib.Path(path)
    if not dataset_path.exists():
        raise FileNotFoundError(path)

    bad = 0
    yielded = 0
    total_size = dataset_path.stat().st_size
    processed_bytes = 0
    last_reported_bytes = 0
    last_reported_at = 0.0
    report_granularity_bytes = 16 * 1024 * 1024

    with dataset_path.open("rb") as handle:
        for raw in handle:
            if not raw:
                break
            processed_bytes += len(raw)
            if checksum is not None:
                checksum.update(raw)
            if progress_callback is not None:
                now = time.monotonic()
                should_report = (
                    processed_bytes >= total_size
                    or (processed_bytes - last_reported_bytes) >= report_granularity_bytes
                    or (now - last_reported_at) >= 0.5
                )
                if should_report:
                    progress_callback(processed_bytes, total_size)
                    last_reported_bytes = processed_bytes
                    last_reported_at = now

            stripped = raw.strip()
            if not stripped or stripped.startswith(b"#"):
                continue
            if b":" in stripped:
                stripped = stripped.split(b":", 1)[0]
            if b" " in stripped:
                stripped = stripped.replace(b" ", b"")
            if len(stripped) != HEX_LEN:
                bad += 1
                continue
            try:
                key = binascii.unhexlify(stripped)
            except Exception:
                bad += 1
                continue
            if len(key) != KEY_LEN_BYTES:
                bad += 1
                continue
            yielded += 1
            yield key

    if bad:
        print(
            f"Skipped {human(bad)} malformed lines; yielded {human(yielded)}.",
            file=sys.stderr,
        )
    if progress_callback is not None:
        progress_callback(total_size, total_size)


def build_db_from_file(
    input_path: str,
    *,
    db_path: str,
    map_size_gb: int = MAP_SIZE_GB,
    workers: int | None = None,
    tmp_dir: str | None = None,
    shards: int | None = None,
    progress_callback: Callable[[str, int, int], None] | None = None,
) -> BuildDbResult:
    """Build an LMDB presence database from a sorted NTLM text corpus."""

    db_dir = pathlib.Path(str(db_path))
    db_dir.mkdir(parents=True, exist_ok=True)
    env = _open_lmdb_env(str(db_dir), map_size_gb=map_size_gb)
    checksum = hashlib.sha256()
    total = 0
    inserted_total = 0
    previous_key: bytes | None = None
    pending_inserts = 0
    transaction = env.begin(write=True)

    try:
        put = transaction.put
        for key in iter_lines(
            input_path,
            progress_callback=(
                (lambda current, total_bytes: progress_callback("stream_insert", current, total_bytes))
                if progress_callback is not None
                else None
            ),
            checksum=checksum,
        ):
            total += 1
            if previous_key is not None:
                if key < previous_key:
                    raise ValueError(
                        "Offline HIBP NTLM dataset must be sorted by NTLM hash for fast "
                        "streaming LMDB ingestion."
                    )
                if key == previous_key:
                    continue

            inserted = put(key, b"", dupdata=False, overwrite=False, append=True)
            if not inserted:
                raise RuntimeError(
                    "Failed to append an ordered NTLM hash into the LMDB lookup store."
                )
            inserted_total += 1
            pending_inserts += 1
            previous_key = key

            if pending_inserts >= DEFAULT_STREAM_TRANSACTION_KEYS:
                transaction.commit()
                transaction = env.begin(write=True)
                put = transaction.put
                pending_inserts = 0

        transaction.commit()
        env.sync()
    finally:
        try:
            transaction.abort()
        except Exception:
            pass
        env.close()

    if progress_callback is not None:
        source_size = pathlib.Path(input_path).stat().st_size
        progress_callback("stream_insert", source_size, source_size)

    print(f"Inserted ~{human(inserted_total)} ordered keys into LMDB at {db_dir}")
    print("DB ready!")
    return BuildDbResult(
        checksum=checksum.hexdigest(),
        input_record_count=total,
        inserted_record_count=inserted_total,
    )
