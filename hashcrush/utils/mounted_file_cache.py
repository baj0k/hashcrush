"""Helpers for caching mounted file listings outside request-time scans."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Callable

from hashcrush.utils.storage_paths import get_runtime_subdir


@dataclass(frozen=True)
class MountedFileCacheSnapshot:
    """Cached mounted-file listing for a configured root."""

    root: str
    files: list[str]
    refreshed_at: datetime | None = None


def natural_sort_key(value: str) -> list[object]:
    """Sort strings with embedded numbers in natural order."""

    return [
        int(chunk) if chunk.isdigit() else chunk.lower()
        for chunk in re.split(r"(\d+)", str(value or ""))
    ]


def _cache_dir() -> str:
    path = get_runtime_subdir("mounted-file-cache")
    os.makedirs(path, exist_ok=True)
    return path


def _cache_path(cache_name: str) -> str:
    safe_name = re.sub(r"[^a-z0-9_.-]+", "-", str(cache_name or "").strip().lower())
    safe_name = safe_name or "mounted-files"
    return os.path.join(_cache_dir(), f"{safe_name}.json")


def _parse_refreshed_at(raw_value: object) -> datetime | None:
    if not raw_value:
        return None
    try:
        parsed = datetime.fromisoformat(str(raw_value))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def load_mounted_file_cache(
    cache_name: str,
    *,
    expected_root: str,
    validator: Callable[[str | None, str | None], bool],
) -> MountedFileCacheSnapshot:
    """Return cached readable files for the expected mounted root."""

    normalized_root = os.path.abspath(os.path.expanduser(str(expected_root or "").strip()))
    cache_path = _cache_path(cache_name)
    if not os.path.isfile(cache_path):
        return MountedFileCacheSnapshot(root=normalized_root, files=[], refreshed_at=None)

    try:
        with open(cache_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError, TypeError):
        return MountedFileCacheSnapshot(root=normalized_root, files=[], refreshed_at=None)

    if not isinstance(payload, dict):
        return MountedFileCacheSnapshot(root=normalized_root, files=[], refreshed_at=None)

    cached_root = os.path.abspath(
        os.path.expanduser(str(payload.get("root") or "").strip())
    )
    if cached_root != normalized_root:
        return MountedFileCacheSnapshot(root=normalized_root, files=[], refreshed_at=None)

    files: list[str] = []
    for raw_path in payload.get("files") or []:
        candidate = os.path.abspath(os.path.expanduser(str(raw_path or "").strip()))
        if not validator(candidate, normalized_root):
            continue
        if not os.path.isfile(candidate):
            continue
        if not os.access(candidate, os.R_OK):
            continue
        files.append(candidate)

    return MountedFileCacheSnapshot(
        root=normalized_root,
        files=files,
        refreshed_at=_parse_refreshed_at(payload.get("refreshed_at")),
    )


def rescan_mounted_files(
    cache_name: str,
    *,
    root: str,
    validator: Callable[[str | None, str | None], bool],
) -> MountedFileCacheSnapshot:
    """Scan a mounted root once, cache the readable files, and return the snapshot."""

    normalized_root = os.path.abspath(os.path.expanduser(str(root or "").strip()))
    files: list[str] = []
    if normalized_root and os.path.isdir(normalized_root):
        for current_root, dirnames, filenames in os.walk(normalized_root):
            dirnames.sort(key=natural_sort_key)
            for filename in sorted(filenames, key=natural_sort_key):
                candidate = os.path.abspath(os.path.join(current_root, filename))
                if not validator(candidate, normalized_root):
                    continue
                if not os.path.isfile(candidate):
                    continue
                if not os.access(candidate, os.R_OK):
                    continue
                files.append(candidate)

    refreshed_at = datetime.now(UTC)
    payload = {
        "root": normalized_root,
        "files": files,
        "refreshed_at": refreshed_at.isoformat(),
    }
    cache_path = _cache_path(cache_name)
    tmp_path = f"{cache_path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, sort_keys=True)
    os.replace(tmp_path, cache_path)
    return MountedFileCacheSnapshot(
        root=normalized_root,
        files=files,
        refreshed_at=refreshed_at,
    )
