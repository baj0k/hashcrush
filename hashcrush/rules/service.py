"""Shared helpers for externally mounted rule files."""

from __future__ import annotations

import os

from flask import current_app

from hashcrush.models import Rules, db
from hashcrush.utils.file_ops import analyze_text_file
from hashcrush.utils.mounted_file_cache import (
    MountedFileCacheSnapshot,
    load_mounted_file_cache,
    rescan_mounted_files,
)
from hashcrush.utils.paths import is_path_within_root, normalize_path as _normalize_path


def get_external_rule_root() -> str:
    """Return the single configured container-visible root for external rules."""
    return _normalize_path(
        current_app.config.get("EXTERNAL_RULES_PATH")
        or "/mnt/hashcrush-rules"
    )


def list_external_rule_files() -> list[str]:
    """Return cached readable mounted rule files under the configured root."""
    root = get_external_rule_root()
    return load_mounted_file_cache(
        "external-rules",
        expected_root=root,
        validator=is_path_within_root,
    ).files


def get_external_rule_cache_snapshot() -> MountedFileCacheSnapshot:
    """Return cached metadata for external mounted rule files."""
    root = get_external_rule_root()
    return load_mounted_file_cache(
        "external-rules",
        expected_root=root,
        validator=is_path_within_root,
    )


def rescan_external_rule_files() -> MountedFileCacheSnapshot:
    """Rescan the configured external rule root and refresh the cache."""
    return rescan_mounted_files(
        "external-rules",
        root=get_external_rule_root(),
        validator=is_path_within_root,
    )


def is_external_rule_path(stored_path: str | None) -> bool:
    """Return True when a stored rule path lives under an external root."""
    if not stored_path:
        return False
    root = get_external_rule_root()
    if not root:
        return False
    return is_path_within_root(stored_path, root)


def derive_rule_name(form_name: str | None, fallback_path: str | None) -> str:
    """Prefer explicit names and otherwise derive from the filename."""
    preferred = str(form_name or "").strip()
    if preferred:
        return preferred
    filename = os.path.basename(str(fallback_path or "").strip())
    if not filename:
        return ""
    return os.path.splitext(filename)[0]


def validate_external_rule_path(
    selected_path: str | None,
) -> tuple[str | None, str | None]:
    """Validate a container-visible external rule path against the allowlist."""
    raw_value = str(selected_path or "").strip()
    if not raw_value:
        return None, "Mounted rule path is required."
    if not os.path.isabs(raw_value):
        return None, "Mounted rule paths must be absolute container paths."

    normalized_path = _normalize_path(raw_value)
    allowed_root = get_external_rule_root()
    if not allowed_root:
        return None, "No external rule roots are configured for this deployment."
    if not is_path_within_root(normalized_path, allowed_root):
        return (
            None,
            f"Mounted rule path must live under: {allowed_root}.",
        )
    if not os.path.isfile(normalized_path):
        return None, "Mounted rule file does not exist at that path."
    if not os.access(normalized_path, os.R_OK):
        return None, "Mounted rule file is not readable by the application."
    return normalized_path, None


def create_rule_from_path(
    rule_name: str,
    rule_path: str,
    *,
    progress_callback=None,
) -> Rules:
    """Analyze and persist a rule record for an existing file path."""
    normalized_path = _normalize_path(rule_path)
    file_analysis = analyze_text_file(
        normalized_path,
        progress_callback=progress_callback,
    )
    rule = Rules(
        name=rule_name,
        path=normalized_path,
        checksum=file_analysis.checksum,
        size=file_analysis.line_count,
    )
    db.session.add(rule)
    db.session.commit()
    return rule
