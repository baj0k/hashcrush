"""Shared helpers for managed and externally mounted wordlists."""

from __future__ import annotations

import os

from flask import current_app

from hashcrush.models import Wordlists, db
from hashcrush.utils.file_ops import analyze_text_file
from hashcrush.utils.storage_paths import get_storage_subdir


def _normalize_path(value: str | None) -> str:
    return os.path.realpath(
        os.path.abspath(os.path.expanduser(str(value or "").strip()))
    )


def is_path_within_root(path: str | None, root: str | None) -> bool:
    """Return True when path resolves under root."""
    normalized_path = _normalize_path(path)
    normalized_root = _normalize_path(root)
    if not normalized_path or not normalized_root:
        return False
    try:
        return os.path.commonpath([normalized_path, normalized_root]) == normalized_root
    except ValueError:
        return False


def managed_wordlists_dir() -> str:
    """Return the managed storage directory for uploaded wordlists."""
    path = get_storage_subdir("wordlists")
    os.makedirs(path, exist_ok=True)
    return path


def get_external_wordlist_root() -> str:
    """Return the single configured container-visible root for external wordlists."""
    return _normalize_path(
        current_app.config.get("EXTERNAL_WORDLISTS_PATH")
        or "/mnt/hashcrush-wordlists"
    )


def is_managed_wordlist_path(stored_path: str | None) -> bool:
    """Return True when a stored wordlist path lives under managed storage."""
    return is_path_within_root(stored_path, managed_wordlists_dir())


def is_external_wordlist_path(stored_path: str | None) -> bool:
    """Return True when a stored wordlist path lives under an external root."""
    if not stored_path or is_managed_wordlist_path(stored_path):
        return False
    root = get_external_wordlist_root()
    if not root:
        return False
    return is_path_within_root(stored_path, root)


def get_wordlist_source(wordlist: Wordlists) -> str:
    """Return a stable UI/source label for a wordlist row."""
    normalized_type = str(wordlist.type or "").strip().lower()
    if normalized_type == "dynamic":
        return "dynamic"
    if is_managed_wordlist_path(wordlist.path):
        return "managed"
    if is_external_wordlist_path(wordlist.path):
        return "external"
    return "static"


def remove_managed_wordlist_file(stored_path: str) -> None:
    """Delete only managed uploaded wordlist files."""
    if not is_managed_wordlist_path(stored_path):
        return
    resolved_path = _normalize_path(stored_path)
    if os.path.isfile(resolved_path):
        try:
            os.remove(resolved_path)
        except OSError:
            pass


def derive_wordlist_name(form_name: str | None, fallback_path: str | None) -> str:
    """Prefer explicit names and otherwise derive from the filename."""
    preferred = str(form_name or "").strip()
    if preferred:
        return preferred
    filename = os.path.basename(str(fallback_path or "").strip())
    if not filename:
        return ""
    return os.path.splitext(filename)[0]


def validate_external_wordlist_path(
    selected_path: str | None,
) -> tuple[str | None, str | None]:
    """Validate a container-visible external wordlist path against the allowlist."""
    raw_value = str(selected_path or "").strip()
    if not raw_value:
        return None, "Mounted wordlist path is required."
    if not os.path.isabs(raw_value):
        return None, "Mounted wordlist paths must be absolute container paths."

    normalized_path = _normalize_path(raw_value)
    allowed_root = get_external_wordlist_root()
    if not allowed_root:
        return None, "No external wordlist roots are configured for this deployment."
    if not is_path_within_root(normalized_path, allowed_root):
        return (
            None,
            f"Mounted wordlist path must live under: {allowed_root}.",
        )
    if not os.path.isfile(normalized_path):
        return None, "Mounted wordlist file does not exist at that path."
    if not os.access(normalized_path, os.R_OK):
        return None, "Mounted wordlist file is not readable by the application."
    return normalized_path, None


def create_static_wordlist_from_path(
    wordlist_name: str,
    wordlist_path: str,
    *,
    progress_callback=None,
) -> Wordlists:
    """Analyze and persist a static wordlist record for an existing file path."""
    normalized_path = _normalize_path(wordlist_path)
    file_analysis = analyze_text_file(
        normalized_path,
        progress_callback=progress_callback,
    )
    wordlist = Wordlists(
        name=wordlist_name,
        type="static",
        path=normalized_path,
        checksum=file_analysis.checksum,
        size=file_analysis.line_count,
    )
    db.session.add(wordlist)
    db.session.commit()
    return wordlist
