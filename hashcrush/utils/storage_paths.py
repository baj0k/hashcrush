"""Filesystem path and UTC timestamp helpers."""

from __future__ import annotations

import os
import tempfile
from datetime import UTC, datetime

from flask import current_app


def get_runtime_root_path() -> str:
    """Return absolute runtime root path for ephemeral task artifacts."""
    configured = current_app.config.get("RUNTIME_PATH")
    if configured:
        return os.path.abspath(os.path.expanduser(str(configured)))
    return os.path.join(tempfile.gettempdir(), "hashcrush-runtime")


def utc_now_naive() -> datetime:
    """Return a naive UTC timestamp matching the existing persistence style."""
    return datetime.now(UTC).replace(tzinfo=None)


def get_runtime_subdir(name: str) -> str:
    """Return absolute path to a runtime subdirectory."""
    return os.path.join(get_runtime_root_path(), name)


def get_storage_root_path() -> str:
    """Return absolute persistent storage root path for uploaded assets."""
    configured = current_app.config.get("STORAGE_PATH")
    if configured:
        return os.path.abspath(os.path.expanduser(str(configured)))
    return os.path.join(tempfile.gettempdir(), "hashcrush-storage")


def get_storage_subdir(name: str) -> str:
    """Return absolute path to a persistent storage subdirectory."""
    return os.path.join(get_storage_root_path(), name)


def resolve_stored_path(stored_path: str) -> str:
    """Resolve a DB-stored path to an absolute filesystem path."""
    if not stored_path:
        return stored_path
    if os.path.isabs(stored_path):
        return stored_path

    normalized = stored_path.replace("\\", "/")
    package_root = os.path.abspath(current_app.root_path)
    project_root = os.path.abspath(os.path.join(package_root, os.pardir))

    candidates = [
        os.path.join(project_root, normalized),
        os.path.join(package_root, normalized),
    ]

    if normalized.startswith("hashcrush/"):
        stripped = normalized[len("hashcrush/") :]
        candidates.extend(
            [
                os.path.join(package_root, stripped),
                os.path.join(project_root, stripped),
            ]
        )

    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate

    if normalized.startswith("hashcrush/"):
        return os.path.join(project_root, normalized)
    return os.path.join(package_root, normalized)
