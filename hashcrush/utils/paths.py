"""Shared filesystem path utilities."""

from __future__ import annotations

import os
from pathlib import Path


def normalize_path(value: str | None) -> str:
    """Resolve a path string to its canonical absolute form."""
    return os.path.realpath(
        os.path.abspath(os.path.expanduser(str(value or "").strip()))
    )


def is_path_within_root(path: str | None, root: str | None) -> bool:
    """Return True when *path* resolves under *root*."""
    normalized_path = normalize_path(path)
    normalized_root = normalize_path(root)
    if not normalized_path or not normalized_root:
        return False
    try:
        return os.path.commonpath([normalized_path, normalized_root]) == normalized_root
    except ValueError:
        return False


def get_package_root() -> Path:
    """Return the absolute package root path."""
    return Path(__file__).resolve().parent


def get_project_root() -> Path:
    """Return the absolute repository root path."""
    return get_package_root().parent
