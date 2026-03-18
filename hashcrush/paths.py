"""Shared filesystem locations for config and local test artifacts."""

from __future__ import annotations

import os
from pathlib import Path


def get_package_root() -> Path:
    """Return the absolute package root path."""
    return Path(__file__).resolve().parent


def get_project_root() -> Path:
    """Return the absolute repository root path."""
    return get_package_root().parent


def get_repo_runtime_root() -> Path:
    """Return the repo-local runtime folder used for generated local artifacts."""
    return get_project_root() / ".runtime"


def get_legacy_config_path() -> Path:
    """Return the historical in-package config path."""
    return get_package_root() / "config.conf"


def get_default_config_path() -> Path:
    """Return the active config path, preferring explicit env and legacy installs."""
    configured = str(os.getenv("HASHCRUSH_CONFIG_PATH") or "").strip()
    if configured:
        return Path(os.path.abspath(os.path.expanduser(configured)))

    legacy_path = get_legacy_config_path()
    if legacy_path.exists():
        return legacy_path

    return get_repo_runtime_root() / "config.conf"


def get_config_template_path() -> Path:
    """Return the packaged example config path."""
    return get_package_root() / "config.conf.example"


def get_default_test_env_path() -> Path:
    """Return the preferred generated external-E2E dotenv path."""
    return get_project_root() / "tests" / ".env.test"


def get_legacy_test_env_path() -> Path:
    """Return the historical generated external-E2E dotenv path."""
    return get_project_root() / ".env.test"


def iter_test_env_paths() -> tuple[Path, ...]:
    """Return dotenv paths to try for external-E2E configuration."""
    ordered_paths: list[Path] = []
    for candidate in (get_default_test_env_path(), get_legacy_test_env_path()):
        if candidate not in ordered_paths:
            ordered_paths.append(candidate)
    return tuple(ordered_paths)


def get_repo_ssl_dir() -> Path:
    """Return the repo-local fallback TLS directory for disposable test setup."""
    return get_repo_runtime_root() / "ssl"
