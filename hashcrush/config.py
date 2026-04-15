"""Manage parsing of config.conf and loading into the Flask config."""

from __future__ import annotations

import os
import tempfile
from configparser import ConfigParser

from sqlalchemy.engine import URL

from hashcrush.utils.paths import get_config_template_path, get_default_config_path


def sanitize_config_input(value: str | None) -> str:
    """Normalize config input and strip terminal control artifacts.

    Handles embedded backspace/delete characters (for example from broken terminal
    input capture) by applying backspace semantics, then removes remaining control
    bytes except tab.
    """
    if value is None:
        return ""
    cleaned_chars: list[str] = []
    for char in str(value):
        if char in ("\b", "\x7f"):
            if cleaned_chars:
                cleaned_chars.pop()
            continue
        if ord(char) < 32 and char != "\t":
            continue
        cleaned_chars.append(char)
    return "".join(cleaned_chars)


def _normalize_dir_path(value: str | None, fallback: str) -> str:
    selected = sanitize_config_input(value or fallback or "").strip()
    if not selected:
        selected = sanitize_config_input(fallback)
    return os.path.abspath(os.path.expanduser(selected))


def _normalize_file_path(value: str | None, fallback: str) -> str:
    selected = sanitize_config_input(value or fallback or "").strip()
    if not selected:
        selected = sanitize_config_input(fallback)
    return os.path.abspath(os.path.expanduser(selected))


def _parse_bool(value: str | None, fallback: bool | None = None) -> bool | None:
    normalized = sanitize_config_input(value).strip().lower()
    if not normalized:
        return fallback
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return fallback


def _parse_int(value: str | None, fallback: int, minimum: int = 0) -> int:
    try:
        parsed = int(sanitize_config_input(value).strip())
    except (TypeError, ValueError):
        return fallback
    if parsed < minimum:
        return fallback
    return parsed


def _parse_path_list(
    value: str | None,
    fallback: tuple[str, ...] = (),
) -> tuple[str, ...]:
    normalized_value = sanitize_config_input(value)
    if not normalized_value.strip():
        return tuple(
            os.path.abspath(os.path.expanduser(str(item).strip()))
            for item in fallback
            if str(item).strip()
        )
    results: list[str] = []
    for raw_item in normalized_value.replace(";", ",").split(","):
        selected = raw_item.strip()
        if not selected:
            continue
        normalized = os.path.abspath(os.path.expanduser(selected))
        if normalized not in results:
            results.append(normalized)
    return tuple(results)


def _load_file_config(config_path: str) -> tuple[ConfigParser, list[str]]:
    parser = ConfigParser(interpolation=None)
    loaded_files = parser.read(config_path)
    return parser, loaded_files


def build_config(overrides: dict[str, object] | None = None) -> dict[str, object]:
    """Build the runtime Flask config lazily.

    This function intentionally does not run at module import time so helper
    functions from this module remain importable in a clean checkout without a
    local config file.
    """
    overrides = overrides or {}
    config_path = str(get_default_config_path())
    file_config, config_files = _load_file_config(config_path)

    database_uri_from_override = sanitize_config_input(
        str(overrides.get("SQLALCHEMY_DATABASE_URI") or "")
    ).strip()
    database_uri_from_env = sanitize_config_input(
        os.getenv("HASHCRUSH_DATABASE_URI")
    ).strip()
    database_uri_from_config = sanitize_config_input(
        file_config.get("database", "uri", fallback="")
    ).strip()
    if database_uri_from_override:
        sqlalchemy_database_uri = database_uri_from_override
    elif database_uri_from_env:
        sqlalchemy_database_uri = database_uri_from_env
    elif database_uri_from_config:
        sqlalchemy_database_uri = database_uri_from_config
    else:
        db_host = sanitize_config_input(os.getenv("HASHCRUSH_DB_HOST")) or file_config.get(
            "database", "host", fallback=""
        )
        db_host = sanitize_config_input(db_host).strip()
        db_port = sanitize_config_input(os.getenv("HASHCRUSH_DB_PORT")) or file_config.get(
            "database", "port", fallback="5432"
        )
        db_port = sanitize_config_input(db_port).strip()
        db_name = sanitize_config_input(os.getenv("HASHCRUSH_DB_NAME")) or file_config.get(
            "database", "name", fallback="hashcrush"
        )
        db_name = sanitize_config_input(db_name).strip()
        db_username = sanitize_config_input(
            os.getenv("HASHCRUSH_DB_USERNAME")
        ) or file_config.get("database", "username", fallback="")
        db_username = sanitize_config_input(db_username).strip()
        db_password = sanitize_config_input(
            os.getenv("HASHCRUSH_DB_PASSWORD")
        ) or file_config.get("database", "password", fallback="")
        db_password = sanitize_config_input(db_password).strip()

        if not (db_host and db_port and db_name and db_username and db_password):
            if config_files:
                raise RuntimeError(
                    "Invalid database configuration. Provide HASHCRUSH_DATABASE_URI, set [database] uri, "
                    "or provide HASHCRUSH_DB_HOST/HASHCRUSH_DB_PORT/HASHCRUSH_DB_NAME/"
                    "HASHCRUSH_DB_USERNAME/HASHCRUSH_DB_PASSWORD (or matching [database] values in config)."
                )
            raise RuntimeError(
                f"Missing config file: {config_path}. Create it from {get_config_template_path()}, "
                "or set HASHCRUSH_DATABASE_URI (or HASHCRUSH_DB_HOST/HASHCRUSH_DB_PORT/HASHCRUSH_DB_NAME/"
                "HASHCRUSH_DB_USERNAME/HASHCRUSH_DB_PASSWORD)."
            )

        try:
            db_port_number = int(db_port)
        except ValueError as exc:
            raise RuntimeError(
                "Invalid database configuration. HASHCRUSH_DB_PORT/[database] port must be an integer."
            ) from exc

        sqlalchemy_database_uri = URL.create(
            "postgresql+psycopg",
            username=db_username,
            password=db_password,
            host=db_host,
            port=db_port_number,
            database=db_name,
        ).render_as_string(hide_password=False)

    configured_secret = sanitize_config_input(str(overrides.get("SECRET_KEY") or ""))
    if not configured_secret:
        configured_secret = sanitize_config_input(
            os.getenv("HASHCRUSH_SECRET_KEY")
        ) or file_config.get("app", "secret_key", fallback="")
    configured_secret = sanitize_config_input(configured_secret).strip()
    if not configured_secret:
        raise RuntimeError(
            "Missing application secret key. Set HASHCRUSH_SECRET_KEY or [app] secret_key in config.conf."
        )

    hashcat_bin = sanitize_config_input(os.getenv("HASHCRUSH_HASHCAT_BIN")) or file_config.get(
        "app", "hashcat_bin", fallback="hashcat"
    )
    hashcat_bin = sanitize_config_input(hashcat_bin).strip() or "hashcat"

    configured_data_encryption_key = sanitize_config_input(
        str(overrides.get("DATA_ENCRYPTION_KEY") or "")
    )
    if not configured_data_encryption_key:
        configured_data_encryption_key = sanitize_config_input(
            os.getenv("HASHCRUSH_DATA_ENCRYPTION_KEY")
        ) or file_config.get("app", "data_encryption_key", fallback="")
    configured_data_encryption_key = sanitize_config_input(
        configured_data_encryption_key
    ).strip()
    if not configured_data_encryption_key:
        raise RuntimeError(
            "Missing data encryption key. Set HASHCRUSH_DATA_ENCRYPTION_KEY or "
            "[app] data_encryption_key in config.conf."
        )

    hashcat_status_timer = _parse_int(
        os.getenv("HASHCRUSH_HASHCAT_STATUS_TIMER")
        or file_config.get("app", "hashcat_status_timer", fallback="5"),
        fallback=5,
        minimum=1,
    )
    hashfile_max_line_length = _parse_int(
        os.getenv("HASHCRUSH_HASHFILE_MAX_LINE_LENGTH")
        or file_config.get("app", "hashfile_max_line_length", fallback="50000"),
        fallback=50000,
        minimum=1,
    )
    hashfile_max_total_lines = _parse_int(
        os.getenv("HASHCRUSH_HASHFILE_MAX_TOTAL_LINES")
        or file_config.get("app", "hashfile_max_total_lines", fallback="1000000"),
        fallback=1000000,
        minimum=1,
    )
    hashfile_max_total_bytes = _parse_int(
        os.getenv("HASHCRUSH_HASHFILE_MAX_TOTAL_BYTES")
        or file_config.get("app", "hashfile_max_total_bytes", fallback="1073741824"),
        fallback=1073741824,
        minimum=1,
    )
    auth_throttle_enabled = _parse_bool(
        os.getenv("HASHCRUSH_AUTH_THROTTLE_ENABLED")
        or file_config.get("app", "auth_throttle_enabled", fallback="true"),
        True,
    )
    auth_throttle_max_attempts = _parse_int(
        os.getenv("HASHCRUSH_AUTH_THROTTLE_MAX_ATTEMPTS")
        or file_config.get("app", "auth_throttle_max_attempts", fallback="5"),
        fallback=5,
        minimum=1,
    )
    auth_throttle_window_seconds = _parse_int(
        os.getenv("HASHCRUSH_AUTH_THROTTLE_WINDOW_SECONDS")
        or file_config.get("app", "auth_throttle_window_seconds", fallback="300"),
        fallback=300,
        minimum=1,
    )
    auth_throttle_lockout_seconds = _parse_int(
        os.getenv("HASHCRUSH_AUTH_THROTTLE_LOCKOUT_SECONDS")
        or file_config.get("app", "auth_throttle_lockout_seconds", fallback="900"),
        fallback=900,
        minimum=1,
    )
    enable_inline_upload_worker = _parse_bool(
        os.getenv("HASHCRUSH_ENABLE_INLINE_UPLOAD_WORKER")
        or file_config.get("app", "enable_inline_upload_worker", fallback=""),
        None,
    )
    upload_operation_retention_seconds = _parse_int(
        os.getenv("HASHCRUSH_UPLOAD_OPERATION_RETENTION_SECONDS")
        or file_config.get(
            "app",
            "upload_operation_retention_seconds",
            fallback="3600",
        ),
        fallback=3600,
        minimum=60,
    )
    upload_operation_lease_seconds = _parse_int(
        os.getenv("HASHCRUSH_UPLOAD_OPERATION_LEASE_SECONDS")
        or file_config.get("app", "upload_operation_lease_seconds", fallback="300"),
        fallback=300,
        minimum=30,
    )
    upload_inline_max_workers = _parse_int(
        os.getenv("HASHCRUSH_UPLOAD_INLINE_MAX_WORKERS")
        or file_config.get("app", "upload_inline_max_workers", fallback="2"),
        fallback=2,
        minimum=1,
    )
    upload_worker_poll_interval_seconds = _parse_int(
        os.getenv("HASHCRUSH_UPLOAD_WORKER_POLL_INTERVAL_SECONDS")
        or file_config.get(
            "app",
            "upload_worker_poll_interval_seconds",
            fallback="2",
        ),
        fallback=2,
        minimum=1,
    )
    hibp_dataset_min_map_size_gb = _parse_int(
        os.getenv("HASHCRUSH_HIBP_DATASET_MIN_MAP_SIZE_GB")
        or file_config.get("app", "hibp_dataset_min_map_size_gb", fallback="128"),
        fallback=128,
        minimum=4,
    )
    trust_x_forwarded_for = _parse_bool(
        os.getenv("HASHCRUSH_TRUST_X_FORWARDED_FOR")
        or file_config.get("app", "trust_x_forwarded_for", fallback="false"),
        False,
    )
    session_cookie_httponly = _parse_bool(
        os.getenv("HASHCRUSH_SESSION_COOKIE_HTTPONLY")
        or file_config.get("app", "session_cookie_httponly", fallback="true"),
        True,
    )
    cookie_samesite = sanitize_config_input(
        os.getenv("HASHCRUSH_SESSION_COOKIE_SAMESITE")
    ) or file_config.get("app", "session_cookie_samesite", fallback="Lax")
    cookie_samesite = sanitize_config_input(cookie_samesite).strip().lower()
    if cookie_samesite == "strict":
        session_cookie_samesite = "Strict"
    elif cookie_samesite == "none":
        session_cookie_samesite = "None"
    else:
        session_cookie_samesite = "Lax"

    default_runtime_path = os.path.join(tempfile.gettempdir(), "hashcrush-runtime")
    default_storage_path = "/var/lib/hashcrush"
    default_ssl_cert_path = "/etc/hashcrush/ssl/cert.pem"
    default_ssl_key_path = "/etc/hashcrush/ssl/key.pem"
    default_external_wordlists_path = "/mnt/hashcrush-wordlists"
    default_hibp_datasets_path = "/mnt/hashcrush-hibp"

    return {
        "HASHCRUSH_CONFIG_PATH": config_path,
        "SQLALCHEMY_DATABASE_URI": sqlalchemy_database_uri,
        "SECRET_KEY": configured_secret,
        "HASHCAT_BIN": hashcat_bin,
        "DATA_ENCRYPTION_KEY": configured_data_encryption_key,
        "HASHCAT_STATUS_TIMER": hashcat_status_timer,
        "HASHFILE_MAX_LINE_LENGTH": hashfile_max_line_length,
        "HASHFILE_MAX_TOTAL_LINES": hashfile_max_total_lines,
        "HASHFILE_MAX_TOTAL_BYTES": hashfile_max_total_bytes,
        "MAX_CONTENT_LENGTH": hashfile_max_total_bytes,
        "AUTH_THROTTLE_ENABLED": auth_throttle_enabled,
        "AUTH_THROTTLE_MAX_ATTEMPTS": auth_throttle_max_attempts,
        "AUTH_THROTTLE_WINDOW_SECONDS": auth_throttle_window_seconds,
        "AUTH_THROTTLE_LOCKOUT_SECONDS": auth_throttle_lockout_seconds,
        "ENABLE_INLINE_UPLOAD_WORKER": enable_inline_upload_worker,
        "UPLOAD_OPERATION_RETENTION_SECONDS": upload_operation_retention_seconds,
        "UPLOAD_OPERATION_LEASE_SECONDS": upload_operation_lease_seconds,
        "UPLOAD_INLINE_MAX_WORKERS": upload_inline_max_workers,
        "UPLOAD_WORKER_POLL_INTERVAL_SECONDS": upload_worker_poll_interval_seconds,
        "HIBP_DATASET_MIN_MAP_SIZE_GB": hibp_dataset_min_map_size_gb,
        "TRUST_X_FORWARDED_FOR": trust_x_forwarded_for,
        "SESSION_COOKIE_HTTPONLY": session_cookie_httponly,
        "SESSION_COOKIE_SAMESITE": session_cookie_samesite,
        "RUNTIME_PATH": _normalize_dir_path(
            os.getenv("HASHCRUSH_RUNTIME_PATH")
            or file_config.get("app", "runtime_path", fallback=default_runtime_path),
            default_runtime_path,
        ),
        "STORAGE_PATH": _normalize_dir_path(
            os.getenv("HASHCRUSH_STORAGE_PATH")
            or file_config.get("app", "storage_path", fallback=default_storage_path),
            default_storage_path,
        ),
        "EXTERNAL_WORDLISTS_PATH": _normalize_dir_path(
            default_external_wordlists_path,
            default_external_wordlists_path,
        ),
        "HIBP_DATASETS_PATH": _normalize_dir_path(
            default_hibp_datasets_path,
            default_hibp_datasets_path,
        ),
        "SSL_CERT_PATH": _normalize_file_path(
            os.getenv("HASHCRUSH_SSL_CERT_PATH")
            or file_config.get("app", "ssl_cert_path", fallback=default_ssl_cert_path),
            default_ssl_cert_path,
        ),
        "SSL_KEY_PATH": _normalize_file_path(
            os.getenv("HASHCRUSH_SSL_KEY_PATH")
            or file_config.get("app", "ssl_key_path", fallback=default_ssl_key_path),
            default_ssl_key_path,
        ),
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
    }
