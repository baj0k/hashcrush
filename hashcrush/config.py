"""Load application configuration from environment variables."""

from __future__ import annotations

import os
import tempfile

from sqlalchemy.engine import URL


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


def _env(name: str) -> str:
    """Read and sanitize an environment variable."""
    return sanitize_config_input(os.getenv(name)).strip()


def build_config(overrides: dict[str, object] | None = None) -> dict[str, object]:
    """Build the runtime Flask config from environment variables."""
    overrides = overrides or {}

    database_uri_from_override = sanitize_config_input(
        str(overrides.get("SQLALCHEMY_DATABASE_URI") or "")
    ).strip()
    database_uri_from_env = _env("HASHCRUSH_DATABASE_URI")

    if database_uri_from_override:
        sqlalchemy_database_uri = database_uri_from_override
    elif database_uri_from_env:
        sqlalchemy_database_uri = database_uri_from_env
    else:
        db_host = _env("HASHCRUSH_DB_HOST")
        db_port = _env("HASHCRUSH_DB_PORT") or "5432"
        db_name = _env("HASHCRUSH_DB_NAME") or "hashcrush"
        db_username = _env("HASHCRUSH_DB_USERNAME")
        db_password = _env("HASHCRUSH_DB_PASSWORD")

        if not (db_host and db_port and db_name and db_username and db_password):
            raise RuntimeError(
                "Missing database configuration. Set HASHCRUSH_DATABASE_URI, "
                "or set HASHCRUSH_DB_HOST/HASHCRUSH_DB_PORT/HASHCRUSH_DB_NAME/"
                "HASHCRUSH_DB_USERNAME/HASHCRUSH_DB_PASSWORD."
            )

        try:
            db_port_number = int(db_port)
        except ValueError as exc:
            raise RuntimeError(
                "Invalid database configuration. HASHCRUSH_DB_PORT must be an integer."
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
        configured_secret = _env("HASHCRUSH_SECRET_KEY")
    if not configured_secret:
        raise RuntimeError(
            "Missing application secret key. Set HASHCRUSH_SECRET_KEY."
        )

    hashcat_bin = _env("HASHCRUSH_HASHCAT_BIN") or "hashcat"

    configured_data_encryption_key = sanitize_config_input(
        str(overrides.get("DATA_ENCRYPTION_KEY") or "")
    )
    if not configured_data_encryption_key:
        configured_data_encryption_key = _env("HASHCRUSH_DATA_ENCRYPTION_KEY")
    if not configured_data_encryption_key:
        raise RuntimeError(
            "Missing data encryption key. Set HASHCRUSH_DATA_ENCRYPTION_KEY."
        )

    default_runtime_path = os.path.join(tempfile.gettempdir(), "hashcrush-runtime")
    default_storage_path = "/var/lib/hashcrush"
    default_ssl_cert_path = "/etc/hashcrush/ssl/cert.pem"
    default_ssl_key_path = "/etc/hashcrush/ssl/key.pem"
    default_external_wordlists_path = "/mnt/hashcrush-wordlists"
    default_external_rules_path = "/mnt/hashcrush-rules"
    default_hibp_datasets_path = "/mnt/hashcrush-hibp"

    return {
        "SQLALCHEMY_DATABASE_URI": sqlalchemy_database_uri,
        "SECRET_KEY": configured_secret,
        "HASHCAT_BIN": hashcat_bin,
        "DATA_ENCRYPTION_KEY": configured_data_encryption_key,
        "HASHCAT_STATUS_TIMER": _parse_int(
            os.getenv("HASHCRUSH_HASHCAT_STATUS_TIMER"), fallback=5, minimum=1
        ),
        "HASHFILE_MAX_LINE_LENGTH": _parse_int(
            os.getenv("HASHCRUSH_HASHFILE_MAX_LINE_LENGTH"), fallback=50000, minimum=1
        ),
        "HASHFILE_MAX_TOTAL_LINES": _parse_int(
            os.getenv("HASHCRUSH_HASHFILE_MAX_TOTAL_LINES"), fallback=1000000, minimum=1
        ),
        "HASHFILE_MAX_TOTAL_BYTES": _parse_int(
            os.getenv("HASHCRUSH_HASHFILE_MAX_TOTAL_BYTES"), fallback=1073741824, minimum=1
        ),
        "MAX_CONTENT_LENGTH": _parse_int(
            os.getenv("HASHCRUSH_HASHFILE_MAX_TOTAL_BYTES"), fallback=1073741824, minimum=1
        ),
        "AUTH_THROTTLE_ENABLED": _parse_bool(
            os.getenv("HASHCRUSH_AUTH_THROTTLE_ENABLED"), True
        ),
        "AUTH_THROTTLE_MAX_ATTEMPTS": _parse_int(
            os.getenv("HASHCRUSH_AUTH_THROTTLE_MAX_ATTEMPTS"), fallback=5, minimum=1
        ),
        "AUTH_THROTTLE_WINDOW_SECONDS": _parse_int(
            os.getenv("HASHCRUSH_AUTH_THROTTLE_WINDOW_SECONDS"), fallback=300, minimum=1
        ),
        "AUTH_THROTTLE_LOCKOUT_SECONDS": _parse_int(
            os.getenv("HASHCRUSH_AUTH_THROTTLE_LOCKOUT_SECONDS"), fallback=900, minimum=1
        ),
        "ENABLE_INLINE_UPLOAD_WORKER": _parse_bool(
            os.getenv("HASHCRUSH_ENABLE_INLINE_UPLOAD_WORKER"), None
        ),
        "UPLOAD_OPERATION_RETENTION_SECONDS": _parse_int(
            os.getenv("HASHCRUSH_UPLOAD_OPERATION_RETENTION_SECONDS"),
            fallback=3600, minimum=60,
        ),
        "UPLOAD_OPERATION_LEASE_SECONDS": _parse_int(
            os.getenv("HASHCRUSH_UPLOAD_OPERATION_LEASE_SECONDS"),
            fallback=300, minimum=30,
        ),
        "UPLOAD_INLINE_MAX_WORKERS": _parse_int(
            os.getenv("HASHCRUSH_UPLOAD_INLINE_MAX_WORKERS"), fallback=2, minimum=1
        ),
        "UPLOAD_WORKER_POLL_INTERVAL_SECONDS": _parse_int(
            os.getenv("HASHCRUSH_UPLOAD_WORKER_POLL_INTERVAL_SECONDS"),
            fallback=2, minimum=1,
        ),
        "HIBP_DATASET_MIN_MAP_SIZE_GB": _parse_int(
            os.getenv("HASHCRUSH_HIBP_DATASET_MIN_MAP_SIZE_GB"), fallback=128, minimum=4
        ),
        "TRUST_X_FORWARDED_FOR": _parse_bool(
            os.getenv("HASHCRUSH_TRUST_X_FORWARDED_FOR"), True,
        ),
        "SESSION_COOKIE_HTTPONLY": _parse_bool(
            os.getenv("HASHCRUSH_SESSION_COOKIE_HTTPONLY"), True
        ),
        "SESSION_COOKIE_SAMESITE": (
            lambda v: {"strict": "Strict", "none": "None"}.get(v, "Lax")
        )(sanitize_config_input(os.getenv("HASHCRUSH_SESSION_COOKIE_SAMESITE")).strip().lower()),
        "RUNTIME_PATH": _normalize_dir_path(
            os.getenv("HASHCRUSH_RUNTIME_PATH"), default_runtime_path
        ),
        "STORAGE_PATH": _normalize_dir_path(
            os.getenv("HASHCRUSH_STORAGE_PATH"), default_storage_path
        ),
        "EXTERNAL_WORDLISTS_PATH": _normalize_dir_path(
            default_external_wordlists_path, default_external_wordlists_path
        ),
        "EXTERNAL_RULES_PATH": _normalize_dir_path(
            default_external_rules_path, default_external_rules_path
        ),
        "HIBP_DATASETS_PATH": _normalize_dir_path(
            default_hibp_datasets_path, default_hibp_datasets_path
        ),
        "SSL_CERT_PATH": _normalize_file_path(
            os.getenv("HASHCRUSH_SSL_CERT_PATH"), default_ssl_cert_path
        ),
        "SSL_KEY_PATH": _normalize_file_path(
            os.getenv("HASHCRUSH_SSL_KEY_PATH"), default_ssl_key_path
        ),
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
    }
