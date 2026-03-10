"""Manage parsing of config.conf and loading into the Flask Config."""

import os
import tempfile
from configparser import ConfigParser

file_config = ConfigParser(interpolation=None)


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


class Config:
    """Class representing Config"""

    _config_path = os.getenv("HASHCRUSH_CONFIG_PATH", "hashcrush/config.conf")
    _config_files = file_config.read(_config_path)
    _database_uri_from_env = sanitize_config_input(
        os.getenv("HASHCRUSH_DATABASE_URI")
    ).strip()
    if _database_uri_from_env:
        SQLALCHEMY_DATABASE_URI = _database_uri_from_env
    else:
        _db_host = sanitize_config_input(
            os.getenv("HASHCRUSH_DB_HOST")
        ) or file_config.get("database", "host", fallback="")
        _db_host = sanitize_config_input(_db_host).strip()
        _db_username = sanitize_config_input(
            os.getenv("HASHCRUSH_DB_USERNAME")
        ) or file_config.get("database", "username", fallback="")
        _db_username = sanitize_config_input(_db_username).strip()
        _db_password = sanitize_config_input(
            os.getenv("HASHCRUSH_DB_PASSWORD")
        ) or file_config.get("database", "password", fallback="")
        _db_password = sanitize_config_input(_db_password).strip()

        if not (_db_host and _db_username and _db_password):
            if _config_files:
                raise RuntimeError(
                    "Invalid database configuration. Provide HASHCRUSH_DATABASE_URI or HASHCRUSH_DB_HOST/"
                    "HASHCRUSH_DB_USERNAME/HASHCRUSH_DB_PASSWORD, or set [database] host/username/password in config."
                )
            raise RuntimeError(
                f"Missing config file: {_config_path}. Create it from hashcrush/config.conf.example, "
                "or set HASHCRUSH_DATABASE_URI (or HASHCRUSH_DB_HOST/HASHCRUSH_DB_USERNAME/HASHCRUSH_DB_PASSWORD)."
            )

        SQLALCHEMY_DATABASE_URI = (
            "mysql+mysqlconnector://"
            + _db_username
            + ":"
            + _db_password
            + "@"
            + _db_host
            + "/hashcrush"
        )

    # Require explicit key from env/app config.
    _configured_secret = sanitize_config_input(
        os.getenv("HASHCRUSH_SECRET_KEY")
    ) or file_config.get("app", "secret_key", fallback="")
    _configured_secret = sanitize_config_input(_configured_secret)
    if _configured_secret and _configured_secret.strip():
        SECRET_KEY = _configured_secret.strip()
    else:
        raise RuntimeError(
            "Missing application secret key. Set HASHCRUSH_SECRET_KEY or [app] secret_key in config.conf."
        )

    _hashcat_bin = sanitize_config_input(
        os.getenv("HASHCRUSH_HASHCAT_BIN")
    ) or file_config.get("app", "hashcat_bin", fallback="hashcat")
    _hashcat_bin = sanitize_config_input(_hashcat_bin)
    HASHCAT_BIN = _hashcat_bin.strip() if _hashcat_bin else "hashcat"

    HASHCAT_STATUS_TIMER = _parse_int(
        os.getenv("HASHCRUSH_HASHCAT_STATUS_TIMER")
        or file_config.get("app", "hashcat_status_timer", fallback="5"),
        fallback=5,
        minimum=1,
    )
    AUTO_CREATE_SCHEMA = _parse_bool(
        os.getenv("HASHCRUSH_AUTO_CREATE_SCHEMA")
        or file_config.get("app", "auto_create_schema", fallback="true"),
        True,
    )
    HASHFILE_MAX_LINE_LENGTH = _parse_int(
        os.getenv("HASHCRUSH_HASHFILE_MAX_LINE_LENGTH")
        or file_config.get("app", "hashfile_max_line_length", fallback="50000"),
        fallback=50000,
        minimum=1,
    )
    HASHFILE_MAX_TOTAL_LINES = _parse_int(
        os.getenv("HASHCRUSH_HASHFILE_MAX_TOTAL_LINES")
        or file_config.get("app", "hashfile_max_total_lines", fallback="1000000"),
        fallback=1000000,
        minimum=1,
    )
    HASHFILE_MAX_TOTAL_BYTES = _parse_int(
        os.getenv("HASHCRUSH_HASHFILE_MAX_TOTAL_BYTES")
        or file_config.get("app", "hashfile_max_total_bytes", fallback="1073741824"),
        fallback=1073741824,
        minimum=1,
    )

    AUTH_THROTTLE_ENABLED = _parse_bool(
        os.getenv("HASHCRUSH_AUTH_THROTTLE_ENABLED")
        or file_config.get("app", "auth_throttle_enabled", fallback="true"),
        True,
    )
    AUTH_THROTTLE_MAX_ATTEMPTS = _parse_int(
        os.getenv("HASHCRUSH_AUTH_THROTTLE_MAX_ATTEMPTS")
        or file_config.get("app", "auth_throttle_max_attempts", fallback="5"),
        fallback=5,
        minimum=1,
    )
    AUTH_THROTTLE_WINDOW_SECONDS = _parse_int(
        os.getenv("HASHCRUSH_AUTH_THROTTLE_WINDOW_SECONDS")
        or file_config.get("app", "auth_throttle_window_seconds", fallback="300"),
        fallback=300,
        minimum=1,
    )
    AUTH_THROTTLE_LOCKOUT_SECONDS = _parse_int(
        os.getenv("HASHCRUSH_AUTH_THROTTLE_LOCKOUT_SECONDS")
        or file_config.get("app", "auth_throttle_lockout_seconds", fallback="900"),
        fallback=900,
        minimum=1,
    )
    TRUST_X_FORWARDED_FOR = _parse_bool(
        os.getenv("HASHCRUSH_TRUST_X_FORWARDED_FOR")
        or file_config.get("app", "trust_x_forwarded_for", fallback="false"),
        False,
    )

    SESSION_COOKIE_SECURE = _parse_bool(
        os.getenv("HASHCRUSH_SESSION_COOKIE_SECURE")
        or file_config.get("app", "session_cookie_secure", fallback=""),
        None,
    )
    SESSION_COOKIE_HTTPONLY = _parse_bool(
        os.getenv("HASHCRUSH_SESSION_COOKIE_HTTPONLY")
        or file_config.get("app", "session_cookie_httponly", fallback="true"),
        True,
    )
    _cookie_samesite = sanitize_config_input(
        os.getenv("HASHCRUSH_SESSION_COOKIE_SAMESITE")
    ) or file_config.get("app", "session_cookie_samesite", fallback="Lax")
    _cookie_samesite = sanitize_config_input(_cookie_samesite).strip().lower()
    if _cookie_samesite == "strict":
        SESSION_COOKIE_SAMESITE = "Strict"
    elif _cookie_samesite == "none":
        SESSION_COOKIE_SAMESITE = "None"
    else:
        SESSION_COOKIE_SAMESITE = "Lax"

    _default_wordlists_path = "/usr/share/seclists/Passwords"
    _default_rules_path = "/usr/share/hashcat/rules"
    _default_runtime_path = os.path.join(tempfile.gettempdir(), "hashcrush-runtime")
    _default_ssl_cert_path = "/etc/hashcrush/ssl/cert.pem"
    _default_ssl_key_path = "/etc/hashcrush/ssl/key.pem"

    WORDLISTS_PATH = _normalize_dir_path(
        os.getenv("HASHCRUSH_WORDLISTS_PATH")
        or file_config.get("app", "wordlists_path", fallback=_default_wordlists_path),
        _default_wordlists_path,
    )
    RULES_PATH = _normalize_dir_path(
        os.getenv("HASHCRUSH_RULES_PATH")
        or file_config.get("app", "rules_path", fallback=_default_rules_path),
        _default_rules_path,
    )
    RUNTIME_PATH = _normalize_dir_path(
        os.getenv("HASHCRUSH_RUNTIME_PATH")
        or file_config.get("app", "runtime_path", fallback=_default_runtime_path),
        _default_runtime_path,
    )
    SSL_CERT_PATH = _normalize_file_path(
        os.getenv("HASHCRUSH_SSL_CERT_PATH")
        or file_config.get("app", "ssl_cert_path", fallback=_default_ssl_cert_path),
        _default_ssl_cert_path,
    )
    SSL_KEY_PATH = _normalize_file_path(
        os.getenv("HASHCRUSH_SSL_KEY_PATH")
        or file_config.get("app", "ssl_key_path", fallback=_default_ssl_key_path),
        _default_ssl_key_path,
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False
