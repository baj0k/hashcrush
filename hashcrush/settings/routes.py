"""Flask routes to handle Settings"""

import os
import sys
from configparser import ConfigParser

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import select

import hashcrush
from hashcrush.audit import record_audit_event
from hashcrush.config import sanitize_config_input
from hashcrush.db_upgrade import get_schema_status
from hashcrush.models import Settings, db
from hashcrush.paths import get_default_config_path
from hashcrush.utils.utils import get_runtime_subdir

settings = Blueprint("settings", __name__)

HASHCRUSH_CONFIG_FIELDS = [
    {
        "section": "database",
        "key": "uri",
        "label": "Database URI",
        "env_name": "HASHCRUSH_DATABASE_URI",
        "default_display": "Preferred production path. Leave empty to use discrete PostgreSQL fields below.",
    },
    {
        "section": "database",
        "key": "host",
        "label": "Database Host",
        "env_name": "HASHCRUSH_DB_HOST",
        "default_display": "Required when database.uri is empty.",
    },
    {
        "section": "database",
        "key": "port",
        "label": "Database Port",
        "env_name": "HASHCRUSH_DB_PORT",
        "default_display": "5432",
    },
    {
        "section": "database",
        "key": "name",
        "label": "Database Name",
        "env_name": "HASHCRUSH_DB_NAME",
        "default_display": "hashcrush",
    },
    {
        "section": "database",
        "key": "username",
        "label": "Database Username",
        "env_name": "HASHCRUSH_DB_USERNAME",
        "default_display": "Required when database.uri is empty.",
    },
    {
        "section": "database",
        "key": "password",
        "label": "Database Password",
        "env_name": "HASHCRUSH_DB_PASSWORD",
        "default_display": "Required when database.uri is empty.",
    },
    {
        "section": "app",
        "key": "secret_key",
        "label": "Flask Secret Key",
        "env_name": "HASHCRUSH_SECRET_KEY",
        "default_display": "Required (no default).",
    },
    {
        "section": "app",
        "key": "hashcat_bin",
        "label": "Hashcat Binary Path",
        "env_name": "HASHCRUSH_HASHCAT_BIN",
        "default_display": "hashcat",
    },
    {
        "section": "app",
        "key": "hashcat_status_timer",
        "label": "Hashcat Status Timer (seconds)",
        "env_name": "HASHCRUSH_HASHCAT_STATUS_TIMER",
        "default_display": "5",
    },
    {
        "section": "app",
        "key": "hashfile_max_line_length",
        "label": "Hashfile Max Line Length",
        "env_name": "HASHCRUSH_HASHFILE_MAX_LINE_LENGTH",
        "default_display": "50000",
    },
    {
        "section": "app",
        "key": "hashfile_max_total_lines",
        "label": "Hashfile Max Total Lines",
        "env_name": "HASHCRUSH_HASHFILE_MAX_TOTAL_LINES",
        "default_display": "1000000",
    },
    {
        "section": "app",
        "key": "hashfile_max_total_bytes",
        "label": "Hashfile Max Total Bytes",
        "env_name": "HASHCRUSH_HASHFILE_MAX_TOTAL_BYTES",
        "default_display": "1073741824",
    },
    {
        "section": "app",
        "key": "runtime_path",
        "label": "Runtime Directory",
        "env_name": "HASHCRUSH_RUNTIME_PATH",
        "default_display": "/tmp/hashcrush-runtime",
    },
    {
        "section": "app",
        "key": "storage_path",
        "label": "Persistent Storage Directory",
        "env_name": "HASHCRUSH_STORAGE_PATH",
        "default_display": "/var/lib/hashcrush",
    },
    {
        "section": "app",
        "key": "ssl_cert_path",
        "label": "TLS Certificate Path",
        "env_name": "HASHCRUSH_SSL_CERT_PATH",
        "default_display": "/etc/hashcrush/ssl/cert.pem",
    },
    {
        "section": "app",
        "key": "ssl_key_path",
        "label": "TLS Key Path",
        "env_name": "HASHCRUSH_SSL_KEY_PATH",
        "default_display": "/etc/hashcrush/ssl/key.pem",
    },
    {
        "section": "app",
        "key": "auth_throttle_enabled",
        "label": "Auth Throttle Enabled",
        "env_name": "HASHCRUSH_AUTH_THROTTLE_ENABLED",
        "default_display": "true",
    },
    {
        "section": "app",
        "key": "auth_throttle_max_attempts",
        "label": "Auth Throttle Max Attempts",
        "env_name": "HASHCRUSH_AUTH_THROTTLE_MAX_ATTEMPTS",
        "default_display": "5",
    },
    {
        "section": "app",
        "key": "auth_throttle_window_seconds",
        "label": "Auth Throttle Window Seconds",
        "env_name": "HASHCRUSH_AUTH_THROTTLE_WINDOW_SECONDS",
        "default_display": "300",
    },
    {
        "section": "app",
        "key": "auth_throttle_lockout_seconds",
        "label": "Auth Throttle Lockout Seconds",
        "env_name": "HASHCRUSH_AUTH_THROTTLE_LOCKOUT_SECONDS",
        "default_display": "900",
    },
    {
        "section": "app",
        "key": "trust_x_forwarded_for",
        "label": "Trust X-Forwarded-For Header",
        "env_name": "HASHCRUSH_TRUST_X_FORWARDED_FOR",
        "default_display": "false",
    },
    {
        "section": "app",
        "key": "session_cookie_secure",
        "label": "Session Cookie Secure",
        "env_name": "HASHCRUSH_SESSION_COOKIE_SECURE",
        "default_display": "Auto-enabled in non-debug/non-testing deployments.",
    },
    {
        "section": "app",
        "key": "session_cookie_httponly",
        "label": "Session Cookie HttpOnly",
        "env_name": "HASHCRUSH_SESSION_COOKIE_HTTPONLY",
        "default_display": "true",
    },
    {
        "section": "app",
        "key": "session_cookie_samesite",
        "label": "Session Cookie SameSite",
        "env_name": "HASHCRUSH_SESSION_COOKIE_SAMESITE",
        "default_display": "Lax",
    },
]


def _temp_folder_path() -> str:
    return get_runtime_subdir("tmp")


def _hashcrush_config_path() -> str:
    configured = current_app.config.get("HASHCRUSH_CONFIG_PATH")
    if configured:
        return os.path.abspath(os.path.expanduser(str(configured)))
    return str(get_default_config_path())


def _load_hashcrush_config(config_path: str) -> ConfigParser:
    parser = ConfigParser(interpolation=None)
    parser.read(config_path)
    return parser


def _resolve_field_default(field: dict) -> str:
    return str(field["default_display"])


def _hashcrush_config_rows(parser: ConfigParser) -> list[dict[str, str | bool]]:
    rows: list[dict[str, str | bool]] = []
    for field in HASHCRUSH_CONFIG_FIELDS:
        section = field["section"]
        key = field["key"]
        env_name = field["env_name"]
        rows.append(
            {
                "section": section,
                "key": key,
                "label": field["label"],
                "form_name": f"cfg__{section}__{key}",
                "value": sanitize_config_input(parser.get(section, key, fallback="")),
                "default_display": _resolve_field_default(field),
                "env_name": env_name,
                "env_active": bool((os.getenv(env_name) or "").strip()),
            }
        )
    return rows


def _format_bytes(size_bytes: int) -> str:
    """Render a byte count into a compact human-readable string."""
    units = ["bytes", "KB", "MB", "GB", "TB"]
    value = float(max(size_bytes, 0))
    unit_index = 0
    while value >= 1024 and unit_index < len(units) - 1:
        value /= 1024
        unit_index += 1
    if unit_index == 0:
        return f"{int(value)} {units[unit_index]}"
    return f"{value:.2f} {units[unit_index]}"


def _temp_folder_size_bytes() -> int:
    """Calculate total bytes for regular files in the temp folder."""
    temp_folder_path = _temp_folder_path()
    if not os.path.isdir(temp_folder_path):
        return 0

    total = 0
    for entry in os.scandir(temp_folder_path):
        if not entry.is_file(follow_symlinks=False):
            continue
        try:
            total += entry.stat().st_size
        except OSError:
            continue
    return total


#############################################
# Settings
#############################################


@settings.route("/settings", methods=["GET"])
@login_required
def settings_list():
    """Function to return list of Settings"""

    if current_user.admin:
        settings = db.session.execute(select(Settings)).scalars().first()
        if not settings:
            settings = Settings()
            db.session.add(settings)
            db.session.commit()

        temp_folder_path = _temp_folder_path()
        os.makedirs(temp_folder_path, exist_ok=True)
        tmp_folder_size = _temp_folder_size_bytes()
        tmp_folder_size_human = _format_bytes(tmp_folder_size)

        config_path = _hashcrush_config_path()
        config_parser = _load_hashcrush_config(config_path)
        config_rows = _hashcrush_config_rows(config_parser)
        schema_status = get_schema_status()

        return render_template(
            "settings.html",
            title="settings",
            settings=settings,
            tmp_folder_size=tmp_folder_size,
            tmp_folder_size_human=tmp_folder_size_human,
            temp_folder_path=temp_folder_path,
            application_version=hashcrush.__version__,
            database_schema_mode=schema_status["mode"],
            database_schema_detail=schema_status["detail"],
            python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            config_path=config_path,
            config_file_exists=os.path.isfile(config_path),
            config_rows=config_rows,
        )

    abort(403)


@settings.route("/settings/hashcrush_config", methods=["POST"])
@login_required
def update_hashcrush_config():
    """Save editable HashCrush config values from the settings UI."""
    if not current_user.admin:
        abort(403)

    config_path = _hashcrush_config_path()
    config_parser = _load_hashcrush_config(config_path)
    original_values = {
        (field["section"], field["key"]): sanitize_config_input(
            config_parser.get(field["section"], field["key"], fallback="")
        ).strip()
        for field in HASHCRUSH_CONFIG_FIELDS
    }

    for field in HASHCRUSH_CONFIG_FIELDS:
        section = field["section"]
        if not config_parser.has_section(section):
            config_parser.add_section(section)

    for field in HASHCRUSH_CONFIG_FIELDS:
        section = field["section"]
        key = field["key"]
        form_name = f"cfg__{section}__{key}"

        if form_name not in request.form:
            continue

        submitted_value = sanitize_config_input(request.form.get(form_name)).strip()
        if submitted_value:
            config_parser.set(section, key, submitted_value)
        elif config_parser.has_option(section, key):
            config_parser.remove_option(section, key)

    for section in ("database", "app"):
        if config_parser.has_section(section) and not config_parser.items(section):
            config_parser.remove_section(section)

    try:
        config_directory = os.path.dirname(config_path)
        if config_directory:
            os.makedirs(config_directory, exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as config_file:
            config_parser.write(config_file)
    except OSError as error:
        flash(f'Failed to save config file at "{config_path}": {error}', "danger")
        return redirect(url_for("settings.settings_list") + "#nav-hashcrush")

    changed_fields = []
    for field in HASHCRUSH_CONFIG_FIELDS:
        key = (field["section"], field["key"])
        updated_value = sanitize_config_input(
            config_parser.get(field["section"], field["key"], fallback="")
        ).strip()
        if updated_value != original_values.get(key, ""):
            changed_fields.append(f"{field['section']}.{field['key']}")

    record_audit_event(
        'settings.config_update',
        'settings',
        target_id='hashcrush_config',
        summary='Updated HashCrush configuration file values.',
        details={'config_path': config_path, 'changed_fields': changed_fields},
    )
    flash(
        f'Updated configuration values in "{config_path}". Restart HashCrush to apply all changes.',
        "success",
    )
    return redirect(url_for("settings.settings_list") + "#nav-hashcrush")


@settings.route("/settings/clear_temp", methods=["POST"])
@login_required
def clear_temp_folder():
    """Function to clear temp folder"""
    if not current_user.admin:
        abort(403)

    temp_folder_path = _temp_folder_path()
    os.makedirs(temp_folder_path, exist_ok=True)
    removed_files = 0
    removed_bytes = 0
    failed_files = 0

    for entry in os.scandir(temp_folder_path):
        if not entry.is_file(follow_symlinks=False):
            continue
        try:
            removed_bytes += entry.stat().st_size
            os.remove(entry.path)
            removed_files += 1
        except OSError:
            failed_files += 1

    if failed_files:
        flash(
            f"Cleared {removed_files} temp file(s), freed {_format_bytes(removed_bytes)}. "
            f"{failed_files} file(s) could not be removed.",
            "warning",
        )
    elif removed_files:
        flash(
            f"Cleared {removed_files} temp file(s), freed {_format_bytes(removed_bytes)}.",
            "success",
        )
    else:
        flash("Temp folder is already empty.", "info")

    record_audit_event(
        'settings.temp_clear',
        'runtime_temp',
        target_id=temp_folder_path,
        summary='Cleared runtime temp folder contents.',
        details={
            'temp_folder_path': temp_folder_path,
            'removed_files': removed_files,
            'removed_bytes': removed_bytes,
            'failed_files': failed_files,
        },
    )
    return redirect(url_for("settings.settings_list") + "#nav-data")
