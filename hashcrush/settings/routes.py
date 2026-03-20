"""Flask routes to handle Settings"""

import os
import sys

from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    url_for,
)
from flask_login import current_user, login_required

import hashcrush
from hashcrush.audit import record_audit_event
from hashcrush.db_upgrade import get_schema_status
from hashcrush.utils.utils import get_runtime_subdir

settings = Blueprint("settings", __name__)


def _temp_folder_path() -> str:
    return get_runtime_subdir("tmp")


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
        temp_folder_path = _temp_folder_path()
        os.makedirs(temp_folder_path, exist_ok=True)
        tmp_folder_size = _temp_folder_size_bytes()
        tmp_folder_size_human = _format_bytes(tmp_folder_size)
        schema_status = get_schema_status()

        return render_template(
            "settings.html",
            title="settings",
            tmp_folder_size=tmp_folder_size,
            tmp_folder_size_human=tmp_folder_size_human,
            temp_folder_path=temp_folder_path,
            application_version=hashcrush.__version__,
            database_schema_mode=schema_status["mode"],
            database_schema_detail=schema_status["detail"],
            python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        )

    abort(403)


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
