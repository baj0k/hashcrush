"""Flask routes to handle Settings"""
import os
import sys
from flask import Blueprint, render_template, abort, url_for, flash, redirect
from flask_login import login_required, current_user
from sqlalchemy import text
import hashcrush
from hashcrush.models import Settings
from hashcrush.models import db


settings = Blueprint('settings', __name__)
TEMP_FOLDER_PATH = os.path.join('hashcrush', 'control', 'tmp')


def _format_bytes(size_bytes: int) -> str:
    """Render a byte count into a compact human-readable string."""
    units = ['bytes', 'KB', 'MB', 'GB', 'TB']
    value = float(max(size_bytes, 0))
    unit_index = 0
    while value >= 1024 and unit_index < len(units) - 1:
        value /= 1024
        unit_index += 1
    if unit_index == 0:
        return f'{int(value)} {units[unit_index]}'
    return f'{value:.2f} {units[unit_index]}'


def _temp_folder_size_bytes() -> int:
    """Calculate total bytes for regular files in the temp folder."""
    if not os.path.isdir(TEMP_FOLDER_PATH):
        return 0

    total = 0
    for entry in os.scandir(TEMP_FOLDER_PATH):
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


@settings.route("/settings", methods=['GET'])
@login_required
def settings_list():
    """Function to return list of Settings"""

    if current_user.admin:
        settings = Settings.query.first()
        if not settings:
            settings = Settings(retention_period=0, enabled_job_weights=False)
            db.session.add(settings)
            db.session.commit()

        os.makedirs(TEMP_FOLDER_PATH, exist_ok=True)
        tmp_folder_size = _temp_folder_size_bytes()
        tmp_folder_size_human = _format_bytes(tmp_folder_size)

        try:
            database_version = db.session.execute(text('SELECT version_num FROM alembic_version LIMIT 1;')).scalar()
        except Exception:
            database_version = None

        return render_template(
            'settings.html',
            title='settings',
            settings=settings,
            tmp_folder_size=tmp_folder_size,
            tmp_folder_size_human=tmp_folder_size_human,
            temp_folder_path=TEMP_FOLDER_PATH,
            application_version=hashcrush.__version__,
            database_version=database_version,
            python_version=f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}',
        )

    abort(403)


@settings.route('/settings/clear_temp', methods=['POST'])
@login_required
def clear_temp_folder():
    """Function to clear temp folder"""
    if not current_user.admin:
        abort(403)

    os.makedirs(TEMP_FOLDER_PATH, exist_ok=True)
    removed_files = 0
    removed_bytes = 0
    failed_files = 0

    for entry in os.scandir(TEMP_FOLDER_PATH):
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
            f'Cleared {removed_files} temp file(s), freed {_format_bytes(removed_bytes)}. '
            f'{failed_files} file(s) could not be removed.',
            'warning',
        )
    elif removed_files:
        flash(f'Cleared {removed_files} temp file(s), freed {_format_bytes(removed_bytes)}.', 'success')
    else:
        flash('Temp folder is already empty.', 'info')

    return redirect(url_for('settings.settings_list') + '#nav-data')

