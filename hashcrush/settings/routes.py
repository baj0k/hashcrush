"""Flask routes for admin runtime operations and instance info."""

import os
import sys

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required

import hashcrush
from hashcrush.audit import capture_audit_actor, record_audit_event
from hashcrush.db_upgrade import get_schema_status
from hashcrush.hibp.service import (
    get_hibp_ntlm_dataset_mount_root,
    get_mounted_hibp_ntlm_dataset_cache_snapshot,
    get_hibp_ntlm_dataset_summary,
    rescan_mounted_hibp_ntlm_dataset_files,
    validate_mounted_hibp_ntlm_dataset_path,
)
from hashcrush.utils.formatting import format_bytes as _format_bytes
from hashcrush.utils.storage_paths import get_runtime_subdir
from hashcrush.rules.service import (
    get_external_rule_cache_snapshot,
    get_external_rule_root,
    rescan_external_rule_files,
)
from hashcrush.wordlists.service import (
    get_external_wordlist_cache_snapshot,
    get_external_wordlist_root,
    rescan_external_wordlist_files,
)

settings = Blueprint("settings", __name__)


def _is_async_upload_request() -> bool:
    return request.headers.get("X-Requested-With") == "XMLHttpRequest"


def _async_operation_response(operation):
    payload = operation.to_response_dict()
    payload["status_url"] = url_for(
        "uploads.upload_operation_status",
        operation_id=operation.id,
    )
    return jsonify(payload), 202


def _async_error_response(title: str, detail: str):
    return jsonify({"title": title, "detail": detail}), 400


def _temp_folder_path() -> str:
    return get_runtime_subdir("tmp")


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


def _breach_intelligence_context() -> dict[str, object]:
    """Build template context for the offline HIBP management page."""

    hibp_dataset_summary = get_hibp_ntlm_dataset_summary()
    hibp_dataset_mount_root = get_hibp_ntlm_dataset_mount_root()
    hibp_cache_snapshot = get_mounted_hibp_ntlm_dataset_cache_snapshot()
    hibp_mounted_dataset_files = hibp_cache_snapshot.files
    default_mounted_dataset_path = os.path.join(
        hibp_dataset_mount_root,
        "hibp-ntlm.txt",
    )
    if default_mounted_dataset_path in hibp_mounted_dataset_files:
        hibp_selected_mounted_dataset_path = default_mounted_dataset_path
    elif hibp_mounted_dataset_files:
        hibp_selected_mounted_dataset_path = hibp_mounted_dataset_files[0]
    else:
        hibp_selected_mounted_dataset_path = default_mounted_dataset_path

    return {
        "hibp_dataset_summary": hibp_dataset_summary,
        "hibp_dataset_mount_root": hibp_dataset_mount_root,
        "hibp_mounted_dataset_files": hibp_mounted_dataset_files,
        "hibp_selected_mounted_dataset_path": hibp_selected_mounted_dataset_path,
        "hibp_cache_refreshed_at": hibp_cache_snapshot.refreshed_at,
    }


@settings.route("/settings", methods=["GET"])
@login_required
def settings_list():
    """Render the admin settings page."""

    if current_user.admin:
        temp_folder_path = _temp_folder_path()
        os.makedirs(temp_folder_path, exist_ok=True)
        tmp_folder_size = _temp_folder_size_bytes()
        tmp_folder_size_human = _format_bytes(tmp_folder_size)
        schema_status = get_schema_status()
        wordlist_cache_snapshot = get_external_wordlist_cache_snapshot()
        rule_cache_snapshot = get_external_rule_cache_snapshot()
        hibp_cache_snapshot = get_mounted_hibp_ntlm_dataset_cache_snapshot()

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
            external_wordlist_root=get_external_wordlist_root(),
            external_wordlist_cache_count=len(wordlist_cache_snapshot.files),
            external_wordlist_cache_refreshed_at=wordlist_cache_snapshot.refreshed_at,
            external_rule_root=get_external_rule_root(),
            external_rule_cache_count=len(rule_cache_snapshot.files),
            external_rule_cache_refreshed_at=rule_cache_snapshot.refreshed_at,
            hibp_dataset_mount_root=get_hibp_ntlm_dataset_mount_root(),
            hibp_cache_count=len(hibp_cache_snapshot.files),
            hibp_cache_refreshed_at=hibp_cache_snapshot.refreshed_at,
        )

    abort(403)


@settings.route("/breach-intelligence", methods=["GET"])
@login_required
def breach_intelligence():
    """Render the offline breach-intelligence admin page."""

    if not current_user.admin:
        abort(403)

    return render_template(
        "breach_intelligence.html",
        title="breach intelligence",
        **_breach_intelligence_context(),
    )


@settings.route("/settings/clear_temp", methods=["POST"])
@login_required
def clear_temp_folder():
    """Clear generated files from the runtime temp directory."""
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


@settings.route("/settings/rescan-mounted-folders", methods=["POST"])
@login_required
def rescan_mounted_folders():
    """Refresh cached file listings for mounted external resources."""

    if not current_user.admin:
        abort(403)

    wordlist_snapshot = rescan_external_wordlist_files()
    rule_snapshot = rescan_external_rule_files()
    hibp_snapshot = rescan_mounted_hibp_ntlm_dataset_files()
    flash(
        (
            "Rescanned mounted folders. "
            f"Cached {len(wordlist_snapshot.files)} wordlist file(s), "
            f"{len(rule_snapshot.files)} rule file(s), and "
            f"{len(hibp_snapshot.files)} HIBP dataset file(s)."
        ),
        "success",
    )
    record_audit_event(
        "settings.rescan_mounted_folders",
        "mounted_folders",
        summary="Rescanned mounted folders for cached file listings.",
        details={
            "external_wordlist_root": wordlist_snapshot.root,
            "external_wordlist_count": len(wordlist_snapshot.files),
            "external_rule_root": rule_snapshot.root,
            "external_rule_count": len(rule_snapshot.files),
            "hibp_root": hibp_snapshot.root,
            "hibp_count": len(hibp_snapshot.files),
        },
    )
    return redirect(url_for("settings.settings_list") + "#nav-data")



@settings.route("/settings/hibp_ntlm_dataset/mounted", methods=["POST"])
@login_required
def load_mounted_hibp_ntlm_dataset():
    """Queue an offline HIBP NTLM dataset load from a mounted container path."""

    if not current_user.admin:
        abort(403)

    mounted_dataset_path, error_message = validate_mounted_hibp_ntlm_dataset_path(
        request.form.get("mounted_dataset_path")
    )
    if error_message:
        if _is_async_upload_request():
            return _async_error_response("Mounted dataset load failed.", error_message)
        flash(error_message, "danger")
        return redirect(url_for("settings.breach_intelligence"))

    version_label = (request.form.get("version_label") or "").strip() or None
    operation = current_app.extensions["upload_operations"].start_operation(
        owner_user_id=getattr(current_user, "id", None),
        operation_type="hibp_ntlm_dataset_register",
        redirect_url=url_for("settings.breach_intelligence"),
        payload={
            "source_path": mounted_dataset_path,
            "version_label": version_label or "",
            "source_filename": os.path.basename(mounted_dataset_path),
            "audit_actor": capture_audit_actor(),
        },
    )

    if _is_async_upload_request():
        return _async_operation_response(operation)

    flash(
        "Mounted offline HIBP NTLM dataset load queued. Processing will continue in the background.",
        "info",
    )
    return redirect(url_for("settings.breach_intelligence"))


@settings.route("/settings/hibp_ntlm_dataset/backfill", methods=["POST"])
@login_required
def backfill_hibp_ntlm_dataset():
    """Queue a refresh of stored NTLM hashes against the active offline dataset."""

    if not current_user.admin:
        abort(403)

    dataset_summary = get_hibp_ntlm_dataset_summary()
    if not dataset_summary.loaded:
        message = "Load an offline HIBP NTLM dataset before refreshing existing hashes."
        if _is_async_upload_request():
            return _async_error_response("Exposure refresh failed.", message)
        flash(message, "danger")
        return redirect(url_for("settings.breach_intelligence"))

    operation = current_app.extensions["upload_operations"].start_operation(
        owner_user_id=getattr(current_user, "id", None),
        operation_type="hibp_ntlm_dataset_backfill",
        redirect_url=url_for("settings.breach_intelligence"),
        payload={
            "audit_actor": capture_audit_actor(),
        },
    )

    if _is_async_upload_request():
        return _async_operation_response(operation)

    flash(
        "Existing NTLM hashes queued for refresh against the offline dataset.",
        "info",
    )
    return redirect(url_for("settings.breach_intelligence"))
