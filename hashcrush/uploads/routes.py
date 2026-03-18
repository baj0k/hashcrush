"""Routes for polling async upload operations."""

from __future__ import annotations

from flask import Blueprint, abort, current_app, flash, jsonify
from flask_login import current_user, login_required

uploads = Blueprint("uploads", __name__)


@uploads.route("/uploads/operations/<string:operation_id>", methods=["GET"])
@login_required
def upload_operation_status(operation_id: str):
    """Return JSON status for an in-progress upload operation."""

    service = current_app.extensions.get("upload_operations")
    if service is None:
        abort(503)

    snapshot = service.get_operation(operation_id)
    if snapshot is None:
        abort(404)

    current_user_id = getattr(current_user, "id", None)
    if (not getattr(current_user, "admin", False)) and (
        snapshot.owner_user_id != current_user_id
    ):
        abort(403)

    for category, message in service.consume_completion_flashes(operation_id):
        flash(message, category)

    refreshed_snapshot = service.get_operation(operation_id)
    if refreshed_snapshot is None:
        abort(404)
    return jsonify(refreshed_snapshot.to_response_dict())
