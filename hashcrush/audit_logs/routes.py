"""Admin-only audit log views."""

from __future__ import annotations

import json

from flask import Blueprint, abort, render_template
from flask_login import current_user, login_required
from sqlalchemy import select

from hashcrush.models import AuditLog, db

audit_logs = Blueprint("audit_logs", __name__)


def _pretty_details(raw_details: str | None) -> str:
    try:
        parsed = json.loads(raw_details or "{}")
    except (TypeError, ValueError):
        return str(raw_details or "{}")
    return json.dumps(parsed, indent=2, sort_keys=True, ensure_ascii=True)


@audit_logs.route("/audit", methods=["GET"])
@login_required
def audit_logs_list():
    """Display recent audit log entries for administrators."""
    if not current_user.admin:
        abort(403)

    entries = db.session.execute(
        select(AuditLog)
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(200)
    ).scalars().all()
    entry_details = {entry.id: _pretty_details(entry.details_json) for entry in entries}
    return render_template(
        "audit_logs.html",
        title="Audit Log",
        entries=entries,
        entry_details=entry_details,
    )
