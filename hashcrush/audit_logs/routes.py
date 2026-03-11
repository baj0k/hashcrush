"""Admin-only audit log views."""

from __future__ import annotations

import csv
import io
import json
from datetime import date, datetime, time, timedelta
from urllib.parse import urlencode

from flask import Blueprint, abort, render_template, request, send_file, url_for
from flask_login import current_user, login_required
from sqlalchemy import select

from hashcrush.models import AuditLog, db
from hashcrush.view_utils import paginate_scalars, parse_page_arg

audit_logs = Blueprint("audit_logs", __name__)
AUDIT_PAGE_SIZE = 50


def _pretty_details(raw_details: str | None) -> str:
    try:
        parsed = json.loads(raw_details or "{}")
    except (TypeError, ValueError):
        return str(raw_details or "{}")
    return json.dumps(parsed, indent=2, sort_keys=True, ensure_ascii=True)


def _normalized_filter(value: str | None) -> str:
    return (value or "").strip()


def _parse_filter_date(raw_value: str | None) -> date | None:
    value = _normalized_filter(raw_value)
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def _audit_filter_values():
    actor_username = _normalized_filter(request.args.get("actor"))
    event_type = _normalized_filter(request.args.get("event_type"))
    target_type = _normalized_filter(request.args.get("target_type"))
    date_from = _parse_filter_date(request.args.get("date_from"))
    date_to = _parse_filter_date(request.args.get("date_to"))
    export = _normalized_filter(request.args.get("export"))
    return {
        "actor": actor_username,
        "event_type": event_type,
        "target_type": target_type,
        "date_from": date_from.isoformat() if date_from else "",
        "date_to": date_to.isoformat() if date_to else "",
        "date_from_value": date_from,
        "date_to_value": date_to,
        "export": export,
    }


def _filtered_audit_stmt(filters: dict):
    stmt = select(AuditLog)
    actor_username = filters["actor"]
    event_type = filters["event_type"]
    target_type = filters["target_type"]
    date_from = filters["date_from_value"]
    date_to = filters["date_to_value"]

    if actor_username:
        stmt = stmt.where(AuditLog.actor_username.ilike(f"%{actor_username}%"))
    if event_type:
        stmt = stmt.where(AuditLog.event_type == event_type)
    if target_type:
        stmt = stmt.where(AuditLog.target_type == target_type)
    if date_from:
        stmt = stmt.where(
            AuditLog.created_at >= datetime.combine(date_from, time.min)
        )
    if date_to:
        stmt = stmt.where(
            AuditLog.created_at < datetime.combine(date_to + timedelta(days=1), time.min)
        )
    return stmt.order_by(AuditLog.created_at.desc(), AuditLog.id.desc())


def _distinct_column_values(column):
    return [
        value
        for value in db.session.execute(
            select(column).distinct().order_by(column.asc())
        ).scalars().all()
        if value
    ]


def _query_string_for_page(filters: dict, page: int) -> str:
    query = {
        key: value
        for key, value in {
            "actor": filters["actor"],
            "event_type": filters["event_type"],
            "target_type": filters["target_type"],
            "date_from": filters["date_from"],
            "date_to": filters["date_to"],
            "page": page,
        }.items()
        if value not in ("", None)
    }
    return urlencode(query)


def _audit_export_response(entries: list[AuditLog]):
    str_io = io.StringIO()
    writer = csv.writer(str_io)
    writer.writerow(
        [
            "created_at_utc",
            "actor_username",
            "actor_admin",
            "actor_ip",
            "event_type",
            "target_type",
            "target_id",
            "summary",
            "details_json",
        ]
    )
    for entry in entries:
        writer.writerow(
            [
                entry.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                entry.actor_username,
                "true" if entry.actor_admin else "false",
                entry.actor_ip or "",
                entry.event_type,
                entry.target_type,
                entry.target_id or "",
                entry.summary,
                entry.details_json,
            ]
        )
    byte_io = io.BytesIO(str_io.getvalue().encode("utf-8"))
    byte_io.seek(0)
    str_io.close()
    return send_file(
        byte_io,
        mimetype="text/csv",
        download_name="audit_log.csv",
        as_attachment=True,
    )


@audit_logs.route("/audit", methods=["GET"])
@login_required
def audit_logs_list():
    """Display recent audit log entries for administrators."""
    if not current_user.admin:
        abort(403)

    filters = _audit_filter_values()
    filtered_stmt = _filtered_audit_stmt(filters)
    if filters["export"] == "csv":
        entries = db.session.execute(filtered_stmt).scalars().all()
        return _audit_export_response(entries)

    page = parse_page_arg(request.args.get("page"))
    entries, pagination = paginate_scalars(
        db.session,
        filtered_stmt,
        page=page,
        per_page=AUDIT_PAGE_SIZE,
    )
    entry_details = {entry.id: _pretty_details(entry.details_json) for entry in entries}
    return render_template(
        "audit_logs.html",
        title="Audit Log",
        entries=entries,
        entry_details=entry_details,
        filters=filters,
        event_types=_distinct_column_values(AuditLog.event_type),
        target_types=_distinct_column_values(AuditLog.target_type),
        pagination=pagination,
        prev_page_url=(
            url_for("audit_logs.audit_logs_list")
            + "?"
            + _query_string_for_page(filters, pagination.prev_page)
            if pagination.has_prev and pagination.prev_page
            else None
        ),
        next_page_url=(
            url_for("audit_logs.audit_logs_list")
            + "?"
            + _query_string_for_page(filters, pagination.next_page)
            if pagination.has_next and pagination.next_page
            else None
        ),
        csv_export_url=(
            url_for("audit_logs.audit_logs_list")
            + "?"
            + urlencode(
                {
                    key: value
                    for key, value in {
                        "actor": filters["actor"],
                        "event_type": filters["event_type"],
                        "target_type": filters["target_type"],
                        "date_from": filters["date_from"],
                        "date_to": filters["date_to"],
                        "export": "csv",
                    }.items()
                    if value not in ("", None)
                }
            )
        ),
    )
