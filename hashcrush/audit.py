"""Audit logging helpers for sensitive application actions."""

from __future__ import annotations

import ipaddress
import json

from flask import current_app, has_request_context, request
from flask_login import current_user

from hashcrush.models import AuditLog, db


def _audit_client_ip() -> str | None:
    if not has_request_context():
        return None

    if current_app.config.get("TRUST_X_FORWARDED_FOR", False):
        forwarded_for = (request.headers.get("X-Forwarded-For") or "").strip()
        if forwarded_for:
            first_hop = forwarded_for.split(",", maxsplit=1)[0].strip()
            if first_hop:
                try:
                    ipaddress.ip_address(first_hop)
                    return first_hop
                except ValueError:
                    current_app.logger.warning(
                        "Ignoring invalid X-Forwarded-For value in audit log: %s",
                        first_hop,
                    )

    return request.remote_addr or None


def _actor_snapshot() -> tuple[int | None, str, bool]:
    if not has_request_context() or not getattr(current_user, "is_authenticated", False):
        return None, "<anonymous>", False

    return (
        getattr(current_user, "id", None),
        str(getattr(current_user, "username", "<unknown>") or "<unknown>"),
        bool(getattr(current_user, "admin", False)),
    )


def _serialize_details(details) -> str:
    if details is None:
        payload = {}
    elif isinstance(details, dict | list | tuple):
        payload = details
    else:
        payload = {"value": str(details)}
    return json.dumps(payload, sort_keys=True, ensure_ascii=True)


def record_audit_event(
    event_type: str,
    target_type: str,
    *,
    target_id=None,
    summary: str,
    details=None,
) -> None:
    """Persist an audit record without mutating the caller's ORM session."""
    actor_user_id, actor_username, actor_admin = _actor_snapshot()
    payload = {
        "actor_user_id": actor_user_id,
        "actor_username": actor_username,
        "actor_admin": actor_admin,
        "actor_ip": _audit_client_ip(),
        "event_type": str(event_type),
        "target_type": str(target_type),
        "target_id": None if target_id is None else str(target_id),
        "summary": str(summary),
        "details_json": _serialize_details(details),
    }
    try:
        with db.engine.begin() as connection:
            connection.execute(AuditLog.__table__.insert().values(**payload))
    except Exception:
        current_app.logger.exception(
            "Failed recording audit event type=%s target=%s target_id=%s",
            event_type,
            target_type,
            target_id,
        )
