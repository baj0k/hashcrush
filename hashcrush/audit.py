"""Audit logging helpers for sensitive application actions."""

from __future__ import annotations

import ipaddress
import json
import logging

from flask import current_app, has_request_context, request
from flask_login import current_user
from sqlalchemy import event
from sqlalchemy.orm import Session as OrmSession

from hashcrush.models import AuditLog, db

_PENDING_AUDIT_EVENTS_KEY = "hashcrush_pending_audit_events"


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


def _insert_audit_payloads(payloads: list[dict]) -> None:
    if not payloads:
        return
    with db.engine.begin() as connection:
        connection.execute(AuditLog.__table__.insert(), payloads)


def _audit_logger():
    if has_request_context():
        return current_app.logger
    return logging.getLogger("hashcrush.audit")


def _pop_pending_audit_events(session) -> list[dict]:
    return list(session.info.pop(_PENDING_AUDIT_EVENTS_KEY, []))


@event.listens_for(OrmSession, "after_commit")
def _flush_pending_audit_events(session) -> None:
    payloads = _pop_pending_audit_events(session)
    if not payloads:
        return
    try:
        _insert_audit_payloads(payloads)
    except Exception:
        _audit_logger().exception(
            "Failed flushing %s pending audit event(s) after commit.",
            len(payloads),
        )


@event.listens_for(OrmSession, "after_rollback")
def _clear_pending_audit_events_on_rollback(session) -> None:
    session.info.pop(_PENDING_AUDIT_EVENTS_KEY, None)


@event.listens_for(OrmSession, "after_soft_rollback")
def _clear_pending_audit_events_on_soft_rollback(session, previous_transaction) -> None:
    del previous_transaction
    session.info.pop(_PENDING_AUDIT_EVENTS_KEY, None)


def record_audit_event(
    event_type: str,
    target_type: str,
    *,
    target_id=None,
    summary: str,
    details=None,
) -> None:
    """Queue audit persistence for after-commit, or write immediately post-commit."""
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
        session = db.session()
        should_defer = bool(
            session.info.get(_PENDING_AUDIT_EVENTS_KEY)
            or session.new
            or session.dirty
            or session.deleted
        )
        if should_defer:
            session.info.setdefault(_PENDING_AUDIT_EVENTS_KEY, []).append(payload)
            return
        _insert_audit_payloads([payload])
    except Exception:
        _audit_logger().exception(
            "Failed recording audit event type=%s target=%s target_id=%s",
            event_type,
            target_type,
            target_id,
        )
