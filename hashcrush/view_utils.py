"""Shared helpers for paginated list views and progress presentation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sqlalchemy import func, select

LIST_PAGE_SIZE = 50


@dataclass(frozen=True)
class PaginationState:
    """Simple pagination metadata for list pages."""

    page: int
    per_page: int
    total_items: int
    total_pages: int
    offset: int
    has_prev: bool
    has_next: bool
    prev_page: int | None
    next_page: int | None
    start_item: int
    end_item: int


def parse_page_arg(raw_value) -> int:
    """Normalize a query-string page value to a positive integer."""
    try:
        parsed = int(raw_value)
    except (TypeError, ValueError):
        return 1
    return parsed if parsed > 0 else 1


def build_pagination(total_items: int, page: int, per_page: int = LIST_PAGE_SIZE) -> PaginationState:
    """Return pagination metadata with page clamped into valid bounds."""
    safe_per_page = max(1, int(per_page))
    safe_total = max(0, int(total_items))
    total_pages = max(1, ((safe_total - 1) // safe_per_page) + 1) if safe_total else 1
    safe_page = min(max(1, int(page)), total_pages)
    offset = (safe_page - 1) * safe_per_page
    start_item = offset + 1 if safe_total else 0
    end_item = min(offset + safe_per_page, safe_total) if safe_total else 0
    return PaginationState(
        page=safe_page,
        per_page=safe_per_page,
        total_items=safe_total,
        total_pages=total_pages,
        offset=offset,
        has_prev=safe_page > 1,
        has_next=safe_page < total_pages,
        prev_page=(safe_page - 1) if safe_page > 1 else None,
        next_page=(safe_page + 1) if safe_page < total_pages else None,
        start_item=start_item,
        end_item=end_item,
    )


def paginate_scalars(session, stmt, *, page: int, per_page: int = LIST_PAGE_SIZE):
    """Execute a scalar select with COUNT/LIMIT/OFFSET pagination."""
    total_items = int(
        session.scalar(
            select(func.count()).select_from(stmt.order_by(None).subquery())
        )
        or 0
    )
    pagination = build_pagination(total_items, page, per_page)
    rows = session.execute(
        stmt.limit(pagination.per_page).offset(pagination.offset)
    ).scalars().all()
    return rows, pagination


def safe_relative_url(raw_url: str | None) -> str | None:
    """Return a safe same-host relative redirect target or ``None``."""

    if not raw_url:
        return None

    parsed = urlsplit(raw_url)
    if parsed.scheme or parsed.netloc:
        return None
    if not parsed.path.startswith('/'):
        return None
    if '\n' in raw_url or '\r' in raw_url:
        return None
    return raw_url


def append_query_params(url: str, **params: object | None) -> str:
    """Return ``url`` with query params merged and ``None`` values removed."""

    parsed = urlsplit(url)
    query_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    for key, value in params.items():
        if value in (None, ''):
            query_params.pop(key, None)
        else:
            query_params[key] = str(value)
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urlencode(query_params),
            parsed.fragment,
        )
    )


def parse_jobtask_progress(progress_payload: str | None) -> tuple[str | None, str | None]:
    """Extract percent done and ETA from persisted JobTask.progress JSON."""
    if not progress_payload:
        return None, None

    try:
        parsed = json.loads(progress_payload)
    except (TypeError, ValueError):
        return None, None

    if not isinstance(parsed, dict):
        return None, None

    eta_value = str(parsed.get('Time_Estimated') or '').strip() or None
    progress_value = str(parsed.get('Progress') or '').strip()

    percent_value = None
    if progress_value:
        match = re.search(r'\((\d+(?:\.\d+)?)%\)', progress_value)
        if match:
            percent_value = f"{match.group(1)}%"

    return percent_value, eta_value
