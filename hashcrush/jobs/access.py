"""Shared job access, visibility, and lightweight parsing helpers."""

from __future__ import annotations

from flask import flash
from flask_login import current_user

from hashcrush.authz import PUBLIC_JOB_VIEW_STATUSES, visible_jobs_query
from hashcrush.models import Jobs

ACTIVE_JOB_TASK_MUTATION_STATUSES = {"Running", "Queued", "Paused"}
ACTIVE_JOB_TASK_EXECUTION_STATUSES = {"Running", "Importing", "Queued", "Paused"}


def _can_manage_job(job: Jobs | None) -> bool:
    return bool(job and (current_user.admin or job.owner_id == current_user.id))


def _job_is_publicly_viewable(job: Jobs | None) -> bool:
    return bool(job and job.status in PUBLIC_JOB_VIEW_STATUSES)


def _can_view_job(job: Jobs | None) -> bool:
    return bool(job and (_can_manage_job(job) or _job_is_publicly_viewable(job)))


def _visible_jobs_query():
    return visible_jobs_query()


def _job_allows_task_mutation(job: Jobs) -> bool:
    return job.status not in ACTIVE_JOB_TASK_MUTATION_STATUSES


def _require_job_allows_task_mutation(job: Jobs) -> bool:
    if _job_allows_task_mutation(job):
        return True
    flash(
        "You cannot edit assigned tasks while the job is running, queued, or paused.",
        "danger",
    )
    return False


def _parse_positive_int(raw_value) -> int | None:
    try:
        parsed = int(raw_value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _normalize_task_id_list(raw_values) -> list[int]:
    if not isinstance(raw_values, list):
        return []
    normalized: list[int] = []
    for value in raw_values:
        parsed = _parse_positive_int(value)
        if parsed is None or parsed in normalized:
            continue
        normalized.append(parsed)
    return normalized
