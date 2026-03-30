"""Job task status lifecycle helpers."""

from __future__ import annotations

from datetime import datetime

from flask import current_app
from sqlalchemy import func, select

from hashcrush.models import Hashfiles, Jobs, JobTasks, db
from hashcrush.utils.storage_paths import utc_now_naive


def update_job_task_status(jobtask_id, status):
    """Update the status of a JobTask and cascade changes to its Job."""
    jobtask = db.session.get(JobTasks, jobtask_id)
    if jobtask is None:
        return False

    jobtask.status = status
    if status in ("Completed", "Canceled", "Paused"):
        jobtask.worker_pid = None

    db.session.commit()

    job = db.session.get(Jobs, jobtask.job_id)
    if not job:
        return True

    if status in ("Running", "Importing") and job.status in ("Queued", "Paused"):
        job.status = "Running"
        if not job.started_at:
            job.started_at = utc_now_naive()
        db.session.commit()

    if status == "Paused" and job.status != "Paused":
        job.status = "Paused"
        db.session.commit()

    active_statuses = {"Queued", "Running", "Importing", "Paused"}
    remaining_active = int(
        db.session.scalar(
            select(func.count())
            .select_from(JobTasks)
            .where(JobTasks.job_id == job.id)
            .where(JobTasks.status.in_(active_statuses))
        )
        or 0
    )

    if remaining_active == 0 and job.status in ("Queued", "Running", "Paused"):
        any_canceled = bool(
            db.session.scalar(
                select(JobTasks.id)
                .where(JobTasks.job_id == job.id)
                .where(JobTasks.status == "Canceled")
                .limit(1)
            )
        )

        job.status = "Canceled" if any_canceled else "Completed"
        job.ended_at = utc_now_naive()
        db.session.commit()
        current_app.logger.info(
            'Job lifecycle update: job_id=%s name="%s" finished with status=%s',
            job.id,
            job.name,
            job.status,
        )

        try:
            start_time = job.started_at
            end_time = job.ended_at
            if isinstance(start_time, str):
                start_time = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
            if isinstance(end_time, str):
                end_time = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
            if isinstance(start_time, datetime) and isinstance(end_time, datetime):
                duration = int(abs((end_time - start_time).total_seconds()))
            else:
                duration = 0
        except Exception:
            duration = 0

        if duration and job.hashfile_id:
            hashfile = db.session.get(Hashfiles, job.hashfile_id)
            if hashfile:
                hashfile.runtime += duration
                db.session.commit()

    elif remaining_active > 0:
        has_running = bool(
            db.session.scalar(
                select(JobTasks.id)
                .where(JobTasks.job_id == job.id)
                .where(JobTasks.status.in_(("Running", "Importing")))
                .limit(1)
            )
        )
        has_paused = bool(
            db.session.scalar(
                select(JobTasks.id)
                .where(JobTasks.job_id == job.id)
                .where(JobTasks.status == "Paused")
                .limit(1)
            )
        )
        has_queued = bool(
            db.session.scalar(
                select(JobTasks.id)
                .where(JobTasks.job_id == job.id)
                .where(JobTasks.status == "Queued")
                .limit(1)
            )
        )

        if has_running and job.status != "Running":
            job.status = "Running"
            db.session.commit()
        elif not has_running and has_paused and job.status != "Paused":
            job.status = "Paused"
            db.session.commit()
        elif not has_running and not has_paused and has_queued and job.status != "Queued":
            job.status = "Queued"
            db.session.commit()

    return True
