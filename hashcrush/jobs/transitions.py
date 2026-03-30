"""Job lifecycle transition helpers."""

from __future__ import annotations

from sqlalchemy import delete, select

from hashcrush.executor.hashcat_command import build_hashcat_command
from hashcrush.jobs.access import ACTIVE_JOB_TASK_EXECUTION_STATUSES
from hashcrush.models import Jobs, JobTasks, Tasks, db
from hashcrush.utils.storage_paths import utc_now_naive


class JobTransitionError(ValueError):
    """Raised when a requested job transition is invalid."""

    def __init__(self, message: str, *, builder_tab: str | None = None):
        super().__init__(message)
        self.builder_tab = builder_tab


def finalize_job(job: Jobs, job_tasks: list[JobTasks]) -> None:
    """Mark a draft job ready for scheduling."""
    for job_task in job_tasks:
        job_task.status = "Ready"

    job.status = "Ready"
    job.updated_at = utc_now_naive()


def queue_job_for_start(job: Jobs, job_tasks: list[JobTasks]) -> str:
    """Queue a ready or canceled job for worker execution."""
    if not job_tasks:
        raise JobTransitionError("Error in starting job")

    if job.status not in ("Ready", "Canceled"):
        raise JobTransitionError("Only ready or canceled jobs can be started.")

    previous_status = job.status
    job.status = "Queued"
    job.queued_at = utc_now_naive()
    job.started_at = None
    job.ended_at = None
    visible_task_ids = set(db.session.scalars(select(Tasks.id)).all())
    for job_task in job_tasks:
        if job_task.task_id not in visible_task_ids:
            raise JobTransitionError(
                "One or more assigned tasks are invalid or no longer available.",
                builder_tab="tasks",
            )
        job_task.status = "Queued"
        job_task.priority = job.priority
        job_task.started_at = None
        job_task.progress = None
        job_task.benchmark = None
        job_task.worker_pid = None
        try:
            job_task.command = build_hashcat_command(job.id, job_task.task_id)
        except ValueError as exc:
            raise JobTransitionError(str(exc)) from exc

    return previous_status


def stop_job_execution(job: Jobs, job_tasks: list[JobTasks]) -> tuple[str, int]:
    """Cancel an actively executing job."""
    if job.status not in ("Running", "Queued", "Paused"):
        raise JobTransitionError("Job is not actively running.")

    previous_status = job.status
    job.status = "Canceled"
    job.ended_at = utc_now_naive()

    canceled_task_count = 0
    for job_task in job_tasks:
        if job_task.status in ACTIVE_JOB_TASK_EXECUTION_STATUSES:
            job_task.status = "Canceled"
            canceled_task_count += 1

    return previous_status, canceled_task_count


def pause_job_execution(job: Jobs, job_tasks: list[JobTasks]) -> str:
    """Pause a running or queued job."""
    if job.status not in ("Running", "Queued"):
        raise JobTransitionError("Job is not running or queued.")

    previous_status = job.status
    job.status = "Paused"
    for job_task in job_tasks:
        if job_task.status in ("Running", "Importing", "Queued"):
            job_task.status = "Paused"

    return previous_status


def resume_job_execution(job: Jobs, job_tasks: list[JobTasks]) -> tuple[str, str]:
    """Resume a paused job."""
    if job.status != "Paused":
        raise JobTransitionError("Job is not paused.")

    previous_status = job.status
    for job_task in job_tasks:
        if job_task.status == "Paused":
            job_task.status = "Queued"

    has_running = any(task.status in ("Running", "Importing") for task in job_tasks)
    has_queued = any(task.status == "Queued" for task in job_tasks)

    if has_running:
        job.status = "Running"
    elif has_queued:
        job.status = "Queued"
        job.queued_at = utc_now_naive()
    else:
        job.status = "Paused"

    return previous_status, job.status


def delete_job_with_tasks(job: Jobs) -> dict[str, object]:
    """Delete a job and its task links, returning audit metadata."""
    deleted_job_name = job.name
    deleted_job_status = job.status
    deleted_owner_id = job.owner_id
    job_id = job.id

    db.session.execute(delete(JobTasks).filter_by(job_id=job_id))
    db.session.delete(job)

    return {
        "job_id": job_id,
        "job_name": deleted_job_name,
        "previous_status": deleted_job_status,
        "owner_id": deleted_owner_id,
    }
