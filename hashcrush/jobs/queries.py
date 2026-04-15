"""Job-specific query and presentation data assembly helpers."""

from __future__ import annotations

from collections import defaultdict

from sqlalchemy import case, func, select

from hashcrush.domains.service import job_domain_summaries
from hashcrush.jobs.access import _parse_positive_int, _visible_jobs_query
from hashcrush.models import (
    Hashes,
    HashfileHashes,
    Hashfiles,
    Jobs,
    JobTasks,
    Tasks,
    Users,
    db,
)
from hashcrush.utils.views import paginate_scalars, parse_jobtask_progress


def _visible_hashfiles_for_job(job: Jobs) -> list[Hashfiles]:
    return db.session.execute(
        select(Hashfiles).order_by(Hashfiles.uploaded_at.desc(), Hashfiles.name.asc())
    ).scalars().all()


def _job_task_ordering():
    return (JobTasks.position.asc(), JobTasks.id.asc())


def _next_job_task_position(job_id: int) -> int:
    current_max = db.session.scalar(
        select(func.max(JobTasks.position)).where(JobTasks.job_id == job_id)
    )
    return int(current_max if current_max is not None else -1) + 1


def _build_active_jobs_summary():
    active_jobs = db.session.execute(
        _visible_jobs_query()
        .where(Jobs.status.in_(("Running", "Queued")))
        .order_by(
            case((Jobs.status == "Running", 0), else_=1),
            Jobs.priority.desc(),
            Jobs.queued_at.asc(),
            Jobs.id.asc(),
        )
    ).scalars().all()
    running_jobs = [job for job in active_jobs if job.status == "Running"]
    queued_jobs = [job for job in active_jobs if job.status == "Queued"]
    active_job_ids = [job.id for job in active_jobs]
    owner_ids = sorted({job.owner_id for job in active_jobs})

    active_owner_names = {
        row.id: row.username
        for row in (
            db.session.execute(
                select(Users.id, Users.username).where(Users.id.in_(owner_ids))
            ).all()
            if owner_ids
            else []
        )
    }
    active_job_domain_summaries = job_domain_summaries(active_job_ids)

    active_job_tasks = (
        db.session.execute(
            select(JobTasks)
            .where(JobTasks.job_id.in_(active_job_ids))
            .order_by(JobTasks.job_id.asc(), *_job_task_ordering())
        ).scalars().all()
        if active_job_ids
        else []
    )
    active_task_ids = sorted({job_task.task_id for job_task in active_job_tasks})
    task_names = {
        row.id: row.name
        for row in (
            db.session.execute(
                select(Tasks.id, Tasks.name).where(Tasks.id.in_(active_task_ids))
            ).all()
            if active_task_ids
            else []
        )
    }

    hashfile_ids = [job.hashfile_id for job in active_jobs if job.hashfile_id]
    hashfile_stats = {}
    if hashfile_ids:
        stats_rows = db.session.execute(
            select(
                HashfileHashes.hashfile_id,
                func.count(Hashes.id).label("total_count"),
                func.sum(case((Hashes.cracked.is_(True), 1), else_=0)).label(
                    "cracked_count"
                ),
            )
            .select_from(HashfileHashes)
            .join(Hashes, Hashes.id == HashfileHashes.hash_id)
            .where(HashfileHashes.hashfile_id.in_(hashfile_ids))
            .group_by(HashfileHashes.hashfile_id)
        ).all()
        hashfile_stats = {
            row.hashfile_id: (int(row.cracked_count or 0), int(row.total_count or 0))
            for row in stats_rows
        }

    active_job_recovered = {}
    for job in active_jobs:
        cracked, total = hashfile_stats.get(job.hashfile_id, (0, 0))
        active_job_recovered[job.id] = f"{cracked}/{total}"

    active_job_task_runtime_progress: dict[int, dict[str, str]] = {}
    active_job_task_rows_by_job_id: dict[int, list[dict[str, object]]] = defaultdict(list)
    active_job_progress_summary: dict[int, dict[str, int]] = defaultdict(
        lambda: {"total": 0, "completed": 0, "running": 0}
    )
    for job_task in active_job_tasks:
        percent_done, eta = parse_jobtask_progress(job_task.progress)
        active_job_task_runtime_progress[job_task.id] = {
            "percent_done": percent_done or "N/A",
            "eta": eta or "N/A",
        }
        active_job_task_rows_by_job_id[job_task.job_id].append(
            {
                "job_task": job_task,
                "task_name": task_names.get(job_task.task_id, ""),
            }
        )
        active_job_progress_summary[job_task.job_id]["total"] += 1
        if job_task.status == "Completed":
            active_job_progress_summary[job_task.job_id]["completed"] += 1
        elif job_task.status in ("Running", "Importing"):
            active_job_progress_summary[job_task.job_id]["running"] += 1

    return {
        "running_jobs": running_jobs,
        "queued_jobs": queued_jobs,
        "active_job_domain_summaries": active_job_domain_summaries,
        "active_owner_names": active_owner_names,
        "active_job_task_rows_by_job_id": active_job_task_rows_by_job_id,
        "active_job_progress_summary": active_job_progress_summary,
        "active_job_task_runtime_progress": active_job_task_runtime_progress,
        "active_job_recovered": active_job_recovered,
    }


def _hashfile_rate_rows(hashfiles: list[Hashfiles]) -> dict[int, str]:
    if not hashfiles:
        return {}

    hashfile_ids = [hashfile.id for hashfile in hashfiles]
    stats_rows = (
        db.session.execute(
            select(
                HashfileHashes.hashfile_id,
                func.count(Hashes.id).label("total_count"),
                func.sum(case((Hashes.cracked.is_(True), 1), else_=0)).label(
                    "cracked_count"
                ),
            )
            .select_from(HashfileHashes)
            .join(Hashes, Hashes.id == HashfileHashes.hash_id)
            .where(HashfileHashes.hashfile_id.in_(hashfile_ids))
            .group_by(HashfileHashes.hashfile_id)
        ).all()
        if hashfile_ids
        else []
    )
    stats_by_hashfile_id = {
        row.hashfile_id: (int(row.cracked_count or 0), int(row.total_count or 0))
        for row in stats_rows
    }
    return {
        hashfile.id: f"({stats_by_hashfile_id.get(hashfile.id, (0, 0))[0]}/{stats_by_hashfile_id.get(hashfile.id, (0, 0))[1]})"
        for hashfile in hashfiles
    }


def _selected_hashfile_local_hits(hashfile_id: int | None):
    if not hashfile_id:
        return []
    return (
        db.session.execute(
            select(Hashes, HashfileHashes)
            .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
            .where(Hashes.cracked.is_(True))
            .where(HashfileHashes.hashfile_id == hashfile_id)
        )
        .tuples()
        .all()
    )


def _ordered_job_task_names(job_tasks: list[JobTasks]) -> list[str]:
    task_ids = sorted({job_task.task_id for job_task in job_tasks})
    task_rows = (
        db.session.execute(
            select(Tasks.id, Tasks.name).where(Tasks.id.in_(task_ids))
        ).all()
        if task_ids
        else []
    )
    task_names = {row.id: row.name for row in task_rows}
    return [
        task_names[job_task.task_id]
        for job_task in job_tasks
        if job_task.task_id in task_names
    ]


def _get_assignable_hashfile(job: Jobs, raw_hashfile_id) -> Hashfiles | None:
    hashfile_id = _parse_positive_int(raw_hashfile_id)
    if hashfile_id is None:
        return None

    return db.session.get(Hashfiles, hashfile_id)


def _build_jobs_list_context(*, page: int, per_page: int):
    jobs, pagination = paginate_scalars(
        db.session,
        _visible_jobs_query().order_by(Jobs.created_at.desc()),
        page=page,
        per_page=per_page,
    )
    visible_job_ids = [job.id for job in jobs]
    owner_ids = sorted({job.owner_id for job in jobs})
    hashfile_ids = sorted({job.hashfile_id for job in jobs if job.hashfile_id})
    job_domain_summary_rows = job_domain_summaries(visible_job_ids)
    owner_names = {
        row.id: row.username
        for row in (
            db.session.execute(
                select(Users.id, Users.username).where(Users.id.in_(owner_ids))
            ).all()
            if owner_ids
            else []
        )
    }
    hashfile_names = {
        row.id: row.name
        for row in (
            db.session.execute(
                select(Hashfiles.id, Hashfiles.name).where(Hashfiles.id.in_(hashfile_ids))
            ).all()
            if hashfile_ids
            else []
        )
    }
    job_tasks = (
        db.session.execute(
            select(JobTasks)
            .where(JobTasks.job_id.in_(visible_job_ids))
            .order_by(JobTasks.job_id.asc(), *_job_task_ordering())
        ).scalars().all()
        if visible_job_ids
        else []
    )
    hashfile_stats = {}
    if hashfile_ids:
        stats_rows = db.session.execute(
            select(
                HashfileHashes.hashfile_id,
                func.count(Hashes.id).label("total_count"),
                func.sum(case((Hashes.cracked.is_(True), 1), else_=0)).label(
                    "cracked_count"
                ),
            )
            .select_from(HashfileHashes)
            .join(Hashes, Hashes.id == HashfileHashes.hash_id)
            .where(HashfileHashes.hashfile_id.in_(hashfile_ids))
            .group_by(HashfileHashes.hashfile_id)
        ).all()
        hashfile_stats = {
            row.hashfile_id: (int(row.cracked_count or 0), int(row.total_count or 0))
            for row in stats_rows
        }
    job_recovered = {}
    for job in jobs:
        cracked, total = hashfile_stats.get(job.hashfile_id, (0, 0))
        job_recovered[job.id] = f"{cracked}/{total}"

    status_rank = {"Running": 0, "Importing": 1, "Paused": 2, "Queued": 3}
    job_runtime_progress: dict[int, dict[str, str]] = {}
    for job_task in job_tasks:
        if job_task.status not in status_rank:
            continue

        percent_done, eta = parse_jobtask_progress(job_task.progress)
        existing = job_runtime_progress.get(job_task.job_id)
        if existing and existing["rank"] <= status_rank[job_task.status]:
            continue

        job_runtime_progress[job_task.job_id] = {
            "percent_done": percent_done or "N/A",
            "eta": eta or "N/A",
            "rank": status_rank[job_task.status],
        }

    return {
        "jobs": jobs,
        "job_domain_summaries": job_domain_summary_rows,
        "owner_names": owner_names,
        "hashfile_names": hashfile_names,
        "job_runtime_progress": job_runtime_progress,
        "job_recovered": job_recovered,
        "pagination": pagination,
        **_build_active_jobs_summary(),
    }
