"""Flask routes to main page"""

import json
import re

from flask import Blueprint, flash, redirect, render_template
from flask_login import current_user, login_required
from sqlalchemy import case, func

from hashcrush.models import (
    Domains,
    Hashes,
    HashfileHashes,
    Jobs,
    JobTasks,
    Tasks,
    Users,
    db,
)
from hashcrush.utils.utils import update_job_task_status

main = Blueprint('main', __name__)


def _parse_jobtask_progress(progress_payload: str | None) -> tuple[str | None, str | None]:
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

@main.route("/")
@login_required
def home():
    """Function to return the home page"""
    running_jobs = (
        Jobs.query
        .filter_by(status='Running')
        .order_by(Jobs.priority.desc(), Jobs.queued_at.asc())
        .all()
    )
    queued_jobs = (
        Jobs.query
        .filter_by(status='Queued')
        .order_by(Jobs.priority.desc(), Jobs.queued_at.asc())
        .all()
    )
    jobs = running_jobs + queued_jobs
    users = Users.query.all()
    domain_ids = sorted({job.domain_id for job in jobs})
    domains = (
        Domains.query.filter(Domains.id.in_(domain_ids)).all()
        if domain_ids
        else []
    )
    visible_job_ids = [job.id for job in jobs]
    job_tasks = (
        JobTasks.query.filter(JobTasks.job_id.in_(visible_job_ids)).all()
        if visible_job_ids
        else []
    )
    visible_task_ids = sorted({job_task.task_id for job_task in job_tasks})
    tasks = (
        Tasks.query.filter(Tasks.id.in_(visible_task_ids)).all()
        if visible_task_ids
        else []
    )
    hashfile_ids = [job.hashfile_id for job in jobs if job.hashfile_id]
    hashfile_stats = {}
    if hashfile_ids:
        stats_rows = (
            db.session.query(
                HashfileHashes.hashfile_id,
                func.count(Hashes.id).label('total_count'),
                func.sum(case((Hashes.cracked.is_(True), 1), else_=0)).label('cracked_count'),
            )
            .join(Hashes, Hashes.id == HashfileHashes.hash_id)
            .filter(HashfileHashes.hashfile_id.in_(hashfile_ids))
            .group_by(HashfileHashes.hashfile_id)
            .all()
        )
        hashfile_stats = {
            row.hashfile_id: (int(row.cracked_count or 0), int(row.total_count or 0))
            for row in stats_rows
        }
    job_recovered = {}
    for job in jobs:
        cracked, total = hashfile_stats.get(job.hashfile_id, (0, 0))
        job_recovered[job.id] = f'{cracked}/{total}'

    job_task_runtime_progress: dict[int, dict[str, str]] = {}
    for job_task in job_tasks:
        percent_done, eta = _parse_jobtask_progress(job_task.progress)
        job_task_runtime_progress[job_task.id] = {
            'percent_done': percent_done or 'N/A',
            'eta': eta or 'N/A',
        }

    collapse_all = ""
    for job in jobs:
        collapse_all = collapse_all + "collapse" + str(job.id) + " "

    return render_template(
        'home.html',
        jobs=jobs,
        running_jobs=running_jobs,
        queued_jobs=queued_jobs,
        users=users,
        domains=domains,
        job_tasks=job_tasks,
        tasks=tasks,
        collapse_all=collapse_all,
        job_task_runtime_progress=job_task_runtime_progress,
        job_recovered=job_recovered,
    )

@main.route("/job_task/stop/<int:job_task_id>", methods=['POST'])
@login_required
def stop_job_task(job_task_id):
    """Function to stop specific task on a running job"""

    job_task = JobTasks.query.get(job_task_id)
    if not job_task:
        return redirect("/")
    job = Jobs.query.get(job_task.job_id)

    if job_task and job:
        if current_user.admin or job.owner_id == current_user.id:
            if job_task.status not in ('Running', 'Importing'):
                flash('Task is not actively running.', 'danger')
                return redirect("/")
            update_job_task_status(job_task.id, 'Canceled')
        else:
            flash('You are unauthorized to stop this task', 'danger')

    return redirect("/")
