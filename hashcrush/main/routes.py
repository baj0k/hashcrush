"""Flask routes to main page"""

import json
import re

from flask import Blueprint, render_template, redirect, flash
from flask_login import login_required, current_user
from sqlalchemy import or_

from hashcrush.models import Jobs, JobTasks, Users, Domains, Tasks
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
    jobs = Jobs.query.filter(or_((Jobs.status.like('Running')),(Jobs.status.like('Queued'))))
    running_jobs = Jobs.query.filter_by(status = 'Running').order_by(Jobs.priority.desc(), Jobs.queued_at.asc()).all()
    queued_jobs = Jobs.query.filter_by(status = 'Queued').order_by(Jobs.priority.desc(), Jobs.queued_at.asc()).all()
    users = Users.query.all()
    domains = Domains.query.all()
    job_tasks = JobTasks.query.all()
    tasks = Tasks.query.all()

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
    )

@main.route("/job_task/stop/<int:job_task_id>")
@login_required
def stop_job_task(job_task_id):
    """Function to stop specific task on a running job"""

    job_task = JobTasks.query.get(job_task_id)
    job = Jobs.query.get(job_task.job_id)

    if job_task and job:
        if current_user.admin or job.owner_id == current_user.id:
            update_job_task_status(job_task.id, 'Canceled')
        else:
            flash('You are unauthorized to stop this task', 'danger')

    return redirect("/")
