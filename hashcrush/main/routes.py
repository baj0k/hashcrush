"""Flask routes to main page."""

from flask import Blueprint, Response, flash, redirect, url_for
from flask_login import current_user, login_required

from hashcrush.audit import record_audit_event
from hashcrush.models import Jobs, JobTasks, db
from hashcrush.jobs.status import update_job_task_status

main = Blueprint('main', __name__)

@main.route("/healthz")
def healthz():
    """Simple readiness endpoint for container and proxy health checks."""
    return Response("ok\n", mimetype="text/plain")

@main.route("/")
@login_required
def home():
    """Redirect the root landing page to the unified jobs view."""
    return redirect(url_for('jobs.jobs_list'))

@main.route("/job_task/stop/<int:job_task_id>", methods=['POST'])
@login_required
def stop_job_task(job_task_id):
    """Function to stop specific task on a running job"""

    job_task = db.session.get(JobTasks, job_task_id)
    if not job_task:
        return redirect("/")
    job = db.session.get(Jobs, job_task.job_id)

    if job_task and job:
        if current_user.admin or job.owner_id == current_user.id:
            if job_task.status not in ('Running', 'Importing'):
                flash('Task is not actively running.', 'danger')
                return redirect(url_for('jobs.jobs_list'))
            previous_status = job_task.status
            update_job_task_status(job_task.id, 'Canceled')
            record_audit_event(
                'job_task.stop',
                'job_task',
                target_id=job_task.id,
                summary=f'Stopped task {job_task.id} for job "{job.name}".',
                details={
                    'job_id': job.id,
                    'task_id': job_task.task_id,
                    'previous_status': previous_status,
                },
            )
        else:
            flash('You are unauthorized to stop this task', 'danger')

    return redirect(url_for('jobs.jobs_list'))
