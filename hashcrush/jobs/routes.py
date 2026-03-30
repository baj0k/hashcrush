"""Flask routes to handle Jobs"""

import json

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError

from hashcrush.audit import record_audit_event
from hashcrush.domains.service import resolve_or_create_shared_domain
from hashcrush.hashfiles.service import create_hashfile_from_form
from hashcrush.jobs.access import (
    _can_manage_job,
    _can_view_job,
    _normalize_task_id_list,
    _require_job_allows_task_mutation,
)
from hashcrush.jobs.builder_service import (
    _build_jobs_form,
    _builder_redirect,
    _render_job_review,
    _render_jobs_builder,
)
from hashcrush.jobs.forms import JobsNewHashFileForm, JobSummaryForm
from hashcrush.jobs.queries import (
    _build_jobs_list_context,
    _get_assignable_hashfile,
    _job_task_ordering,
    _next_job_task_position,
    _selected_hashfile_local_hits,
)
from hashcrush.jobs.transitions import (
    JobTransitionError,
    delete_job_with_tasks,
    finalize_job,
    pause_job_execution,
    queue_job_for_start,
    resume_job_execution,
    stop_job_execution,
)
from hashcrush.models import (
    Hashfiles,
    Jobs,
    JobTasks,
    TaskGroups,
    Tasks,
    db,
)
from hashcrush.view_utils import LIST_PAGE_SIZE, parse_page_arg

jobs = Blueprint('jobs', __name__)

@jobs.route("/jobs", methods=['GET', 'POST'])
@login_required
def jobs_list():
    """Function to return list of Jobs"""
    page = parse_page_arg(request.args.get('page'))
    context = _build_jobs_list_context(page=page, per_page=LIST_PAGE_SIZE)
    return render_template(
        'jobs.html',
        title='Jobs',
        **context,
    )

@jobs.route("/jobs/add", methods=['GET', 'POST'])
@login_required
def jobs_add():
    """Render and create draft jobs through the unified builder."""
    jobs_form = _build_jobs_form()
    if jobs_form.validate_on_submit():
        domain_result, domain_error = resolve_or_create_shared_domain(
            jobs_form.domain_id.data,
            new_domain_name=jobs_form.domain_name.data,
            allow_create=current_user.admin,
        )
        if domain_error:
            flash(domain_error, 'danger')
            return _render_jobs_builder(jobs_form=jobs_form, active_tab='basics')
        visible_domain = domain_result.domain

        try:
            selected_priority = int(jobs_form.priority.data)
        except (TypeError, ValueError):
            selected_priority = 3
        job_priority = selected_priority if 1 <= selected_priority <= 5 else 3

        job = Jobs( name = jobs_form.name.data,
                    priority = job_priority,
                    status = 'Incomplete',
                    domain_id = int(visible_domain.id),
                    owner_id = current_user.id)
        db.session.add(job)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Job could not be created because its name already exists or the selected domain changed. Refresh and retry.', 'danger')
            return _render_jobs_builder(jobs_form=jobs_form, active_tab='basics')
        if domain_result.created:
            record_audit_event(
                'domain.create',
                'domain',
                target_id=visible_domain.id,
                summary=f'Created shared domain "{visible_domain.name}" from job creation.',
                details={'domain_name': visible_domain.name, 'source': 'jobs.add'},
            )
        elif jobs_form.domain_id.data == 'add_new':
            flash(f'Using existing shared domain "{visible_domain.name}".', 'info')
        record_audit_event(
            'job.create',
            'job',
            target_id=job.id,
            summary=f'Created draft job "{job.name}".',
            details={
                'job_name': job.name,
                'status': job.status,
                'domain_id': job.domain_id,
                'priority': job.priority,
                'owner_id': job.owner_id,
            },
        )
        return _builder_redirect(job.id, 'hashes')
    return _render_jobs_builder(jobs_form=jobs_form, active_tab='basics')


@jobs.route("/jobs/<int:job_id>/builder", methods=['GET'])
@login_required
def jobs_builder(job_id):
    """Render the unified single-page job builder."""
    job = db.get_or_404(Jobs, job_id)
    if not _can_view_job(job):
        flash('You do not have rights to view this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))
    return _render_jobs_builder(job=job, active_tab=request.args.get('tab'))


@jobs.route("/jobs/<int:job_id>/builder/basics", methods=['POST'])
@login_required
def jobs_builder_update_basics(job_id):
    """Update job basics from the single-page builder."""
    job = db.get_or_404(Jobs, job_id)
    if not _can_manage_job(job):
        flash('You do not have rights to modify this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))
    if not _require_job_allows_task_mutation(job):
        return _builder_redirect(job.id, 'basics')

    jobs_form = _build_jobs_form(job=job)
    if not jobs_form.validate_on_submit():
        return _render_jobs_builder(job=job, jobs_form=jobs_form, active_tab='basics')

    domain_result, domain_error = resolve_or_create_shared_domain(
        jobs_form.domain_id.data,
        new_domain_name=jobs_form.domain_name.data,
        allow_create=current_user.admin,
    )
    if domain_error:
        flash(domain_error, 'danger')
        return _render_jobs_builder(job=job, jobs_form=jobs_form, active_tab='basics')
    visible_domain = domain_result.domain

    try:
        selected_priority = int(jobs_form.priority.data)
    except (TypeError, ValueError):
        selected_priority = 3
    job_priority = selected_priority if 1 <= selected_priority <= 5 else 3

    previous_domain_id = job.domain_id
    job.name = jobs_form.name.data
    job.priority = job_priority
    job.domain_id = int(visible_domain.id)
    if (
        job.hashfile_id
        and previous_domain_id != job.domain_id
        and (
            not db.session.get(Hashfiles, job.hashfile_id)
            or db.session.get(Hashfiles, job.hashfile_id).domain_id != job.domain_id
        )
    ):
        job.hashfile_id = None
        flash('Domain changed. Please re-select a hashfile for the new domain.', 'warning')

    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash('Job could not be updated because its name already exists or the selected domain changed. Refresh and retry.', 'danger')
        return _render_jobs_builder(job=job, jobs_form=jobs_form, active_tab='basics')

    if domain_result.created:
        record_audit_event(
            'domain.create',
            'domain',
            target_id=visible_domain.id,
            summary=f'Created shared domain "{visible_domain.name}" from job builder.',
            details={'domain_name': visible_domain.name, 'source': 'jobs.builder'},
        )
    elif jobs_form.domain_id.data == 'add_new':
        flash(f'Using existing shared domain "{visible_domain.name}".', 'info')

    flash('Updated draft job basics.', 'success')
    return _builder_redirect(job.id, 'hashes')

@jobs.route("/jobs/<int:job_id>/assigned_hashfile/", methods=['GET', 'POST'])
@login_required
def jobs_assigned_hashfile(job_id):
    """Function to manage assigning hashfile to job"""

    job = db.get_or_404(Jobs, job_id)
    if request.method == 'GET':
        if not _can_view_job(job):
            flash('You do not have rights to view this job!', 'danger')
            return redirect(url_for('jobs.jobs_list'))
        return _builder_redirect(job.id, 'hashes')
    if not _can_manage_job(job):
        flash('You do not have rights to modify this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    jobs_new_hashfile_form = JobsNewHashFileForm()

    if job.status in ('Running', 'Queued', 'Paused'):
        flash('You can not edit a running, queued, or paused job. First stop it before editing.', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    if jobs_new_hashfile_form.validate_on_submit():
        creation_result, error_message = create_hashfile_from_form(
            jobs_new_hashfile_form,
            domain_id=job.domain_id,
        )
        if error_message:
            flash(error_message, 'danger')
            return _render_jobs_builder(
                job=job,
                jobs_new_hashfile_form=jobs_new_hashfile_form,
                active_tab='hashes',
                active_hashes_tab='new',
            )

        hashfile = creation_result.hashfile
        job.hashfile_id = hashfile.id
        db.session.commit()
        record_audit_event(
            'hashfile.create',
            'hashfile',
            target_id=hashfile.id,
            summary=f'Registered shared hashfile "{hashfile.name}" via job assignment.',
            details={
                'hashfile_name': hashfile.name,
                'domain_id': job.domain_id,
                'job_id': job.id,
                'hash_type': creation_result.hash_type,
                'imported_hash_links': creation_result.imported_hash_links,
            },
        )
        cracked_hashfiles_hashes_cnt = len(_selected_hashfile_local_hits(hashfile.id))
        if cracked_hashfiles_hashes_cnt > 0:
            flash(str(cracked_hashfiles_hashes_cnt) + " instacracked Hashes!", 'success')
        return _builder_redirect(job.id, 'tasks')

    elif request.method == 'POST' and request.form.get('hashfile_id'):
        selected_hashfile = _get_assignable_hashfile(job, request.form.get('hashfile_id'))
        if not selected_hashfile:
            flash('Selected hashfile is invalid for this job domain.', 'danger')
            return _render_jobs_builder(
                job=job,
                active_tab='hashes',
                active_hashes_tab='existing',
            )

        job.hashfile_id = selected_hashfile.id
        db.session.commit()
        return _builder_redirect(job.id, 'tasks')
    elif request.method == 'POST' and 'hashfile_id' in request.form:
        flash('Please select a valid hashfile.', 'danger')
        return _render_jobs_builder(
            job=job,
            active_tab='hashes',
            active_hashes_tab='existing',
        )

    return _render_jobs_builder(
        job=job,
        jobs_new_hashfile_form=jobs_new_hashfile_form,
        active_tab='hashes',
        active_hashes_tab='new',
    )

@jobs.route("/jobs/<int:job_id>/assigned_hashfile/<int:hashfile_id>", methods=['GET'])
@login_required
def jobs_assigned_hashfile_cracked(job_id, hashfile_id):
    """Redirect the legacy local-check step back into the builder."""

    job = db.get_or_404(Jobs, job_id)
    if not _can_manage_job(job):
        flash('You do not have rights to view this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    hashfile = db.session.get(Hashfiles, hashfile_id)
    if (
        not hashfile
        or hashfile.id != job.hashfile_id
        or hashfile.domain_id != job.domain_id
    ):
        flash('Invalid hashfile for this job.', 'danger')
        return _builder_redirect(job.id, 'hashes')
    cracked_hashfiles_hashes_cnt = len(_selected_hashfile_local_hits(hashfile.id))
    if cracked_hashfiles_hashes_cnt > 0:
        flash(str(cracked_hashfiles_hashes_cnt) + " instacracked Hashes!", 'success')
    return _builder_redirect(job.id, 'tasks')

@jobs.route("/jobs/<int:job_id>/tasks", methods=['GET'])
@login_required
def jobs_list_tasks(job_id):
    """Redirect legacy tasks step requests into the builder."""
    job = db.get_or_404(Jobs, job_id)
    if not _can_view_job(job):
        flash('You do not have rights to view this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))
    return _builder_redirect(job.id, 'tasks')

@jobs.route("/jobs/<int:job_id>/assign_task/<int:task_id>", methods=['POST'])
@login_required
def jobs_assigned_task(job_id, task_id):
    """Function to assign task to job"""
    job = db.get_or_404(Jobs, job_id)
    if not _can_manage_job(job):
        flash('You do not have rights to modify this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))
    if not _require_job_allows_task_mutation(job):
        return _builder_redirect(job.id, 'tasks')

    task = db.session.scalar(select(Tasks).where(Tasks.id == task_id))
    if not task:
        flash('Task is invalid or no longer available.', 'danger')
        return _builder_redirect(job.id, 'tasks')

    existing_job_task = db.session.scalar(
        select(JobTasks).filter_by(job_id=job_id, task_id=task_id)
    )
    if existing_job_task:
        flash('Task already assigned to the job.', 'warning')
    else:
        job_task = JobTasks(
            job_id=job_id,
            task_id=task_id,
            status='Not Started',
            position=_next_job_task_position(job_id),
        )
        db.session.add(job_task)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Task already assigned to the job.', 'warning')

    return _builder_redirect(job.id, 'tasks')

@jobs.route("/jobs/<int:job_id>/assign_task_group/<int:task_group_id>", methods=['POST'])
@login_required
def jobs_assign_task_group(job_id, task_group_id):
    """Function to assign task group to job"""

    job = db.get_or_404(Jobs, job_id)
    if not _can_manage_job(job):
        flash('You do not have rights to modify this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))
    if not _require_job_allows_task_mutation(job):
        return _builder_redirect(job.id, 'tasks')

    task_group = db.session.scalar(select(TaskGroups).where(TaskGroups.id == task_group_id))
    if not task_group:
        flash('Task Group is invalid or no longer available.', 'danger')
        return _builder_redirect(job.id, 'tasks')
    try:
        task_group_entries = json.loads(task_group.tasks)
    except (TypeError, ValueError):
        task_group_entries = []
    task_group_task_ids = _normalize_task_id_list(task_group_entries)

    existing_task_ids = {
        row.task_id
        for row in db.session.execute(
            select(JobTasks).where(JobTasks.job_id == job.id)
        ).scalars().all()
    }
    visible_task_ids = set(
        db.session.scalars(
            select(Tasks.id).where(Tasks.id.in_(task_group_task_ids))
        ).all()
    )
    new_assignments = 0
    next_position = _next_job_task_position(job.id)
    for task_group_entry in task_group_task_ids:
        if task_group_entry not in visible_task_ids:
            continue
        if task_group_entry in existing_task_ids:
            continue
        job_task = JobTasks(
            job_id=job_id,
            task_id=task_group_entry,
            status='Not Started',
            position=next_position,
        )
        db.session.add(job_task)
        existing_task_ids.add(task_group_entry)
        new_assignments += 1
        next_position += 1
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash('One or more tasks were already assigned to this job. Refresh and retry.', 'warning')
        return _builder_redirect(job.id, 'tasks')
    if new_assignments == 0:
        flash('Task Group did not add any new tasks to this job.', 'info')
	
    return _builder_redirect(job.id, 'tasks')

@jobs.route("/jobs/<int:job_id>/move_task_up/<int:task_id>", methods=['POST'])
@login_required
def jobs_move_task_up(job_id, task_id):
    """Function to move assigned task up on task list for job"""
    job = db.get_or_404(Jobs, job_id)
    if not _can_manage_job(job):
        flash('You do not have rights to modify this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))
    if not _require_job_allows_task_mutation(job):
        return _builder_redirect(job.id, 'tasks')

    job_tasks = db.session.execute(
        select(JobTasks).filter_by(job_id=job_id).order_by(*_job_task_ordering())
    ).scalars().all()
    if not job_tasks:
        flash('No tasks assigned to this job.', 'warning')
        return _builder_redirect(job.id, 'tasks')

    ordered_task_ids = [entry.task_id for entry in job_tasks]
    if task_id not in ordered_task_ids:
        flash('Task is not assigned to this job.', 'warning')
        return _builder_redirect(job.id, 'tasks')

    element_index = ordered_task_ids.index(task_id)
    if element_index == 0:
        flash('Task is already at the top', 'warning')
        return _builder_redirect(job.id, 'tasks')

    current_task = job_tasks[element_index]
    previous_task = job_tasks[element_index - 1]
    current_task.position, previous_task.position = (
        previous_task.position,
        current_task.position,
    )
    db.session.commit()

    return _builder_redirect(job.id, 'tasks')

@jobs.route("/jobs/<int:job_id>/move_task_down/<int:task_id>", methods=['POST'])
@login_required
def jobs_move_task_down(job_id, task_id):
    """Function to move assigned task down on task list for job"""
    job = db.get_or_404(Jobs, job_id)
    if not _can_manage_job(job):
        flash('You do not have rights to modify this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))
    if not _require_job_allows_task_mutation(job):
        return _builder_redirect(job.id, 'tasks')

    job_tasks = db.session.execute(
        select(JobTasks).filter_by(job_id=job_id).order_by(*_job_task_ordering())
    ).scalars().all()
    if not job_tasks:
        flash('No tasks assigned to this job.', 'warning')
        return _builder_redirect(job.id, 'tasks')

    ordered_task_ids = [entry.task_id for entry in job_tasks]
    if task_id not in ordered_task_ids:
        flash('Task is not assigned to this job.', 'warning')
        return _builder_redirect(job.id, 'tasks')

    element_index = ordered_task_ids.index(task_id)
    if element_index == len(ordered_task_ids) - 1:
        flash('Task is already at the bottom', 'warning')
        return _builder_redirect(job.id, 'tasks')

    current_task = job_tasks[element_index]
    next_task = job_tasks[element_index + 1]
    current_task.position, next_task.position = (
        next_task.position,
        current_task.position,
    )
    db.session.commit()

    return _builder_redirect(job.id, 'tasks')

@jobs.route("/jobs/<int:job_id>/remove_task/<int:task_id>", methods=['POST'])
@login_required
def jobs_remove_task(job_id, task_id):
    """Function to remove task from task list on job"""
    job = db.get_or_404(Jobs, job_id)
    if not _can_manage_job(job):
        flash('You do not have rights to modify this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))
    if not _require_job_allows_task_mutation(job):
        return _builder_redirect(job.id, 'tasks')

    job_task = db.session.scalar(
        select(JobTasks).filter_by(job_id=job_id, task_id=task_id)
    )
    if not job_task:
        flash('Task is not assigned to this job.', 'warning')
        return _builder_redirect(job.id, 'tasks')

    db.session.delete(job_task)
    db.session.commit()

    return _builder_redirect(job.id, 'tasks')

@jobs.route("/jobs/<int:job_id>/remove_all_tasks", methods=['POST'])
@login_required
def jobs_remove_all_tasks(job_id):
    """Function to remove all tasks from job"""
    job = db.get_or_404(Jobs, job_id)
    if not _can_manage_job(job):
        flash('You do not have rights to modify this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))
    if not _require_job_allows_task_mutation(job):
        return _builder_redirect(job.id, 'tasks')

    db.session.execute(delete(JobTasks).filter_by(job_id=job_id))
    db.session.commit()
    return _builder_redirect(job.id, 'tasks')

@jobs.route("/jobs/delete/<int:job_id>", methods=['POST'])
@login_required
def jobs_delete(job_id):
    """Function to delete job"""

    job = db.get_or_404(Jobs, job_id)
    if _can_manage_job(job):
        audit_details = delete_job_with_tasks(job)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Job could not be deleted because it changed concurrently. Refresh and retry.', 'danger')
            return redirect(url_for('jobs.jobs_list'))
        record_audit_event(
            'job.delete',
            'job',
            target_id=audit_details['job_id'],
            summary=f'Deleted job "{audit_details["job_name"]}".',
            details={
                'job_name': audit_details['job_name'],
                'previous_status': audit_details['previous_status'],
                'owner_id': audit_details['owner_id'],
            },
        )
        flash('Job has been deleted!', 'success')
        return redirect(url_for('jobs.jobs_list'))

    flash('You do not have rights to delete this job!', 'danger')
    return redirect(url_for('jobs.jobs_list'))

@jobs.route("/jobs/<int:job_id>/summary", methods=['GET', 'POST'])
@login_required
def jobs_summary(job_id):
    """Finalize jobs from the unified builder."""
    job = db.get_or_404(Jobs, job_id)
    if not _can_view_job(job):
        flash('You do not have rights to view this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    form = JobSummaryForm()
    if request.method == 'GET':
        return _render_job_review(job, summary_form=form)

    job_tasks = db.session.execute(
        select(JobTasks).filter_by(job_id=job_id).order_by(*_job_task_ordering())
    ).scalars().all()
    if len(job_tasks) == 0:
        flash('You must assign at least one task.', 'warning')
        return _builder_redirect(job.id, 'tasks')

    hashfile = db.session.get(Hashfiles, job.hashfile_id)
    if not hashfile:
        flash('You must assign a valid hashfile before reviewing summary.', 'danger')
        return _builder_redirect(job.id, 'hashes')

    can_manage_job = _can_manage_job(job)
    if request.method == 'POST' and not can_manage_job:
        flash('You do not have rights to modify this job!', 'danger')
        return redirect(url_for('jobs.jobs_summary', job_id=job.id))

    if form.validate_on_submit():
        finalize_job(job, job_tasks)
        db.session.commit()
        record_audit_event(
            'job.finalize',
            'job',
            target_id=job.id,
            summary=f'Finalized job "{job.name}" and queued it for scheduling.',
            details={
                'job_name': job.name,
                'job_task_count': len(job_tasks),
                'hashfile_id': job.hashfile_id,
                'domain_id': job.domain_id,
            },
        )

        flash('Job successfully created', 'success')

        return redirect(url_for('jobs.jobs_list'))

    return _render_job_review(job, summary_form=form)

@jobs.route("/jobs/start/<int:job_id>", methods=['POST'])
@login_required
def jobs_start(job_id):
    """Function to start job"""

    job = db.get_or_404(Jobs, job_id)
    job_tasks = db.session.execute(
        select(JobTasks).filter_by(job_id=job_id).order_by(*_job_task_ordering())
    ).scalars().all()

    if not _can_manage_job(job):
        flash('You do not have rights to start this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    try:
        previous_status = queue_job_for_start(job, job_tasks)
    except JobTransitionError as error:
        db.session.rollback()
        flash(str(error), 'danger')
        if error.builder_tab:
            return _builder_redirect(job.id, error.builder_tab)
        if job.status in ('Ready', 'Canceled'):
            return redirect(url_for('jobs.jobs_summary', job_id=job.id))
        return redirect(url_for('jobs.jobs_list'))

    db.session.commit()
    record_audit_event(
        'job.start',
        'job',
        target_id=job.id,
        summary=f'Started job "{job.name}".',
        details={
            'job_name': job.name,
            'previous_status': previous_status,
            'job_task_count': len(job_tasks),
        },
    )
    flash('Job has been Started!', 'success')
    return redirect(url_for('main.home'))

@jobs.route("/jobs/stop/<int:job_id>", methods=['POST'])
@login_required
def jobs_stop(job_id):
    """Function to stop a job"""

    job = db.get_or_404(Jobs, job_id)
    job_tasks = db.session.execute(
        select(JobTasks).filter_by(job_id=job_id).order_by(*_job_task_ordering())
    ).scalars().all()

    if not _can_manage_job(job):
        flash('You do not have rights to stop this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    try:
        previous_status, canceled_task_count = stop_job_execution(job, job_tasks)
    except JobTransitionError as error:
        flash(str(error), 'danger')
        return redirect(url_for('jobs.jobs_list'))

    db.session.commit()
    record_audit_event(
        'job.stop',
        'job',
        target_id=job.id,
        summary=f'Stopped job "{job.name}".',
        details={
            'job_name': job.name,
            'previous_status': previous_status,
            'canceled_task_count': canceled_task_count,
        },
    )
    flash('Job has been stopped!', 'success')
    return redirect(url_for('jobs.jobs_list'))

@jobs.route("/jobs/pause/<int:job_id>", methods=['POST'])
@login_required
def jobs_pause(job_id):
    """Pause a running or queued job."""

    job = db.get_or_404(Jobs, job_id)
    job_tasks = db.session.execute(
        select(JobTasks).filter_by(job_id=job_id).order_by(*_job_task_ordering())
    ).scalars().all()

    if not _can_manage_job(job):
        flash('You do not have rights to pause this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    try:
        previous_status = pause_job_execution(job, job_tasks)
    except JobTransitionError as error:
        flash(str(error), 'danger')
        return redirect(url_for('jobs.jobs_list'))

    db.session.commit()
    record_audit_event(
        'job.pause',
        'job',
        target_id=job.id,
        summary=f'Paused job "{job.name}".',
        details={'job_name': job.name, 'previous_status': previous_status},
    )

    flash('Job has been paused!', 'success')
    return redirect(url_for('jobs.jobs_list'))

@jobs.route("/jobs/resume/<int:job_id>", methods=['POST'])
@login_required
def jobs_resume(job_id):
    """Resume a paused job."""

    job = db.get_or_404(Jobs, job_id)
    job_tasks = db.session.execute(
        select(JobTasks).filter_by(job_id=job_id).order_by(*_job_task_ordering())
    ).scalars().all()

    if not _can_manage_job(job):
        flash('You do not have rights to resume this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    try:
        previous_status, new_status = resume_job_execution(job, job_tasks)
    except JobTransitionError as error:
        flash(str(error), 'danger')
        return redirect(url_for('jobs.jobs_list'))

    db.session.commit()
    record_audit_event(
        'job.resume',
        'job',
        target_id=job.id,
        summary=f'Resumed job "{job.name}".',
        details={
            'job_name': job.name,
            'previous_status': previous_status,
            'new_status': new_status,
        },
    )
    flash('Job has been resumed!', 'success')
    return redirect(url_for('jobs.jobs_list'))
