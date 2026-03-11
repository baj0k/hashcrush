"""Flask routes to handle Jobs"""

import json
from collections import defaultdict
from datetime import UTC, datetime

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import case, delete, func, select
from sqlalchemy.exc import IntegrityError

from hashcrush.audit import record_audit_event
from hashcrush.authz import PUBLIC_JOB_VIEW_STATUSES, visible_jobs_query
from hashcrush.domains.service import resolve_or_create_shared_domain
from hashcrush.hashfiles.service import create_hashfile_from_form
from hashcrush.jobs.forms import JobsForm, JobsNewHashFileForm, JobSummaryForm
from hashcrush.models import (
    Domains,
    Hashes,
    HashfileHashes,
    Hashfiles,
    Jobs,
    JobTasks,
    TaskGroups,
    Tasks,
    Users,
    db,
)
from hashcrush.utils.utils import build_hashcat_command
from hashcrush.view_utils import (
    LIST_PAGE_SIZE,
    paginate_scalars,
    parse_jobtask_progress,
    parse_page_arg,
)

jobs = Blueprint('jobs', __name__)
ACTIVE_JOB_TASK_MUTATION_STATUSES = {'Running', 'Queued', 'Paused'}
ACTIVE_JOB_TASK_EXECUTION_STATUSES = {'Running', 'Importing', 'Queued', 'Paused'}


def _utc_now_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


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
    flash('You cannot edit assigned tasks while the job is running, queued, or paused.', 'danger')
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


def _visible_hashfiles_for_job(job: Jobs) -> list[Hashfiles]:
    return db.session.execute(
        select(Hashfiles).filter_by(domain_id=job.domain_id)
    ).scalars().all()


def _build_active_jobs_summary():
    active_jobs = db.session.execute(
        _visible_jobs_query()
        .where(Jobs.status.in_(('Running', 'Queued')))
        .order_by(
            case((Jobs.status == 'Running', 0), else_=1),
            Jobs.priority.desc(),
            Jobs.queued_at.asc(),
            Jobs.id.asc(),
        )
    ).scalars().all()
    running_jobs = [job for job in active_jobs if job.status == 'Running']
    queued_jobs = [job for job in active_jobs if job.status == 'Queued']
    active_job_ids = [job.id for job in active_jobs]
    owner_ids = sorted({job.owner_id for job in active_jobs})
    domain_ids = sorted({job.domain_id for job in active_jobs})

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
    active_domain_names = {
        row.id: row.name
        for row in (
            db.session.execute(
                select(Domains.id, Domains.name).where(Domains.id.in_(domain_ids))
            ).all()
            if domain_ids
            else []
        )
    }

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
                func.count(Hashes.id).label('total_count'),
                func.sum(case((Hashes.cracked.is_(True), 1), else_=0)).label('cracked_count'),
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
        active_job_recovered[job.id] = f'{cracked}/{total}'

    active_job_task_runtime_progress: dict[int, dict[str, str]] = {}
    active_job_task_rows_by_job_id: dict[int, list[dict[str, object]]] = defaultdict(list)
    active_job_progress_summary: dict[int, dict[str, int]] = defaultdict(
        lambda: {'total': 0, 'completed': 0, 'running': 0}
    )
    for job_task in active_job_tasks:
        percent_done, eta = parse_jobtask_progress(job_task.progress)
        active_job_task_runtime_progress[job_task.id] = {
            'percent_done': percent_done or 'N/A',
            'eta': eta or 'N/A',
        }
        active_job_task_rows_by_job_id[job_task.job_id].append(
            {
                'job_task': job_task,
                'task_name': task_names.get(job_task.task_id, ''),
            }
        )
        active_job_progress_summary[job_task.job_id]['total'] += 1
        if job_task.status == 'Completed':
            active_job_progress_summary[job_task.job_id]['completed'] += 1
        elif job_task.status in ('Running', 'Importing'):
            active_job_progress_summary[job_task.job_id]['running'] += 1

    return {
        'running_jobs': running_jobs,
        'queued_jobs': queued_jobs,
        'active_domain_names': active_domain_names,
        'active_owner_names': active_owner_names,
        'active_job_task_rows_by_job_id': active_job_task_rows_by_job_id,
        'active_job_progress_summary': active_job_progress_summary,
        'active_job_task_runtime_progress': active_job_task_runtime_progress,
        'active_job_recovered': active_job_recovered,
    }

def _visible_domains_query():
    return select(Domains).order_by(Domains.name)


def _job_task_ordering():
    return (JobTasks.position.asc(), JobTasks.id.asc())


def _next_job_task_position(job_id: int) -> int:
    current_max = db.session.scalar(
        select(func.max(JobTasks.position)).where(JobTasks.job_id == job_id)
    )
    return int(current_max if current_max is not None else -1) + 1


def _render_jobs_add_form(domains, jobs_form):
    return render_template('jobs_add.html', title='Jobs', domains=domains, jobsForm=jobs_form)


def _get_assignable_hashfile(job: Jobs, raw_hashfile_id) -> Hashfiles | None:
    hashfile_id = _parse_positive_int(raw_hashfile_id)
    if hashfile_id is None:
        return None

    return db.session.scalar(
        select(Hashfiles).where(
            Hashfiles.id == hashfile_id,
            Hashfiles.domain_id == job.domain_id,
        )
    )

@jobs.route("/jobs", methods=['GET', 'POST'])
@login_required
def jobs_list():
    """Function to return list of Jobs"""
    page = parse_page_arg(request.args.get('page'))
    jobs, pagination = paginate_scalars(
        db.session,
        _visible_jobs_query().order_by(Jobs.created_at.desc()),
        page=page,
        per_page=LIST_PAGE_SIZE,
    )
    visible_job_ids = [job.id for job in jobs]
    domain_ids = sorted({job.domain_id for job in jobs})
    owner_ids = sorted({job.owner_id for job in jobs})
    hashfile_ids = sorted({job.hashfile_id for job in jobs if job.hashfile_id})
    domain_names = {
        row.id: row.name
        for row in (
            db.session.execute(
                select(Domains.id, Domains.name).where(Domains.id.in_(domain_ids))
            ).all()
            if domain_ids
            else []
        )
    }
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
    visible_task_ids = sorted({job_task.task_id for job_task in job_tasks})
    task_rows = (
        db.session.execute(
            select(Tasks.id, Tasks.name).where(Tasks.id.in_(visible_task_ids))
        ).all()
        if visible_task_ids
        else []
    )
    task_names = {row.id: row.name for row in task_rows}
    task_names_by_job_id: dict[int, list[str]] = defaultdict(list)
    for job_task in job_tasks:
        task_name = task_names.get(job_task.task_id)
        if task_name:
            task_names_by_job_id[job_task.job_id].append(task_name)
    hashfile_stats = {}
    if hashfile_ids:
        stats_rows = (
            db.session.execute(
                select(
                    HashfileHashes.hashfile_id,
                    func.count(Hashes.id).label('total_count'),
                    func.sum(case((Hashes.cracked.is_(True), 1), else_=0)).label('cracked_count'),
                )
                .select_from(HashfileHashes)
                .join(Hashes, Hashes.id == HashfileHashes.hash_id)
                .where(HashfileHashes.hashfile_id.in_(hashfile_ids))
                .group_by(HashfileHashes.hashfile_id)
            )
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

    # Surface latest active task telemetry per job for jobs table (ETA + % done).
    status_rank = {'Running': 0, 'Importing': 1, 'Paused': 2, 'Queued': 3}
    job_runtime_progress: dict[int, dict[str, str]] = {}
    for job_task in job_tasks:
        if job_task.status not in status_rank:
            continue

        percent_done, eta = parse_jobtask_progress(job_task.progress)
        existing = job_runtime_progress.get(job_task.job_id)
        if existing and existing['rank'] <= status_rank[job_task.status]:
            continue

        job_runtime_progress[job_task.job_id] = {
            'percent_done': percent_done or 'N/A',
            'eta': eta or 'N/A',
            'rank': status_rank[job_task.status],
        }
    active_summary = _build_active_jobs_summary()

    return render_template(
        'jobs.html',
        title='Jobs',
        jobs=jobs,
        domain_names=domain_names,
        owner_names=owner_names,
        hashfile_names=hashfile_names,
        task_names_by_job_id=task_names_by_job_id,
        job_runtime_progress=job_runtime_progress,
        job_recovered=job_recovered,
        pagination=pagination,
        **active_summary,
    )

@jobs.route("/jobs/add", methods=['GET', 'POST'])
@login_required
def jobs_add():
    """Function to manage adding of new job"""
    domains = db.session.execute(_visible_domains_query()).scalars().all()
    jobs_form = JobsForm()
    jobs_form.domain_id.choices = [("", "--SELECT--")] + [
        (str(domain.id), domain.name) for domain in domains
    ]
    if current_user.admin:
        jobs_form.domain_id.choices.append(("add_new", "Add New Domain"))
    if jobs_form.validate_on_submit():
        domain_result, domain_error = resolve_or_create_shared_domain(
            jobs_form.domain_id.data,
            new_domain_name=jobs_form.domain_name.data,
            allow_create=current_user.admin,
        )
        if domain_error:
            flash(domain_error, 'danger')
            return _render_jobs_add_form(domains, jobs_form)
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
            return _render_jobs_add_form(domains, jobs_form)
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
        return redirect(str(job.id)+"/assigned_hashfile/")
    return _render_jobs_add_form(domains, jobs_form)

@jobs.route("/jobs/<int:job_id>/assigned_hashfile/", methods=['GET', 'POST'])
@login_required
def jobs_assigned_hashfile(job_id):
    """Function to manage assigning hashfile to job"""

    job = db.get_or_404(Jobs, job_id)
    if not _can_manage_job(job):
        flash('You do not have rights to modify this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    hashfiles = _visible_hashfiles_for_job(job)
    jobs_new_hashfile_form = JobsNewHashFileForm()
    hashfile_cracked_rate = {}

    if job.status in ('Running', 'Queued', 'Paused'):
        flash('You can not edit a running, queued, or paused job. First stop it before editing.', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    hashfile_ids = [hashfile.id for hashfile in hashfiles]
    stats_by_hashfile_id = {}
    if hashfile_ids:
        stats_rows = (
            db.session.execute(
                select(
                    HashfileHashes.hashfile_id,
                    func.count(Hashes.id).label('total_count'),
                    func.sum(case((Hashes.cracked.is_(True), 1), else_=0)).label('cracked_count'),
                )
                .select_from(HashfileHashes)
                .join(Hashes, Hashes.id == HashfileHashes.hash_id)
                .where(HashfileHashes.hashfile_id.in_(hashfile_ids))
                .group_by(HashfileHashes.hashfile_id)
            )
            .all()
        )
        stats_by_hashfile_id = {
            row.hashfile_id: (int(row.cracked_count or 0), int(row.total_count or 0))
            for row in stats_rows
        }

    for hashfile in hashfiles:
        cracked_cnt, total = stats_by_hashfile_id.get(hashfile.id, (0, 0))
        hashfile_cracked_rate[hashfile.id] = "(" + str(cracked_cnt) + "/" + str(total) + ")"

    if jobs_new_hashfile_form.validate_on_submit():
        creation_result, error_message = create_hashfile_from_form(
            jobs_new_hashfile_form,
            domain_id=job.domain_id,
        )
        if error_message:
            flash(error_message, 'danger')
            return redirect(url_for('jobs.jobs_assigned_hashfile', job_id=job_id))

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
        return redirect(
            url_for(
                'jobs.jobs_assigned_hashfile_cracked',
                job_id=job.id,
                hashfile_id=hashfile.id,
            )
        )

    elif request.method == 'POST' and request.form.get('hashfile_id'):
        selected_hashfile = _get_assignable_hashfile(job, request.form.get('hashfile_id'))
        if not selected_hashfile:
            flash('Selected hashfile is invalid for this job domain.', 'danger')
            return redirect(url_for('jobs.jobs_assigned_hashfile', job_id=job_id))

        job.hashfile_id = selected_hashfile.id
        db.session.commit()
        return redirect("/jobs/" + str(job.id)+"/tasks")
    elif request.method == 'POST' and 'hashfile_id' in request.form:
        flash('Please select a valid hashfile.', 'danger')
        return redirect(url_for('jobs.jobs_assigned_hashfile', job_id=job_id))

    return render_template('jobs_assigned_hashfiles.html', title='Jobs Assigned Hashfiles', hashfiles=hashfiles, job=job, jobs_new_hashfile_form=jobs_new_hashfile_form, hashfile_cracked_rate=hashfile_cracked_rate)

@jobs.route("/jobs/<int:job_id>/assigned_hashfile/<int:hashfile_id>", methods=['GET'])
@login_required
def jobs_assigned_hashfile_cracked(job_id, hashfile_id):
    """Function to show instacrack results"""

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
        return redirect(url_for('jobs.jobs_assigned_hashfile', job_id=job.id))
    # Can be optimized to only return the hash and plaintext
    cracked_hashfiles_hashes = (
        db.session.execute(
            select(Hashes, HashfileHashes)
            .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
            .where(Hashes.cracked.is_(True))
            .where(HashfileHashes.hashfile_id == hashfile.id)
        )
        .tuples()
        .all()
    )
    cracked_hashfiles_hashes_cnt = int(
        db.session.scalar(
            select(func.count())
            .select_from(Hashes)
            .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
            .where(Hashes.cracked.is_(True))
            .where(HashfileHashes.hashfile_id == hashfile.id)
        )
        or 0
    )
    if cracked_hashfiles_hashes_cnt > 0:
        flash(str(cracked_hashfiles_hashes_cnt) + " instacracked Hashes!", 'success')
    # Opportunity for either a stored procedure or more advanced queries.

    return render_template('jobs_assigned_hashfiles_cracked.html', title='Jobs Assigned Hashfiles Cracked', hashfile=hashfile, job=job, cracked_hashfiles_hashes=cracked_hashfiles_hashes)

@jobs.route("/jobs/<int:job_id>/tasks", methods=['GET'])
@login_required
def jobs_list_tasks(job_id):
    """Function to list tasks for a given job"""    
    job = db.get_or_404(Jobs, job_id)
    if not _can_view_job(job):
        flash('You do not have rights to view this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    tasks = db.session.execute(select(Tasks).order_by(Tasks.name.asc())).scalars().all()
    job_tasks = db.session.execute(
        select(JobTasks).filter_by(job_id=job_id).order_by(*_job_task_ordering())
    ).scalars().all()
    task_groups = db.session.execute(
        select(TaskGroups).order_by(TaskGroups.name.asc())
    ).scalars().all()
    task_by_id = {task.id: task for task in tasks}
    assigned_task_ids = {job_task.task_id for job_task in job_tasks}
    available_tasks = [task for task in tasks if task.id not in assigned_task_ids]

    return render_template(
        'jobs_assigned_tasks.html',
        title='Jobs Assigned Tasks',
        job=job,
        job_tasks=job_tasks,
        task_groups=task_groups,
        task_by_id=task_by_id,
        available_tasks=available_tasks,
        can_manage_job=_can_manage_job(job),
    )

@jobs.route("/jobs/<int:job_id>/assign_task/<int:task_id>", methods=['POST'])
@login_required
def jobs_assigned_task(job_id, task_id):
    """Function to assign task to job"""
    job = db.get_or_404(Jobs, job_id)
    if not _can_manage_job(job):
        flash('You do not have rights to modify this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))
    if not _require_job_allows_task_mutation(job):
        return redirect(url_for('jobs.jobs_list_tasks', job_id=job.id))

    task = db.session.scalar(select(Tasks).where(Tasks.id == task_id))
    if not task:
        flash('Task is invalid or no longer available.', 'danger')
        return redirect(url_for('jobs.jobs_list_tasks', job_id=job.id))

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

    return redirect("/jobs/"+str(job_id)+"/tasks")

@jobs.route("/jobs/<int:job_id>/assign_task_group/<int:task_group_id>", methods=['POST'])
@login_required
def jobs_assign_task_group(job_id, task_group_id):
    """Function to assign task group to job"""

    job = db.get_or_404(Jobs, job_id)
    if not _can_manage_job(job):
        flash('You do not have rights to modify this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))
    if not _require_job_allows_task_mutation(job):
        return redirect(url_for('jobs.jobs_list_tasks', job_id=job.id))

    task_group = db.session.scalar(select(TaskGroups).where(TaskGroups.id == task_group_id))
    if not task_group:
        flash('Task Group is invalid or no longer available.', 'danger')
        return redirect(url_for('jobs.jobs_list_tasks', job_id=job.id))
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
        return redirect("/jobs/" + str(job_id) + "/tasks")
    if new_assignments == 0:
        flash('Task Group did not add any new tasks to this job.', 'info')
	
    return redirect("/jobs/" + str(job_id) + "/tasks")

@jobs.route("/jobs/<int:job_id>/move_task_up/<int:task_id>", methods=['POST'])
@login_required
def jobs_move_task_up(job_id, task_id):
    """Function to move assigned task up on task list for job"""
    job = db.get_or_404(Jobs, job_id)
    if not _can_manage_job(job):
        flash('You do not have rights to modify this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))
    if not _require_job_allows_task_mutation(job):
        return redirect(url_for('jobs.jobs_list_tasks', job_id=job.id))

    job_tasks = db.session.execute(
        select(JobTasks).filter_by(job_id=job_id).order_by(*_job_task_ordering())
    ).scalars().all()
    if not job_tasks:
        flash('No tasks assigned to this job.', 'warning')
        return redirect("/jobs/"+str(job_id)+"/tasks")

    ordered_task_ids = [entry.task_id for entry in job_tasks]
    if task_id not in ordered_task_ids:
        flash('Task is not assigned to this job.', 'warning')
        return redirect("/jobs/"+str(job_id)+"/tasks")

    element_index = ordered_task_ids.index(task_id)
    if element_index == 0:
        flash('Task is already at the top', 'warning')
        return redirect("/jobs/"+str(job_id)+"/tasks")

    current_task = job_tasks[element_index]
    previous_task = job_tasks[element_index - 1]
    current_task.position, previous_task.position = (
        previous_task.position,
        current_task.position,
    )
    db.session.commit()

    return redirect("/jobs/"+str(job_id)+"/tasks")

@jobs.route("/jobs/<int:job_id>/move_task_down/<int:task_id>", methods=['POST'])
@login_required
def jobs_move_task_down(job_id, task_id):
    """Function to move assigned task down on task list for job"""
    job = db.get_or_404(Jobs, job_id)
    if not _can_manage_job(job):
        flash('You do not have rights to modify this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))
    if not _require_job_allows_task_mutation(job):
        return redirect(url_for('jobs.jobs_list_tasks', job_id=job.id))

    job_tasks = db.session.execute(
        select(JobTasks).filter_by(job_id=job_id).order_by(*_job_task_ordering())
    ).scalars().all()
    if not job_tasks:
        flash('No tasks assigned to this job.', 'warning')
        return redirect("/jobs/"+str(job_id)+"/tasks")

    ordered_task_ids = [entry.task_id for entry in job_tasks]
    if task_id not in ordered_task_ids:
        flash('Task is not assigned to this job.', 'warning')
        return redirect("/jobs/"+str(job_id)+"/tasks")

    element_index = ordered_task_ids.index(task_id)
    if element_index == len(ordered_task_ids) - 1:
        flash('Task is already at the bottom', 'warning')
        return redirect("/jobs/"+str(job_id)+"/tasks")

    current_task = job_tasks[element_index]
    next_task = job_tasks[element_index + 1]
    current_task.position, next_task.position = (
        next_task.position,
        current_task.position,
    )
    db.session.commit()

    return redirect("/jobs/"+str(job_id)+"/tasks")

@jobs.route("/jobs/<int:job_id>/remove_task/<int:task_id>", methods=['POST'])
@login_required
def jobs_remove_task(job_id, task_id):
    """Function to remove task from task list on job"""
    job = db.get_or_404(Jobs, job_id)
    if not _can_manage_job(job):
        flash('You do not have rights to modify this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))
    if not _require_job_allows_task_mutation(job):
        return redirect(url_for('jobs.jobs_list_tasks', job_id=job.id))

    job_task = db.session.scalar(
        select(JobTasks).filter_by(job_id=job_id, task_id=task_id)
    )
    if not job_task:
        flash('Task is not assigned to this job.', 'warning')
        return redirect("/jobs/"+str(job_id)+"/tasks")

    db.session.delete(job_task)
    db.session.commit()

    return redirect("/jobs/"+str(job_id)+"/tasks")

@jobs.route("/jobs/<int:job_id>/remove_all_tasks", methods=['POST'])
@login_required
def jobs_remove_all_tasks(job_id):
    """Function to remove all tasks from job"""
    job = db.get_or_404(Jobs, job_id)
    if not _can_manage_job(job):
        flash('You do not have rights to modify this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))
    if not _require_job_allows_task_mutation(job):
        return redirect(url_for('jobs.jobs_list_tasks', job_id=job.id))

    db.session.execute(delete(JobTasks).filter_by(job_id=job_id))
    db.session.commit()
    return redirect("/jobs/"+str(job_id)+"/tasks")

@jobs.route("/jobs/delete/<int:job_id>", methods=['POST'])
@login_required
def jobs_delete(job_id):
    """Function to delete job"""

    job = db.get_or_404(Jobs, job_id)
    if _can_manage_job(job):
        deleted_job_name = job.name
        deleted_job_status = job.status
        deleted_owner_id = job.owner_id
        db.session.execute(delete(JobTasks).filter_by(job_id=job_id))

        db.session.delete(job)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Job could not be deleted because it changed concurrently. Refresh and retry.', 'danger')
            return redirect(url_for('jobs.jobs_list'))
        record_audit_event(
            'job.delete',
            'job',
            target_id=job_id,
            summary=f'Deleted job "{deleted_job_name}".',
            details={
                'job_name': deleted_job_name,
                'previous_status': deleted_job_status,
                'owner_id': deleted_owner_id,
            },
        )
        flash('Job has been deleted!', 'success')
        return redirect(url_for('jobs.jobs_list'))

    flash('You do not have rights to delete this job!', 'danger')
    return redirect(url_for('jobs.jobs_list'))

@jobs.route("/jobs/<int:job_id>/summary", methods=['GET', 'POST'])
@login_required
def jobs_summary(job_id):
    """Function to present job summary"""    
    job = db.get_or_404(Jobs, job_id)
    if not _can_view_job(job):
        flash('You do not have rights to view this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    # Check if job has any assigned tasks, and if not, send the user back to the task assigned page.
    job_tasks = db.session.execute(
        select(JobTasks).filter_by(job_id=job_id).order_by(*_job_task_ordering())
    ).scalars().all()
    if len(job_tasks) == 0:
        flash('You must assign at least one task.', 'warning')
        return redirect("/jobs/"+str(job_id)+"/tasks")

    form = JobSummaryForm()
    task_ids = sorted({job_task.task_id for job_task in job_tasks})
    task_rows = (
        db.session.execute(
            select(Tasks.id, Tasks.name).where(Tasks.id.in_(task_ids))
        ).all()
        if task_ids
        else []
    )
    task_names = {row.id: row.name for row in task_rows}
    ordered_task_names = [
        task_names[job_task.task_id]
        for job_task in job_tasks
        if job_task.task_id in task_names
    ]
    hashfile = db.session.get(Hashfiles, job.hashfile_id)
    if not hashfile:
        flash('You must assign a valid hashfile before reviewing summary.', 'danger')
        return redirect(url_for('jobs.jobs_assigned_hashfile', job_id=job.id))
    domain = db.session.get(Domains, job.domain_id)
    cracked_cnt = int(
        db.session.scalar(
            select(func.count())
            .select_from(Hashes)
            .outerjoin(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
            .where(Hashes.cracked.is_(True))
            .where(HashfileHashes.hashfile_id == hashfile.id)
        )
        or 0
    )
    hash_total = int(
        db.session.scalar(
            select(func.count())
            .select_from(Hashes)
            .outerjoin(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
            .where(HashfileHashes.hashfile_id == hashfile.id)
        )
        or 0
    )
    cracked_rate = str(cracked_cnt) + '/' + str(hash_total)

    can_manage_job = _can_manage_job(job)
    if request.method == 'POST' and not can_manage_job:
        flash('You do not have rights to modify this job!', 'danger')
        return redirect(url_for('jobs.jobs_summary', job_id=job.id))

    if form.validate_on_submit():
        for job_task in job_tasks:
            job_task.status = 'Ready'

        job.status = 'Ready'
        job.updated_at = _utc_now_naive()
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

    return render_template(
        'jobs_summary.html',
        title='Job Summary',
        job=job,
        form=form,
        cracked_rate=cracked_rate,
        job_tasks=job_tasks,
        domain=domain,
        hashfile=hashfile,
        ordered_task_names=ordered_task_names,
        can_manage_job=can_manage_job,
    )

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

    if not job_tasks:
        flash('Error in starting job', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    previous_status = job.status
    job.status = 'Queued'
    job.queued_at = _utc_now_naive()
    visible_task_ids = set(db.session.scalars(select(Tasks.id)).all())
    for job_task in job_tasks:
        if job_task.task_id not in visible_task_ids:
            db.session.rollback()
            flash('One or more assigned tasks are invalid or no longer available.', 'danger')
            return redirect(url_for('jobs.jobs_list_tasks', job_id=job.id))
        job_task.status = 'Queued'
        job_task.priority = job.priority
        try:
            job_task.command = build_hashcat_command(job.id, job_task.task_id)
        except ValueError as e:
            db.session.rollback()
            flash(str(e), 'danger')
            return redirect(url_for('jobs.jobs_summary', job_id=job.id))

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

    if job.status in ('Running', 'Queued', 'Paused'):
        previous_status = job.status
        job.status = 'Canceled'
        job.ended_at = _utc_now_naive()

        for job_task in job_tasks:
            if job_task.status in ACTIVE_JOB_TASK_EXECUTION_STATUSES:
                job_task.status = 'Canceled'
        db.session.commit()
        record_audit_event(
            'job.stop',
            'job',
            target_id=job.id,
            summary=f'Stopped job "{job.name}".',
            details={
                'job_name': job.name,
                'previous_status': previous_status,
                'canceled_task_count': sum(
                    1 for job_task in job_tasks if job_task.status == 'Canceled'
                ),
            },
        )
        flash('Job has been stopped!', 'success')
    else:
        flash('Job is not actively running.', 'danger')
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

    if job.status not in ('Running', 'Queued'):
        flash('Job is not running or queued.', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    previous_status = job.status
    job.status = 'Paused'
    for job_task in job_tasks:
        if job_task.status in ('Running', 'Importing', 'Queued'):
            job_task.status = 'Paused'
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

    if job.status != 'Paused':
        flash('Job is not paused.', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    previous_status = job.status
    for job_task in job_tasks:
        if job_task.status == 'Paused':
            job_task.status = 'Queued'

    has_running = any(task.status in ('Running', 'Importing') for task in job_tasks)
    has_queued = any(task.status == 'Queued' for task in job_tasks)

    if has_running:
        job.status = 'Running'
    elif has_queued:
        job.status = 'Queued'
        job.queued_at = _utc_now_naive()
    else:
        # Fallback: if every task completed/canceled while paused, leave current job state unchanged.
        job.status = 'Paused'

    db.session.commit()
    record_audit_event(
        'job.resume',
        'job',
        target_id=job.id,
        summary=f'Resumed job "{job.name}".',
        details={
            'job_name': job.name,
            'previous_status': previous_status,
            'new_status': job.status,
        },
    )
    flash('Job has been resumed!', 'success')
    return redirect(url_for('jobs.jobs_list'))
