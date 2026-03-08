"""Flask routes to handle Jobs"""
import os
import secrets
import json
from datetime import datetime
from flask import Blueprint, render_template, redirect, flash, url_for, current_app, request
from flask_login import login_required, current_user
from sqlalchemy import func, case
from hashcrush.jobs.forms import JobsForm, JobsNewHashFileForm, JobSummaryForm
from hashcrush.models import Jobs, Domains, Hashfiles, Users, HashfileHashes, Hashes, JobTasks, Tasks, TaskGroups
from hashcrush.utils.utils import save_file, import_hashfilehashes, build_hashcat_command, validate_pwdump_hashfile, validate_netntlm_hashfile, validate_kerberos_hashfile, validate_shadow_hashfile, validate_user_hash_hashfile, validate_hash_only_hashfile
from hashcrush.models import db


jobs = Blueprint('jobs', __name__)


def _can_manage_job(job: Jobs | None) -> bool:
    return bool(job and (current_user.admin or job.owner_id == current_user.id))

@jobs.route("/jobs", methods=['GET', 'POST'])
@login_required
def jobs_list():
    """Function to return list of Jobs"""
    jobs = Jobs.query.order_by(Jobs.created_at.desc()).all()
    domains = Domains.query.all()
    users = Users.query.all()
    hashfiles = Hashfiles.query.all()
    job_tasks = JobTasks.query.all()
    tasks = Tasks.query.all()
    return render_template('jobs.html', title='Jobs', jobs=jobs, domains=domains, users=users, hashfiles=hashfiles, job_tasks=job_tasks, tasks=tasks)

@jobs.route("/jobs/add", methods=['GET', 'POST'])
@login_required
def jobs_add():
    """Function to manage adding of new job"""
    jobs = Jobs.query.all()
    domains = Domains.query.order_by(Domains.name).all()
    jobs_form = JobsForm()
    if jobs_form.validate_on_submit():
        domain_id = jobs_form.domain_id.data
        if jobs_form.domain_id.data == 'add_new':
            domain = Domains(name=jobs_form.domain_name.data)
            db.session.add(domain)
            db.session.commit()
            domain_id = domain.id

        try:
            selected_priority = int(jobs_form.priority.data)
        except (TypeError, ValueError):
            selected_priority = 3
        job_priority = selected_priority if 1 <= selected_priority <= 5 else 3

        job = Jobs( name = jobs_form.name.data,
                    priority = job_priority,
                    status = 'Incomplete',
                    domain_id = domain_id,
                    owner_id = current_user.id)
        db.session.add(job)
        db.session.commit()
        return redirect(str(job.id)+"/assigned_hashfile/")
    return render_template('jobs_add.html', title='Jobs', jobs=jobs, domains=domains, jobsForm=jobs_form)

@jobs.route("/jobs/<int:job_id>/assigned_hashfile/", methods=['GET', 'POST'])
@login_required
def jobs_assigned_hashfile(job_id):
    """Function to manage assigning hashfile to job"""

    job = Jobs.query.get(job_id)
    if not _can_manage_job(job):
        flash('You do not have rights to modify this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    hashfiles = Hashfiles.query.filter_by(domain_id=job.domain_id).all()
    jobs_new_hashfile_form = JobsNewHashFileForm()
    hashfile_cracked_rate = {}

    if job.status in ('Running', 'Queued', 'Paused'):
        flash('You can not edit a running, queued, or paused job. First stop it before editing.', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    hashfile_ids = [hashfile.id for hashfile in hashfiles]
    stats_by_hashfile_id = {}
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
        stats_by_hashfile_id = {
            row.hashfile_id: (int(row.cracked_count or 0), int(row.total_count or 0))
            for row in stats_rows
        }

    for hashfile in hashfiles:
        cracked_cnt, total = stats_by_hashfile_id.get(hashfile.id, (0, 0))
        hashfile_cracked_rate[hashfile.id] = "(" + str(cracked_cnt) + "/" + str(total) + ")"

    if jobs_new_hashfile_form.validate_on_submit():

        hashfile_path = ""
        if jobs_new_hashfile_form.hashfile.data:
            # User submitted a file upload
            hashfile_path = save_file('control/tmp', jobs_new_hashfile_form.hashfile.data)
        elif jobs_new_hashfile_form.hashfilehashes.data:
            # User submitted copied/pasted hashes
            # Going to have to save a file manually instead of using save_file since save_file requires form data to be passed and we're not collecting that object for this tab

            if len(jobs_new_hashfile_form.name.data) == 0:
                flash('You must assign a name to the hashfile', 'danger')
                return redirect(url_for('jobs.jobs_assigned_hashfile', job_id=job_id))

            random_hex = secrets.token_hex(8)
            hashfile_path = os.path.join(current_app.root_path, 'control', 'tmp', random_hex)
            with open(hashfile_path, 'w+') as hashfilehashes_file:
                hashfilehashes_file.write(jobs_new_hashfile_form.hashfilehashes.data)

        if len(hashfile_path) > 0:
            if jobs_new_hashfile_form.file_type.data == 'pwdump':
                has_problem = validate_pwdump_hashfile(hashfile_path, jobs_new_hashfile_form.pwdump_hash_type.data)
                hash_type = jobs_new_hashfile_form.pwdump_hash_type.data
            elif jobs_new_hashfile_form.file_type.data == 'NetNTLM':
                has_problem = validate_netntlm_hashfile(hashfile_path)
                hash_type = jobs_new_hashfile_form.netntlm_hash_type.data
            elif jobs_new_hashfile_form.file_type.data == 'kerberos':
                has_problem = validate_kerberos_hashfile(hashfile_path, jobs_new_hashfile_form.kerberos_hash_type.data)
                hash_type = jobs_new_hashfile_form.kerberos_hash_type.data
            elif jobs_new_hashfile_form.file_type.data == 'shadow':
                has_problem = validate_shadow_hashfile(hashfile_path, jobs_new_hashfile_form.shadow_hash_type.data)
                hash_type = jobs_new_hashfile_form.shadow_hash_type.data
            elif jobs_new_hashfile_form.file_type.data == 'user_hash':
                has_problem = validate_user_hash_hashfile(hashfile_path)
                hash_type = jobs_new_hashfile_form.hash_type.data
            elif jobs_new_hashfile_form.file_type.data == 'hash_only':
                has_problem = validate_hash_only_hashfile(hashfile_path, jobs_new_hashfile_form.hash_type.data)
                hash_type = jobs_new_hashfile_form.hash_type.data
            else:
                has_problem = 'Invalid File Format'

            if has_problem:
                flash(has_problem, 'danger')
                return redirect(url_for('jobs.jobs_assigned_hashfile', job_id=job_id))
            else:
                hashfile_name = jobs_new_hashfile_form.name.data
                if not hashfile_name and jobs_new_hashfile_form.hashfile.data:
                    hashfile_name = jobs_new_hashfile_form.hashfile.data.filename
                hashfile_name = hashfile_name or f'hashfile_{secrets.token_hex(4)}.txt'
                hashfile = Hashfiles(name=hashfile_name, domain_id=job.domain_id, owner_id=current_user.id)
                db.session.add(hashfile)
                db.session.commit()

                # Parse Hashfile
                if not import_hashfilehashes(   hashfile_id=hashfile.id,
                                                hashfile_path=hashfile_path,
                                                file_type=jobs_new_hashfile_form.file_type.data,
                                                hash_type=hash_type
                                                ):
                    return ('Something went wrong. Check the filetype / hashtype and try again.')

                # Temporary upload cleanup is handled separately.
                job.hashfile_id = hashfile.id
                db.session.commit()

            return redirect(str(hashfile.id))

    elif request.method == 'POST' and request.form['hashfile_id']:
        # User selected an existing hashfile
        job.hashfile_id = request.form['hashfile_id']
        db.session.commit()
        return redirect("/jobs/" + str(job.id)+"/tasks")

    else:
        for error in jobs_new_hashfile_form.name.errors:
            print(str(error))
        for error in jobs_new_hashfile_form.file_type.errors:
            print(str(error))
        for error in jobs_new_hashfile_form.hash_type.errors:
            print(str(error))
        for error in jobs_new_hashfile_form.hashfile.errors:
            print(str(error))
        for error in jobs_new_hashfile_form.hashfilehashes.errors:
            print(str(error))
        for error in jobs_new_hashfile_form.submit.errors:
            print(str(error))

    return render_template('jobs_assigned_hashfiles.html', title='Jobs Assigned Hashfiles', hashfiles=hashfiles, job=job, jobs_new_hashfile_form=jobs_new_hashfile_form, hashfile_cracked_rate=hashfile_cracked_rate)

@jobs.route("/jobs/<int:job_id>/assigned_hashfile/<int:hashfile_id>", methods=['GET'])
@login_required
def jobs_assigned_hashfile_cracked(job_id, hashfile_id):
    """Function to show instacrack results"""

    job = Jobs.query.get(job_id)
    if not _can_manage_job(job):
        flash('You do not have rights to view this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    hashfile = Hashfiles.query.get(hashfile_id)
    # Can be optimized to only return the hash and plaintext
    cracked_hashfiles_hashes = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==hashfile.id).all()
    cracked_hashfiles_hashes_cnt = db.session.query(Hashes).join(HashfileHashes, Hashes.id == HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==hashfile.id).count()
    if cracked_hashfiles_hashes_cnt > 0:
        flash(str(cracked_hashfiles_hashes_cnt) + " instacracked Hashes!", 'success')
    # Opportunity for either a stored procedure or more advanced queries.

    return render_template('jobs_assigned_hashfiles_cracked.html', title='Jobs Assigned Hashfiles Cracked', hashfile=hashfile, job=job, cracked_hashfiles_hashes=cracked_hashfiles_hashes)

@jobs.route("/jobs/<int:job_id>/tasks", methods=['GET'])
@login_required
def jobs_list_tasks(job_id):
    """Function to list tasks for a given job"""    
    job = Jobs.query.get(job_id)
    if not _can_manage_job(job):
        flash('You do not have rights to view this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    tasks = Tasks.query.all()
    job_tasks = JobTasks.query.filter_by(job_id=job_id)
    task_groups = TaskGroups.query.all()
    # Right now we're doing nested loops in the template, this could probably be solved with a left/join select

    return render_template('jobs_assigned_tasks.html', title='Jobs Assigned Tasks', job=job, tasks=tasks, job_tasks=job_tasks, task_groups=task_groups)

@jobs.route("/jobs/<int:job_id>/assign_task/<int:task_id>", methods=['GET'])
@login_required
def jobs_assigned_task(job_id, task_id):
    """Function to assign task to job"""
    job = Jobs.query.get(job_id)
    if not _can_manage_job(job):
        flash('You do not have rights to modify this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    exists = JobTasks.query.filter_by(job_id=job_id, task_id=task_id).first()
    if exists:
        flash('Task already assigned to the job.', 'warning')
    else:
        job_task = JobTasks(job_id=job_id, task_id=task_id, status='Not Started')
        db.session.add(job_task)
        db.session.commit()

    return redirect("/jobs/"+str(job_id)+"/tasks")

@jobs.route("/jobs/<int:job_id>/assign_task_group/<int:task_group_id>", methods=['GET'])
@login_required
def jobs_assign_task_group(job_id, task_group_id):
    """Function to assign task group to job"""

    job = Jobs.query.get(job_id)
    if not _can_manage_job(job):
        flash('You do not have rights to modify this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    task_group = TaskGroups.query.get(task_group_id)

    for task_group_entry in json.loads(task_group.tasks):
        job_task = JobTasks(job_id=job_id, task_id=task_group_entry, status='Not Started')
        db.session.add(job_task)
    db.session.commit()

    return redirect("/jobs/" + str(job_id) + "/tasks")

@jobs.route("/jobs/<int:job_id>/move_task_up/<int:task_id>", methods=['GET'])
@login_required
def jobs_move_task_up(job_id, task_id):
    """Function to move assigned task up on task list for job"""
    job = Jobs.query.get(job_id)
    if not _can_manage_job(job):
        flash('You do not have rights to modify this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    job_tasks = JobTasks.query.filter_by(job_id=job_id).all()

    # Rebuild task ordering so sequence is preserved without requiring contiguous IDs.
    temp_jobtasks = []
    new_jobtasks = []

    for entry in job_tasks:
        temp_jobtasks.append(str(entry.task_id))

    if temp_jobtasks[0] == str(task_id):
        flash('Task is already at the top', 'warning')
        return redirect("/jobs/"+str(job_id)+"/tasks")

    element_index = temp_jobtasks.index(str(task_id))
    temp_value = temp_jobtasks[element_index - 1]
    temp_jobtasks[element_index - 1] = str(task_id)
    temp_jobtasks[element_index] = str(temp_value)

    new_jobtasks = temp_jobtasks

    JobTasks.query.filter_by(job_id=job_id).delete()
    db.session.commit()

    for entry in new_jobtasks:
        job_task = JobTasks(job_id=job_id, task_id=entry, status='Not Started')
        db.session.add(job_task)
    db.session.commit()

    return redirect("/jobs/"+str(job_id)+"/tasks")

@jobs.route("/jobs/<int:job_id>/move_task_down/<int:task_id>", methods=['GET'])
@login_required
def jobs_move_task_down(job_id, task_id):
    """Function to move assigned task down on task list for job"""
    job = Jobs.query.get(job_id)
    if not _can_manage_job(job):
        flash('You do not have rights to modify this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    job_tasks = JobTasks.query.filter_by(job_id=job_id).all()

    # Rebuild task ordering so sequence is preserved without requiring contiguous IDs.
    temp_jobtasks = []
    new_jobtasks = []

    for entry in job_tasks:
        temp_jobtasks.append(str(entry.task_id))

    if temp_jobtasks[-1] == str(task_id):
        flash('Task is already at the bottom', 'warning')
        return redirect("/jobs/"+str(job_id)+"/tasks")

    for index in range(len(temp_jobtasks)):
        if int(index+1) <= len(temp_jobtasks):
            if  temp_jobtasks[int(index)] == str(task_id):
                new_jobtasks.append(temp_jobtasks[int(index+1)])
                new_jobtasks.append(str(task_id))
                del temp_jobtasks[int(index+1)]
            else:
                new_jobtasks.append(temp_jobtasks[int(index)])

    JobTasks.query.filter_by(job_id=job_id).delete()
    db.session.commit()

    for entry in new_jobtasks:
        job_task = JobTasks(job_id=job_id, task_id=entry, status='Not Started')
        db.session.add(job_task)
    db.session.commit()

    return redirect("/jobs/"+str(job_id)+"/tasks")

@jobs.route("/jobs/<int:job_id>/remove_task/<int:task_id>", methods=['GET'])
@login_required
def jobs_remove_task(job_id, task_id):
    """Function to remove task from task list on job"""
    job = Jobs.query.get(job_id)
    if not _can_manage_job(job):
        flash('You do not have rights to modify this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    job_task = JobTasks.query.filter_by(job_id=job_id, task_id=task_id).first()
    db.session.delete(job_task)
    db.session.commit()

    return redirect("/jobs/"+str(job_id)+"/tasks")

@jobs.route("/jobs/<int:job_id>/remove_all_tasks", methods=['GET'])
@login_required
def jobs_remove_all_tasks(job_id):
    """Function to remove all tasks from job"""
    job = Jobs.query.get(job_id)
    if not _can_manage_job(job):
        flash('You do not have rights to modify this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    JobTasks.query.filter_by(job_id=job_id).delete()
    db.session.commit()
    return redirect("/jobs/"+str(job_id)+"/tasks")

@jobs.route("/jobs/delete/<int:job_id>", methods=['GET', 'POST'])
@login_required
def jobs_delete(job_id):
    """Function to delete job"""

    job = Jobs.query.get(job_id)
    if current_user.admin or job.owner_id == current_user.id:
        JobTasks.query.filter_by(job_id=job_id).delete()

        db.session.delete(job)
        db.session.commit()
        flash('Job has been deleted!', 'success')
        return redirect(url_for('jobs.jobs_list'))

    flash('You do not have rights to delete this job!', 'danger')
    return redirect(url_for('jobs.jobs_list'))

@jobs.route("/jobs/<int:job_id>/summary", methods=['GET', 'POST'])
@login_required
def jobs_summary(job_id):
    """Function to present job summary"""    
    job = Jobs.query.get(job_id)
    if not _can_manage_job(job):
        flash('You do not have rights to view this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    # Check if job has any assigned tasks, and if not, send the user back to the task assigned page.
    job_tasks = JobTasks.query.filter_by(job_id=job_id).all()
    if len(job_tasks) == 0:
        flash('You must assign at least one task.', 'warning')
        return redirect("/jobs/"+str(job_id)+"/tasks")

    form = JobSummaryForm()
    tasks = Tasks.query.all()
    hashfile = Hashfiles.query.get(job.hashfile_id)
    domain = Domains.query.get(job.domain_id)
    cracked_cnt = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.cracked == '1').filter(HashfileHashes.hashfile_id==hashfile.id).count()
    hash_total = db.session.query(Hashes).outerjoin(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(HashfileHashes.hashfile_id==hashfile.id).count()
    cracked_rate = str(cracked_cnt) + '/' + str(hash_total)

    if form.validate_on_submit():
        for job_task in job_tasks:
            job_task.status = 'Ready'

        job.status = 'Ready'
        job.updated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        db.session.commit()

        flash('Job successfully created', 'success')

        return redirect(url_for('jobs.jobs_list'))

    return render_template('jobs_summary.html', title='Job Summary', job=job, form=form, cracked_rate=cracked_rate, job_tasks=job_tasks, domain=domain, hashfile=hashfile, tasks=tasks)

@jobs.route("/jobs/start/<int:job_id>", methods=['GET'])
@login_required
def jobs_start(job_id):
    """Function to start job"""

    job = Jobs.query.get(job_id)
    job_tasks = JobTasks.query.filter_by(job_id = job_id).all()

    if job and job_tasks:
        if current_user.admin or job.owner_id == current_user.id:
            job.status = 'Queued'
            job.queued_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            for job_task in job_tasks:
                job_task.status = 'Queued'
                job_task.priority = job.priority
                try:
                    job_task.command = build_hashcat_command(job.id, job_task.task_id)
                except ValueError as e:
                    db.session.rollback()
                    flash(str(e), 'danger')
                    return redirect(url_for('jobs.jobs_summary', job_id=job.id))

            db.session.commit()
            flash('Job has been Started!', 'success')
            return redirect(url_for('main.home'))
        else:
            flash('You do not have rights to start this job!', 'danger')
            return redirect(url_for('jobs.jobs_list'))
    else:
        flash('Error in starting job', 'danger')
        return redirect(url_for('jobs.jobs_list'))

@jobs.route("/jobs/stop/<int:job_id>", methods=['GET'])
@login_required
def jobs_stop(job_id):
    """Function to stop a job"""

    job = Jobs.query.get(job_id)
    job_tasks = JobTasks.query.filter_by(job_id = job_id).all()

    if job:
        if current_user.admin or job.owner_id == current_user.id:
            if job.status in ('Running', 'Queued', 'Paused'):
                job.status = 'Canceled'
                job.ended_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                for job_task in job_tasks:
                    job_task.status = 'Canceled'
                    job_task.worker_pid = None
                db.session.commit()
                flash('Job has been stopped!', 'success')
            else:
                flash('Job is not actively running.', 'danger')
        else:
            flash('You do not have rights to stop this job!', 'danger')
    else:
        flash('Error in stopping job', 'danger')
    return redirect(url_for('jobs.jobs_list'))

@jobs.route("/jobs/pause/<int:job_id>", methods=['GET'])
@login_required
def jobs_pause(job_id):
    """Pause a running or queued job."""

    job = Jobs.query.get(job_id)
    job_tasks = JobTasks.query.filter_by(job_id=job_id).all()

    if not job:
        flash('Error in pausing job', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    if not _can_manage_job(job):
        flash('You do not have rights to pause this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    if job.status not in ('Running', 'Queued'):
        flash('Job is not running or queued.', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    job.status = 'Paused'
    for job_task in job_tasks:
        if job_task.status in ('Running', 'Importing', 'Queued'):
            job_task.status = 'Paused'
    db.session.commit()

    flash('Job has been paused!', 'success')
    return redirect(url_for('jobs.jobs_list'))

@jobs.route("/jobs/resume/<int:job_id>", methods=['GET'])
@login_required
def jobs_resume(job_id):
    """Resume a paused job."""

    job = Jobs.query.get(job_id)
    job_tasks = JobTasks.query.filter_by(job_id=job_id).all()

    if not job:
        flash('Error in resuming job', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    if not _can_manage_job(job):
        flash('You do not have rights to resume this job!', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    if job.status != 'Paused':
        flash('Job is not paused.', 'danger')
        return redirect(url_for('jobs.jobs_list'))

    for job_task in job_tasks:
        if job_task.status == 'Paused':
            job_task.status = 'Queued'

    has_running = any(task.status in ('Running', 'Importing') for task in job_tasks)
    has_queued = any(task.status == 'Queued' for task in job_tasks)

    if has_running:
        job.status = 'Running'
    elif has_queued:
        job.status = 'Queued'
        job.queued_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    else:
        # Fallback: if every task completed/canceled while paused, leave current job state unchanged.
        job.status = 'Paused'

    db.session.commit()
    flash('Job has been resumed!', 'success')
    return redirect(url_for('jobs.jobs_list'))

