"""Flask routes to handle Tasks"""
import json

from flask import Blueprint, flash, redirect, render_template, url_for
from flask_login import login_required
from sqlalchemy.exc import IntegrityError

from hashcrush.authz import admin_required_redirect
from hashcrush.models import Jobs, JobTasks, Rules, TaskGroups, Tasks, Wordlists, db
from hashcrush.tasks.forms import TasksForm

tasks = Blueprint('tasks', __name__)


def _parse_positive_int(raw_value) -> int | None:
    try:
        parsed = int(raw_value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _parse_task_group_task_ids(payload: str | None) -> set[int]:
    try:
        entries = json.loads(payload or "[]")
    except (TypeError, ValueError):
        return set()
    if not isinstance(entries, list):
        return set()

    parsed_ids: set[int] = set()
    for entry in entries:
        parsed = _parse_positive_int(entry)
        if parsed is not None:
            parsed_ids.add(parsed)
    return parsed_ids


def _render_task_form(template_name, title, tasks_form, task=None, wordlists=None, rules=None):
    return render_template(
        template_name,
        title=title,
        tasksForm=tasks_form,
        task=task,
        wordlists=wordlists,
        rules=rules,
    )


def _task_save_conflict_response(template_name, title, tasks_form, task=None, wordlists=None, rules=None):
    db.session.rollback()
    flash(
        'Task could not be saved because its name already exists or the selected resources changed. Refresh and retry.',
        'danger',
    )
    return _render_task_form(template_name, title, tasks_form, task=task, wordlists=wordlists, rules=rules)


@tasks.route("/tasks", methods=['GET', 'POST'])
@login_required
def tasks_list():
    """Function to list tasks"""

    tasks = Tasks.query.all()
    jobs = Jobs.query.all()
    visible_job_ids = [job.id for job in jobs]
    job_tasks = (
        JobTasks.query.filter(JobTasks.job_id.in_(visible_job_ids)).all()
        if visible_job_ids
        else []
    )
    wordlists = Wordlists.query.all()
    task_groups = TaskGroups.query.all()
    task_group_task_ids = {
        task_group.id: _parse_task_group_task_ids(task_group.tasks)
        for task_group in task_groups
    }
    return render_template(
        'tasks.html',
        title='tasks',
        tasks=tasks,
        jobs=jobs,
        job_tasks=job_tasks,
        wordlists=wordlists,
        task_groups=task_groups,
        task_group_task_ids=task_group_task_ids,
    )

@tasks.route("/tasks/add", methods=['GET', 'POST'])
@login_required
@admin_required_redirect('tasks.tasks_list')
def tasks_add():
    """Function to add a new task"""

    tasksForm = TasksForm()

    # clear select field for wordlists and rules
    tasksForm.rule_id.choices = []
    tasksForm.wl_id.choices = []

    wordlists = Wordlists.query.all()
    rules = Rules.query.all()

    for wordlist in wordlists:
        tasksForm.wl_id.choices += [(wordlist.id, wordlist.name)]

    tasksForm.rule_id.choices = [('None', 'None')]
    for rule in rules:
        tasksForm.rule_id.choices += [(rule.id, rule.name)]

    if tasksForm.validate_on_submit():
        if tasksForm.hc_attackmode.data == 'dictionary':
            selected_wl_id = _parse_positive_int(tasksForm.wl_id.data)
            selected_wordlist = (
                Wordlists.query.filter(Wordlists.id == selected_wl_id).first()
                if selected_wl_id is not None
                else None
            )
            if not selected_wordlist:
                flash('Dictionary tasks require a valid registered wordlist.', 'danger')
                return _render_task_form('tasks_add.html', 'Tasks Add', tasksForm)

            selected_rule_id = None
            if tasksForm.rule_id.data not in ('None', None, ''):
                selected_rule_id = _parse_positive_int(tasksForm.rule_id.data)
                selected_rule = (
                    Rules.query.filter(Rules.id == selected_rule_id).first()
                    if selected_rule_id is not None
                    else None
                )
                if not selected_rule:
                    flash('Selected rule is invalid or no longer available.', 'danger')
                    return _render_task_form('tasks_add.html', 'Tasks Add', tasksForm)

            task = Tasks(
                name=tasksForm.name.data,
                wl_id=selected_wordlist.id,
                rule_id=selected_rule_id,
                hc_attackmode=tasksForm.hc_attackmode.data,
            )
            db.session.add(task)
            try:
                db.session.commit()
            except IntegrityError:
                return _task_save_conflict_response('tasks_add.html', 'Tasks Add', tasksForm)
            flash(f'Task {tasksForm.name.data} created!', 'success')
        elif tasksForm.hc_attackmode.data == 'maskmode':
            selected_mask = (tasksForm.mask.data or '').strip()
            if not selected_mask:
                flash('Maskmode tasks require a non-empty hashcat mask.', 'danger')
                return _render_task_form('tasks_add.html', 'Tasks Add', tasksForm)
            task = Tasks(   name=tasksForm.name.data,
                            wl_id=None,
                            rule_id=None,
                            hc_attackmode=tasksForm.hc_attackmode.data,
                            hc_mask=selected_mask
            )
            db.session.add(task)
            try:
                db.session.commit()
            except IntegrityError:
                return _task_save_conflict_response('tasks_add.html', 'Tasks Add', tasksForm)
            flash(f'Task {tasksForm.name.data} created!', 'success')
        else:
            flash('Invalid attack mode selection.', 'danger')
        return redirect(url_for('tasks.tasks_list'))
    return render_template('tasks_add.html', title='Tasks Add', tasksForm=tasksForm)

@tasks.route("/tasks/edit/<int:task_id>", methods=['GET', 'POST'])
@login_required
@admin_required_redirect('tasks.tasks_list')
def task_edit(task_id):
    """Function to edit task"""

    task = Tasks.query.filter(Tasks.id == task_id).first_or_404()

    # Shared tasks are immutable once any job references them.
    affected_jobs = JobTasks.query.filter_by(task_id=task_id).all()
    if affected_jobs:
        flash('Cannot edit this task. It is already associated with one or more jobs.', 'danger')
        return redirect(url_for('tasks.tasks_list'))

    tasksForm = TasksForm(current_task_id=task.id)

    # clear select field for wordlists and rules
    tasksForm.rule_id.choices = []
    tasksForm.wl_id.choices = []

    wordlists = Wordlists.query.all()
    # Add the current value for wordlist.
    if task.hc_attackmode == 'dictionary':
        edit_task_wl = Wordlists.query.filter(Wordlists.id == task.wl_id).first()
        if edit_task_wl:
            tasksForm.wl_id.choices.append((edit_task_wl.id, edit_task_wl.name))
    rules = Rules.query.all()
    # Check if the current value for rule is an integer.
    if isinstance(task.rule_id, int):
        edit_task_rl = Rules.query.filter(Rules.id == task.rule_id).first()
        if edit_task_rl:
            tasksForm.rule_id.choices.append((edit_task_rl.id, edit_task_rl.name))
            tasksForm.rule_id.choices.append(('None', 'None'))
    else:
        # If it's not an integer, set rule_id and rule_name to 'None'.
        tasksForm.rule_id.choices.append(('None', 'None'))

    # Populate the choices for wordlists excluding the current value.
    tasksForm.wl_id.choices += [(wordlist.id, wordlist.name) for wordlist in wordlists if wordlist.id != task.wl_id]

    # Populate the choices for rules excluding the current value.
    tasksForm.rule_id.choices += [(rule.id, rule.name) for rule in rules if rule.id != task.rule_id]

    tasksForm.submit.label.text = 'Update'

    if tasksForm.validate_on_submit():
        if tasksForm.hc_attackmode.data == 'dictionary':
            selected_wl_id = _parse_positive_int(tasksForm.wl_id.data)
            selected_wordlist = (
                Wordlists.query.filter(Wordlists.id == selected_wl_id).first()
                if selected_wl_id is not None
                else None
            )
            if not selected_wordlist:
                flash('Dictionary tasks require a valid registered wordlist.', 'danger')
                return _render_task_form('tasks_edit.html', 'Tasks Edit', tasksForm, task=task, wordlists=wordlists, rules=rules)

            selected_rule_id = None
            if tasksForm.rule_id.data not in ('None', None, ''):
                selected_rule_id = _parse_positive_int(tasksForm.rule_id.data)
                selected_rule = (
                    Rules.query.filter(Rules.id == selected_rule_id).first()
                    if selected_rule_id is not None
                    else None
                )
                if not selected_rule:
                    flash('Selected rule is invalid or no longer available.', 'danger')
                    return _render_task_form('tasks_edit.html', 'Tasks Edit', tasksForm, task=task, wordlists=wordlists, rules=rules)

            task.name = tasksForm.name.data
            task.wl_id = selected_wordlist.id
            task.rule_id = selected_rule_id
            task.hc_attackmode = tasksForm.hc_attackmode.data
            task.hc_mask = None

            db.session.add(task)
            try:
                db.session.commit()
            except IntegrityError:
                return _task_save_conflict_response(
                    'tasks_edit.html',
                    'Tasks Edit',
                    tasksForm,
                    task=task,
                    wordlists=wordlists,
                    rules=rules,
                )
            flash(f'Task {tasksForm.name.data} updated!', 'success')
        elif tasksForm.hc_attackmode.data == 'maskmode':
            selected_mask = (tasksForm.mask.data or '').strip()
            if not selected_mask:
                flash('Maskmode tasks require a non-empty hashcat mask.', 'danger')
                return _render_task_form('tasks_edit.html', 'Tasks Edit', tasksForm, task=task, wordlists=wordlists, rules=rules)
            task.name = tasksForm.name.data
            task.wl_id = None
            task.rule_id = None
            task.hc_attackmode = tasksForm.hc_attackmode.data
            task.hc_mask = selected_mask

            db.session.add(task)
            try:
                db.session.commit()
            except IntegrityError:
                return _task_save_conflict_response(
                    'tasks_edit.html',
                    'Tasks Edit',
                    tasksForm,
                    task=task,
                    wordlists=wordlists,
                    rules=rules,
                )
            flash(f'Task {tasksForm.name.data} updated!', 'success')
        else:
            flash('Invalid attack mode selection.', 'danger')
        return redirect(url_for('tasks.tasks_list'))

    tasksForm.name.data = task.name
    tasksForm.hc_attackmode.data = task.hc_attackmode
    tasksForm.wl_id.data = str(task.wl_id) if task.wl_id is not None else ''
    tasksForm.rule_id.data = str(task.rule_id) if isinstance(task.rule_id, int) else 'None'
    tasksForm.mask.data = task.hc_mask

    return render_template('tasks_edit.html', title='Tasks Edit', tasksForm=tasksForm, task=task, wordlists=wordlists, rules=rules)

@tasks.route("/tasks/delete/<int:task_id>", methods=['POST'])
@login_required
@admin_required_redirect('tasks.tasks_list')
def tasks_delete(task_id):
    """Function to delete task"""

    task = Tasks.query.filter(Tasks.id == task_id).first_or_404()
    task_groups = TaskGroups.query.all()

    # Check if associated with JobTask (which implies its associated with a job)
    jobtask = JobTasks.query.filter_by(task_id=task_id).first()
    if jobtask:
        flash('Cannot delete. Task is associated with one or more jobs.', 'danger')
        return redirect(url_for('tasks.tasks_list'))

    for task_group in task_groups:
        if task_id in _parse_task_group_task_ids(task_group.tasks):
            flash('Cannot delete. Task is associated with one or more task groups.', 'danger')
            return redirect(url_for('tasks.tasks_list'))

    db.session.delete(task)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash('Cannot delete. Task is associated with one or more jobs or task groups.', 'danger')
        return redirect(url_for('tasks.tasks_list'))
    flash('Task has been deleted!', 'success')
    return redirect(url_for('tasks.tasks_list'))
