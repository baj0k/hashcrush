"""Flask routes to handle Tasks"""
import json

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import login_required
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from hashcrush.audit import record_audit_event
from hashcrush.authz import admin_required_redirect, visible_jobs_query
from hashcrush.models import JobTasks, Jobs, Rules, TaskGroups, Tasks, Wordlists, db
from hashcrush.tasks.forms import TasksForm
from hashcrush.tasks.sorting import sort_tasks_naturally
from hashcrush.utils.formatting import parse_positive_int as _parse_positive_int
from hashcrush.utils.views import append_query_params, safe_relative_url

tasks = Blueprint('tasks', __name__)


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
    next_url = safe_relative_url(
        (request.form.get('next') or request.args.get('next'))
        if request.method == 'POST'
        else request.args.get('next')
    )
    selected_wordlist_id = _parse_positive_int(tasks_form.wl_id.data)
    selected_rule_id = _parse_positive_int(tasks_form.rule_id.data)
    return_target = (
        url_for('tasks.task_edit', task_id=task.id)
        if task is not None
        else url_for('tasks.tasks_add')
    )
    add_resource_return_url = append_query_params(
        return_target,
        next=next_url or url_for('tasks.tasks_list'),
        selected_wordlist_id=selected_wordlist_id,
        selected_rule_id=selected_rule_id,
    )
    return render_template(
        template_name,
        title=title,
        tasksForm=tasks_form,
        task=task,
        wordlists=wordlists,
        rules=rules,
        next_url=next_url or url_for('tasks.tasks_list'),
        add_wordlist_url=url_for('wordlists.wordlists_add', next=add_resource_return_url),
        add_rule_url=url_for('rules.rules_add', next=add_resource_return_url),
    )


def _task_save_conflict_response(template_name, title, tasks_form, task=None, wordlists=None, rules=None):
    db.session.rollback()
    flash(
        'Task could not be saved because its name already exists or the selected resources changed. Refresh and retry.',
        'danger',
    )
    return _render_task_form(template_name, title, tasks_form, task=task, wordlists=wordlists, rules=rules)


def _task_detail_context(task: Tasks) -> dict[str, object]:
    associated_jobs = db.session.execute(
        visible_jobs_query()
        .join(JobTasks, JobTasks.job_id == Jobs.id)
        .where(JobTasks.task_id == task.id)
        .order_by(Jobs.name.asc())
    ).scalars().all()
    associated_task_groups = [
        task_group
        for task_group in db.session.execute(
            select(TaskGroups).order_by(TaskGroups.name.asc())
        ).scalars().all()
        if task.id in _parse_task_group_task_ids(task_group.tasks)
    ]
    return {
        'associated_jobs': associated_jobs,
        'associated_task_groups': associated_task_groups,
        'associated_wordlist': task.wordlist,
        'associated_rule': task.rule,
        'delete_blockers': {
            'jobs': len(associated_jobs),
            'task_groups': len(associated_task_groups),
        },
    }

@tasks.route("/tasks", methods=['GET', 'POST'])
@login_required
def tasks_list():
    """Function to list tasks"""

    tasks = sort_tasks_naturally(
        db.session.execute(select(Tasks)).scalars().all()
    )
    return render_template(
        'tasks.html',
        title='tasks',
        tasks=tasks,
    )


@tasks.route("/tasks/<int:task_id>", methods=['GET'])
@login_required
def task_detail(task_id):
    """Show usage and configuration details for a shared task."""

    task = db.get_or_404(Tasks, task_id)
    return render_template(
        'tasks_detail.html',
        title=f'Task: {task.name}',
        task=task,
        **_task_detail_context(task),
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

    wordlists = db.session.execute(select(Wordlists)).scalars().all()
    rules = db.session.execute(select(Rules)).scalars().all()

    for wordlist in wordlists:
        tasksForm.wl_id.choices += [(wordlist.id, wordlist.name)]

    tasksForm.rule_id.choices = [('None', 'None')]
    for rule in rules:
        tasksForm.rule_id.choices += [(rule.id, rule.name)]

    next_url = safe_relative_url(
        (request.form.get('next') or request.args.get('next'))
        if request.method == 'POST'
        else request.args.get('next')
    )
    available_wordlist_ids = {wordlist.id for wordlist in wordlists}
    available_rule_ids = {rule.id for rule in rules}

    if request.method == 'GET':
        selected_wordlist_id = _parse_positive_int(request.args.get('selected_wordlist_id'))
        selected_rule_id = _parse_positive_int(request.args.get('selected_rule_id'))
        if selected_wordlist_id in available_wordlist_ids:
            tasksForm.wl_id.data = str(selected_wordlist_id)
            tasksForm.hc_attackmode.data = 'dictionary'
        if selected_rule_id in available_rule_ids:
            tasksForm.rule_id.data = str(selected_rule_id)
            tasksForm.hc_attackmode.data = 'dictionary'

    if tasksForm.validate_on_submit():
        if tasksForm.hc_attackmode.data == 'dictionary':
            selected_wl_id = _parse_positive_int(tasksForm.wl_id.data)
            selected_wordlist = (
                db.session.scalar(select(Wordlists).where(Wordlists.id == selected_wl_id))
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
                    db.session.scalar(select(Rules).where(Rules.id == selected_rule_id))
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
            record_audit_event(
                'task.create',
                'task',
                target_id=task.id,
                summary=f'Created shared task "{task.name}".',
                details={
                    'task_name': task.name,
                    'attack_mode': task.hc_attackmode,
                    'wordlist_id': task.wl_id,
                    'rule_id': task.rule_id,
                },
            )
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
            record_audit_event(
                'task.create',
                'task',
                target_id=task.id,
                summary=f'Created shared task "{task.name}".',
                details={
                    'task_name': task.name,
                    'attack_mode': task.hc_attackmode,
                    'mask': task.hc_mask,
                },
            )
            flash(f'Task {tasksForm.name.data} created!', 'success')
        else:
            flash('Invalid attack mode selection.', 'danger')
        return redirect(next_url or url_for('tasks.tasks_list'))
    return _render_task_form(
        'tasks_add.html',
        'Tasks Add',
        tasksForm,
        wordlists=wordlists,
        rules=rules,
    )

@tasks.route("/tasks/edit/<int:task_id>", methods=['GET', 'POST'])
@login_required
@admin_required_redirect('tasks.tasks_list')
def task_edit(task_id):
    """Function to edit task"""

    task = db.get_or_404(Tasks, task_id)

    # Shared tasks are immutable once any job references them.
    affected_jobs = db.session.execute(
        select(JobTasks).filter_by(task_id=task_id)
    ).scalars().all()
    if affected_jobs:
        flash('Cannot edit this task. It is already associated with one or more jobs.', 'danger')
        return redirect(url_for('tasks.tasks_list'))

    tasksForm = TasksForm(current_task_id=task.id)

    # clear select field for wordlists and rules
    tasksForm.rule_id.choices = []
    tasksForm.wl_id.choices = []

    wordlists = db.session.execute(select(Wordlists)).scalars().all()
    # Add the current value for wordlist.
    if task.hc_attackmode == 'dictionary':
        edit_task_wl = db.session.scalar(select(Wordlists).where(Wordlists.id == task.wl_id))
        if edit_task_wl:
            tasksForm.wl_id.choices.append((edit_task_wl.id, edit_task_wl.name))
    rules = db.session.execute(select(Rules)).scalars().all()
    # Check if the current value for rule is an integer.
    if isinstance(task.rule_id, int):
        edit_task_rl = db.session.scalar(select(Rules).where(Rules.id == task.rule_id))
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
    next_url = safe_relative_url(
        (request.form.get('next') or request.args.get('next'))
        if request.method == 'POST'
        else request.args.get('next')
    )
    available_wordlist_ids = {wordlist.id for wordlist in wordlists}
    available_rule_ids = {rule.id for rule in rules}

    if tasksForm.validate_on_submit():
        previous_name = task.name
        previous_attack_mode = task.hc_attackmode
        if tasksForm.hc_attackmode.data == 'dictionary':
            selected_wl_id = _parse_positive_int(tasksForm.wl_id.data)
            selected_wordlist = (
                db.session.scalar(select(Wordlists).where(Wordlists.id == selected_wl_id))
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
                    db.session.scalar(select(Rules).where(Rules.id == selected_rule_id))
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
            record_audit_event(
                'task.update',
                'task',
                target_id=task.id,
                summary=f'Updated shared task "{task.name}".',
                details={
                    'task_name': task.name,
                    'previous_name': previous_name,
                    'previous_attack_mode': previous_attack_mode,
                    'attack_mode': task.hc_attackmode,
                    'wordlist_id': task.wl_id,
                    'rule_id': task.rule_id,
                },
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
            record_audit_event(
                'task.update',
                'task',
                target_id=task.id,
                summary=f'Updated shared task "{task.name}".',
                details={
                    'task_name': task.name,
                    'previous_name': previous_name,
                    'previous_attack_mode': previous_attack_mode,
                    'attack_mode': task.hc_attackmode,
                    'mask': task.hc_mask,
                },
            )
            flash(f'Task {tasksForm.name.data} updated!', 'success')
        else:
            flash('Invalid attack mode selection.', 'danger')
        return redirect(next_url or url_for('tasks.tasks_list'))

    if request.method == 'GET':
        tasksForm.name.data = task.name
        tasksForm.hc_attackmode.data = task.hc_attackmode
        tasksForm.wl_id.data = str(task.wl_id) if task.wl_id is not None else ''
        tasksForm.rule_id.data = str(task.rule_id) if isinstance(task.rule_id, int) else 'None'
        tasksForm.mask.data = task.hc_mask

        selected_wordlist_id = _parse_positive_int(request.args.get('selected_wordlist_id'))
        selected_rule_id = _parse_positive_int(request.args.get('selected_rule_id'))
        if selected_wordlist_id in available_wordlist_ids:
            tasksForm.wl_id.data = str(selected_wordlist_id)
            tasksForm.hc_attackmode.data = 'dictionary'
        if selected_rule_id in available_rule_ids:
            tasksForm.rule_id.data = str(selected_rule_id)
            tasksForm.hc_attackmode.data = 'dictionary'

    return _render_task_form(
        'tasks_edit.html',
        'Tasks Edit',
        tasksForm,
        task=task,
        wordlists=wordlists,
        rules=rules,
    )

@tasks.route("/tasks/delete/<int:task_id>", methods=['POST'])
@login_required
@admin_required_redirect('tasks.tasks_list')
def tasks_delete(task_id):
    """Function to delete task"""

    task = db.get_or_404(Tasks, task_id)
    next_url = safe_relative_url(request.form.get('next'))
    task_groups = db.session.execute(select(TaskGroups)).scalars().all()

    # Check if associated with JobTask (which implies its associated with a job)
    jobtask = db.session.scalar(select(JobTasks).filter_by(task_id=task_id))
    if jobtask:
        flash('Cannot delete. Task is associated with one or more jobs.', 'danger')
        return redirect(next_url or url_for('tasks.tasks_list'))

    for task_group in task_groups:
        if task_id in _parse_task_group_task_ids(task_group.tasks):
            flash('Cannot delete. Task is associated with one or more task groups.', 'danger')
            return redirect(next_url or url_for('tasks.tasks_list'))

    deleted_task_name = task.name
    deleted_attack_mode = task.hc_attackmode
    db.session.delete(task)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash('Cannot delete. Task is associated with one or more jobs or task groups.', 'danger')
        return redirect(next_url or url_for('tasks.tasks_list'))
    record_audit_event(
        'task.delete',
        'task',
        target_id=task_id,
        summary=f'Deleted shared task "{deleted_task_name}".',
        details={
            'task_name': deleted_task_name,
            'attack_mode': deleted_attack_mode,
        },
    )
    flash('Task has been deleted!', 'success')
    return redirect(next_url or url_for('tasks.tasks_list'))
