"""Flask routes to handle Rules."""
import os

from flask import Blueprint, flash, redirect, render_template, url_for
from flask_login import login_required
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from hashcrush.audit import record_audit_event
from hashcrush.authz import admin_required_redirect
from hashcrush.models import Rules, Tasks, db
from hashcrush.rules.forms import RulesForm
from hashcrush.utils.utils import (
    get_filehash,
    get_linecount,
    get_storage_subdir,
    save_file,
)

rules = Blueprint('rules', __name__)


def _render_rules_add_form(form):
    return render_template(
        'rules_add.html',
        title='Rules Add',
        form=form,
    )


def _managed_rules_dir() -> str:
    path = get_storage_subdir('rules')
    os.makedirs(path, exist_ok=True)
    return path


def _remove_managed_rule_file(stored_path: str) -> None:
    resolved_path = os.path.abspath(stored_path)
    managed_root = os.path.abspath(_managed_rules_dir())
    try:
        if os.path.commonpath([resolved_path, managed_root]) != managed_root:
            return
    except ValueError:
        return
    if os.path.isfile(resolved_path):
        try:
            os.remove(resolved_path)
        except OSError:
            pass


def _derive_rule_name(form_name: str | None, uploaded_filename: str | None) -> str:
    preferred = (form_name or '').strip()
    if preferred:
        return preferred
    filename = os.path.basename(uploaded_filename or '').strip()
    if not filename:
        return ''
    return os.path.splitext(filename)[0]


#############################################
# Rules
#############################################


@rules.route("/rules", methods=['GET'])
@login_required
def rules_list():
    """Function to return list of rules"""
    rules = db.session.execute(select(Rules)).scalars().all()
    tasks = db.session.execute(select(Tasks)).scalars().all()
    return render_template(
        'rules.html',
        title='Rules',
        rules=rules,
        tasks=tasks,
    )


@rules.route("/rules/add", methods=['GET', 'POST'])
@login_required
@admin_required_redirect('rules.rules_list')
def rules_add():
    """Upload a shared rule file."""
    form = RulesForm()

    if form.validate_on_submit():
        uploaded_file = form.upload.data
        if not uploaded_file or not getattr(uploaded_file, 'filename', ''):
            flash('Select a rule file to upload.', 'danger')
            return _render_rules_add_form(form)
        if not uploaded_file.filename.lower().endswith('.rule'):
            flash('Rule uploads must use the .rule extension.', 'danger')
            return _render_rules_add_form(form)

        rule_name = _derive_rule_name(form.name.data, uploaded_file.filename)
        if not rule_name:
            flash('Rule name is required.', 'danger')
            return _render_rules_add_form(form)
        if db.session.scalar(select(Rules).filter_by(name=rule_name)):
            flash('Rules name is already registered.', 'warning')
            return redirect(url_for('rules.rules_list'))

        rules_path = save_file(_managed_rules_dir(), uploaded_file)
        rules_path = os.path.abspath(rules_path)
        if db.session.scalar(select(Rules).filter_by(path=rules_path)):
            _remove_managed_rule_file(rules_path)
            flash('Rules file is already registered.', 'warning')
            return redirect(url_for('rules.rules_list'))

        rule = Rules(
            name=rule_name,
            path=rules_path,
            size=get_linecount(rules_path),
            checksum=get_filehash(rules_path),
        )
        db.session.add(rule)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            _remove_managed_rule_file(rules_path)
            flash('Rule file could not be uploaded because that name or file already exists. Refresh and retry.', 'danger')
            return _render_rules_add_form(form)
        record_audit_event(
            'rule.create',
            'rule',
            target_id=rule.id,
            summary=f'Uploaded shared rule "{rule.name}".',
            details={
                'rule_name': rule.name,
                'path': rule.path,
                'size': rule.size,
            },
        )
        flash('Rule file uploaded!', 'success')
        return redirect(url_for('rules.rules_list'))

    return _render_rules_add_form(form)


@rules.route("/rules/delete/<int:rule_id>", methods=['POST'])
@login_required
@admin_required_redirect('rules.rules_list')
def rules_delete(rule_id):
    """Function to delete rule file record"""
    rule = db.get_or_404(Rules, rule_id)
    # Check if part of a task.
    task = db.session.scalar(select(Tasks).filter_by(rule_id=rule.id))
    if task:
        flash('Rule file is currently used in a task and cannot be deleted.', 'danger')
    else:
        deleted_rule_name = rule.name
        deleted_rule_path = rule.path
        db.session.delete(rule)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Rule file is currently used in a task or changed concurrently and cannot be deleted.', 'danger')
            return redirect(url_for('rules.rules_list'))
        _remove_managed_rule_file(deleted_rule_path)
        record_audit_event(
            'rule.delete',
            'rule',
            target_id=rule_id,
            summary=f'Deleted shared rule "{deleted_rule_name}".',
            details={
                'rule_name': deleted_rule_name,
                'path': deleted_rule_path,
            },
        )
        flash('Rule file has been deleted!', 'success')
    return redirect(url_for('rules.rules_list'))
