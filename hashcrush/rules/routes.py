"""Flask routes to handle Rules."""
import os

from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from hashcrush.audit import capture_audit_actor, record_audit_event
from hashcrush.authz import admin_required_redirect
from hashcrush.models import Rules, Tasks, db
from hashcrush.rules.forms import RulesForm
from hashcrush.utils.file_ops import (
    analyze_text_file,
    save_file,
)
from hashcrush.utils.storage_paths import get_storage_subdir
from hashcrush.view_utils import append_query_params, safe_relative_url

rules = Blueprint('rules', __name__)


def _is_async_upload_request() -> bool:
    return request.headers.get('X-Requested-With') == 'XMLHttpRequest'


def _async_operation_response(operation):
    payload = operation.to_response_dict()
    payload['status_url'] = url_for(
        'uploads.upload_operation_status',
        operation_id=operation.id,
    )
    return jsonify(payload), 202


def _render_rules_add_form(form, next_url: str | None = None):
    return render_template(
        'rules_add.html',
        title='Rules Add',
        form=form,
        next_url=next_url or url_for('rules.rules_list'),
    )


def _rule_redirect_target(
    next_url: str | None,
    *,
    fallback_url: str,
    rule_id: int | None = None,
) -> str:
    if not next_url:
        return fallback_url
    return append_query_params(next_url, selected_rule_id=rule_id)


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


def _rule_detail_context(rule: Rules) -> dict[str, object]:
    associated_tasks = db.session.execute(
        select(Tasks)
        .where(Tasks.rule_id == rule.id)
        .order_by(Tasks.name.asc())
    ).scalars().all()
    return {
        'associated_tasks': associated_tasks,
        'delete_blockers': {
            'tasks': len(associated_tasks),
        },
    }


#############################################
# Rules
#############################################


@rules.route("/rules", methods=['GET'])
@login_required
def rules_list():
    """Function to return list of rules"""
    rules = db.session.execute(select(Rules).order_by(Rules.name.asc())).scalars().all()
    return render_template(
        'rules.html',
        title='Rules',
        rules=rules,
    )


@rules.route("/rules/<int:rule_id>", methods=['GET'])
@login_required
def rules_detail(rule_id):
    """Show usage and management details for a shared rule file."""

    rule = db.get_or_404(Rules, rule_id)
    return render_template(
        'rules_detail.html',
        title=f'Rule: {rule.name}',
        rule=rule,
        **_rule_detail_context(rule),
    )


@rules.route("/rules/add", methods=['GET', 'POST'])
@login_required
@admin_required_redirect('rules.rules_list')
def rules_add():
    """Upload a shared rule file."""
    form = RulesForm()
    fallback_url = url_for('rules.rules_list')
    next_url = safe_relative_url(
        (request.form.get('next') or request.args.get('next'))
        if request.method == 'POST'
        else request.args.get('next')
    )

    if form.validate_on_submit():
        uploaded_file = form.upload.data
        if not uploaded_file or not getattr(uploaded_file, 'filename', ''):
            flash('Select a rule file to upload.', 'danger')
            return _render_rules_add_form(form, next_url)
        if not uploaded_file.filename.lower().endswith('.rule'):
            flash('Rule uploads must use the .rule extension.', 'danger')
            return _render_rules_add_form(form, next_url)

        rule_name = _derive_rule_name(form.name.data, uploaded_file.filename)
        if not rule_name:
            flash('Rule name is required.', 'danger')
            return _render_rules_add_form(form, next_url)
        existing_rule = db.session.scalar(select(Rules).filter_by(name=rule_name))
        if existing_rule:
            flash('Rules name is already registered.', 'warning')
            return redirect(
                _rule_redirect_target(
                    next_url,
                    fallback_url=fallback_url,
                    rule_id=existing_rule.id,
                )
            )

        rules_path = save_file(_managed_rules_dir(), uploaded_file)
        rules_path = os.path.abspath(rules_path)
        existing_rule = db.session.scalar(select(Rules).filter_by(path=rules_path))
        if existing_rule:
            _remove_managed_rule_file(rules_path)
            flash('Rules file is already registered.', 'warning')
            return redirect(
                _rule_redirect_target(
                    next_url,
                    fallback_url=fallback_url,
                    rule_id=existing_rule.id,
                )
            )

        if _is_async_upload_request():
            operation = current_app.extensions['upload_operations'].start_operation(
                owner_user_id=getattr(current_user, 'id', None),
                operation_type='rule_upload',
                redirect_url=_rule_redirect_target(
                    next_url,
                    fallback_url=fallback_url,
                ),
                payload={
                    'rule_name': rule_name,
                    'rules_path': rules_path,
                    'audit_actor': capture_audit_actor(),
                    'redirect_url': next_url,
                    'fallback_url': fallback_url,
                },
            )
            return _async_operation_response(operation)

        file_analysis = analyze_text_file(rules_path)
        rule = Rules(
            name=rule_name,
            path=rules_path,
            size=file_analysis.line_count,
            checksum=file_analysis.checksum,
        )
        db.session.add(rule)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            _remove_managed_rule_file(rules_path)
            flash('Rule file could not be uploaded because that name or file already exists. Refresh and retry.', 'danger')
            return _render_rules_add_form(form, next_url)
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
        return redirect(
            _rule_redirect_target(
                next_url,
                fallback_url=fallback_url,
                rule_id=rule.id,
            )
        )

    return _render_rules_add_form(form, next_url)


@rules.route("/rules/delete/<int:rule_id>", methods=['POST'])
@login_required
@admin_required_redirect('rules.rules_list')
def rules_delete(rule_id):
    """Function to delete rule file record"""
    rule = db.get_or_404(Rules, rule_id)
    next_url = safe_relative_url(request.form.get('next'))
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
            return redirect(next_url or url_for('rules.rules_list'))
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
    return redirect(next_url or url_for('rules.rules_list'))
