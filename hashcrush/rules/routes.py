"""Flask routes to handle Rules."""

from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from hashcrush.audit import capture_audit_actor, record_audit_event
from hashcrush.authz import admin_required_redirect
from hashcrush.models import Rules, Tasks, db
from hashcrush.rules.forms import RulesForm
from hashcrush.rules.service import (
    create_rule_from_path,
    derive_rule_name,
    get_external_rule_root,
    list_external_rule_files,
    validate_external_rule_path,
)
from hashcrush.tasks.sorting import sort_tasks_naturally
from hashcrush.utils.views import append_query_params, safe_relative_url

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
    external_rule_files = list_external_rule_files()
    selected_external_path = (form.external_path.data or "").strip()
    if not selected_external_path and len(external_rule_files) == 1:
        selected_external_path = external_rule_files[0]
        form.external_path.data = selected_external_path
    return render_template(
        'rules_add.html',
        title='Add Rule',
        form=form,
        next_url=next_url or url_for('rules.rules_list'),
        external_root=get_external_rule_root(),
        external_rule_files=external_rule_files,
        selected_external_path=selected_external_path,
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


def _rule_detail_context(rule: Rules) -> dict[str, object]:
    associated_tasks = sort_tasks_naturally(
        db.session.execute(
            select(Tasks)
            .where(Tasks.rule_id == rule.id)
        ).scalars().all()
    )
    return {
        'associated_tasks': associated_tasks,
        'delete_blockers': {
            'tasks': len(associated_tasks),
        },
    }


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
    """Register a mounted rule file."""
    form = RulesForm()
    fallback_url = url_for('rules.rules_list')
    next_url = safe_relative_url(
        (request.form.get('next') or request.args.get('next'))
        if request.method == 'POST'
        else request.args.get('next')
    )

    if form.validate_on_submit():
        rule_path, error_message = validate_external_rule_path(form.external_path.data)
        if error_message:
            flash(error_message, 'danger')
            return _render_rules_add_form(form, next_url)
        rule_name = derive_rule_name(form.name.data, rule_path)

        if not rule_name:
            flash('Rule name is required.', 'danger')
            return _render_rules_add_form(form, next_url)
        existing_rule = db.session.scalar(select(Rules).filter_by(name=rule_name))
        if existing_rule:
            flash('Rule name is already registered.', 'warning')
            return redirect(
                _rule_redirect_target(
                    next_url,
                    fallback_url=fallback_url,
                    rule_id=existing_rule.id,
                )
            )

        existing_rule = db.session.scalar(select(Rules).filter_by(path=rule_path))
        if existing_rule:
            flash('Rule file is already registered.', 'warning')
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
                operation_type='rule_external_register',
                redirect_url=_rule_redirect_target(
                    next_url,
                    fallback_url=fallback_url,
                ),
                payload={
                    'rule_name': rule_name,
                    'rule_path': rule_path,
                    'audit_actor': capture_audit_actor(),
                    'redirect_url': next_url,
                    'fallback_url': fallback_url,
                },
            )
            return _async_operation_response(operation)

        try:
            rule = create_rule_from_path(rule_name, rule_path)
        except IntegrityError:
            db.session.rollback()
            flash('Rule could not be saved because that name or file already exists. Refresh and retry.', 'danger')
            return _render_rules_add_form(form, next_url)
        except Exception:
            db.session.rollback()
            current_app.logger.exception(
                'Failed creating shared rule %s from %s',
                rule_name,
                rule_path,
            )
            flash('The server hit an unexpected error while processing the rule.', 'danger')
            return _render_rules_add_form(form, next_url)
        record_audit_event(
            'rule.create',
            'rule',
            target_id=rule.id,
            summary=f'Registered external shared rule "{rule.name}".',
            details={
                'rule_name': rule.name,
                'path': rule.path,
                'source': 'external',
                'size': rule.size,
            },
        )
        flash('Rule registered!', 'success')
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
