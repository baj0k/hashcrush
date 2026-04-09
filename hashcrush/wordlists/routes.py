"""Flask routes to handle Wordlists."""
import os

from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from hashcrush.audit import capture_audit_actor, record_audit_event
from hashcrush.authz import admin_required_redirect
from hashcrush.models import Tasks, Wordlists, db
from hashcrush.tasks.sorting import sort_tasks_naturally
from hashcrush.utils.file_ops import save_file
from hashcrush.view_utils import append_query_params, safe_relative_url
from hashcrush.wordlists.forms import WordlistsForm
from hashcrush.wordlists.service import (
    create_static_wordlist_from_path,
    derive_wordlist_name,
    get_external_wordlist_root,
    get_wordlist_source,
    list_external_wordlist_files,
    managed_wordlists_dir,
    remove_managed_wordlist_file,
    validate_external_wordlist_path,
)

wordlists = Blueprint('wordlists', __name__)


def _is_async_upload_request() -> bool:
    return request.headers.get('X-Requested-With') == 'XMLHttpRequest'


def _async_operation_response(operation):
    payload = operation.to_response_dict()
    payload['status_url'] = url_for(
        'uploads.upload_operation_status',
        operation_id=operation.id,
    )
    return jsonify(payload), 202


def _render_wordlists_add_form(form, next_url: str | None = None):
    external_wordlist_files = list_external_wordlist_files()
    selected_external_path = (form.external_path.data or "").strip()
    if (
        (form.source_mode.data or "").strip().lower() == "external"
        and not selected_external_path
        and len(external_wordlist_files) == 1
    ):
        selected_external_path = external_wordlist_files[0]
        form.external_path.data = selected_external_path
    return render_template(
        'wordlists_add.html',
        title='Add Wordlist',
        form=form,
        next_url=next_url or url_for('wordlists.wordlists_list'),
        external_root=get_external_wordlist_root(),
        external_wordlist_files=external_wordlist_files,
        selected_external_path=selected_external_path,
    )


def _wordlist_redirect_target(
    next_url: str | None,
    *,
    fallback_url: str,
    wordlist_id: int | None = None,
) -> str:
    if not next_url:
        return fallback_url
    return append_query_params(next_url, selected_wordlist_id=wordlist_id)


def _wordlist_detail_context(wordlist: Wordlists) -> dict[str, object]:
    associated_tasks = sort_tasks_naturally(
        db.session.execute(
            select(Tasks)
            .where(Tasks.wl_id == wordlist.id)
        ).scalars().all()
    )
    return {
        'associated_tasks': associated_tasks,
        'delete_blockers': {
            'tasks': len(associated_tasks),
            'is_dynamic': wordlist.type == 'dynamic',
        },
        'wordlist_source': get_wordlist_source(wordlist),
        'external_root': get_external_wordlist_root(),
    }


@wordlists.route("/wordlists", methods=['GET'])
@login_required
def wordlists_list():
    """Function to present list of wordlists"""

    wordlists = db.session.execute(
        select(Wordlists).order_by(Wordlists.type.asc(), Wordlists.name.asc())
    ).scalars().all()
    wordlist_sources = {
        wordlist.id: get_wordlist_source(wordlist) for wordlist in wordlists
    }
    return render_template(
        'wordlists.html',
        title='Wordlists',
        wordlists=wordlists,
        wordlist_sources=wordlist_sources,
    )


@wordlists.route("/wordlists/<int:wordlist_id>", methods=['GET'])
@login_required
def wordlists_detail(wordlist_id):
    """Show usage and management details for a shared wordlist."""

    wordlist = db.get_or_404(Wordlists, wordlist_id)
    return render_template(
        'wordlists_detail.html',
        title=f'Wordlist: {wordlist.name}',
        wordlist=wordlist,
        **_wordlist_detail_context(wordlist),
    )


@wordlists.route("/wordlists/add", methods=['GET', 'POST'])
@login_required
@admin_required_redirect('wordlists.wordlists_list')
def wordlists_add():
    """Upload or register a shared static wordlist."""

    form = WordlistsForm()
    fallback_url = url_for('wordlists.wordlists_list')
    next_url = safe_relative_url(
        (request.form.get('next') or request.args.get('next'))
        if request.method == 'POST'
        else request.args.get('next')
    )
    source_mode = (form.source_mode.data or request.values.get('source_mode') or 'upload').strip().lower()
    if source_mode not in {'upload', 'external'}:
        source_mode = 'upload'
    form.source_mode.data = source_mode

    if form.validate_on_submit():
        wordlist_name = ''
        wordlist_path = ''
        operation_type = 'wordlist_upload'
        success_flash = 'Wordlist uploaded!'
        audit_summary = 'Uploaded shared wordlist "{name}".'
        source_label = 'managed'

        if source_mode == 'external':
            wordlist_path, error_message = validate_external_wordlist_path(form.external_path.data)
            if error_message:
                flash(error_message, 'danger')
                return _render_wordlists_add_form(form, next_url)
            wordlist_name = derive_wordlist_name(form.name.data, wordlist_path)
            operation_type = 'wordlist_external_register'
            success_flash = 'External wordlist registered!'
            audit_summary = 'Registered external shared wordlist "{name}".'
            source_label = 'external'
        else:
            uploaded_file = form.upload.data
            if not uploaded_file or not getattr(uploaded_file, 'filename', ''):
                flash('Select a wordlist file to upload.', 'danger')
                return _render_wordlists_add_form(form, next_url)
            if not uploaded_file.filename.lower().endswith('.txt'):
                flash('Wordlist uploads must use the .txt extension.', 'danger')
                return _render_wordlists_add_form(form, next_url)
            wordlist_name = derive_wordlist_name(form.name.data, uploaded_file.filename)

        if not wordlist_name:
            flash('Wordlist name is required.', 'danger')
            return _render_wordlists_add_form(form, next_url)
        existing_wordlist = db.session.scalar(select(Wordlists).filter_by(name=wordlist_name))
        if existing_wordlist:
            flash('Wordlist name is already registered.', 'warning')
            return redirect(
                _wordlist_redirect_target(
                    next_url,
                    fallback_url=fallback_url,
                    wordlist_id=existing_wordlist.id,
                )
            )

        if source_mode != 'external':
            wordlist_path = save_file(managed_wordlists_dir(), form.upload.data)
            wordlist_path = os.path.abspath(wordlist_path)
        existing_wordlist = db.session.scalar(select(Wordlists).filter_by(path=wordlist_path))
        if existing_wordlist:
            remove_managed_wordlist_file(wordlist_path)
            flash('Wordlist is already registered.', 'warning')
            return redirect(
                _wordlist_redirect_target(
                    next_url,
                    fallback_url=fallback_url,
                    wordlist_id=existing_wordlist.id,
                )
            )

        if _is_async_upload_request():
            operation = current_app.extensions['upload_operations'].start_operation(
                owner_user_id=getattr(current_user, 'id', None),
                operation_type=operation_type,
                redirect_url=_wordlist_redirect_target(
                    next_url,
                    fallback_url=fallback_url,
                ),
                payload={
                    'wordlist_name': wordlist_name,
                    'wordlist_path': wordlist_path,
                    'wordlist_source': source_label,
                    'audit_actor': capture_audit_actor(),
                    'redirect_url': next_url,
                    'fallback_url': fallback_url,
                },
            )
            return _async_operation_response(operation)

        try:
            wordlist = create_static_wordlist_from_path(wordlist_name, wordlist_path)
        except IntegrityError:
            db.session.rollback()
            remove_managed_wordlist_file(wordlist_path)
            flash('Wordlist could not be saved because that name or file already exists. Refresh and retry.', 'danger')
            return _render_wordlists_add_form(form, next_url)
        except Exception:
            db.session.rollback()
            remove_managed_wordlist_file(wordlist_path)
            current_app.logger.exception(
                'Failed creating shared wordlist %s from %s',
                wordlist_name,
                wordlist_path,
            )
            flash('The server hit an unexpected error while processing the wordlist.', 'danger')
            return _render_wordlists_add_form(form, next_url)
        record_audit_event(
            'wordlist.create',
            'wordlist',
            target_id=wordlist.id,
            summary=audit_summary.format(name=wordlist.name),
            details={
                'wordlist_name': wordlist.name,
                'path': wordlist.path,
                'type': wordlist.type,
                'source': source_label,
                'size': wordlist.size,
            },
        )
        flash(success_flash, 'success')
        return redirect(
            _wordlist_redirect_target(
                next_url,
                fallback_url=fallback_url,
                wordlist_id=wordlist.id,
            )
        )

    return _render_wordlists_add_form(form, next_url)


@wordlists.route("/wordlists/delete/<int:wordlist_id>", methods=['POST'])
@login_required
@admin_required_redirect('wordlists.wordlists_list')
def wordlists_delete(wordlist_id):
    """Function to delete wordlist record"""

    wordlist = db.get_or_404(Wordlists, wordlist_id)
    next_url = safe_relative_url(request.form.get('next'))
    # prevent deletion of dynamic list
    if wordlist.type == 'dynamic':
        flash('Dynamic Wordlists can not be deleted.', 'danger')
        return redirect(next_url or url_for('wordlists.wordlists_list'))

    # Check if associated with a Task
    task = db.session.scalar(select(Tasks).filter_by(wl_id=wordlist_id))
    if task:
        flash('Failed. Wordlist is associated to one or more tasks', 'danger')
        return redirect(next_url or url_for('wordlists.wordlists_list'))

    deleted_wordlist_name = wordlist.name
    deleted_wordlist_path = wordlist.path
    deleted_wordlist_source = get_wordlist_source(wordlist)
    db.session.delete(wordlist)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash('Failed. Wordlist is associated to one or more tasks or changed concurrently.', 'danger')
        return redirect(next_url or url_for('wordlists.wordlists_list'))
    remove_managed_wordlist_file(deleted_wordlist_path)
    record_audit_event(
        'wordlist.delete',
        'wordlist',
        target_id=wordlist_id,
        summary=f'Deleted shared wordlist "{deleted_wordlist_name}".',
        details={
            'wordlist_name': deleted_wordlist_name,
            'path': deleted_wordlist_path,
            'source': deleted_wordlist_source,
        },
    )
    flash('Wordlist has been deleted!', 'success')
    return redirect(next_url or url_for('wordlists.wordlists_list'))
