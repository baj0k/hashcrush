"""Flask routes to handle Wordlists."""
import os

from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from hashcrush.audit import capture_audit_actor, record_audit_event
from hashcrush.authz import admin_required_redirect
from hashcrush.models import Tasks, Wordlists, db
from hashcrush.utils.file_ops import (
    get_filehash,
    get_linecount,
    save_file,
)
from hashcrush.utils.storage_paths import get_storage_subdir
from hashcrush.view_utils import append_query_params, safe_relative_url
from hashcrush.wordlists.forms import WordlistsForm

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
    return render_template(
        'wordlists_add.html',
        title='Wordlist Add',
        form=form,
        next_url=next_url or url_for('wordlists.wordlists_list'),
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


def _managed_wordlists_dir() -> str:
    path = get_storage_subdir('wordlists')
    os.makedirs(path, exist_ok=True)
    return path


def _remove_managed_wordlist_file(stored_path: str) -> None:
    resolved_path = os.path.abspath(stored_path)
    managed_root = os.path.abspath(_managed_wordlists_dir())
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


def _derive_wordlist_name(form_name: str | None, uploaded_filename: str | None) -> str:
    preferred = (form_name or '').strip()
    if preferred:
        return preferred
    filename = os.path.basename(uploaded_filename or '').strip()
    if not filename:
        return ''
    return os.path.splitext(filename)[0]


def _wordlist_detail_context(wordlist: Wordlists) -> dict[str, object]:
    associated_tasks = db.session.execute(
        select(Tasks)
        .where(Tasks.wl_id == wordlist.id)
        .order_by(Tasks.name.asc())
    ).scalars().all()
    return {
        'associated_tasks': associated_tasks,
        'delete_blockers': {
            'tasks': len(associated_tasks),
            'is_dynamic': wordlist.type == 'dynamic',
        },
    }


@wordlists.route("/wordlists", methods=['GET'])
@login_required
def wordlists_list():
    """Function to present list of wordlists"""

    wordlists = db.session.execute(
        select(Wordlists).order_by(Wordlists.type.asc(), Wordlists.name.asc())
    ).scalars().all()
    return render_template(
        'wordlists.html',
        title='Wordlists',
        wordlists=wordlists,
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
    """Upload a new shared static wordlist."""

    form = WordlistsForm()
    fallback_url = url_for('wordlists.wordlists_list')
    next_url = safe_relative_url(
        (request.form.get('next') or request.args.get('next'))
        if request.method == 'POST'
        else request.args.get('next')
    )

    if form.validate_on_submit():
        uploaded_file = form.upload.data
        if not uploaded_file or not getattr(uploaded_file, 'filename', ''):
            flash('Select a wordlist file to upload.', 'danger')
            return _render_wordlists_add_form(form, next_url)
        if not uploaded_file.filename.lower().endswith('.txt'):
            flash('Wordlist uploads must use the .txt extension.', 'danger')
            return _render_wordlists_add_form(form, next_url)

        wordlist_name = _derive_wordlist_name(form.name.data, uploaded_file.filename)
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

        wordlist_path = save_file(_managed_wordlists_dir(), uploaded_file)
        wordlist_path = os.path.abspath(wordlist_path)
        existing_wordlist = db.session.scalar(select(Wordlists).filter_by(path=wordlist_path))
        if existing_wordlist:
            _remove_managed_wordlist_file(wordlist_path)
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
                operation_type='wordlist_upload',
                redirect_url=_wordlist_redirect_target(
                    next_url,
                    fallback_url=fallback_url,
                ),
                payload={
                    'wordlist_name': wordlist_name,
                    'wordlist_path': wordlist_path,
                    'audit_actor': capture_audit_actor(),
                    'redirect_url': next_url,
                    'fallback_url': fallback_url,
                },
            )
            return _async_operation_response(operation)

        wordlist = Wordlists(
            name=wordlist_name,
            type='static',
            path=wordlist_path,
            checksum=get_filehash(wordlist_path),
            size=get_linecount(wordlist_path),
        )
        db.session.add(wordlist)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            _remove_managed_wordlist_file(wordlist_path)
            flash('Wordlist could not be uploaded because that name or file already exists. Refresh and retry.', 'danger')
            return _render_wordlists_add_form(form, next_url)
        record_audit_event(
            'wordlist.create',
            'wordlist',
            target_id=wordlist.id,
            summary=f'Uploaded shared wordlist "{wordlist.name}".',
            details={
                'wordlist_name': wordlist.name,
                'path': wordlist.path,
                'type': wordlist.type,
                'size': wordlist.size,
            },
        )
        flash('Wordlist uploaded!', 'success')
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
    db.session.delete(wordlist)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash('Failed. Wordlist is associated to one or more tasks or changed concurrently.', 'danger')
        return redirect(next_url or url_for('wordlists.wordlists_list'))
    _remove_managed_wordlist_file(deleted_wordlist_path)
    record_audit_event(
        'wordlist.delete',
        'wordlist',
        target_id=wordlist_id,
        summary=f'Deleted shared wordlist "{deleted_wordlist_name}".',
        details={
            'wordlist_name': deleted_wordlist_name,
            'path': deleted_wordlist_path,
        },
    )
    flash('Wordlist has been deleted!', 'success')
    return redirect(next_url or url_for('wordlists.wordlists_list'))
