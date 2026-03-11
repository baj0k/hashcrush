"""Flask routes to handle Wordlists."""
import os

from flask import Blueprint, flash, redirect, render_template, url_for
from flask_login import login_required
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from hashcrush.audit import record_audit_event
from hashcrush.authz import admin_required_redirect
from hashcrush.models import Tasks, Wordlists, db
from hashcrush.utils.utils import (
    get_filehash,
    get_linecount,
    get_storage_subdir,
    save_file,
    update_dynamic_wordlist,
)
from hashcrush.wordlists.forms import WordlistsForm

wordlists = Blueprint('wordlists', __name__)


def _render_wordlists_add_form(form):
    return render_template(
        'wordlists_add.html',
        title='Wordlist Add',
        form=form,
    )


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


@wordlists.route("/wordlists", methods=['GET'])
@login_required
def wordlists_list():
    """Function to present list of wordlists"""

    wordlists = db.session.execute(select(Wordlists)).scalars().all()
    static_wordlists = [wordlist for wordlist in wordlists if wordlist.type == 'static']
    dynamic_wordlists = [wordlist for wordlist in wordlists if wordlist.type == 'dynamic']
    tasks = db.session.execute(select(Tasks)).scalars().all()
    return render_template(
        'wordlists.html',
        title='Wordlists',
        static_wordlists=static_wordlists,
        dynamic_wordlists=dynamic_wordlists,
        wordlists=wordlists,
        tasks=tasks,
    )


@wordlists.route("/wordlists/add", methods=['GET', 'POST'])
@login_required
@admin_required_redirect('wordlists.wordlists_list')
def wordlists_add():
    """Upload a new shared static wordlist."""

    form = WordlistsForm()

    if form.validate_on_submit():
        uploaded_file = form.upload.data
        if not uploaded_file or not getattr(uploaded_file, 'filename', ''):
            flash('Select a wordlist file to upload.', 'danger')
            return _render_wordlists_add_form(form)
        if not uploaded_file.filename.lower().endswith('.txt'):
            flash('Wordlist uploads must use the .txt extension.', 'danger')
            return _render_wordlists_add_form(form)

        wordlist_name = _derive_wordlist_name(form.name.data, uploaded_file.filename)
        if not wordlist_name:
            flash('Wordlist name is required.', 'danger')
            return _render_wordlists_add_form(form)
        if db.session.scalar(select(Wordlists).filter_by(name=wordlist_name)):
            flash('Wordlist name is already registered.', 'warning')
            return redirect(url_for('wordlists.wordlists_list'))

        wordlist_path = save_file(_managed_wordlists_dir(), uploaded_file)
        wordlist_path = os.path.abspath(wordlist_path)
        if db.session.scalar(select(Wordlists).filter_by(path=wordlist_path)):
            _remove_managed_wordlist_file(wordlist_path)
            flash('Wordlist is already registered.', 'warning')
            return redirect(url_for('wordlists.wordlists_list'))

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
            return _render_wordlists_add_form(form)
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
        return redirect(url_for('wordlists.wordlists_list'))

    return _render_wordlists_add_form(form)


@wordlists.route("/wordlists/delete/<int:wordlist_id>", methods=['POST'])
@login_required
@admin_required_redirect('wordlists.wordlists_list')
def wordlists_delete(wordlist_id):
    """Function to delete wordlist record"""

    wordlist = db.get_or_404(Wordlists, wordlist_id)
    # prevent deletion of dynamic list
    if wordlist.type == 'dynamic':
        flash('Dynamic Wordlists can not be deleted.', 'danger')
        return redirect(url_for('wordlists.wordlists_list'))

    # Check if associated with a Task
    task = db.session.scalar(select(Tasks).filter_by(wl_id=wordlist_id))
    if task:
        flash('Failed. Wordlist is associated to one or more tasks', 'danger')
        return redirect(url_for('wordlists.wordlists_list'))

    deleted_wordlist_name = wordlist.name
    deleted_wordlist_path = wordlist.path
    db.session.delete(wordlist)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash('Failed. Wordlist is associated to one or more tasks or changed concurrently.', 'danger')
        return redirect(url_for('wordlists.wordlists_list'))
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
    return redirect(url_for('wordlists.wordlists_list'))


@wordlists.route("/wordlists/update/<int:wordlist_id>", methods=['POST'])
@login_required
@admin_required_redirect('wordlists.wordlists_list')
def dynamicwordlist_update(wordlist_id):
    """Function to update dynamic wordlist"""

    wordlist = db.get_or_404(Wordlists, wordlist_id)
    if wordlist.type != 'dynamic':
        flash('Invalid wordlist', 'danger')
        return redirect(url_for('wordlists.wordlists_list'))

    update_dynamic_wordlist(wordlist_id)
    db.session.refresh(wordlist)
    record_audit_event(
        'wordlist.update_dynamic',
        'wordlist',
        target_id=wordlist.id,
        summary=f'Updated dynamic shared wordlist "{wordlist.name}".',
        details={
            'wordlist_name': wordlist.name,
            'path': wordlist.path,
            'size': wordlist.size,
        },
    )
    flash('Updated Dynamic Wordlist', 'success')
    return redirect(url_for('wordlists.wordlists_list'))
