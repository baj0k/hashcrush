"""Flask routes to handle Wordlists"""
import os

from flask import Blueprint, current_app, flash, redirect, render_template, url_for
from flask_login import login_required, current_user

from hashcrush.models import Tasks, Users, Wordlists
from hashcrush.models import db
from hashcrush.utils.utils import get_filehash, get_linecount, update_dynamic_wordlist
from hashcrush.wordlists.forms import WordlistsForm


wordlists = Blueprint('wordlists', __name__)
MAX_SELECTABLE_WORDLIST_FILES = 5000


def _is_selectable_wordlist_filename(filename: str) -> bool:
    lowered = (filename or '').lower()
    return lowered.endswith('.txt')


def _wordlists_root_path() -> str:
    configured = current_app.config.get('WORDLISTS_PATH')
    if configured:
        return os.path.abspath(os.path.expanduser(str(configured)))
    return os.path.abspath(os.path.join(current_app.root_path, 'control', 'wordlists'))


def _list_selectable_files(base_dir: str, max_entries: int = MAX_SELECTABLE_WORDLIST_FILES) -> tuple[list[tuple[str, str]], bool]:
    if (not base_dir) or (not os.path.isdir(base_dir)):
        return [], False

    discovered: list[str] = []
    for dirpath, dirnames, files in os.walk(base_dir):
        # Skip hidden directories from recursive discovery.
        dirnames[:] = [dirname for dirname in dirnames if not dirname.startswith('.')]
        for filename in files:
            if not _is_selectable_wordlist_filename(filename):
                continue
            abs_path = os.path.abspath(os.path.join(dirpath, filename))
            rel_path = os.path.relpath(abs_path, base_dir).replace(os.path.sep, '/')
            discovered.append(rel_path)
            if len(discovered) >= max_entries:
                discovered.sort(key=str.casefold)
                return [(path, path) for path in discovered], True

    discovered.sort(key=str.casefold)
    return [(path, path) for path in discovered], False


def _resolve_selected_file(selected_relative_path: str, base_dir: str) -> str | None:
    selected = (selected_relative_path or '').strip()
    if not selected:
        return None
    if not _is_selectable_wordlist_filename(selected):
        return None

    candidate = os.path.abspath(os.path.join(base_dir, selected))
    try:
        if os.path.commonpath([candidate, base_dir]) != base_dir:
            return None
    except ValueError:
        return None

    return candidate if os.path.isfile(candidate) else None


@wordlists.route("/wordlists", methods=['GET'])
@login_required
def wordlists_list():
    """Function to present list of wordlists"""

    static_wordlists = Wordlists.query.filter_by(type='static').all()
    dynamic_wordlists = Wordlists.query.filter_by(type='dynamic').all()
    wordlists = Wordlists.query.all()
    tasks = Tasks.query.all()
    users = Users.query.all()
    return render_template(
        'wordlists.html',
        title='Wordlists',
        static_wordlists=static_wordlists,
        dynamic_wordlists=dynamic_wordlists,
        wordlists=wordlists,
        tasks=tasks,
        users=users,
        wordlists_root=_wordlists_root_path(),
    )


@wordlists.route("/wordlists/add", methods=['GET', 'POST'])
@login_required
def wordlists_add():
    """Function to add or register a new static wordlist"""

    form = WordlistsForm()
    wordlists_root = _wordlists_root_path()
    wordlists_root_exists = os.path.isdir(wordlists_root)
    selectable_files, selectable_truncated = _list_selectable_files(wordlists_root)
    form.existing_file.choices = [('', '--SELECT FILE--')] + selectable_files

    if form.validate_on_submit():
        if not wordlists_root_exists:
            flash('Configured wordlists_path directory does not exist. Cannot register wordlists until it is fixed.', 'danger')
            return render_template(
                'wordlists_add.html',
                title='Wordlist Add',
                form=form,
                wordlists_root=wordlists_root,
                wordlists_root_exists=wordlists_root_exists,
                selectable_count=len(selectable_files),
                selectable_truncated=selectable_truncated,
            )

        wordlist_path = _resolve_selected_file(form.existing_file.data, wordlists_root)
        if not wordlist_path:
            flash('Invalid file selection. Choose an existing file from the configured wordlists_path list.', 'danger')
            return render_template(
                'wordlists_add.html',
                title='Wordlist Add',
                form=form,
                wordlists_root=wordlists_root,
                wordlists_root_exists=wordlists_root_exists,
                selectable_count=len(selectable_files),
                selectable_truncated=selectable_truncated,
            )

        wordlist_path = os.path.abspath(wordlist_path)
        if Wordlists.query.filter_by(path=wordlist_path).first():
            flash('Wordlist is already registered.', 'warning')
            return redirect(url_for('wordlists.wordlists_list'))

        wordlist = Wordlists(
            name=form.name.data,
            owner_id=current_user.id,
            type='static',
            path=wordlist_path,
            checksum=get_filehash(wordlist_path),
            size=get_linecount(wordlist_path),
        )
        db.session.add(wordlist)
        db.session.commit()
        flash('Wordlist created!', 'success')
        return redirect(url_for('wordlists.wordlists_list'))

    return render_template(
        'wordlists_add.html',
        title='Wordlist Add',
        form=form,
        wordlists_root=wordlists_root,
        wordlists_root_exists=wordlists_root_exists,
        selectable_count=len(selectable_files),
        selectable_truncated=selectable_truncated,
    )


@wordlists.route("/wordlists/delete/<int:wordlist_id>", methods=['POST'])
@login_required
def wordlists_delete(wordlist_id):
    """Function to delete wordlist record"""

    wordlist = Wordlists.query.get(wordlist_id)
    if current_user.admin or wordlist.owner_id == current_user.id:

        # prevent deletion of dynamic list
        if wordlist.type == 'dynamic':
            flash('Dynamic Wordlists can not be deleted.', 'danger')
            return redirect(url_for('wordlists.wordlists_list'))

        # Check if associated with a Task
        tasks = Tasks.query.all()
        for task in tasks:
            if task.wl_id == wordlist_id:
                flash('Failed. Wordlist is associated to one or more tasks', 'danger')
                return redirect(url_for('wordlists.wordlists_list'))

        db.session.delete(wordlist)
        db.session.commit()
        flash('Wordlist has been deleted!', 'success')
    else:
        flash('Unauthorized Action!', 'danger')
    return redirect(url_for('wordlists.wordlists_list'))


@wordlists.route("/wordlists/update/<int:wordlist_id>", methods=['GET'])
@login_required
def dynamicwordlist_update(wordlist_id):
    """Function to update dynamic wordlist"""

    wordlist = Wordlists.query.get(wordlist_id)
    if wordlist.type == 'dynamic':
        update_dynamic_wordlist(wordlist_id)
        flash('Updated Dynamic Wordlist', 'success')
    else:
        flash('Invalid wordlist', 'danger')
    return redirect(url_for('wordlists.wordlists_list'))
