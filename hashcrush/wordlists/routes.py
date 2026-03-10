"""Flask routes to handle Wordlists"""
import os

from flask import Blueprint, current_app, flash, redirect, render_template, url_for
from flask_login import login_required
from sqlalchemy.exc import IntegrityError

from hashcrush.audit import record_audit_event
from hashcrush.authz import admin_required_redirect
from hashcrush.models import Tasks, Wordlists, db
from hashcrush.utils.utils import get_filehash, get_linecount, update_dynamic_wordlist
from hashcrush.wordlists.forms import WordlistsForm

wordlists = Blueprint('wordlists', __name__)
MAX_SELECTABLE_WORDLIST_FILES = 5000


def _render_wordlists_add_form(form, wordlists_root, wordlists_root_exists, selectable_files, selectable_truncated, selectable_tree):
    return render_template(
        'wordlists_add.html',
        title='Wordlist Add',
        form=form,
        wordlists_root=wordlists_root,
        wordlists_root_exists=wordlists_root_exists,
        selectable_count=len(selectable_files),
        selectable_truncated=selectable_truncated,
        selectable_tree=selectable_tree,
    )


def _contains_hidden_segment(relative_path: str) -> bool:
    return any(segment.startswith('.') for segment in relative_path.split('/') if segment not in ('', '.'))


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


def _build_file_tree(relative_paths: list[str]) -> dict:
    root = {"dirs": {}, "files": []}
    for relative_path in relative_paths:
        parts = [segment for segment in relative_path.split('/') if segment]
        if not parts:
            continue
        node = root
        for segment in parts[:-1]:
            node = node["dirs"].setdefault(segment, {"dirs": {}, "files": []})
        node["files"].append(parts[-1])
    return _serialize_file_tree(root, "")


def _serialize_file_tree(node: dict, prefix: str) -> dict:
    serialized_dirs = []
    for dirname in sorted(node["dirs"].keys(), key=str.casefold):
        child = node["dirs"][dirname]
        child_prefix = f"{prefix}/{dirname}" if prefix else dirname
        serialized_child = _serialize_file_tree(child, child_prefix)
        serialized_child["name"] = dirname
        serialized_child["path"] = child_prefix
        serialized_dirs.append(serialized_child)

    serialized_files = []
    for filename in sorted(node["files"], key=str.casefold):
        file_path = f"{prefix}/{filename}" if prefix else filename
        serialized_files.append({"name": filename, "path": file_path})

    return {"dirs": serialized_dirs, "files": serialized_files}


def _resolve_selected_file(selected_relative_path: str, base_dir: str) -> str | None:
    selected = (selected_relative_path or '').strip()
    if not selected:
        return None
    normalized_selected = selected.replace('\\', '/')
    if _contains_hidden_segment(normalized_selected):
        return None
    if not _is_selectable_wordlist_filename(normalized_selected):
        return None

    candidate = os.path.abspath(os.path.join(base_dir, normalized_selected))
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

    visible_wordlists = Wordlists.query
    static_wordlists = visible_wordlists.filter_by(type='static').all()
    dynamic_wordlists = visible_wordlists.filter_by(type='dynamic').all()
    wordlists = visible_wordlists.all()
    tasks = Tasks.query.all()
    return render_template(
        'wordlists.html',
        title='Wordlists',
        static_wordlists=static_wordlists,
        dynamic_wordlists=dynamic_wordlists,
        wordlists=wordlists,
        tasks=tasks,
        wordlists_root=_wordlists_root_path(),
    )


@wordlists.route("/wordlists/add", methods=['GET', 'POST'])
@login_required
@admin_required_redirect('wordlists.wordlists_list')
def wordlists_add():
    """Function to add or register a new static wordlist"""

    form = WordlistsForm()
    wordlists_root = _wordlists_root_path()
    wordlists_root_exists = os.path.isdir(wordlists_root)
    selectable_files, selectable_truncated = _list_selectable_files(wordlists_root)
    selectable_paths = [path for path, _ in selectable_files]
    selectable_tree = _build_file_tree(selectable_paths)
    form.existing_file.choices = [('', '--SELECT FILE--')] + selectable_files

    if form.validate_on_submit():
        if not wordlists_root_exists:
            flash('Configured wordlists_path directory does not exist. Cannot register wordlists until it is fixed.', 'danger')
            return _render_wordlists_add_form(
                form,
                wordlists_root,
                wordlists_root_exists,
                selectable_files,
                selectable_truncated,
                selectable_tree,
            )

        wordlist_path = _resolve_selected_file(form.existing_file.data, wordlists_root)
        if not wordlist_path:
            flash('Invalid file selection. Choose an existing file from the configured wordlists_path list.', 'danger')
            return _render_wordlists_add_form(
                form,
                wordlists_root,
                wordlists_root_exists,
                selectable_files,
                selectable_truncated,
                selectable_tree,
            )

        wordlist_path = os.path.abspath(wordlist_path)
        if Wordlists.query.filter_by(path=wordlist_path).first():
            flash('Wordlist is already registered.', 'warning')
            return redirect(url_for('wordlists.wordlists_list'))
        if Wordlists.query.filter_by(name=form.name.data).first():
            flash('Wordlist name is already registered.', 'warning')
            return redirect(url_for('wordlists.wordlists_list'))

        wordlist = Wordlists(
            name=form.name.data,
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
            flash('Wordlist could not be registered because that name or path already exists. Refresh and retry.', 'danger')
            return _render_wordlists_add_form(
                form,
                wordlists_root,
                wordlists_root_exists,
                selectable_files,
                selectable_truncated,
                selectable_tree,
            )
        record_audit_event(
            'wordlist.create',
            'wordlist',
            target_id=wordlist.id,
            summary=f'Registered shared wordlist "{wordlist.name}".',
            details={
                'wordlist_name': wordlist.name,
                'path': wordlist.path,
                'type': wordlist.type,
                'size': wordlist.size,
            },
        )
        flash('Wordlist created!', 'success')
        return redirect(url_for('wordlists.wordlists_list'))

    return _render_wordlists_add_form(
        form,
        wordlists_root,
        wordlists_root_exists,
        selectable_files,
        selectable_truncated,
        selectable_tree,
    )


@wordlists.route("/wordlists/delete/<int:wordlist_id>", methods=['POST'])
@login_required
@admin_required_redirect('wordlists.wordlists_list')
def wordlists_delete(wordlist_id):
    """Function to delete wordlist record"""

    wordlist = Wordlists.query.get_or_404(wordlist_id)
    # prevent deletion of dynamic list
    if wordlist.type == 'dynamic':
        flash('Dynamic Wordlists can not be deleted.', 'danger')
        return redirect(url_for('wordlists.wordlists_list'))

    # Check if associated with a Task
    task = Tasks.query.filter_by(wl_id=wordlist_id).first()
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

    wordlist = Wordlists.query.get_or_404(wordlist_id)
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
