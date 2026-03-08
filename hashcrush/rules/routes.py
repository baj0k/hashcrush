"""Flask routes to handle Rules"""
import os

from flask import Blueprint, current_app, flash, redirect, render_template, url_for
from flask_login import login_required, current_user

from hashcrush.models import JobTasks, Jobs, Rules, Tasks, Users
from hashcrush.models import db
from hashcrush.rules.forms import RulesForm
from hashcrush.utils.utils import get_filehash, get_linecount


rules = Blueprint('rules', __name__)
MAX_SELECTABLE_RULE_FILES = 5000


def _contains_hidden_segment(relative_path: str) -> bool:
    return any(segment.startswith('.') for segment in relative_path.split('/') if segment not in ('', '.'))


def _rules_root_path() -> str:
    configured = current_app.config.get('RULES_PATH')
    if configured:
        return os.path.abspath(os.path.expanduser(str(configured)))
    return os.path.abspath(os.path.join(current_app.root_path, 'control', 'rules'))


def _list_selectable_files(base_dir: str, max_entries: int = MAX_SELECTABLE_RULE_FILES) -> tuple[list[tuple[str, str]], bool]:
    if (not base_dir) or (not os.path.isdir(base_dir)):
        return [], False

    discovered: list[str] = []
    for dirpath, dirnames, files in os.walk(base_dir):
        # Skip hidden directories from recursive discovery.
        dirnames[:] = [dirname for dirname in dirnames if not dirname.startswith('.')]
        for filename in files:
            if not filename.lower().endswith('.rule'):
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

    candidate = os.path.abspath(os.path.join(base_dir, normalized_selected))
    try:
        if os.path.commonpath([candidate, base_dir]) != base_dir:
            return None
    except ValueError:
        return None

    return candidate if os.path.isfile(candidate) else None


#############################################
# Rules
#############################################


@rules.route("/rules", methods=['GET'])
@login_required
def rules_list():
    """Function to return list of rules"""
    rules = Rules.query.all()
    tasks = Tasks.query.all()
    jobs = Jobs.query.all()
    jobtasks = JobTasks.query.all()
    users = Users.query.all()
    return render_template('rules.html', title='Rules', rules=rules, tasks=tasks, jobs=jobs, jobtasks=jobtasks, users=users, rules_root=_rules_root_path())


@rules.route("/rules/add", methods=['GET', 'POST'])
@login_required
def rules_add():
    """Function to add or register a rules file"""
    form = RulesForm()
    rules_root = _rules_root_path()
    rules_root_exists = os.path.isdir(rules_root)
    selectable_files, selectable_truncated = _list_selectable_files(rules_root)
    selectable_paths = [path for path, _ in selectable_files]
    selectable_tree = _build_file_tree(selectable_paths)
    form.existing_file.choices = [('', '--SELECT FILE--')] + selectable_files

    if form.validate_on_submit():
        if not rules_root_exists:
            flash('Configured rules_path directory does not exist. Cannot register rules until it is fixed.', 'danger')
            return render_template(
                'rules_add.html',
                title='Rules Add',
                form=form,
                rules_root=rules_root,
                rules_root_exists=rules_root_exists,
                selectable_count=len(selectable_files),
                selectable_truncated=selectable_truncated,
                selectable_tree=selectable_tree,
            )

        rules_path = _resolve_selected_file(form.existing_file.data, rules_root)
        if not rules_path:
            flash('Invalid file selection. Choose an existing file from the configured rules_path list.', 'danger')
            return render_template(
                'rules_add.html',
                title='Rules Add',
                form=form,
                rules_root=rules_root,
                rules_root_exists=rules_root_exists,
                selectable_count=len(selectable_files),
                selectable_truncated=selectable_truncated,
                selectable_tree=selectable_tree,
            )

        rules_path = os.path.abspath(rules_path)
        if Rules.query.filter_by(path=rules_path).first():
            flash('Rules file is already registered.', 'warning')
            return redirect(url_for('rules.rules_list'))

        rule = Rules(
            name=form.name.data,
            owner_id=current_user.id,
            path=rules_path,
            size=get_linecount(rules_path),
            checksum=get_filehash(rules_path),
        )
        db.session.add(rule)
        db.session.commit()
        flash('Rules File created!', 'success')
        return redirect(url_for('rules.rules_list'))

    return render_template(
        'rules_add.html',
        title='Rules Add',
        form=form,
        rules_root=rules_root,
        rules_root_exists=rules_root_exists,
        selectable_count=len(selectable_files),
        selectable_truncated=selectable_truncated,
        selectable_tree=selectable_tree,
    )


@rules.route("/rules/delete/<int:rule_id>", methods=['GET', 'POST'])
@login_required
def rules_delete(rule_id):
    """Function to delete rule file record"""
    rule = Rules.query.get(rule_id)
    if current_user.admin or rule.owner_id == current_user.id:
        # Check if part of a task
        tasks = Tasks.query.filter_by(rule_id=rule.id).first()
        if tasks:
            flash('Rules is currently used in a task and can not be delete.', 'danger')
        else:
            db.session.delete(rule)
            db.session.commit()
            flash('Rule file has been deleted!', 'success')
    else:
        flash('Unauthorized action!', 'danger')
    return redirect(url_for('rules.rules_list'))
