"""Flask routes to handle Rules"""
import os

from flask import Blueprint, render_template, flash, url_for, redirect, current_app
from flask_login import login_required, current_user

from hashcrush.models import Rules, Tasks, Jobs, JobTasks, Users
from hashcrush.rules.forms import RulesForm
from hashcrush.utils.utils import save_file, get_linecount, get_filehash
from hashcrush.models import db


rules = Blueprint('rules', __name__)


def _rules_root_path() -> str:
    configured = current_app.config.get('RULES_PATH')
    if configured:
        return os.path.abspath(os.path.expanduser(str(configured)))
    return os.path.abspath(os.path.join(current_app.root_path, 'control', 'rules'))


def _resolve_existing_file(user_path: str, base_dir: str) -> str | None:
    raw_value = os.path.expanduser((user_path or '').strip())
    if not raw_value:
        return None

    input_is_absolute = os.path.isabs(raw_value)
    candidate = os.path.abspath(raw_value if input_is_absolute else os.path.join(base_dir, raw_value))

    try:
        if os.path.commonpath([candidate, base_dir]) != base_dir:
            return None
    except ValueError:
        return None

    if os.path.isfile(candidate):
        return candidate

    # Allow bare filename lookup in nested directories under rules_path.
    has_path_separator = (os.path.sep in raw_value) or (os.path.altsep and os.path.altsep in raw_value)
    if (not input_is_absolute) and (not has_path_separator):
        matches: list[str] = []
        for dirpath, _, files in os.walk(base_dir):
            if raw_value in files:
                matches.append(os.path.abspath(os.path.join(dirpath, raw_value)))
                if len(matches) > 1:
                    return None
        if len(matches) == 1:
            return matches[0]

    return None


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

    if form.validate_on_submit():
        upload_file = form.rules.data
        existing_path_input = (form.existing_path.data or '').strip()

        if not upload_file and not existing_path_input:
            flash('Provide either a rules upload or an existing path.', 'danger')
            return render_template('rules_add.html', title='Rules Add', form=form, rules_root=rules_root)

        if existing_path_input:
            rules_path = _resolve_existing_file(existing_path_input, rules_root)
            if not rules_path or not os.path.isfile(rules_path):
                flash('Invalid existing rules path. Use an absolute path, a nested relative path, or a unique filename under configured rules_path.', 'danger')
                return render_template('rules_add.html', title='Rules Add', form=form, rules_root=rules_root)
        else:
            os.makedirs(rules_root, exist_ok=True)
            rules_path = save_file(rules_root, upload_file)

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

    return render_template('rules_add.html', title='Rules Add', form=form, rules_root=rules_root)


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
