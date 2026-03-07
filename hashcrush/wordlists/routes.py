"""Flask routes to handle Wordlists"""
import os

from flask import Blueprint, render_template, redirect, url_for, flash, current_app
from flask_login import login_required, current_user

from hashcrush.wordlists.forms import WordlistsForm
from hashcrush.models import Tasks, Wordlists, Users
from hashcrush.models import db
from hashcrush.utils.utils import save_file, get_linecount, get_filehash, update_dynamic_wordlist


wordlists = Blueprint('wordlists', __name__)


def _wordlists_root_path() -> str:
    configured = current_app.config.get('WORDLISTS_PATH')
    if configured:
        return os.path.abspath(os.path.expanduser(str(configured)))
    return os.path.abspath(os.path.join(current_app.root_path, 'control', 'wordlists'))


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

    # Allow bare filename lookup in nested directories under wordlists_path.
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

    if form.validate_on_submit():
        upload_file = form.wordlist.data
        existing_path_input = (form.existing_path.data or '').strip()

        if not upload_file and not existing_path_input:
            flash('Provide either a wordlist upload or an existing path.', 'danger')
            return render_template('wordlists_add.html', title='Wordlist Add', form=form, wordlists_root=wordlists_root)

        if existing_path_input:
            wordlist_path = _resolve_existing_file(existing_path_input, wordlists_root)
            if not wordlist_path or not os.path.isfile(wordlist_path):
                flash('Invalid existing wordlist path. Use an absolute path, a nested relative path, or a unique filename under configured wordlists_path.', 'danger')
                return render_template('wordlists_add.html', title='Wordlist Add', form=form, wordlists_root=wordlists_root)
        else:
            os.makedirs(wordlists_root, exist_ok=True)
            wordlist_path = save_file(wordlists_root, upload_file)

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

    return render_template('wordlists_add.html', title='Wordlist Add', form=form, wordlists_root=wordlists_root)


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
