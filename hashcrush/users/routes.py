"""Flask routes to handle Users"""
from datetime import datetime

from flask import Blueprint, render_template, url_for, flash, abort, redirect, request, current_app
from urllib.parse import urlparse
from flask_login import login_required, logout_user, current_user, login_user
from flask_login import LoginManager
from flask_bcrypt import Bcrypt

from hashcrush.models import db
from hashcrush.models import Users, Jobs, Wordlists, Rules, TaskGroups, Tasks
from hashcrush.users.forms import LoginForm, UsersForm, ProfileForm

bcrypt = Bcrypt()


login_manager = LoginManager()
login_manager.login_view = 'users.login_get'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


users = Blueprint('users', __name__)


@users.route("/login", methods=['GET'])
def login_get():
    """Function to present login page"""

    form = LoginForm()
    return render_template('login.html', title='Login', form=form)

@users.route("/login", methods=['POST'])
def login_post():
    """Function to handle login requests"""

    def failed():
        flash('Login Unsuccessful. Please check username and password', 'danger')
        return render_template('login.html', title='Login', form=form)

    form = LoginForm()
    if not form.validate_on_submit():
        current_app.logger.info('Login failed: form validation.')
        return failed()

    user = Users.query.filter_by(username=form.username.data).first()
    if not user:
        current_app.logger.info('Login failed: unknown user for username=%s.', form.username.data)
        return failed()

    if not bcrypt.check_password_hash(user.password, form.password.data):
        current_app.logger.info('Login failed: invalid password.')
        return failed()

    login_user(user, remember=form.remember.data)
    user.last_login_utc = datetime.utcnow()
    db.session.commit()
    current_app.logger.info('Login succeeded: user=%s.', user.username)
    next_url = request.args.get("next")
    if next_url:
        parsed = urlparse(next_url)
        # Only allow relative redirects to prevent open-redirect attacks.
        if parsed.scheme or parsed.netloc:
            next_url = None
    return redirect(next_url or url_for('main.home'))

@users.route("/logout")
def logout():
    """Function to handle logout requests"""

    logout_user()
    return redirect(url_for('main.home'))

@users.route("/users", methods=['GET', 'POST'])
@login_required
def users_list():
    """Function to list users"""

    users = Users.query.all()
    jobs = Jobs.query.all()
    wordlists = Wordlists.query.all()
    rules = Rules.query.all()
    tasks = Tasks.query.all()
    task_groups = TaskGroups.query.all()
    return render_template('users.html', title='Users', users=users, jobs=jobs, wordlists=wordlists, rules=rules, tasks=tasks, task_groups=task_groups)

@users.route("/users/add", methods=['GET', 'POST'])
@login_required
def users_add():
    """Function to add new user"""

    if current_user.admin:
        form = UsersForm()
        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = Users(
                username=form.username.data,
                admin=form.is_admin.data,
                password=hashed_password,
            )
            db.session.add(user)
            db.session.commit()
            flash(f'Account created for {form.username.data}!', 'success')
            return redirect(url_for('users.users_list'))
        return render_template('users_add.html', title='User Add', form=form)
    abort(403)

@users.route("/users/delete/<int:user_id>", methods=['POST'])
@login_required
def users_delete(user_id):
    """Function to delete user"""

    if current_user.admin:
        user = Users.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        flash('User has been deleted!', 'success')
        return redirect(url_for('users.users_list'))
    abort(403)

@users.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    """Function to display user profile"""

    form = ProfileForm()
    if form.validate_on_submit():
        password_change_requested = bool(
            form.current_password.data or form.new_password.data or form.confirm_new_password.data
        )

        if password_change_requested:
            if not (form.current_password.data and form.new_password.data and form.confirm_new_password.data):
                flash('To change password, provide current password, new password, and confirmation.', 'danger')
                return render_template('profile.html', title='Profile', form=form, current_user=current_user)

            if not bcrypt.check_password_hash(current_user.password, form.current_password.data):
                flash('Current password is incorrect.', 'danger')
                return render_template('profile.html', title='Profile', form=form, current_user=current_user)

            current_user.password = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
            current_user.last_login_utc = datetime.utcnow()
            db.session.commit()
            flash('Password updated.', 'success')
        else:
            flash('No profile fields to update. Submit password fields to rotate credentials.', 'info')
        return redirect(url_for('users.profile'))
    return render_template('profile.html', title='Profile', form=form, current_user=current_user)

@users.route("/admin_reset_password/<int:user_id>", methods=['POST'])
@login_required
def admin_reset(user_id):
    """Set a new password for a target user."""

    if not current_user.admin:
        flash('Unauthorized to reset users account.', 'danger')
        return redirect(url_for('users.users_list'))

    user = Users.query.get(user_id)
    if not user:
        flash('User not found.', 'warning')
        return redirect(url_for('users.users_list'))

    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    if len(new_password) < 14:
        flash('Password must be at least 14 characters.', 'danger')
        return redirect(url_for('users.users_list'))

    if new_password != confirm_password:
        flash('Passwords do not match.', 'danger')
        return redirect(url_for('users.users_list'))

    user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    user.last_login_utc = datetime.utcnow()
    db.session.commit()
    flash(f'Password updated for user {user.username}. Share it securely and ask the user to change it in Profile.', 'success')
    return redirect(url_for('users.users_list'))
