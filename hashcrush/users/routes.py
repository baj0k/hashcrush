"""Flask routes to handle Users"""
from datetime import UTC, datetime
import ipaddress
import time

from flask import Blueprint, render_template, url_for, flash, abort, redirect, request, current_app
from urllib.parse import urlparse
from flask_login import login_required, logout_user, current_user, login_user
from flask_login import LoginManager
from flask_bcrypt import Bcrypt

from hashcrush.models import db
from hashcrush.models import AuthThrottle, Users, Jobs, Wordlists, Rules, TaskGroups, Tasks
from hashcrush.users.forms import LoginForm, UsersForm, ProfileForm

bcrypt = Bcrypt()


login_manager = LoginManager()
login_manager.login_view = 'users.login_get'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


users = Blueprint('users', __name__)


def _admin_count() -> int:
    """Return number of admin accounts currently present."""
    return Users.query.filter_by(admin=True).count()


def _utc_now_naive() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _auth_client_ip() -> str:
    if current_app.config.get('TRUST_X_FORWARDED_FOR', False):
        forwarded_for = (request.headers.get('X-Forwarded-For') or '').strip()
        if forwarded_for:
            first_hop = forwarded_for.split(',', maxsplit=1)[0].strip()
            if first_hop:
                try:
                    ipaddress.ip_address(first_hop)
                    return first_hop
                except ValueError:
                    current_app.logger.warning(
                        'Ignoring invalid X-Forwarded-For value: %s',
                        first_hop,
                    )
    return request.remote_addr or 'unknown'


def _auth_throttle_key(username: str | None) -> str:
    normalized_username = (username or '').strip().lower() or '<empty>'
    return f'{_auth_client_ip()}::{normalized_username}'


def _cleanup_auth_throttle_store(now_epoch: float) -> None:
    window_seconds = int(current_app.config.get('AUTH_THROTTLE_WINDOW_SECONDS', 300))
    lockout_seconds = int(current_app.config.get('AUTH_THROTTLE_LOCKOUT_SECONDS', 900))
    stale_before = int(now_epoch - max(window_seconds, lockout_seconds) - 60)
    try:
        AuthThrottle.query.filter(
            AuthThrottle.locked_until <= int(now_epoch),
            AuthThrottle.window_start <= stale_before,
        ).delete(synchronize_session=False)
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception('Failed cleaning auth throttle state.')


def _is_auth_throttled(throttle_key: str, now_epoch: float) -> tuple[bool, int]:
    if not current_app.config.get('AUTH_THROTTLE_ENABLED', True):
        return False, 0
    entry = AuthThrottle.query.get(throttle_key)
    if not entry:
        return False, 0
    locked_until = int(entry.locked_until or 0)
    if locked_until > now_epoch:
        return True, max(1, int(locked_until - now_epoch))
    return False, 0


def _record_failed_login(throttle_key: str, now_epoch: float) -> None:
    if not current_app.config.get('AUTH_THROTTLE_ENABLED', True):
        return

    now_epoch_int = int(now_epoch)
    max_attempts = int(current_app.config.get('AUTH_THROTTLE_MAX_ATTEMPTS', 5))
    window_seconds = int(current_app.config.get('AUTH_THROTTLE_WINDOW_SECONDS', 300))
    lockout_seconds = int(current_app.config.get('AUTH_THROTTLE_LOCKOUT_SECONDS', 900))
    try:
        entry = AuthThrottle.query.get(throttle_key)
        if entry is None:
            entry = AuthThrottle(
                key=throttle_key,
                count=0,
                window_start=now_epoch_int,
                locked_until=0,
            )
            db.session.add(entry)

        if now_epoch_int - int(entry.window_start or 0) > window_seconds:
            entry.count = 0
            entry.window_start = now_epoch_int
            entry.locked_until = 0

        if int(entry.locked_until or 0) > now_epoch_int:
            db.session.commit()
            return

        entry.count = int(entry.count or 0) + 1
        if int(entry.count) >= max_attempts:
            entry.count = 0
            entry.window_start = now_epoch_int
            entry.locked_until = now_epoch_int + lockout_seconds
            current_app.logger.warning(
                'Login throttled for %s for %s seconds after repeated failures.',
                throttle_key,
                lockout_seconds,
            )
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception('Failed updating auth throttle state.')


def _reset_failed_login_counter(throttle_key: str) -> None:
    try:
        AuthThrottle.query.filter_by(key=throttle_key).delete(synchronize_session=False)
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception('Failed clearing auth throttle key=%s', throttle_key)


@users.route("/login", methods=['GET'])
def login_get():
    """Function to present login page"""

    form = LoginForm()
    return render_template('login.html', title='Login', form=form)

@users.route("/login", methods=['POST'])
def login_post():
    """Function to handle login requests"""

    def failed(status_code: int = 200):
        flash('Login Unsuccessful. Please check username and password', 'danger')
        return render_template('login.html', title='Login', form=form), status_code

    form = LoginForm()
    submitted_username = request.form.get('username', '')
    now_epoch = time.time()
    throttle_key = _auth_throttle_key(submitted_username)
    _cleanup_auth_throttle_store(now_epoch)

    throttled, retry_after = _is_auth_throttled(throttle_key, now_epoch)
    if throttled:
        current_app.logger.warning(
            'Login attempt blocked by throttle for username=%s from ip=%s.',
            (submitted_username or '').strip(),
            _auth_client_ip(),
        )
        # Keep generic auth failure wording consistent for UI/tests while still
        # surfacing throttle state and returning 429.
        flash('Login Unsuccessful. Please check username and password', 'danger')
        flash('Too many failed login attempts. Try again later.', 'danger')
        response = render_template('login.html', title='Login', form=form)
        return response, 429, {'Retry-After': str(retry_after)}

    if not form.validate_on_submit():
        _record_failed_login(throttle_key, now_epoch)
        current_app.logger.info('Login failed: form validation.')
        return failed()

    user = Users.query.filter_by(username=form.username.data).first()
    if not user:
        _record_failed_login(throttle_key, now_epoch)
        current_app.logger.info('Login failed: unknown user for username=%s.', form.username.data)
        return failed()

    if not bcrypt.check_password_hash(user.password, form.password.data):
        _record_failed_login(throttle_key, now_epoch)
        current_app.logger.info('Login failed: invalid password.')
        return failed()

    _reset_failed_login_counter(throttle_key)
    login_user(user, remember=form.remember.data)
    user.last_login_utc = _utc_now_naive()
    db.session.commit()
    current_app.logger.info('Login succeeded: user=%s.', user.username)
    next_url = request.args.get("next")
    if next_url:
        parsed = urlparse(next_url)
        # Only allow relative redirects to prevent open-redirect attacks.
        if parsed.scheme or parsed.netloc:
            next_url = None
    return redirect(next_url or url_for('main.home'))

@users.route("/logout", methods=['POST'])
@login_required
def logout():
    """Function to handle logout requests"""

    logout_user()
    return redirect(url_for('main.home'))

@users.route("/users", methods=['GET', 'POST'])
@login_required
def users_list():
    """Function to list users"""
    if not current_user.admin:
        abort(403)

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

    if not current_user.admin:
        abort(403)

    user = Users.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash('You cannot delete your own account while logged in. Use another admin account.', 'warning')
        return redirect(url_for('users.users_list'))

    if user.admin and _admin_count() <= 1:
        flash('Cannot delete the last admin account.', 'danger')
        return redirect(url_for('users.users_list'))

    db.session.delete(user)
    db.session.commit()
    flash('User has been deleted!', 'success')
    return redirect(url_for('users.users_list'))

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
            current_user.last_login_utc = _utc_now_naive()
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

    if user.id == current_user.id:
        flash('Use Profile to change your own password.', 'warning')
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
    user.last_login_utc = _utc_now_naive()
    db.session.commit()
    flash(f'Password updated for user {user.username}. Share it securely and ask the user to change it in Profile.', 'success')
    return redirect(url_for('users.users_list'))
