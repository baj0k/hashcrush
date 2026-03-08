"""Flask routes to handle Setup"""
from datetime import UTC, datetime

from flask import flash
from flask import url_for
from flask import redirect
from flask import Blueprint
from flask import current_app
from flask import render_template
from flask import request
from flask import abort

from hashcrush.setup import admin_pass_needs_changed
from hashcrush.setup import settings_needs_added
from hashcrush.models import db
from hashcrush.models import Users
from hashcrush.models import Settings
from hashcrush.users.routes import bcrypt

from .forms import SetupSettingsForm
from .forms import SetupAdminPassForm


blueprint = Blueprint('setup', __name__)


def _setup_request_allowed() -> bool:
    """Allow setup requests only from localhost."""
    return request.remote_addr in ('127.0.0.1', '::1')


@blueprint.route('/setup/admin-pass', methods=['GET'])
def admin_pass_get():
    """Function to get admin password setup"""
    if not _setup_request_allowed():
        abort(403)

    if not admin_pass_needs_changed(db, bcrypt):
        return redirect(url_for('main.home'))

    admin_user = db.session.query(Users).filter_by(id=1).first()
    if not admin_user:
        abort(404)

    form = SetupAdminPassForm()
    form.username.data = admin_user.username
    return render_template('setup_admin_pass.html.j2', form=form)


@blueprint.route('/setup/admin-pass', methods=['POST'])
def admin_pass_post():
    """Function to set admin password setup"""

    logger = current_app.logger
    if not _setup_request_allowed():
        abort(403)

    if not admin_pass_needs_changed(db, bcrypt):
        logger.info('%s: Admin password does not need to be changed.', admin_pass_post.__name__)
        return redirect(url_for('main.home'))

    form = SetupAdminPassForm()
    if not form.is_submitted():
        logger.info('%s: Form was not submitted.', admin_pass_post.__name__)
        return redirect(url_for('main.home'))

    if not form.validate():
        logger.info('%s: Form was not valid.', admin_pass_post.__name__)
        return render_template('setup_admin_pass.html.j2', form=form)

    admin_user = db.session.query(Users).filter_by(id=1).first()
    if not admin_user:
        abort(404)

    admin_user.username = form.username.data
    admin_user.password      = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
    admin_user.last_login_utc = datetime.now(UTC).replace(tzinfo=None)
    db.session.commit()
    flash('Admin password changed!', 'success')
    return redirect(url_for('setup.settings_get'))


@blueprint.route('/setup/settings', methods=['GET'])
def settings_get():
    """Function to get settings setup"""
    if not _setup_request_allowed():
        abort(403)

    if not settings_needs_added(db):
        return redirect(url_for('main.home'))

    form = SetupSettingsForm()
    return render_template('setup_settings.html.j2', form=form)


@blueprint.route('/setup/settings', methods=['POST'])
def settings_post():
    """Function to set settings setup"""

    logger = current_app.logger
    if not _setup_request_allowed():
        abort(403)

    if not settings_needs_added(db):
        logger.info('%s: Settings do not need to be added.', settings_post.__name__)
        return redirect(url_for('main.home'))

    form = SetupSettingsForm()
    if not form.is_submitted():
        logger.info('%s: Form was not submitted.', settings_post.__name__)
        return redirect(url_for('main.home'))

    if not form.validate():
        logger.info('%s: Form was not valid.', settings_post.__name__)
        return render_template('setup_settings.html.j2', form=form)

    settings = Settings(
        retention_period=0,
        enabled_job_weights=False,
    )
    db.session.add(settings)
    db.session.commit()
    flash('Settings added!', 'success')
    return redirect(url_for('main.home'))
