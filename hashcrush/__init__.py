import logging
import datetime
import os
import sys
import tempfile

from flask import Flask
from flask import request
from flask import url_for
from flask import redirect
from flask_wtf.csrf import generate_csrf
from functools import partial
from logging.config import dictConfig as loggingDictConfig


__version__ = '0.9.97'


def _ensure_runtime_directories(root_path: str, runtime_root: str | None = None) -> None:
    """Create runtime directories required by file IO paths."""
    runtime_base = (
        os.path.abspath(os.path.expanduser(runtime_root))
        if runtime_root
        else os.path.join(root_path, 'control')
    )
    runtime_dirs = (
        os.path.join(runtime_base, 'tmp'),
        os.path.join(runtime_base, 'hashes'),
        os.path.join(runtime_base, 'outfiles'),
        os.path.join(root_path, 'ssl'),
    )
    for runtime_dir in runtime_dirs:
        os.makedirs(runtime_dir, exist_ok=True)


def _is_flask_db_command() -> bool:
    """Detect Flask-Migrate CLI invocations (for example: flask db upgrade)."""
    argv = [arg.lower() for arg in sys.argv[1:]]
    return bool(argv) and argv[0] == 'db'


def get_application_version() -> str:
    """ jinja2 function to get the application version from within a template """
    return __version__


def do_gui_setup_if_needed():
    from flask import current_app
    logger = current_app.logger

    from urllib.parse import urlparse
    static_path = url_for('static', filename='')
    parsed_url  = urlparse(request.url)

    if parsed_url.path.startswith(static_path):
        # allow static files through
        return

    from hashcrush.models import db

    from hashcrush.setup import admin_pass_needs_changed
    from hashcrush.users.routes import bcrypt
    if not admin_pass_needs_changed(db, bcrypt):
        logger.debug('Admin password does not need to be changed.')

    else:
        logger.info('Admin password needs to be changed.')
        if (url_for('setup.admin_pass_get') != parsed_url.path):
            return redirect(url_for('setup.admin_pass_get'))
        else:
            return

    from hashcrush.setup import settings_needs_added
    if not settings_needs_added(db):
        logger.debug('Settings do not need to be created.')

    else:
        logger.info('Settings need to be created.')
        if (url_for('setup.settings_get') != parsed_url.path):
            return redirect(url_for('setup.settings_get'))
        else:
            return


def setup_defaults_if_needed():
    from flask import current_app
    logger = current_app.logger
    logger.info('Setting up defaults.')

    from hashcrush.models import db

    if current_app.config.get('AUTO_MIGRATE', False):
        try:
            logger.info('Checking for required database upgrades.')
            import alembic.command
            migrate_ext = current_app.extensions['migrate']
            config = migrate_ext.migrate.get_config(migrate_ext.directory)
            # set configure_logger so that migrations/env.py doesn't override the logging setup
            config.attributes['configure_logger'] = False
            alembic.command.upgrade(config, 'head')
            logger.info('Database upgrade check complete.')
        except Exception:
            logger.exception('Upgrading Database failed.')
    else:
        logger.info('AUTO_MIGRATE disabled; skipping automatic DB upgrade.')

    if current_app.config.get('ENABLE_SCHEDULER', False):
        try:
            from hashcrush.scheduler import scheduler
            from hashcrush.scheduler import data_retention_cleanup
            logger.info('Clearing Scheduled Jobs.')
            scheduler.remove_all_jobs()
            logger.info('Scheduling default jobs.')
            scheduler.add_job(id='DATA_RETENTION', func=partial(data_retention_cleanup, current_app), trigger='cron', hour='*')
            logger.info('Default job scheduling complete.')
        except Exception:
            logger.exception('Adding Default Scheduled Jobs failed.')
    else:
        logger.info('ENABLE_SCHEDULER disabled; skipping default job scheduling.')

    try:
        from hashcrush.users.routes import bcrypt
        from hashcrush.setup import add_admin_user
        from hashcrush.setup import admin_user_needs_added
        if admin_user_needs_added(db):
            logger.info('Adding Admin User.')
            add_admin_user(db, bcrypt)
    except Exception:
        logger.exception('Adding Admin User failed.')

    try:
        from hashcrush.setup import add_default_tasks
        from hashcrush.setup import default_tasks_need_added
        if default_tasks_need_added(db):
            logger.info('Adding Default Tasks.')
            add_default_tasks(db)
    except Exception:
        logger.exception('Adding Default Tasks failed.')


def jinja_hex_decode(text):
    """Jinja2 filter to decode stored plaintext with legacy fallback."""
    from hashcrush.utils.utils import decode_plaintext_from_storage
    return decode_plaintext_from_storage(text)


def create_app(testing: bool = False, config_overrides: dict | None = None):
    app = Flask(__name__)

    # https://flask.palletsprojects.com/en/2.2.x/logging/
    # When you want to configure logging for your project, you should do it as
    # soon as possible when the program starts.
    loggingDictConfig({
        'version': 1,
        'formatters': {
            'default': {
                'format': '%(asctime)s [%(levelname)-8s] for %(name)s: %(message)s in (%(module)s:%(lineno)d)',
            }
        },
        'handlers': {
            'wsgi': {
                'class': 'logging.StreamHandler',
                'stream': 'ext://flask.logging.wsgi_errors_stream',
                'formatter': 'default'
            }
        },
        'root': {
            'level': 'DEBUG' if app.debug else 'INFO',
            'handlers': ['wsgi']
        }
    })
    logging.Formatter.formatTime = (
        lambda self, record, datefmt=None: \
            datetime.datetime
                .fromtimestamp(record.created, datetime.timezone.utc)
                .astimezone()
                .isoformat(sep="T", timespec="milliseconds")
    )

    from hashcrush.config import Config
    app.config.from_object(Config)

    # Sensible defaults; can be overridden via config_overrides or app config.
    # These are intentionally conservative for production deployments.
    app.config.setdefault('AUTO_MIGRATE', False)
    app.config.setdefault('AUTO_SETUP_DEFAULTS', True)
    app.config.setdefault('ENABLE_SCHEDULER', False)
    app.config.setdefault('ENABLE_LOCAL_EXECUTOR', True)
    app.config.setdefault('SKIP_RUNTIME_BOOTSTRAP', False)
    app.config.setdefault('AUTO_MIGRATE_PLAINTEXT_STORAGE', True)
    app.config.setdefault('RUNTIME_PATH', os.path.join(tempfile.gettempdir(), 'hashcrush-runtime'))

    if testing:
        app.config['TESTING'] = True

    if config_overrides:
        app.config.update(config_overrides)

    if _is_flask_db_command():
        app.config['SKIP_RUNTIME_BOOTSTRAP'] = True

    if not app.config.get('SKIP_RUNTIME_BOOTSTRAP'):
        _ensure_runtime_directories(app.root_path, app.config.get('RUNTIME_PATH'))

    from hashcrush.models import db
    db.init_app(app)

    from flask_migrate import Migrate
    migrate = Migrate()
    migrate.init_app(app, db)

    from hashcrush.scheduler import scheduler
    scheduler.init_app(app)

    # Avoid starting background scheduler automatically in multi-worker deployments.
    # Enable explicitly via config to prevent duplicate jobs.
    if (
        (not app.config.get('TESTING'))
        and (not app.config.get('SKIP_RUNTIME_BOOTSTRAP'))
        and app.config.get('ENABLE_SCHEDULER', False)
    ):
        # Flask's reloader starts the app twice; only start scheduler in the reloader child.
        if (not app.debug) or (os.environ.get('WERKZEUG_RUN_MAIN') == 'true'):
            scheduler.start()

    from hashcrush.users.routes import bcrypt
    bcrypt.init_app(app)

    from hashcrush.users.routes import login_manager
    login_manager.init_app(app)

    @app.context_processor
    def inject_csrf_token():
        return {'csrf_token': generate_csrf}

    from hashcrush.domains.routes import domains
    from hashcrush.hashfiles.routes import hashfiles
    from hashcrush.jobs.routes import jobs
    from hashcrush.main.routes import main
    from hashcrush.rules.routes import rules
    from hashcrush.settings.routes import settings
    from hashcrush.tasks.routes import tasks
    from hashcrush.task_groups.routes import task_groups
    from hashcrush.users.routes import users
    from hashcrush.wordlists.routes import wordlists
    from hashcrush.analytics.routes import analytics
    from hashcrush.searches.routes import searches
    from hashcrush.setup.routes import blueprint as setup_blueprint

    app.register_blueprint(domains)
    app.register_blueprint(hashfiles)
    app.register_blueprint(jobs)
    app.register_blueprint(main)
    app.register_blueprint(rules)
    app.register_blueprint(settings)
    app.register_blueprint(tasks)
    app.register_blueprint(task_groups)
    app.register_blueprint(users)
    app.register_blueprint(wordlists)
    app.register_blueprint(analytics)
    app.register_blueprint(searches)
    app.register_blueprint(setup_blueprint)

    app.add_template_filter(jinja_hex_decode)
    app.add_template_global(get_application_version, get_application_version.__name__)

    # Default seeding can be enabled/disabled via config.
    if (
        (not app.config.get('TESTING'))
        and (not app.config.get('SKIP_RUNTIME_BOOTSTRAP'))
        and app.config.get('AUTO_SETUP_DEFAULTS', True)
    ):
        with app.app_context():
            setup_defaults_if_needed()

    if (
        (not app.config.get('TESTING'))
        and (not app.config.get('SKIP_RUNTIME_BOOTSTRAP'))
        and app.config.get('AUTO_MIGRATE_PLAINTEXT_STORAGE', True)
    ):
        with app.app_context():
            try:
                from hashcrush.utils.utils import migrate_plaintext_storage_rows
                migrated_rows = migrate_plaintext_storage_rows()
                if migrated_rows:
                    app.logger.info(
                        'Migrated %s legacy plaintext row(s) to canonical hex storage.',
                        migrated_rows,
                    )
            except Exception:
                app.logger.exception('Legacy plaintext migration failed.')

    app.before_request(do_gui_setup_if_needed)

    # Local single-node executor for queued JobTasks.
    if (
        (not app.config.get('TESTING'))
        and (not app.config.get('SKIP_RUNTIME_BOOTSTRAP'))
        and app.config.get('ENABLE_LOCAL_EXECUTOR', True)
    ):
        if (not app.debug) or (os.environ.get('WERKZEUG_RUN_MAIN') == 'true'):
            from hashcrush.executor import LocalExecutorService

            local_executor = LocalExecutorService(app)
            local_executor.start()
            app.extensions['local_executor'] = local_executor

    return app
