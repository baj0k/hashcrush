import datetime
import logging
import os
import sqlite3
import tempfile
from functools import partial
from logging.config import dictConfig as loggingDictConfig

from flask import Flask, redirect, request, url_for
from flask_wtf.csrf import CSRFProtect, generate_csrf
from sqlalchemy import event
from sqlalchemy.engine import Engine

__version__ = "1.0"


@event.listens_for(Engine, "connect")
def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record):
    """Ensure SQLite enforces FK actions during tests and local deployments."""
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def _ensure_runtime_directories(
    root_path: str, runtime_root: str | None = None
) -> None:
    """Create runtime directories required by file IO paths."""
    runtime_base = (
        os.path.abspath(os.path.expanduser(runtime_root))
        if runtime_root
        else os.path.join(root_path, "control")
    )
    runtime_dirs = (
        os.path.join(runtime_base, "tmp"),
        os.path.join(runtime_base, "hashes"),
        os.path.join(runtime_base, "outfiles"),
    )
    for runtime_dir in runtime_dirs:
        os.makedirs(runtime_dir, exist_ok=True)


def _ensure_database_schema(app: Flask) -> None:
    """Guard startup against outdated schemas and bootstrap empty databases."""
    from hashcrush.db_upgrade import get_schema_status, upgrade_database

    app.logger.info("Ensuring database schema exists.")
    with app.app_context():
        schema_status = get_schema_status()
        if not schema_status["has_user_tables"]:
            upgrade_database()
            return
        if not schema_status["tracked"]:
            raise RuntimeError(
                "Database schema is not version-tracked. Run `hashcrush.py upgrade` "
                "before starting this version."
            )
        current_version = int(schema_status["current_version"])
        target_version = int(schema_status["target_version"])
        if current_version < target_version:
            raise RuntimeError(
                f"Database schema version {current_version} is behind required "
                f"version {target_version}. Run `hashcrush.py upgrade`."
            )


def get_application_version() -> str:
    """jinja2 function to get the application version from within a template"""
    return __version__


def _warn_insecure_configuration(app: Flask) -> None:
    """Emit warnings when weak/default-looking security settings are detected."""
    weak_secret_values = {"changeme", "change-me", "default", "secret", "hashcrush"}
    secret_key = str(app.config.get("SECRET_KEY") or "").strip()
    if (len(secret_key) < 32) or (secret_key.lower() in weak_secret_values):
        app.logger.warning(
            "SECURITY WARNING: SECRET_KEY appears weak/short; rotate to a strong random value (>=32 chars)."
        )

    db_uri = str(app.config.get("SQLALCHEMY_DATABASE_URI") or "")
    db_uri_lower = db_uri.lower()
    if (
        "://username:" in db_uri_lower
        or ":password@" in db_uri_lower
        or "://root:" in db_uri_lower
    ):
        app.logger.warning(
            "SECURITY WARNING: database credentials look like defaults/placeholders; rotate DB credentials now."
        )

    cert_path = os.path.abspath(
        os.path.expanduser(str(app.config.get("SSL_CERT_PATH") or ""))
    )
    key_path = os.path.abspath(
        os.path.expanduser(str(app.config.get("SSL_KEY_PATH") or ""))
    )
    project_ssl_path = os.path.abspath(os.path.join(app.root_path, "ssl"))
    if cert_path.startswith(project_ssl_path) or key_path.startswith(project_ssl_path):
        app.logger.warning(
            "SECURITY WARNING: TLS cert/key are loaded from project-local path (%s). "
            "Prefer secret volume or env-configured secure paths.",
            project_ssl_path,
        )


def do_gui_setup_if_needed():
    from flask import current_app

    logger = current_app.logger

    from urllib.parse import urlparse

    static_path = url_for("static", filename="")
    parsed_url = urlparse(request.url)

    if parsed_url.path.startswith(static_path):
        # allow static files through
        return

    from hashcrush.models import db
    from hashcrush.setup import admin_pass_needs_changed
    from hashcrush.users.routes import bcrypt

    if not admin_pass_needs_changed(db, bcrypt):
        logger.debug("Admin password does not need to be changed.")

    else:
        logger.info("Admin password needs to be changed.")
        if url_for("setup.admin_pass_get") != parsed_url.path:
            return redirect(url_for("setup.admin_pass_get"))
        else:
            return

    from hashcrush.setup import settings_needs_added

    if not settings_needs_added(db):
        logger.debug("Settings do not need to be created.")

    else:
        logger.info("Settings need to be created.")
        if url_for("setup.settings_get") != parsed_url.path:
            return redirect(url_for("setup.settings_get"))
        else:
            return


def setup_defaults_if_needed():
    from flask import current_app

    logger = current_app.logger
    logger.info("Setting up defaults.")

    from hashcrush.models import db

    if current_app.config.get("ENABLE_SCHEDULER", False):
        try:
            from hashcrush.scheduler import data_retention_cleanup, scheduler

            logger.info("Clearing Scheduled Jobs.")
            scheduler.remove_all_jobs()
            logger.info("Scheduling default jobs.")
            scheduler.add_job(
                id="DATA_RETENTION",
                func=partial(data_retention_cleanup, current_app),
                trigger="cron",
                hour="*",
            )
            logger.info("Default job scheduling complete.")
        except Exception:
            logger.exception("Adding Default Scheduled Jobs failed.")
    else:
        logger.info("ENABLE_SCHEDULER disabled; skipping default job scheduling.")

    try:
        from hashcrush.setup import add_admin_user, admin_user_needs_added
        from hashcrush.users.routes import bcrypt

        if admin_user_needs_added(db):
            logger.info("Adding Admin User.")
            add_admin_user(db, bcrypt)
    except Exception:
        logger.exception("Adding Admin User failed.")

    try:
        from hashcrush.setup import add_default_tasks, default_tasks_need_added

        if default_tasks_need_added(db):
            logger.info("Adding Default Tasks.")
            add_default_tasks(db)
    except Exception:
        logger.exception("Adding Default Tasks failed.")


def jinja_hex_decode(text):
    """Jinja2 filter to decode stored plaintext with legacy fallback."""
    from hashcrush.utils.utils import decode_plaintext_from_storage

    return decode_plaintext_from_storage(text)


def create_app(testing: bool = False, config_overrides: dict | None = None):
    app = Flask(__name__)

    # https://flask.palletsprojects.com/en/2.2.x/logging/
    # When you want to configure logging for your project, you should do it as
    # soon as possible when the program starts.
    loggingDictConfig(
        {
            "version": 1,
            "formatters": {
                "default": {
                    "format": "%(asctime)s [%(levelname)-8s] for %(name)s: %(message)s in (%(module)s:%(lineno)d)",
                }
            },
            "handlers": {
                "wsgi": {
                    "class": "logging.StreamHandler",
                    "stream": "ext://flask.logging.wsgi_errors_stream",
                    "formatter": "default",
                }
            },
            "root": {"level": "DEBUG" if app.debug else "INFO", "handlers": ["wsgi"]},
        }
    )
    logging.Formatter.formatTime = (
        lambda self, record, datefmt=None: datetime.datetime.fromtimestamp(
            record.created, datetime.UTC
        )
        .astimezone()
        .isoformat(sep="T", timespec="milliseconds")
    )

    from hashcrush.config import Config

    app.config.from_object(Config)

    # Sensible defaults; can be overridden via config_overrides or app config.
    # These are intentionally conservative for production deployments.
    app.config.setdefault("AUTO_SETUP_DEFAULTS", True)
    app.config.setdefault("ENABLE_SCHEDULER", False)
    app.config.setdefault("ENABLE_LOCAL_EXECUTOR", True)
    app.config.setdefault("SKIP_RUNTIME_BOOTSTRAP", False)
    app.config.setdefault("AUTO_NORMALIZE_PLAINTEXT_STORAGE", True)
    app.config.setdefault("AUTO_CREATE_SCHEMA", True)
    app.config.setdefault(
        "RUNTIME_PATH", os.path.join(tempfile.gettempdir(), "hashcrush-runtime")
    )

    if testing:
        app.config["TESTING"] = True

    if config_overrides:
        app.config.update(config_overrides)

    # Secure cookies by default in non-debug deployments.
    if app.config.get("SESSION_COOKIE_SECURE") is None:
        app.config["SESSION_COOKIE_SECURE"] = (not app.config.get("TESTING")) and (
            not app.debug
        )
    app.config["SESSION_COOKIE_HTTPONLY"] = bool(
        app.config.get("SESSION_COOKIE_HTTPONLY", True)
    )
    if app.config.get("SESSION_COOKIE_SAMESITE") not in {"Lax", "Strict", "None"}:
        app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    if (
        (not app.config.get("TESTING"))
        and (not app.debug)
        and (not app.config.get("SESSION_COOKIE_SECURE"))
    ):
        app.logger.warning(
            "SECURITY WARNING: SESSION_COOKIE_SECURE is disabled outside testing/debug."
        )

    _warn_insecure_configuration(app)

    if not app.config.get("SKIP_RUNTIME_BOOTSTRAP"):
        _ensure_runtime_directories(app.root_path, app.config.get("RUNTIME_PATH"))

    from hashcrush.models import db

    db.init_app(app)

    if (not app.config.get("TESTING")) and app.config.get("AUTO_CREATE_SCHEMA", True):
        _ensure_database_schema(app)

    csrf = CSRFProtect()
    csrf.init_app(app)

    from hashcrush.scheduler import scheduler

    scheduler.init_app(app)

    # Avoid starting background scheduler automatically in multi-worker deployments.
    # Enable explicitly via config to prevent duplicate jobs.
    if (
        (not app.config.get("TESTING"))
        and (not app.config.get("SKIP_RUNTIME_BOOTSTRAP"))
        and app.config.get("ENABLE_SCHEDULER", False)
    ):
        # Flask's reloader starts the app twice; only start scheduler in the reloader child.
        if (not app.debug) or (os.environ.get("WERKZEUG_RUN_MAIN") == "true"):
            scheduler.start()

    from hashcrush.users.routes import bcrypt

    bcrypt.init_app(app)

    from hashcrush.users.routes import login_manager

    login_manager.init_app(app)

    @app.context_processor
    def inject_csrf_token():
        return {"csrf_token": generate_csrf}

    from hashcrush.analytics.routes import analytics
    from hashcrush.audit_logs.routes import audit_logs
    from hashcrush.domains.routes import domains
    from hashcrush.hashfiles.routes import hashfiles
    from hashcrush.jobs.routes import jobs
    from hashcrush.main.routes import main
    from hashcrush.rules.routes import rules
    from hashcrush.searches.routes import searches
    from hashcrush.settings.routes import settings
    from hashcrush.setup.routes import blueprint as setup_blueprint
    from hashcrush.task_groups.routes import task_groups
    from hashcrush.tasks.routes import tasks
    from hashcrush.users.routes import users
    from hashcrush.wordlists.routes import wordlists

    app.register_blueprint(audit_logs)
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
        (not app.config.get("TESTING"))
        and (not app.config.get("SKIP_RUNTIME_BOOTSTRAP"))
        and app.config.get("AUTO_SETUP_DEFAULTS", True)
    ):
        with app.app_context():
            setup_defaults_if_needed()

    if (
        (not app.config.get("TESTING"))
        and (not app.config.get("SKIP_RUNTIME_BOOTSTRAP"))
        and app.config.get("AUTO_NORMALIZE_PLAINTEXT_STORAGE", True)
    ):
        with app.app_context():
            try:
                from hashcrush.utils.utils import migrate_plaintext_storage_rows

                migrated_rows = migrate_plaintext_storage_rows()
                if migrated_rows:
                    app.logger.info(
                        "Migrated %s legacy plaintext row(s) to canonical hex storage.",
                        migrated_rows,
                    )
            except Exception:
                app.logger.exception("Legacy plaintext migration failed.")

    app.before_request(do_gui_setup_if_needed)

    # Local single-node executor for queued JobTasks.
    if (
        (not app.config.get("TESTING"))
        and (not app.config.get("SKIP_RUNTIME_BOOTSTRAP"))
        and app.config.get("ENABLE_LOCAL_EXECUTOR", True)
    ):
        if (not app.debug) or (os.environ.get("WERKZEUG_RUN_MAIN") == "true"):
            from hashcrush.executor import LocalExecutorService

            local_executor = LocalExecutorService(app)
            local_executor.start()
            app.extensions["local_executor"] = local_executor

    return app
