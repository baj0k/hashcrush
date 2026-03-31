import datetime
import logging
import os
import ssl
import tempfile
from logging.config import dictConfig as loggingDictConfig

from flask import Flask, jsonify, request
from flask.testing import FlaskClient
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix

__version__ = "2.0"


class _HttpsFlaskClient(FlaskClient):
    """Default test client to HTTPS so secure cookies behave like production."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.environ_base.setdefault("wsgi.url_scheme", "https")
        self.environ_base.setdefault("HTTP_HOST", "localhost")


class _SuppressWerkzeugTlsDisconnects(logging.Filter):
    """Drop noisy werkzeug client-disconnect TLS EOF tracebacks only."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.name != "werkzeug":
            return True
        if not record.exc_info:
            return True
        _exc_type, exc_value, _exc_tb = record.exc_info
        return not isinstance(exc_value, ssl.SSLEOFError)


def _attach_werkzeug_tls_disconnect_filter() -> None:
    """Attach the TLS disconnect filter directly to Werkzeug loggers/handlers."""
    tls_filter = _SuppressWerkzeugTlsDisconnects()
    for logger_name in ("werkzeug", "werkzeug.serving"):
        logger = logging.getLogger(logger_name)
        logger.addFilter(tls_filter)
        for handler in logger.handlers:
            handler.addFilter(tls_filter)

def _validate_runtime_directories(
    root_path: str, runtime_root: str | None = None
) -> None:
    """Ensure runtime directories already exist and are writable."""
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
        if not os.path.isdir(runtime_dir):
            raise RuntimeError(
                "Runtime directory is missing. Run `python3 ./hashcrush.py setup` "
                f"or create it manually: {runtime_dir}"
            )
        if not os.access(runtime_dir, os.W_OK):
            raise RuntimeError(
                f"Runtime directory is not writable by the current process: {runtime_dir}"
            )


def _validate_storage_directories(storage_root: str | None) -> None:
    """Ensure persistent storage directories already exist and are writable."""
    storage_base = (
        os.path.abspath(os.path.expanduser(storage_root))
        if storage_root
        else os.path.join("/var", "lib", "hashcrush")
    )
    storage_dirs = (
        os.path.join(storage_base, "wordlists"),
        os.path.join(storage_base, "rules"),
    )
    for storage_dir in storage_dirs:
        if not os.path.isdir(storage_dir):
            raise RuntimeError(
                "Persistent storage directory is missing. Run `python3 ./hashcrush.py setup` "
                f"or create it manually: {storage_dir}"
            )
        if not os.access(storage_dir, os.W_OK):
                raise RuntimeError(
                    f"Persistent storage directory is not writable by the current process: {storage_dir}"
                )


def _format_bytes(size_bytes: int) -> str:
    """Render a byte count into a compact human-readable string."""
    units = ["bytes", "KB", "MB", "GB", "TB"]
    value = float(max(size_bytes, 0))
    unit_index = 0
    while value >= 1024 and unit_index < len(units) - 1:
        value /= 1024
        unit_index += 1
    if unit_index == 0:
        return f"{int(value)} {units[unit_index]}"
    return f"{value:.2f} {units[unit_index]}"


def _ensure_database_schema(app: Flask) -> None:
    """Guard startup against outdated or uninitialized schemas."""
    from hashcrush.db_upgrade import get_schema_status

    app.logger.info("Ensuring database schema exists.")
    with app.app_context():
        schema_status = get_schema_status()
        if not schema_status["has_user_tables"]:
            raise RuntimeError(
                "Database schema is uninitialized. Run `hashcrush.py setup` for a "
                "destructive bootstrap or `hashcrush.py upgrade` to initialize the "
                "tracked schema."
            )
        if not schema_status["tracked"]:
            raise RuntimeError(str(schema_status["detail"]))
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


def jinja_hex_decode(text):
    """Jinja2 filter to decode stored plaintext with legacy fallback."""
    from hashcrush.utils.secret_storage import decode_plaintext_from_storage

    return decode_plaintext_from_storage(text)


def jinja_ciphertext_decode(text):
    """Jinja2 filter to decode stored ciphertext with legacy fallback."""
    from hashcrush.utils.secret_storage import decode_ciphertext_from_storage

    return decode_ciphertext_from_storage(text)


def jinja_format_hashcat_speed(text):
    """Jinja2 filter to render hashcat speed strings in readable units."""
    from hashcrush.executor.hashcat_command import format_hashcat_speed

    return format_hashcat_speed(text)


def create_app(testing: bool = False, config_overrides: dict | None = None):
    app = Flask(__name__)

    # https://flask.palletsprojects.com/en/2.2.x/logging/
    # When you want to configure logging for your project, you should do it as
    # soon as possible when the program starts.
    loggingDictConfig(
        {
            "version": 1,
            "filters": {
                "suppress_werkzeug_tls_disconnects": {
                    "()": _SuppressWerkzeugTlsDisconnects,
                }
            },
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
                    "filters": ["suppress_werkzeug_tls_disconnects"],
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
    _attach_werkzeug_tls_disconnect_filter()

    from hashcrush.config import build_config

    app.config.from_mapping(build_config(config_overrides))

    # Sensible defaults; can be overridden via config_overrides or app config.
    app.config.setdefault("ENABLE_LOCAL_EXECUTOR", False)
    app.config.setdefault("SKIP_RUNTIME_BOOTSTRAP", False)
    app.config.setdefault(
        "RUNTIME_PATH", os.path.join(tempfile.gettempdir(), "hashcrush-runtime")
    )
    app.config.setdefault("STORAGE_PATH", os.path.join("/var", "lib", "hashcrush"))
    app.config.setdefault("UPLOAD_OPERATION_RETENTION_SECONDS", 3600)
    app.config.setdefault("UPLOAD_OPERATION_LEASE_SECONDS", 300)
    app.config.setdefault("UPLOAD_INLINE_MAX_WORKERS", 2)
    app.config.setdefault("UPLOAD_WORKER_POLL_INTERVAL_SECONDS", 2)

    if testing:
        app.config["TESTING"] = True

    if config_overrides:
        app.config.update(config_overrides)

    if app.config.get("ENABLE_INLINE_UPLOAD_WORKER") is None:
        app.config["ENABLE_INLINE_UPLOAD_WORKER"] = bool(app.config.get("TESTING"))

    # The application is expected to run over HTTPS only.
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_HTTPONLY"] = bool(
        app.config.get("SESSION_COOKIE_HTTPONLY", True)
    )
    if app.config.get("SESSION_COOKIE_SAMESITE") not in {"Lax", "Strict", "None"}:
        app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    if app.config.get("TRUST_X_FORWARDED_FOR"):
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=1,
            x_proto=1,
        )
        app.config.setdefault("PREFERRED_URL_SCHEME", "https")
    if app.config.get("TESTING"):
        app.test_client_class = _HttpsFlaskClient

    _warn_insecure_configuration(app)

    if (not app.config.get("TESTING")) and (not app.config.get("SKIP_RUNTIME_BOOTSTRAP")):
        _validate_runtime_directories(app.root_path, app.config.get("RUNTIME_PATH"))
        _validate_storage_directories(app.config.get("STORAGE_PATH"))

    from hashcrush.models import db

    db.init_app(app)

    if (not app.config.get("TESTING")) and (not app.config.get("SKIP_RUNTIME_BOOTSTRAP")):
        _ensure_database_schema(app)

    csrf = CSRFProtect()
    csrf.init_app(app)

    @app.errorhandler(RequestEntityTooLarge)
    def handle_request_entity_too_large(error):
        limit = app.config.get("MAX_CONTENT_LENGTH")
        detail = "Uploaded payload exceeds the configured size limit."
        if isinstance(limit, int) and limit > 0:
            detail = (
                "Uploaded payload exceeds the configured size limit "
                f"of {_format_bytes(limit)}."
            )
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return (
                jsonify(
                    {
                        "title": "Upload too large.",
                        "detail": detail,
                        "error": detail,
                    }
                ),
                413,
            )
        return detail, 413

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
    from hashcrush.task_groups.routes import task_groups
    from hashcrush.tasks.routes import tasks
    from hashcrush.uploads.routes import uploads
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
    app.register_blueprint(uploads)
    app.register_blueprint(users)
    app.register_blueprint(wordlists)
    app.register_blueprint(analytics)
    app.register_blueprint(searches)

    app.add_template_filter(jinja_hex_decode)
    app.add_template_filter(jinja_ciphertext_decode)
    app.add_template_filter(jinja_format_hashcat_speed)
    app.add_template_global(get_application_version, get_application_version.__name__)
    from hashcrush.uploads import UploadOperationService

    app.extensions["upload_operations"] = UploadOperationService(app)

    return app
