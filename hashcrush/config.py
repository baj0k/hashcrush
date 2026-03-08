"""Manage parsing of config.conf and loading into the Flask Config."""
import os
import tempfile
from configparser import ConfigParser

file_config = ConfigParser(interpolation=None)


def _normalize_dir_path(value: str | None, fallback: str) -> str:
    selected = (value or fallback or '').strip()
    if not selected:
        selected = fallback
    return os.path.abspath(os.path.expanduser(selected))


def _normalize_file_path(value: str | None, fallback: str) -> str:
    selected = (value or fallback or '').strip()
    if not selected:
        selected = fallback
    return os.path.abspath(os.path.expanduser(selected))


class Config:
    """Class representing Config"""

    _config_path = os.getenv('HASHCRUSH_CONFIG_PATH', 'hashcrush/config.conf')
    _config_files = file_config.read(_config_path)
    _database_uri_from_env = (os.getenv('HASHCRUSH_DATABASE_URI') or '').strip()
    if _database_uri_from_env:
        SQLALCHEMY_DATABASE_URI = _database_uri_from_env
    else:
        _db_host = (
            os.getenv('HASHCRUSH_DB_HOST')
            or file_config.get('database', 'host', fallback='')
        ).strip()
        _db_username = (
            os.getenv('HASHCRUSH_DB_USERNAME')
            or file_config.get('database', 'username', fallback='')
        ).strip()
        _db_password = (
            os.getenv('HASHCRUSH_DB_PASSWORD')
            or file_config.get('database', 'password', fallback='')
        ).strip()

        if not (_db_host and _db_username and _db_password):
            if _config_files:
                raise RuntimeError(
                    "Invalid database configuration. Provide HASHCRUSH_DATABASE_URI or HASHCRUSH_DB_HOST/"
                    "HASHCRUSH_DB_USERNAME/HASHCRUSH_DB_PASSWORD, or set [database] host/username/password in config."
                )
            raise RuntimeError(
                f"Missing config file: {_config_path}. Create it from hashcrush/config.conf.example, "
                "or set HASHCRUSH_DATABASE_URI (or HASHCRUSH_DB_HOST/HASHCRUSH_DB_USERNAME/HASHCRUSH_DB_PASSWORD)."
            )

        SQLALCHEMY_DATABASE_URI = (
            'mysql+mysqlconnector://'
            + _db_username + ':'
            + _db_password + '@'
            + _db_host + '/hashcrush'
        )

    # Require explicit key from env/app config.
    _configured_secret = (
        os.getenv('HASHCRUSH_SECRET_KEY')
        or file_config.get('app', 'secret_key', fallback='')
    )
    if _configured_secret and _configured_secret.strip():
        SECRET_KEY = _configured_secret.strip()
    else:
        raise RuntimeError(
            "Missing application secret key. Set HASHCRUSH_SECRET_KEY or [app] secret_key in config.conf."
        )

    _hashcat_bin = (
        os.getenv('HASHCRUSH_HASHCAT_BIN')
        or file_config.get('app', 'hashcat_bin', fallback='hashcat')
    )
    HASHCAT_BIN = _hashcat_bin.strip() if _hashcat_bin else 'hashcat'

    try:
        HASHCAT_STATUS_TIMER = int(
            os.getenv('HASHCRUSH_HASHCAT_STATUS_TIMER')
            or file_config.get('app', 'hashcat_status_timer', fallback='5')
        )
    except ValueError:
        HASHCAT_STATUS_TIMER = 5

    _default_wordlists_path = '/usr/share/seclists/Passwords'
    _default_rules_path = '/usr/share/hashcat/rules'
    _default_runtime_path = os.path.join(tempfile.gettempdir(), 'hashcrush-runtime')
    _default_ssl_cert_path = os.path.join(os.path.dirname(__file__), 'ssl', 'cert.pem')
    _default_ssl_key_path = os.path.join(os.path.dirname(__file__), 'ssl', 'key.pem')

    WORDLISTS_PATH = _normalize_dir_path(
        os.getenv('HASHCRUSH_WORDLISTS_PATH')
        or file_config.get('app', 'wordlists_path', fallback=_default_wordlists_path),
        _default_wordlists_path,
    )
    RULES_PATH = _normalize_dir_path(
        os.getenv('HASHCRUSH_RULES_PATH')
        or file_config.get('app', 'rules_path', fallback=_default_rules_path),
        _default_rules_path,
    )
    RUNTIME_PATH = _normalize_dir_path(
        os.getenv('HASHCRUSH_RUNTIME_PATH')
        or file_config.get('app', 'runtime_path', fallback=_default_runtime_path),
        _default_runtime_path,
    )
    SSL_CERT_PATH = _normalize_file_path(
        os.getenv('HASHCRUSH_SSL_CERT_PATH')
        or file_config.get('app', 'ssl_cert_path', fallback=_default_ssl_cert_path),
        _default_ssl_cert_path,
    )
    SSL_KEY_PATH = _normalize_file_path(
        os.getenv('HASHCRUSH_SSL_KEY_PATH')
        or file_config.get('app', 'ssl_key_path', fallback=_default_ssl_key_path),
        _default_ssl_key_path,
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False
