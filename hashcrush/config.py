"""Manage parsing of config.conf and loading into the Flask Config."""
import os
import tempfile
from configparser import ConfigParser

file_config = ConfigParser()


def _normalize_dir_path(value: str | None, fallback: str) -> str:
    selected = (value or fallback or '').strip()
    if not selected:
        selected = fallback
    return os.path.abspath(os.path.expanduser(selected))


class Config:
    """Class representing Config"""

    _config_path = os.getenv('HASHCRUSH_CONFIG_PATH', 'hashcrush/config.conf')
    _config_files = file_config.read(_config_path)
    if not _config_files:
        raise RuntimeError(
            f"Missing config file: {_config_path}. "
            "Create it from hashcrush/config.conf.example (or refer to README)."
        )

    try:
        SQLALCHEMY_DATABASE_URI = (
            'mysql+mysqlconnector://'
            + file_config['database']['username'] + ':'
            + file_config['database']['password'] + '@'
            + file_config['database']['host'] + '/hashcrush'
        )
    except KeyError as exc:
        raise RuntimeError(
            "Invalid config file: expected [database] section with username/password/host."
        ) from exc

    # Require explicit key from env/app config.
    _configured_secret = (
        os.getenv('HASHCRUSH_SECRET_KEY')
        or file_config.get('app', 'secret_key', fallback=None)
    )
    if _configured_secret:
        SECRET_KEY = _configured_secret
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

    SQLALCHEMY_TRACK_MODIFICATIONS = False
