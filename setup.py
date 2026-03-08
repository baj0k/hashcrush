#!/usr/bin/python3
import sys
import os
import subprocess
import secrets
import tempfile
from configparser import ConfigParser
from getpass import getpass

CONFIG_PATH = os.path.join('hashcrush', 'config.conf')
LOCAL_MYSQL_HOST = '127.0.0.1'
LOCAL_MYSQL_HOST_ALIASES = {'localhost', '127.0.0.1', '::1'}
DEFAULT_DB_HOST = '127.0.0.1'
DEFAULT_HASHCAT_BIN = '/usr/bin/hashcat'
DEFAULT_HASHCAT_STATUS_TIMER = 5
DEFAULT_WORDLISTS_PATH = '/usr/share/seclists/Passwords'
DEFAULT_RULES_PATH = '/usr/share/hashcat/rules'
DEFAULT_RUNTIME_PATH = '/tmp/hashcrush-runtime'
DEFAULT_SSL_DIR = '/etc/hashcrush/ssl'


def _read_existing_app_value(config_path: str, key: str) -> str | None:
    parser = ConfigParser()
    if not os.path.exists(config_path):
        return None
    parser.read(config_path, encoding='utf-8')
    value = parser.get('app', key, fallback='').strip()
    return value or None


def _prompt_existing_directory(prompt: str, default: str | None) -> str:
    while True:
        suffix = f' [{default}]' if default else ''
        value = input(f'{prompt}{suffix}: ').strip()
        if not value:
            value = default or ''
        resolved = os.path.abspath(os.path.expanduser(value))
        if not resolved:
            print('Error: path is required.')
            continue
        if not os.path.isdir(resolved):
            print(f'Error: directory does not exist: {resolved}')
            continue
        return resolved


def _prompt_writable_directory(prompt: str, default: str | None) -> str:
    while True:
        suffix = f' [{default}]' if default else ''
        value = input(f'{prompt}{suffix}: ').strip()
        if not value:
            value = default or ''
        resolved = os.path.abspath(os.path.expanduser(value))
        if not resolved:
            print('Error: path is required.')
            continue
        try:
            os.makedirs(resolved, exist_ok=True)
            probe_file = os.path.join(resolved, f'.write-probe-{secrets.token_hex(4)}')
            with open(probe_file, 'w', encoding='utf-8') as handle:
                handle.write('ok')
            os.remove(probe_file)
        except OSError as exc:
            print(f'Error: cannot write to directory "{resolved}": {exc}')
            continue
        return resolved


def _set_path_mode(path: str, mode: int) -> None:
    if not hasattr(os, 'chmod'):
        return
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _ensure_runtime_directories(
    runtime_root: str,
    ssl_cert_path: str,
    ssl_key_path: str,
) -> None:
    runtime_dirs = (
        os.path.join(runtime_root, 'tmp'),
        os.path.join(runtime_root, 'hashes'),
        os.path.join(runtime_root, 'outfiles'),
        os.path.dirname(ssl_cert_path),
        os.path.dirname(ssl_key_path),
    )
    for runtime_dir in runtime_dirs:
        os.makedirs(runtime_dir, exist_ok=True)
    _set_path_mode(os.path.dirname(ssl_cert_path), 0o700)
    _set_path_mode(os.path.dirname(ssl_key_path), 0o700)


def _write_config_atomic(
    config_path: str,
    db_server: str,
    db_username: str,
    db_password: str,
    secret_key: str,
    hashcat_bin: str,
    hashcat_status_timer: int,
    wordlists_path: str,
    rules_path: str,
    runtime_path: str,
    ssl_cert_path: str,
    ssl_key_path: str,
) -> None:
    parser = ConfigParser()
    parser['database'] = {
        'host': db_server,
        'username': db_username,
        'password': db_password,
    }
    parser['app'] = {
        'secret_key': secret_key,
        'hashcat_bin': hashcat_bin,
        'hashcat_status_timer': str(hashcat_status_timer),
        'wordlists_path': wordlists_path,
        'rules_path': rules_path,
        'runtime_path': runtime_path,
        'ssl_cert_path': ssl_cert_path,
        'ssl_key_path': ssl_key_path,
    }

    config_dir = os.path.dirname(config_path) or '.'
    os.makedirs(config_dir, exist_ok=True)

    if hasattr(os, 'chmod'):
        try:
            os.chmod(config_dir, 0o700)
        except OSError:
            pass

    fd, tmp_path = tempfile.mkstemp(prefix='.config.', dir=config_dir)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as config_file:
            parser.write(config_file)
            config_file.flush()
            os.fsync(config_file.fileno())
        os.replace(tmp_path, config_path)

        if hasattr(os, 'chmod'):
            try:
                os.chmod(config_path, 0o600)
            except OSError:
                pass
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def _escape_mysql_string(value: str) -> str:
    return value.replace('\\', '\\\\').replace("'", "''")


def _normalize_local_mysql_host(value: str) -> str:
    normalized = value.strip().lower()
    if normalized == 'localhost':
        return 'localhost'
    if normalized == '127.0.0.1':
        return '127.0.0.1'
    if normalized == '::1':
        return '::1'
    return normalized


def _bootstrap_local_mysql(app_username: str, app_password: str) -> None:
    escaped_user = _escape_mysql_string(app_username)
    escaped_pass = _escape_mysql_string(app_password)
    sql_lines = [
        "DROP DATABASE IF EXISTS hashcrush;",
        f"DROP USER IF EXISTS '{escaped_user}'@'localhost';",
        f"DROP USER IF EXISTS '{escaped_user}'@'127.0.0.1';",
        f"DROP USER IF EXISTS '{escaped_user}'@'::1';",
        "CREATE DATABASE hashcrush;",
        f"CREATE USER '{escaped_user}'@'localhost' IDENTIFIED BY '{escaped_pass}';",
        f"CREATE USER '{escaped_user}'@'127.0.0.1' IDENTIFIED BY '{escaped_pass}';",
        f"CREATE USER '{escaped_user}'@'::1' IDENTIFIED BY '{escaped_pass}';",
        f"GRANT ALL PRIVILEGES ON hashcrush.* TO '{escaped_user}'@'localhost';",
        f"GRANT ALL PRIVILEGES ON hashcrush.* TO '{escaped_user}'@'127.0.0.1';",
        f"GRANT ALL PRIVILEGES ON hashcrush.* TO '{escaped_user}'@'::1';",
        "FLUSH PRIVILEGES;",
    ]
    sql = "\n".join(sql_lines) + "\n"

    subprocess.run(['sudo', 'mysql'], input=sql.encode('utf-8'), check=True)

# Check version of python
if sys.version_info < (3, 10):
    print('You must be running python 3.10 or newer')
    sys.exit()

# Check if running as root
if getattr(os, 'geteuid', lambda: 1)() == 0:
    print('HashCrush has no need to run as root unless you intend to host the web service on a port < 1024.')
    print('If you continue, any installed python modules will be installed as root.')
    continue_as_root = input('Would you like to continue as root? [y/N]: ')
    if continue_as_root.lower() != 'y':
        sys.exit()

# Install dependencies
subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt', '--break-system-packages'], check=True)

print('\nCollecting HashCrush Database Configuration Information')
db_server = input(f'Enter the IP or hostname of the server running mysql [{DEFAULT_DB_HOST}]: ').strip()
if len(db_server) == 0:
    db_server = DEFAULT_DB_HOST
while db_server.strip().lower() not in LOCAL_MYSQL_HOST_ALIASES:
    print('Error: setup.py requires local mysql host (127.0.0.1, localhost, or ::1).')
    db_server = input(f'Enter the IP or hostname of the server running mysql [{DEFAULT_DB_HOST}]: ').strip()
    if len(db_server) == 0:
        db_server = DEFAULT_DB_HOST
db_server = _normalize_local_mysql_host(db_server)

db_username = input('Enter the user account hashcrush should use to connect to the mysql instance: ')
while len(db_username) == 0:
    print("Error: Invalid entry. Please try again.")
    db_username = input('Enter the user account hashcrush should use to connect to the mysql instance: ')

db_password = getpass('Enter the password for ' + db_username + ': ')
while len(db_password) == 0:
    print("Error: You must provide a password.")
    db_password = getpass('Enter the password for ' + db_username + ': ')

config_exists = os.path.exists(CONFIG_PATH)
existing_hashcat_bin = _read_existing_app_value(CONFIG_PATH, 'hashcat_bin')
existing_wordlists_path = _read_existing_app_value(CONFIG_PATH, 'wordlists_path')
existing_rules_path = _read_existing_app_value(CONFIG_PATH, 'rules_path')
existing_runtime_path = _read_existing_app_value(CONFIG_PATH, 'runtime_path')
existing_ssl_cert_path = _read_existing_app_value(CONFIG_PATH, 'ssl_cert_path')
existing_ssl_key_path = _read_existing_app_value(CONFIG_PATH, 'ssl_key_path')

wordlists_default = (
    os.getenv('HASHCRUSH_WORDLISTS_PATH')
    or existing_wordlists_path
    or DEFAULT_WORDLISTS_PATH
)
rules_default = (
    os.getenv('HASHCRUSH_RULES_PATH')
    or existing_rules_path
    or DEFAULT_RULES_PATH
)

print('\nCollecting External Dictionary and Rules Paths')
wordlists_path = _prompt_existing_directory(
    'Enter path to the SecLists/Passwords wordlists root',
    wordlists_default,
)
rules_path = _prompt_existing_directory(
    'Enter path to the hashcat rules root',
    rules_default,
)

runtime_default = (
    os.getenv('HASHCRUSH_RUNTIME_PATH')
    or existing_runtime_path
    or DEFAULT_RUNTIME_PATH
)
runtime_path = input(
    f'Enter path for runtime temp/artifact storage [{runtime_default}]: '
).strip()
if len(runtime_path) == 0:
    runtime_path = runtime_default
runtime_path = os.path.abspath(os.path.expanduser(runtime_path))
os.makedirs(runtime_path, exist_ok=True)

project_root = os.path.abspath(os.path.dirname(__file__))
env_ssl_cert_path = (os.getenv('HASHCRUSH_SSL_CERT_PATH') or '').strip()
env_ssl_key_path = (os.getenv('HASHCRUSH_SSL_KEY_PATH') or '').strip()
existing_ssl_dir = None
if existing_ssl_cert_path and existing_ssl_key_path:
    existing_cert_dir = os.path.dirname(os.path.abspath(os.path.expanduser(existing_ssl_cert_path)))
    existing_key_dir = os.path.dirname(os.path.abspath(os.path.expanduser(existing_ssl_key_path)))
    if existing_cert_dir == existing_key_dir:
        existing_ssl_dir = existing_cert_dir
env_ssl_dir = None
if env_ssl_cert_path and env_ssl_key_path:
    env_cert_dir = os.path.dirname(os.path.abspath(os.path.expanduser(env_ssl_cert_path)))
    env_key_dir = os.path.dirname(os.path.abspath(os.path.expanduser(env_ssl_key_path)))
    if env_cert_dir == env_key_dir:
        env_ssl_dir = env_cert_dir

ssl_dir_default = env_ssl_dir or existing_ssl_dir or DEFAULT_SSL_DIR
ssl_dir = _prompt_writable_directory(
    'Enter path for TLS certificate/key directory',
    ssl_dir_default,
)
ssl_cert_path = os.path.join(ssl_dir, 'cert.pem')
ssl_key_path = os.path.join(ssl_dir, 'key.pem')

if config_exists and existing_hashcat_bin:
    preserve_hashcat_bin = input(
        f'config.conf exists. Preserve existing hashcat_bin "{existing_hashcat_bin}"? [Y/n]: '
    ).strip().lower()
    while preserve_hashcat_bin not in {'', 'y', 'yes', 'n', 'no'}:
        print('Error: enter Y or N.')
        preserve_hashcat_bin = input(
            f'config.conf exists. Preserve existing hashcat_bin "{existing_hashcat_bin}"? [Y/n]: '
        ).strip().lower()

    if preserve_hashcat_bin in {'', 'y', 'yes'}:
        hashcat_bin = existing_hashcat_bin
    else:
        hashcat_bin = input(f'Enter path to hashcat binary [{DEFAULT_HASHCAT_BIN}]: ').strip()
        if len(hashcat_bin) == 0:
            hashcat_bin = DEFAULT_HASHCAT_BIN
else:
    hashcat_bin_default = existing_hashcat_bin or DEFAULT_HASHCAT_BIN
    hashcat_bin = input(f'Enter path to hashcat binary [{hashcat_bin_default}]: ').strip()
    if len(hashcat_bin) == 0:
        hashcat_bin = hashcat_bin_default

# Rebuild the DB
print('\nCreating local MySQL database')
_bootstrap_local_mysql(db_username, db_password)

# Write config file
secret_key = secrets.token_urlsafe(64)
_write_config_atomic(
    CONFIG_PATH,
    db_server,
    db_username,
    db_password,
    secret_key,
    hashcat_bin,
    DEFAULT_HASHCAT_STATUS_TIMER,
    wordlists_path,
    rules_path,
    runtime_path,
    ssl_cert_path,
    ssl_key_path,
)
print(f'Writing hashcrush config at: {CONFIG_PATH}')
print('Generated a new app secret_key and stored it in config.')
print(f'Set hashcat_bin={hashcat_bin}')
print(f'Set hashcat_status_timer={DEFAULT_HASHCAT_STATUS_TIMER}')
print(f"Set wordlists_path={wordlists_path or '(app default)'}")
print(f"Set rules_path={rules_path or '(app default)'}")
print(f"Set runtime_path={runtime_path}")
print(f"Set ssl_cert_path={ssl_cert_path}")
print(f"Set ssl_key_path={ssl_key_path}")

# TODO POSSIBLE IMPROVEMENT There's probably a better way to do this:
print('Building database schema')
env = os.environ.copy()
env['FLASK_APP'] = 'hashcrush.py'
subprocess.run(['flask', 'db', 'upgrade'], check=True, env=env)

# Generating SSL Certs
print('Generating SSL Certificates')
_ensure_runtime_directories(runtime_path, ssl_cert_path, ssl_key_path)
subprocess.run([
    'openssl',
    'req',
    '-x509',
    '-newkey',
    'rsa:4096',
    '-nodes',
    '-out',
    ssl_cert_path,
    '-keyout',
    ssl_key_path,
    '-days',
    '365',
    '-subj',
    '/C=XX/ST=Local/L=Local/O=HashCrush/OU=Setup/CN=localhost',
], check=True)
_set_path_mode(ssl_cert_path, 0o644)
_set_path_mode(ssl_key_path, 0o600)

print('You can now start your instance of hashcrush by running the following command: ./hashcrush.py')
print('Done.')
