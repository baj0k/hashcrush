"""Main Entry Point when running as standalone script"""
#!/usr/bin/python3
import sys
import os
import logging
import argparse
import builtins
import traceback
import importlib

from datetime import datetime
from pathlib import Path
from functools import partial

from hashcrush import create_app

# Application state
class AppState:
    debug = False
    
app_state = AppState()


def ensure_flask_bcrypt():
    """Ensuring flask_bcrypt module is installed"""

    try:
        flask_bcrypt = importlib.import_module('flask_bcrypt')
        if '1.0.1' >= flask_bcrypt.__version__:
            raise Exception('old version')
    except ImportError:
        print('\nPlease make sure that your dependencies are up to date (including replacing Flask-Bcrypt with Bcrypt-Flask).')
        exit(1)
    except Exception:
        print('\nPlease make sure that your dependencies are up to date (including replacing Flask-Bcrypt with Bcrypt-Flask).')
        exit(1)


def _resolve_ssl_context(app) -> tuple[str, str]:
    """Return validated SSL cert/key paths from app configuration."""
    cert_path = os.path.abspath(os.path.expanduser(str(app.config.get('SSL_CERT_PATH', '')).strip()))
    key_path = os.path.abspath(os.path.expanduser(str(app.config.get('SSL_KEY_PATH', '')).strip()))

    if not cert_path:
        raise RuntimeError('SSL is enabled but SSL_CERT_PATH is not configured.')
    if not key_path:
        raise RuntimeError('SSL is enabled but SSL_KEY_PATH is not configured.')
    if not os.path.isfile(cert_path):
        raise RuntimeError(f'SSL certificate file not found: {cert_path}')
    if not os.path.isfile(key_path):
        raise RuntimeError(f'SSL private key file not found: {key_path}')

    try:
        with open(cert_path, 'rb'):
            pass
    except OSError as exc:
        raise RuntimeError(f'SSL certificate file is not readable: {cert_path}') from exc

    try:
        with open(key_path, 'rb'):
            pass
    except OSError as exc:
        raise RuntimeError(f'SSL private key file is not readable: {key_path}') from exc

    return cert_path, key_path


def ensure_admin_account_cli(db, bcrypt):
    '''
    If no admins exist prompt user to generate new admin account
    '''
    from getpass import getpass

    from hashcrush.models import Users
    from hashcrush.setup import admin_user_needs_added

    if not admin_user_needs_added(db):
        print('✓ Admin user exists in database.')
        return

    else:
        print('\nInitial setup detected. HashCrush will now prompt you to setup an Administrative account.\n')
        admin_username = input('Enter username for the Administrator account. You will use this to log into the app: ')
        while len(admin_username) == 0:
            print('Error: You must provide a username.')
            admin_username = input("Invalid username. Try again: ")

        admin_password = getpass('Enter a password for the Administrator account: ')
        admin_password_verify = getpass('Re-Enter the password for the Administrator account: ')

        while len(admin_password) < 14 or admin_password != admin_password_verify:
            if len(admin_password) < 14:
                print('Error: Password must be more than 14 characters.')
            else:
                print('Error: Passwords do not match.')
            admin_password = getpass('Enter a password for the Administrator account: ')
            admin_password_verify = getpass('Re-Enter the password for the Administrator account: ')

        print('\nProvisioning account in database.')
        hashed_password = bcrypt.generate_password_hash(admin_password).decode('utf-8')

        user = Users(
            username=admin_username,
            password=hashed_password,
            admin=True,
        )
        db.session.add(user)
        db.session.commit()


def ensure_settings_cli(db):
    from hashcrush.models import Settings
    from hashcrush.setup import settings_needs_added

    if not settings_needs_added(db):
        print('Settings exist in database.')
        return

    else:
        settings = Settings(
            retention_period=0,
            enabled_job_weights=False,
        )
        db.session.add(settings)
        db.session.commit()


def _can_run_break_glass(config_path: Path) -> bool:
    """Allow break-glass reset for root or config owner."""
    if not hasattr(os, 'geteuid'):
        return True

    try:
        owner_uid = config_path.stat().st_uid
    except FileNotFoundError:
        # Missing config is handled by normal startup checks.
        return True
    except OSError:
        return False

    euid = os.geteuid()
    return (euid == 0) or (euid == owner_uid)


def reset_admin_password_cli(db, bcrypt, admin_username: str | None = None) -> int:
    """Locally reset an admin password without starting HTTP."""
    from getpass import getpass
    from hashcrush.models import Users

    if not sys.stdin.isatty():
        print('Error: --reset-admin-password requires an interactive terminal.', file=sys.stderr)
        return 1

    config_path = Path(__file__).resolve().parent / 'hashcrush' / 'config.conf'
    if not _can_run_break_glass(config_path):
        print('Error: run this command as root or as the config owner account.', file=sys.stderr)
        return 1

    admin_query = db.session.query(Users).filter_by(admin=True)
    if admin_username:
        admin_query = admin_query.filter_by(username=admin_username)

    admins = admin_query.order_by(Users.id.asc()).all()
    if not admins:
        print('Error: no matching admin account found.', file=sys.stderr)
        return 1

    target_admin = None
    if len(admins) == 1:
        target_admin = admins[0]
    else:
        print('Multiple admin accounts found:')
        for admin in admins:
            username = admin.username or '<empty username>'
            print(f'  id={admin.id} username={username}')
        selected = input('Enter admin username to reset: ').strip()
        if not selected:
            print('Error: admin username is required when multiple admins exist.', file=sys.stderr)
            return 1
        target_admin = next((admin for admin in admins if admin.username == selected), None)
        if not target_admin:
            print('Error: selected username not found in admin list.', file=sys.stderr)
            return 1

    username = target_admin.username or f'id={target_admin.id}'
    print(f'Preparing to reset password for admin account: {username}')
    confirmation = input('Type RESET to continue: ').strip()
    if confirmation != 'RESET':
        print('Canceled.')
        return 1

    new_password = getpass('Enter new admin password: ')
    confirm_password = getpass('Confirm new admin password: ')
    while len(new_password) < 14 or new_password != confirm_password:
        if len(new_password) < 14:
            print('Error: Password must be at least 14 characters.')
        else:
            print('Error: Passwords do not match.')
        new_password = getpass('Enter new admin password: ')
        confirm_password = getpass('Confirm new admin password: ')

    target_admin.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    target_admin.last_login_utc = datetime.utcnow()
    db.session.commit()
    print('Admin password reset complete.')
    return 0


def cli(args) -> int:
    """
        takes in command line args, and returns an exit code
    """
    # conforming to the standard command line interface provides for easier testing
    try:
        # sometimes when called, the first argument is the name of the script,
        # this does not need to be parsed, and should be removed from the args
        if Path(__file__).resolve() == Path(args[0]).resolve():
            args = args[1:]

        parser = argparse.ArgumentParser()
        parser.add_argument("--debug",  action="store_true", help="increase output verbosity")
        parser.add_argument("--no-ssl", action="store_true", help="disable use of ssl")
        parser.add_argument("--reset-admin-password", action="store_true", help="reset an admin password locally and exit")
        parser.add_argument("--admin-username", help="admin username to target with --reset-admin-password")
        parsed_args = parser.parse_args(args)

        if parsed_args.admin_username and (not parsed_args.reset_admin_password):
            parser.error('--admin-username requires --reset-admin-password')

        ensure_flask_bcrypt()

        app = create_app()
        with app.app_context():
            from hashcrush.models import db
            from hashcrush.users.routes import bcrypt
            from hashcrush.scheduler import data_retention_cleanup

            if parsed_args.reset_admin_password:
                return reset_admin_password_cli(db, bcrypt, parsed_args.admin_username)

            ensure_settings_cli(db)
            ensure_admin_account_cli(db, bcrypt)

            print('Done! Running HashCrush! Enjoy.')

            scheduler = app.apscheduler
            scheduler.remove_all_jobs()
            #scheduler.add_job(id='DATA_RETENTION', func=partial(data_retention_cleanup, app), trigger='cron', minute='*') #hour=1
            scheduler.add_job(id='DATA_RETENTION', func=partial(data_retention_cleanup, app), trigger='cron', hour='*')

        if parsed_args.debug:
            app_state.debug = True

        else:
            app_state.debug = False
            werkzeug_logger = logging.getLogger('werkzeug')
            werkzeug_logger.setLevel(logging.ERROR)

        if parsed_args.no_ssl:
            app.run(debug=parsed_args.debug)

        else:
            ssl_context = _resolve_ssl_context(app)
            app.run(host='0.0.0.0', port=8443, ssl_context=ssl_context, debug=parsed_args.debug)

    except Exception as ex:
        print(f'Exception!: {ex}', file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return 1

    else:
        return 0


if __name__ == '__main__':
    sys.exit(cli(sys.argv))

