#!/usr/bin/python3
"""Main CLI entry point for HashCrush."""

import argparse
import importlib
import logging
import os
import sys
import traceback
from datetime import datetime
from pathlib import Path

from sqlalchemy import select


class AppState:
    debug = False


app_state = AppState()


def ensure_flask_bcrypt():
    """Ensure flask_bcrypt is importable and new enough."""
    try:
        flask_bcrypt = importlib.import_module("flask_bcrypt")
        if "1.0.1" >= flask_bcrypt.__version__:
            raise Exception("old version")
    except ImportError:
        print(
            "\nPlease make sure that your dependencies are up to date "
            "(including replacing Flask-Bcrypt with Bcrypt-Flask)."
        )
        raise SystemExit(1) from None
    except Exception:
        print(
            "\nPlease make sure that your dependencies are up to date "
            "(including replacing Flask-Bcrypt with Bcrypt-Flask)."
        )
        raise SystemExit(1) from None


def _load_create_app():
    from hashcrush import create_app

    return create_app


def _load_bootstrap_cli():
    repo_root = Path(__file__).resolve().parent
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    return importlib.import_module("bootstrap_cli")


def _load_external_repos_cli():
    repo_root = Path(__file__).resolve().parent
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    return importlib.import_module("external_repos_cli")


def _resolve_ssl_context(app) -> tuple[str, str]:
    """Return validated SSL cert/key paths from app configuration."""
    cert_path = os.path.abspath(
        os.path.expanduser(str(app.config.get("SSL_CERT_PATH", "")).strip())
    )
    key_path = os.path.abspath(
        os.path.expanduser(str(app.config.get("SSL_KEY_PATH", "")).strip())
    )

    if not cert_path:
        raise RuntimeError("SSL is enabled but SSL_CERT_PATH is not configured.")
    if not key_path:
        raise RuntimeError("SSL is enabled but SSL_KEY_PATH is not configured.")
    if not os.path.isfile(cert_path):
        raise RuntimeError(f"SSL certificate file not found: {cert_path}")
    if not os.path.isfile(key_path):
        raise RuntimeError(f"SSL private key file not found: {key_path}")

    try:
        with open(cert_path, "rb"):
            pass
    except OSError as exc:
        raise RuntimeError(
            f"SSL certificate file is not readable: {cert_path}"
        ) from exc

    try:
        with open(key_path, "rb"):
            pass
    except OSError as exc:
        raise RuntimeError(
            f"SSL private key file is not readable: {key_path}"
        ) from exc

    return cert_path, key_path


def _runtime_bootstrap_errors(db) -> list[str]:
    from hashcrush.setup import admin_user_needs_added, settings_needs_added

    errors: list[str] = []
    if settings_needs_added(db):
        errors.append(
            "Settings row is missing. Run `python3 ./hashcrush.py setup` to bootstrap the instance."
        )
    if admin_user_needs_added(db):
        errors.append(
            "Admin account is missing. Run `python3 ./hashcrush.py setup` to bootstrap the instance."
        )
    return errors


def _can_run_break_glass(config_path: Path) -> bool:
    """Allow break-glass reset for root or config owner."""
    if not hasattr(os, "geteuid"):
        return True

    try:
        owner_uid = config_path.stat().st_uid
    except FileNotFoundError:
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
        print(
            "Error: --reset-admin-password requires an interactive terminal.",
            file=sys.stderr,
        )
        return 1

    config_path = Path(__file__).resolve().parent / "hashcrush" / "config.conf"
    if not _can_run_break_glass(config_path):
        print(
            "Error: run this command as root or as the config owner account.",
            file=sys.stderr,
        )
        return 1

    admin_stmt = select(Users).filter_by(admin=True)
    if admin_username:
        admin_stmt = admin_stmt.filter_by(username=admin_username)

    admins = db.session.execute(admin_stmt.order_by(Users.id.asc())).scalars().all()
    if not admins:
        print("Error: no matching admin account found.", file=sys.stderr)
        return 1

    target_admin = None
    if len(admins) == 1:
        target_admin = admins[0]
    else:
        print("Multiple admin accounts found:")
        for admin in admins:
            username = admin.username or "<empty username>"
            print(f"  id={admin.id} username={username}")
        selected = input("Enter admin username to reset: ").strip()
        if not selected:
            print(
                "Error: admin username is required when multiple admins exist.",
                file=sys.stderr,
            )
            return 1
        target_admin = next(
            (admin for admin in admins if admin.username == selected),
            None,
        )
        if not target_admin:
            print(
                "Error: selected username not found in admin list.",
                file=sys.stderr,
            )
            return 1

    username = target_admin.username or f"id={target_admin.id}"
    print(f"Preparing to reset password for admin account: {username}")
    confirmation = input("Type RESET to continue: ").strip()
    if confirmation != "RESET":
        print("Canceled.")
        return 1

    new_password = getpass("Enter new admin password: ")
    confirm_password = getpass("Confirm new admin password: ")
    while len(new_password) < 14 or new_password != confirm_password:
        if len(new_password) < 14:
            print("Error: Password must be at least 14 characters.")
        else:
            print("Error: Passwords do not match.")
        new_password = getpass("Enter new admin password: ")
        confirm_password = getpass("Confirm new admin password: ")

    target_admin.password = bcrypt.generate_password_hash(new_password).decode("utf-8")
    target_admin.last_login_utc = datetime.utcnow()
    db.session.commit()
    print("Admin password reset complete.")
    return 0


def _build_root_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="HashCrush command-line interface.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=("serve", "setup", "upgrade", "external-repos"),
        help="command to run (default: serve)",
    )
    parser.add_argument(
        "command_args",
        nargs=argparse.REMAINDER,
        help=argparse.SUPPRESS,
    )
    return parser


def _build_serve_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--debug", action="store_true", help="increase output verbosity")
    parser.add_argument(
        "--reset-admin-password",
        action="store_true",
        help="reset an admin password locally and exit",
    )
    parser.add_argument(
        "--admin-username",
        help="admin username to target with --reset-admin-password",
    )
    return parser


def _build_upgrade_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="show pending schema migrations without applying them",
    )
    return parser


def _normalize_cli_args(args: list[str]) -> list[str]:
    if not args:
        return []
    try:
        if Path(__file__).resolve() == Path(args[0]).resolve():
            return args[1:]
    except OSError:
        pass
    return args


def _parse_serve_args(args: list[str]) -> argparse.Namespace:
    parser = _build_serve_parser()
    parsed_args = parser.parse_args(args)
    if parsed_args.admin_username and (not parsed_args.reset_admin_password):
        parser.error("--admin-username requires --reset-admin-password")
    return parsed_args


def _parse_upgrade_args(args: list[str]) -> argparse.Namespace:
    return _build_upgrade_parser().parse_args(args)


def _run_serve(parsed_args: argparse.Namespace) -> int:
    ensure_flask_bcrypt()

    create_app = _load_create_app()
    app = create_app()
    with app.app_context():
        from hashcrush.models import db
        from hashcrush.users.routes import bcrypt

        if parsed_args.reset_admin_password:
            return reset_admin_password_cli(db, bcrypt, parsed_args.admin_username)

        bootstrap_errors = _runtime_bootstrap_errors(db)
        if bootstrap_errors:
            for error in bootstrap_errors:
                print(f"Error: {error}", file=sys.stderr)
            return 1

        print("Done! Running HashCrush! Enjoy.")

    if parsed_args.debug:
        app_state.debug = True
    else:
        app_state.debug = False
        werkzeug_logger = logging.getLogger("werkzeug")
        werkzeug_logger.setLevel(logging.ERROR)

    ssl_context = _resolve_ssl_context(app)
    app.run(
        host="0.0.0.0",
        port=8443,
        ssl_context=ssl_context,
        debug=parsed_args.debug,
    )
    return 0


def _run_setup(args: list[str]) -> int:
    bootstrap_cli = _load_bootstrap_cli()
    return bootstrap_cli.main(args)


def _run_external_repos(args: list[str]) -> int:
    external_repos_cli = _load_external_repos_cli()
    return external_repos_cli.main(args)


def _run_upgrade(parsed_args: argparse.Namespace) -> int:
    create_app = _load_create_app()
    app = create_app(
        config_overrides={
            "ENABLE_LOCAL_EXECUTOR": False,
            "SKIP_RUNTIME_BOOTSTRAP": True,
        }
    )
    with app.app_context():
        from hashcrush.db_upgrade import upgrade_database
        from hashcrush.utils.utils import migrate_plaintext_storage_rows

        result = upgrade_database(dry_run=parsed_args.dry_run)
        normalized_rows = 0
        if not parsed_args.dry_run:
            normalized_rows = migrate_plaintext_storage_rows()

    print(
        f"Schema version: {result.starting_version} -> {result.target_version}"
        + (" (dry-run)" if result.dry_run else "")
    )
    if result.initialized_empty_schema:
        print("Initializing empty schema with version tracking.")
    if result.applied_steps:
        for step in result.applied_steps:
            print(f"- v{step.version}: {step.summary}")
    else:
        print("No schema changes were required.")
    if not parsed_args.dry_run and normalized_rows:
        print(
            "Normalized "
            f"{normalized_rows} legacy plaintext row(s) to canonical hex storage."
        )
    return 0


def cli(args) -> int:
    """Process command line args and return an exit code."""
    try:
        argv = _normalize_cli_args(list(args))

        if not argv:
            return _run_serve(_parse_serve_args([]))

        first = argv[0]
        if first in {"-h", "--help", "help"}:
            _build_root_parser().print_help()
            return 0
        if first == "setup":
            return _run_setup(argv[1:])
        if first == "upgrade":
            return _run_upgrade(_parse_upgrade_args(argv[1:]))
        if first == "external-repos":
            return _run_external_repos(argv[1:])
        if first == "serve":
            return _run_serve(_parse_serve_args(argv[1:]))
        if first.startswith("-"):
            return _run_serve(_parse_serve_args(argv))

        _build_root_parser().error(f"unknown command: {first}")
        return 2
    except SystemExit:
        raise
    except Exception as ex:
        print(f"Exception!: {ex}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(cli(sys.argv))
