#!/usr/bin/python3
"""Main CLI entry point for HashCrush."""

import argparse
import importlib
import logging
import os
import signal
import sys
import traceback

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


def _runtime_bootstrap_errors(db) -> list[str]:
    from hashcrush.setup import admin_user_needs_added

    errors: list[str] = []
    if admin_user_needs_added(db):
        errors.append(
            "Admin account is missing. Check HASHCRUSH_INITIAL_ADMIN_USERNAME and "
            "HASHCRUSH_INITIAL_ADMIN_PASSWORD environment variables and re-run the bootstrap container."
        )
    return errors


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

    from hashcrush.utils.storage_paths import utc_now_naive

    target_admin.password = bcrypt.generate_password_hash(new_password).decode("utf-8")
    target_admin.last_login_utc = utc_now_naive()
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
        choices=("worker", "upload-worker", "upgrade", "reset-admin-password"),
        help="command to run",
    )
    parser.add_argument(
        "command_args",
        nargs=argparse.REMAINDER,
        help=argparse.SUPPRESS,
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


def _build_worker_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=2.0,
        help="seconds between executor queue polls (default: 2.0)",
    )
    return parser


def _build_upload_worker_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=2.0,
        help="seconds between queued upload polls (default: 2.0)",
    )
    return parser


def _build_reset_admin_password_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument(
        "--admin-username",
        help="admin username to target",
    )
    return parser


def _normalize_cli_args(args: list[str]) -> list[str]:
    if not args:
        return []
    try:
        from pathlib import Path

        if Path(__file__).resolve() == Path(args[0]).resolve():
            return args[1:]
    except OSError:
        pass
    return args


def _parse_upgrade_args(args: list[str]) -> argparse.Namespace:
    return _build_upgrade_parser().parse_args(args)


def _parse_worker_args(args: list[str]) -> argparse.Namespace:
    return _build_worker_parser().parse_args(args)


def _parse_upload_worker_args(args: list[str]) -> argparse.Namespace:
    return _build_upload_worker_parser().parse_args(args)


def _parse_reset_admin_password_args(args: list[str]) -> argparse.Namespace:
    return _build_reset_admin_password_parser().parse_args(args)


def _run_worker(parsed_args: argparse.Namespace) -> int:
    ensure_flask_bcrypt()

    create_app = _load_create_app()
    app = create_app(
        config_overrides={
            "ENABLE_LOCAL_EXECUTOR": False,
        }
    )

    with app.app_context():
        from hashcrush.executor import ExecutorOwnershipError, LocalExecutorService
        from hashcrush.models import db

        bootstrap_errors = _runtime_bootstrap_errors(db)
        if bootstrap_errors:
            for error in bootstrap_errors:
                print(f"Error: {error}", file=sys.stderr)
            return 1

        service = LocalExecutorService(app, poll_interval=parsed_args.poll_interval)

    previous_handlers: list[tuple[int, object]] = []

    def _handle_signal(signum, _frame):
        app.logger.info("Worker received signal=%s; stopping.", signum)
        service.stop()

    for signal_name in ("SIGINT", "SIGTERM"):
        if hasattr(signal, signal_name):
            signum = getattr(signal, signal_name)
            previous_handlers.append((signum, signal.getsignal(signum)))
            signal.signal(signum, _handle_signal)

    print("Starting HashCrush worker.")
    try:
        service.run_forever()
    except ExecutorOwnershipError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    finally:
        for signum, previous_handler in previous_handlers:
            signal.signal(signum, previous_handler)
    return 0


def _run_upload_worker(parsed_args: argparse.Namespace) -> int:
    ensure_flask_bcrypt()

    create_app = _load_create_app()
    app = create_app(
        config_overrides={
            "ENABLE_LOCAL_EXECUTOR": False,
            "ENABLE_INLINE_UPLOAD_WORKER": False,
        }
    )

    with app.app_context():
        from hashcrush.models import db
        from hashcrush.uploads import UploadWorkerService

        bootstrap_errors = _runtime_bootstrap_errors(db)
        if bootstrap_errors:
            for error in bootstrap_errors:
                print(f"Error: {error}", file=sys.stderr)
            return 1

        service = UploadWorkerService(app, poll_interval=parsed_args.poll_interval)

    previous_handlers: list[tuple[int, object]] = []

    def _handle_signal(signum, _frame):
        app.logger.info("Upload worker received signal=%s; stopping.", signum)
        service.stop()

    for signal_name in ("SIGINT", "SIGTERM"):
        if hasattr(signal, signal_name):
            signum = getattr(signal, signal_name)
            previous_handlers.append((signum, signal.getsignal(signum)))
            signal.signal(signum, _handle_signal)

    print("Starting HashCrush upload worker.")
    try:
        service.run_forever()
    finally:
        for signum, previous_handler in previous_handlers:
            signal.signal(signum, previous_handler)
    return 0


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
        from hashcrush.utils.secret_storage import migrate_sensitive_storage_rows

        result = upgrade_database(dry_run=parsed_args.dry_run)
        migrated_rows = 0
        if not parsed_args.dry_run:
            migrated_rows = migrate_sensitive_storage_rows()

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
    if not parsed_args.dry_run and migrated_rows:
        print(
            "Migrated "
            f"{migrated_rows} sensitive storage row update(s) to encrypted-at-rest format."
        )
    return 0


def _run_reset_admin_password(parsed_args: argparse.Namespace) -> int:
    ensure_flask_bcrypt()

    create_app = _load_create_app()
    app = create_app(
        config_overrides={
            "ENABLE_LOCAL_EXECUTOR": False,
            "SKIP_RUNTIME_BOOTSTRAP": True,
        }
    )
    with app.app_context():
        from hashcrush.models import db
        from hashcrush.users.routes import bcrypt

        return reset_admin_password_cli(db, bcrypt, parsed_args.admin_username)


def cli(args) -> int:
    """Process command line args and return an exit code."""
    try:
        argv = _normalize_cli_args(list(args))

        if not argv:
            _build_root_parser().print_help()
            return 0

        first = argv[0]
        if first in {"-h", "--help", "help"}:
            _build_root_parser().print_help()
            return 0
        if first == "upgrade":
            return _run_upgrade(_parse_upgrade_args(argv[1:]))
        if first == "worker":
            return _run_worker(_parse_worker_args(argv[1:]))
        if first == "upload-worker":
            return _run_upload_worker(_parse_upload_worker_args(argv[1:]))
        if first == "reset-admin-password":
            return _run_reset_admin_password(_parse_reset_admin_password_args(argv[1:]))

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
