#!/usr/bin/env python3
"""Print recommended E2E environment exports from the current database."""

from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        if key and key not in os.environ:
            os.environ[key] = value


def shell_export(key: str, value: str) -> str:
    return f"export {key}={shlex.quote(str(value))}"


def print_section(title: str) -> None:
    print(f"\n# {title}")


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    load_dotenv(repo_root / ".env.test")

    from hashcrush import create_app
    from hashcrush.models import Domains, Hashfiles, Tasks, Users, Wordlists

    app = create_app(
        testing=True,
        config_overrides={
            "AUTO_SETUP_DEFAULTS": False,
            "ENABLE_SCHEDULER": False,
            "ENABLE_LOCAL_EXECUTOR": False,
            "SKIP_RUNTIME_BOOTSTRAP": True,
        },
    )

    try:
        with app.app_context():
            admin_users = Users.query.filter_by(admin=True).order_by(Users.id.asc()).all()
            non_admin_users = (
                Users.query.filter_by(admin=False).order_by(Users.id.asc()).all()
            )
            domains = Domains.query.order_by(Domains.id.asc()).all()
            hashfiles = Hashfiles.query.order_by(Hashfiles.id.asc()).all()
            tasks = Tasks.query.order_by(Tasks.id.asc()).all()
            wordlists = Wordlists.query.order_by(Wordlists.id.asc()).all()
    except Exception as exc:
        print(f"Failed loading E2E context: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    recommended_hashfile = hashfiles[0] if hashfiles else None
    recommended_domain = None
    if recommended_hashfile is not None:
        recommended_domain = next(
            (domain for domain in domains if domain.id == recommended_hashfile.domain_id),
            None,
        )
    if recommended_domain is None and domains:
        recommended_domain = domains[0]
    recommended_task = tasks[0] if tasks else None
    recommended_admin = admin_users[0] if admin_users else None
    recommended_second_user = non_admin_users[0] if non_admin_users else None

    print("# Recommended E2E exports")
    print("# Copy the lines you want into .env.test and fill in password placeholders.")
    print(
        shell_export(
            "HASHCRUSH_E2E_BASE_URL",
            os.getenv("HASHCRUSH_E2E_BASE_URL", "https://127.0.0.1:8443"),
        )
    )
    print(
        shell_export(
            "HASHCRUSH_E2E_VERIFY_TLS",
            os.getenv("HASHCRUSH_E2E_VERIFY_TLS", "0"),
        )
    )
    print(
        shell_export(
            "HASHCRUSH_E2E_USERNAME",
            recommended_admin.username if recommended_admin else "admin",
        )
    )
    print('export HASHCRUSH_E2E_PASSWORD="<set-admin-password>"')
    if recommended_second_user:
        print(shell_export("HASHCRUSH_E2E_SECOND_USERNAME", recommended_second_user.username))
        print('export HASHCRUSH_E2E_SECOND_PASSWORD="<set-second-user-password>"')
        print(
            shell_export(
                "HASHCRUSH_E2E_SECOND_IS_ADMIN",
                "1" if recommended_second_user.admin else "0",
            )
        )
    else:
        print("# No non-admin user found for HASHCRUSH_E2E_SECOND_USERNAME.")
    if recommended_domain:
        print(shell_export("HASHCRUSH_E2E_DOMAIN_ID", str(recommended_domain.id)))
        print(shell_export("HASHCRUSH_E2E_DOMAIN_NAME", recommended_domain.name))
    else:
        print("# No domain found.")
    if recommended_hashfile:
        print(shell_export("HASHCRUSH_E2E_HASHFILE_ID", str(recommended_hashfile.id)))
    else:
        print("# No hashfile found.")
    if recommended_task:
        print(shell_export("HASHCRUSH_E2E_TASK_ID", str(recommended_task.id)))
        print(shell_export("HASHCRUSH_E2E_TASK_NAME", recommended_task.name))
    else:
        print("# No task found.")

    print_section("Available Admin Users")
    if admin_users:
        for user in admin_users:
            print(f"# id={user.id} username={user.username}")
    else:
        print("# none")

    print_section("Available Non-Admin Users")
    if non_admin_users:
        for user in non_admin_users:
            print(f"# id={user.id} username={user.username}")
    else:
        print("# none")

    print_section("Available Domains")
    if domains:
        for domain in domains:
            print(f"# id={domain.id} name={domain.name}")
    else:
        print("# none")

    print_section("Available Hashfiles")
    if hashfiles:
        for hashfile in hashfiles:
            print(
                f"# id={hashfile.id} domain_id={hashfile.domain_id} name={hashfile.name}"
            )
    else:
        print("# none")

    print_section("Available Tasks")
    if tasks:
        for task in tasks:
            print(f"# id={task.id} mode={task.hc_attackmode} name={task.name}")
    else:
        print("# none")

    print_section("Available Wordlists")
    if wordlists:
        for wordlist in wordlists:
            print(
                f"# id={wordlist.id} type={wordlist.type} "
                f"name={wordlist.name} path={wordlist.path}"
            )
    else:
        print("# none")
        print("# Dictionary-task E2E coverage will skip until at least one wordlist is registered.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
