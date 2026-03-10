#!/usr/bin/python3
import argparse
import os
import secrets
import subprocess
import sys
import tempfile
from configparser import ConfigParser
from getpass import getpass

CONFIG_PATH = os.path.join("hashcrush", "config.conf")
ENV_TEST_PATH = ".env.test"
LOCAL_POSTGRES_HOST_ALIASES = {"localhost", "127.0.0.1", "::1"}
DEFAULT_DB_HOST = "127.0.0.1"
DEFAULT_DB_PORT = "5432"
DEFAULT_DB_NAME = "hashcrush"
DEFAULT_DB_USERNAME = "hashcrush"
DEFAULT_DB_PASSWORD = "hashcrush"
DEFAULT_HASHCAT_BIN = "/usr/bin/hashcat"
DEFAULT_HASHCAT_STATUS_TIMER = 5
DEFAULT_WORDLISTS_PATH = "/usr/share/seclists/Passwords"
DEFAULT_RULES_PATH = "/usr/share/hashcat/rules"
DEFAULT_RUNTIME_PATH = "/tmp/hashcrush-runtime"
DEFAULT_SSL_DIR = "/etc/hashcrush/ssl"
FALLBACK_TEST_SSL_DIR = os.path.join("hashcrush", "ssl")

E2E_ADMIN_USERNAME = "admin"
E2E_ADMIN_PASSWORD = "HashCrushE2EAdmin!2026"
E2E_SECOND_USERNAME = "user"
E2E_SECOND_PASSWORD = "HashCrushE2EUser!2026"
E2E_DOMAIN_NAME = "E2E Domain"
E2E_WORDLIST_NAME = "E2E Passwords"
E2E_RULE_NAME = "E2E Noop Rule"
E2E_DICTIONARY_TASK_NAME = "E2E Dictionary"
E2E_DICTIONARY_RULE_TASK_NAME = "E2E Dictionary + Rule"
E2E_SAMPLE_JOB_NAME = "E2E Seed Job"
E2E_SAMPLE_HASHFILE_NAME = "e2e-sample-hashes.txt"
E2E_MASK_TASK_NAME = "?a [1]"
E2E_SAMPLE_HASH = "5f4dcc3b5aa765d61d8327deb882cf99"


def _read_existing_app_value(config_path: str, key: str) -> str | None:
    parser = ConfigParser()
    if not os.path.exists(config_path):
        return None
    parser.read(config_path, encoding="utf-8")
    value = parser.get("app", key, fallback="").strip()
    return value or None


def _prompt_existing_directory(prompt: str, default: str | None) -> str:
    while True:
        suffix = f" [{default}]" if default else ""
        value = input(f"{prompt}{suffix}: ").strip()
        if not value:
            value = default or ""
        resolved = os.path.abspath(os.path.expanduser(value))
        if not resolved:
            print("Error: path is required.")
            continue
        if not os.path.isdir(resolved):
            print(f"Error: directory does not exist: {resolved}")
            continue
        return resolved


def _probe_writable_directory(path: str) -> str:
    resolved = os.path.abspath(os.path.expanduser(path))
    os.makedirs(resolved, exist_ok=True)
    probe_file = os.path.join(resolved, f".write-probe-{secrets.token_hex(4)}")
    with open(probe_file, "w", encoding="utf-8") as handle:
        handle.write("ok")
    os.remove(probe_file)
    return resolved


def _prompt_writable_directory(prompt: str, default: str | None) -> str:
    while True:
        suffix = f" [{default}]" if default else ""
        value = input(f"{prompt}{suffix}: ").strip()
        if not value:
            value = default or ""
        resolved = os.path.abspath(os.path.expanduser(value))
        if not resolved:
            print("Error: path is required.")
            continue
        try:
            return _probe_writable_directory(resolved)
        except OSError as exc:
            print(f'Error: cannot write to directory "{resolved}": {exc}')
            continue


def _find_first_writable_directory(candidates: list[str]) -> str:
    for candidate in candidates:
        if not candidate:
            continue
        try:
            return _probe_writable_directory(candidate)
        except OSError:
            continue
    raise RuntimeError("Could not find a writable directory for TLS certificate generation.")


def _set_path_mode(path: str, mode: int) -> None:
    if not hasattr(os, "chmod"):
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
        os.path.join(runtime_root, "tmp"),
        os.path.join(runtime_root, "hashes"),
        os.path.join(runtime_root, "outfiles"),
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
    db_port: str,
    db_name: str,
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
    parser["database"] = {
        "uri": "",
        "host": db_server,
        "port": db_port,
        "name": db_name,
        "username": db_username,
        "password": db_password,
    }
    parser["app"] = {
        "secret_key": secret_key,
        "hashcat_bin": hashcat_bin,
        "hashcat_status_timer": str(hashcat_status_timer),
        "wordlists_path": wordlists_path,
        "rules_path": rules_path,
        "runtime_path": runtime_path,
        "ssl_cert_path": ssl_cert_path,
        "ssl_key_path": ssl_key_path,
    }

    config_dir = os.path.dirname(config_path) or "."
    os.makedirs(config_dir, exist_ok=True)

    if hasattr(os, "chmod"):
        try:
            os.chmod(config_dir, 0o700)
        except OSError:
            pass

    fd, tmp_path = tempfile.mkstemp(prefix=".config.", dir=config_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as config_file:
            parser.write(config_file)
            config_file.flush()
            os.fsync(config_file.fileno())
        os.replace(tmp_path, config_path)

        if hasattr(os, "chmod"):
            try:
                os.chmod(config_path, 0o600)
            except OSError:
                pass
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def _escape_postgres_literal(value: str) -> str:
    return value.replace("'", "''")


def _escape_postgres_identifier(value: str) -> str:
    return value.replace('"', '""')


def _normalize_local_postgres_host(value: str) -> str:
    normalized = value.strip().lower()
    if normalized == "localhost":
        return "localhost"
    if normalized == "127.0.0.1":
        return "127.0.0.1"
    if normalized == "::1":
        return "::1"
    return normalized


def _bootstrap_local_postgres(
    db_name: str, app_username: str, app_password: str, db_port: str
) -> None:
    escaped_db_name_literal = _escape_postgres_literal(db_name)
    escaped_db_name_identifier = _escape_postgres_identifier(db_name)
    escaped_user_identifier = _escape_postgres_identifier(app_username)
    escaped_pass_literal = _escape_postgres_literal(app_password)
    sql_lines = [
        "SELECT pg_terminate_backend(pid) "
        "FROM pg_stat_activity "
        f"WHERE datname = '{escaped_db_name_literal}' AND pid <> pg_backend_pid();",
        f'DROP DATABASE IF EXISTS "{escaped_db_name_identifier}";',
        f'DROP ROLE IF EXISTS "{escaped_user_identifier}";',
        f'CREATE ROLE "{escaped_user_identifier}" LOGIN PASSWORD \'{escaped_pass_literal}\';',
        f'CREATE DATABASE "{escaped_db_name_identifier}" OWNER "{escaped_user_identifier}";',
        f'REVOKE ALL ON DATABASE "{escaped_db_name_identifier}" FROM PUBLIC;',
    ]
    sql = "\n".join(sql_lines) + "\n"

    subprocess.run(
        [
            "sudo",
            "-u",
            "postgres",
            "psql",
            "-v",
            "ON_ERROR_STOP=1",
            "-p",
            str(db_port),
            "-d",
            "postgres",
        ],
        input=sql.encode("utf-8"),
        check=True,
    )


def _build_seed_app():
    from hashcrush import create_app

    return create_app(
        config_overrides={
            "ENABLE_LOCAL_EXECUTOR": False,
            "AUTO_SETUP_DEFAULTS": False,
            "AUTO_NORMALIZE_PLAINTEXT_STORAGE": False,
            "SKIP_RUNTIME_BOOTSTRAP": True,
            "AUTO_CREATE_SCHEMA": False,
        }
    )


def _build_database_schema() -> None:
    from hashcrush.db_upgrade import upgrade_database

    schema_app = _build_seed_app()
    with schema_app.app_context():
        upgrade_database()


def _run_root_guard() -> None:
    if getattr(os, "geteuid", lambda: 1)() == 0:
        print(
            "HashCrush has no need to run as root unless you intend to host the web service on a port < 1024."
        )
        print("If you continue, any installed python modules will be installed as root.")
        continue_as_root = input("Would you like to continue as root? [y/N]: ")
        if continue_as_root.lower() != "y":
            sys.exit()


def _install_dependencies() -> None:
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "-r",
            "requirements.txt",
            "--break-system-packages",
        ],
        check=True,
    )


def _existing_ssl_dir(existing_ssl_cert_path: str | None, existing_ssl_key_path: str | None) -> str | None:
    if not existing_ssl_cert_path or not existing_ssl_key_path:
        return None
    existing_cert_dir = os.path.dirname(
        os.path.abspath(os.path.expanduser(existing_ssl_cert_path))
    )
    existing_key_dir = os.path.dirname(
        os.path.abspath(os.path.expanduser(existing_ssl_key_path))
    )
    if existing_cert_dir == existing_key_dir:
        return existing_cert_dir
    return None


def _env_ssl_dir() -> str | None:
    env_ssl_cert_path = (os.getenv("HASHCRUSH_SSL_CERT_PATH") or "").strip()
    env_ssl_key_path = (os.getenv("HASHCRUSH_SSL_KEY_PATH") or "").strip()
    if not env_ssl_cert_path or not env_ssl_key_path:
        return None
    env_cert_dir = os.path.dirname(os.path.abspath(os.path.expanduser(env_ssl_cert_path)))
    env_key_dir = os.path.dirname(os.path.abspath(os.path.expanduser(env_ssl_key_path)))
    if env_cert_dir == env_key_dir:
        return env_cert_dir
    return None


def _collect_interactive_install_config(existing_values: dict[str, str | None]) -> dict[str, str]:
    print("\nCollecting HashCrush Database Configuration Information")
    db_server = input(
        f"Enter the IP or hostname of the server running PostgreSQL [{DEFAULT_DB_HOST}]: "
    ).strip()
    if len(db_server) == 0:
        db_server = DEFAULT_DB_HOST
    while db_server.strip().lower() not in LOCAL_POSTGRES_HOST_ALIASES:
        print(
            "Error: hashcrush.py setup requires local PostgreSQL host "
            "(127.0.0.1, localhost, or ::1)."
        )
        db_server = input(
            f"Enter the IP or hostname of the server running PostgreSQL [{DEFAULT_DB_HOST}]: "
        ).strip()
        if len(db_server) == 0:
            db_server = DEFAULT_DB_HOST
    db_server = _normalize_local_postgres_host(db_server)

    db_port = input(
        f"Enter the TCP port of the local PostgreSQL cluster [{DEFAULT_DB_PORT}]: "
    ).strip()
    if len(db_port) == 0:
        db_port = DEFAULT_DB_PORT
    while not db_port.isdigit() or int(db_port) <= 0:
        print("Error: enter a valid positive TCP port.")
        db_port = input(
            f"Enter the TCP port of the local PostgreSQL cluster [{DEFAULT_DB_PORT}]: "
        ).strip()
        if len(db_port) == 0:
            db_port = DEFAULT_DB_PORT

    db_name = input(
        f"Enter the PostgreSQL database name HashCrush should use [{DEFAULT_DB_NAME}]: "
    ).strip()
    if len(db_name) == 0:
        db_name = DEFAULT_DB_NAME

    db_username = input(
        "Enter the user account HashCrush should use to connect to the PostgreSQL instance: "
    )
    while len(db_username) == 0:
        print("Error: Invalid entry. Please try again.")
        db_username = input(
            "Enter the user account HashCrush should use to connect to the PostgreSQL instance: "
        )

    db_password = getpass("Enter the password for " + db_username + ": ")
    while len(db_password) == 0:
        print("Error: You must provide a password.")
        db_password = getpass("Enter the password for " + db_username + ": ")

    wordlists_default = (
        os.getenv("HASHCRUSH_WORDLISTS_PATH")
        or existing_values["wordlists_path"]
        or DEFAULT_WORDLISTS_PATH
    )
    rules_default = (
        os.getenv("HASHCRUSH_RULES_PATH")
        or existing_values["rules_path"]
        or DEFAULT_RULES_PATH
    )

    print("\nCollecting External Dictionary and Rules Paths")
    wordlists_path = _prompt_existing_directory(
        "Enter path to the SecLists/Passwords wordlists root",
        wordlists_default,
    )
    rules_path = _prompt_existing_directory(
        "Enter path to the hashcat rules root",
        rules_default,
    )

    runtime_default = (
        os.getenv("HASHCRUSH_RUNTIME_PATH")
        or existing_values["runtime_path"]
        or DEFAULT_RUNTIME_PATH
    )
    runtime_path = input(
        f"Enter path for runtime temp/artifact storage [{runtime_default}]: "
    ).strip()
    if len(runtime_path) == 0:
        runtime_path = runtime_default
    runtime_path = os.path.abspath(os.path.expanduser(runtime_path))
    os.makedirs(runtime_path, exist_ok=True)

    ssl_dir_default = (
        _env_ssl_dir()
        or _existing_ssl_dir(
            existing_values["ssl_cert_path"], existing_values["ssl_key_path"]
        )
        or DEFAULT_SSL_DIR
    )
    ssl_dir = _prompt_writable_directory(
        "Enter path for TLS certificate/key directory",
        ssl_dir_default,
    )

    config_exists = os.path.exists(CONFIG_PATH)
    existing_hashcat_bin = existing_values["hashcat_bin"]
    if config_exists and existing_hashcat_bin:
        preserve_hashcat_bin = (
            input(
                f'config.conf exists. Preserve existing hashcat_bin "{existing_hashcat_bin}"? [Y/n]: '
            )
            .strip()
            .lower()
        )
        while preserve_hashcat_bin not in {"", "y", "yes", "n", "no"}:
            print("Error: enter Y or N.")
            preserve_hashcat_bin = (
                input(
                    f'config.conf exists. Preserve existing hashcat_bin "{existing_hashcat_bin}"? [Y/n]: '
                )
                .strip()
                .lower()
            )

        if preserve_hashcat_bin in {"", "y", "yes"}:
            hashcat_bin = existing_hashcat_bin
        else:
            hashcat_bin = input(
                f"Enter path to hashcat binary [{DEFAULT_HASHCAT_BIN}]: "
            ).strip()
            if len(hashcat_bin) == 0:
                hashcat_bin = DEFAULT_HASHCAT_BIN
    else:
        hashcat_bin_default = existing_hashcat_bin or DEFAULT_HASHCAT_BIN
        hashcat_bin = input(
            f"Enter path to hashcat binary [{hashcat_bin_default}]: "
        ).strip()
        if len(hashcat_bin) == 0:
            hashcat_bin = hashcat_bin_default

    return {
        "db_server": db_server,
        "db_port": db_port,
        "db_name": db_name,
        "db_username": db_username,
        "db_password": db_password,
        "hashcat_bin": hashcat_bin,
        "wordlists_path": wordlists_path,
        "rules_path": rules_path,
        "runtime_path": runtime_path,
        "ssl_cert_path": os.path.join(ssl_dir, "cert.pem"),
        "ssl_key_path": os.path.join(ssl_dir, "key.pem"),
    }


def _collect_test_install_config(existing_values: dict[str, str | None]) -> dict[str, str]:
    db_server = _normalize_local_postgres_host(
        os.getenv("HASHCRUSH_DB_HOST") or DEFAULT_DB_HOST
    )
    if db_server.strip().lower() not in LOCAL_POSTGRES_HOST_ALIASES:
        raise RuntimeError(
            "hashcrush.py setup --test requires local PostgreSQL host "
            "(127.0.0.1, localhost, or ::1)."
        )

    db_port = os.getenv("HASHCRUSH_DB_PORT") or DEFAULT_DB_PORT
    if not db_port.isdigit() or int(db_port) <= 0:
        raise RuntimeError(
            "hashcrush.py setup --test requires HASHCRUSH_DB_PORT to be a positive integer."
        )

    db_name = os.getenv("HASHCRUSH_TEST_DB_NAME") or DEFAULT_DB_NAME
    db_username = os.getenv("HASHCRUSH_TEST_DB_USERNAME") or DEFAULT_DB_USERNAME
    db_password = os.getenv("HASHCRUSH_TEST_DB_PASSWORD") or DEFAULT_DB_PASSWORD

    runtime_path = os.path.abspath(
        os.path.expanduser(
            os.getenv("HASHCRUSH_RUNTIME_PATH")
            or existing_values["runtime_path"]
            or DEFAULT_RUNTIME_PATH
        )
    )
    os.makedirs(runtime_path, exist_ok=True)

    fixture_root = os.path.join(runtime_path, "e2e-fixtures")
    wordlists_path = os.path.join(fixture_root, "wordlists")
    rules_path = os.path.join(fixture_root, "rules")

    project_root = os.path.abspath(os.path.dirname(__file__))
    ssl_dir = _find_first_writable_directory(
        [
            _env_ssl_dir() or "",
            _existing_ssl_dir(
                existing_values["ssl_cert_path"], existing_values["ssl_key_path"]
            )
            or "",
            DEFAULT_SSL_DIR,
            os.path.join(project_root, FALLBACK_TEST_SSL_DIR),
        ]
    )

    hashcat_bin = (
        os.getenv("HASHCRUSH_HASHCAT_BIN")
        or existing_values["hashcat_bin"]
        or DEFAULT_HASHCAT_BIN
    )

    print("\nUsing disposable E2E setup defaults")
    print(f"- db_server={db_server}")
    print(f"- db_port={db_port}")
    print(f"- db_name={db_name}")
    print(f"- db_username={db_username}")
    print(f"- wordlists_path={wordlists_path}")
    print(f"- rules_path={rules_path}")
    print(f"- runtime_path={runtime_path}")
    print(f"- ssl_dir={ssl_dir}")

    return {
        "db_server": db_server,
        "db_port": db_port,
        "db_name": db_name,
        "db_username": db_username,
        "db_password": db_password,
        "hashcat_bin": hashcat_bin,
        "wordlists_path": wordlists_path,
        "rules_path": rules_path,
        "runtime_path": runtime_path,
        "ssl_cert_path": os.path.join(ssl_dir, "cert.pem"),
        "ssl_key_path": os.path.join(ssl_dir, "key.pem"),
    }


def _generate_ssl_certificates(runtime_path: str, ssl_cert_path: str, ssl_key_path: str) -> None:
    print("Generating SSL Certificates")
    _ensure_runtime_directories(runtime_path, ssl_cert_path, ssl_key_path)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:4096",
            "-nodes",
            "-out",
            ssl_cert_path,
            "-keyout",
            ssl_key_path,
            "-days",
            "365",
            "-subj",
            "/C=XX/ST=Local/L=Local/O=HashCrush/OU=Setup/CN=localhost",
        ],
        check=True,
    )
    _set_path_mode(ssl_cert_path, 0o644)
    _set_path_mode(ssl_key_path, 0o600)


def _write_text_file(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


def _dotenv_escape(value: str) -> str:
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _write_e2e_env_file(env_path: str, values: dict[str, str]) -> None:
    lines = [
        "# Generated by hashcrush.py setup --test",
        "# Disposable local live-testing credentials and IDs.",
        "HASHCRUSH_E2E_MODE=external",
        f"HASHCRUSH_E2E_BASE_URL={_dotenv_escape(values['HASHCRUSH_E2E_BASE_URL'])}",
        f"HASHCRUSH_E2E_VERIFY_TLS={values['HASHCRUSH_E2E_VERIFY_TLS']}",
        "",
        f"HASHCRUSH_E2E_USERNAME={_dotenv_escape(values['HASHCRUSH_E2E_USERNAME'])}",
        f"HASHCRUSH_E2E_PASSWORD={_dotenv_escape(values['HASHCRUSH_E2E_PASSWORD'])}",
        f"HASHCRUSH_E2E_SETUP_USERNAME={_dotenv_escape(values['HASHCRUSH_E2E_SETUP_USERNAME'])}",
        f"HASHCRUSH_E2E_SETUP_PASSWORD={_dotenv_escape(values['HASHCRUSH_E2E_SETUP_PASSWORD'])}",
        "",
        f"HASHCRUSH_E2E_SECOND_USERNAME={_dotenv_escape(values['HASHCRUSH_E2E_SECOND_USERNAME'])}",
        f"HASHCRUSH_E2E_SECOND_PASSWORD={_dotenv_escape(values['HASHCRUSH_E2E_SECOND_PASSWORD'])}",
        f"HASHCRUSH_E2E_SECOND_IS_ADMIN={values['HASHCRUSH_E2E_SECOND_IS_ADMIN']}",
        "",
        f"HASHCRUSH_E2E_DOMAIN_ID={_dotenv_escape(values['HASHCRUSH_E2E_DOMAIN_ID'])}",
        f"HASHCRUSH_E2E_DOMAIN_NAME={_dotenv_escape(values['HASHCRUSH_E2E_DOMAIN_NAME'])}",
        f"HASHCRUSH_E2E_HASHFILE_ID={_dotenv_escape(values['HASHCRUSH_E2E_HASHFILE_ID'])}",
        f"HASHCRUSH_E2E_TASK_ID={_dotenv_escape(values['HASHCRUSH_E2E_TASK_ID'])}",
        f"HASHCRUSH_E2E_TASK_NAME={_dotenv_escape(values['HASHCRUSH_E2E_TASK_NAME'])}",
        "",
    ]
    with open(env_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines))


def _seed_test_environment(runtime_path: str, env_path: str) -> dict[str, str]:
    from hashcrush.models import (
        Domains,
        Hashfiles,
        Jobs,
        JobTasks,
        Rules,
        Settings,
        Tasks,
        Users,
        Wordlists,
        db,
    )
    from hashcrush.setup import add_default_tasks, default_tasks_need_added
    from hashcrush.users.routes import bcrypt
    from hashcrush.utils.utils import get_filehash, get_linecount, import_hashfilehashes

    seed_app = _build_seed_app()
    fixture_root = os.path.join(runtime_path, "e2e-fixtures")
    wordlists_dir = os.path.join(fixture_root, "wordlists")
    rules_dir = os.path.join(fixture_root, "rules")
    hashes_dir = os.path.join(fixture_root, "hashes")
    wordlist_path = os.path.join(wordlists_dir, "e2e-passwords.txt")
    rule_path = os.path.join(rules_dir, "noop.rule")
    hashfile_path = os.path.join(hashes_dir, E2E_SAMPLE_HASHFILE_NAME)

    _write_text_file(wordlist_path, "password\nPassword123!\nhashcrush\n")
    _write_text_file(rule_path, ":\n")
    _write_text_file(hashfile_path, E2E_SAMPLE_HASH + "\n")

    with seed_app.app_context():
        settings = Settings.query.first()
        if settings is None:
            settings = Settings()
            db.session.add(settings)
            db.session.commit()

        admin_user = Users.query.filter_by(username=E2E_ADMIN_USERNAME).first()
        if not admin_user:
            admin_user = Users(
                username=E2E_ADMIN_USERNAME,
                password=bcrypt.generate_password_hash(E2E_ADMIN_PASSWORD).decode("utf-8"),
                admin=True,
            )
            db.session.add(admin_user)
            db.session.commit()

        second_user = Users.query.filter_by(username=E2E_SECOND_USERNAME).first()
        if not second_user:
            second_user = Users(
                username=E2E_SECOND_USERNAME,
                password=bcrypt.generate_password_hash(E2E_SECOND_PASSWORD).decode("utf-8"),
                admin=False,
            )
            db.session.add(second_user)
            db.session.commit()

        if default_tasks_need_added(db):
            add_default_tasks(db)

        wordlist = Wordlists.query.filter_by(path=wordlist_path).first()
        if not wordlist:
            wordlist = Wordlists(
                name=E2E_WORDLIST_NAME,
                type="static",
                path=wordlist_path,
                size=get_linecount(wordlist_path),
                checksum=get_filehash(wordlist_path),
            )
            db.session.add(wordlist)
            db.session.commit()

        rule = Rules.query.filter_by(path=rule_path).first()
        if not rule:
            rule = Rules(
                name=E2E_RULE_NAME,
                path=rule_path,
                size=get_linecount(rule_path),
                checksum=get_filehash(rule_path),
            )
            db.session.add(rule)
            db.session.commit()

        mask_task = Tasks.query.filter_by(name=E2E_MASK_TASK_NAME).first()
        if not mask_task:
            mask_task = Tasks(
                name=E2E_MASK_TASK_NAME,
                wl_id=None,
                rule_id=None,
                hc_attackmode="maskmode",
                hc_mask="?a",
            )
            db.session.add(mask_task)
            db.session.commit()

        dictionary_task = Tasks.query.filter_by(name=E2E_DICTIONARY_TASK_NAME).first()
        if not dictionary_task:
            dictionary_task = Tasks(
                name=E2E_DICTIONARY_TASK_NAME,
                wl_id=wordlist.id,
                rule_id=None,
                hc_attackmode="dictionary",
                hc_mask=None,
            )
            db.session.add(dictionary_task)
            db.session.commit()

        dictionary_rule_task = Tasks.query.filter_by(name=E2E_DICTIONARY_RULE_TASK_NAME).first()
        if not dictionary_rule_task:
            dictionary_rule_task = Tasks(
                name=E2E_DICTIONARY_RULE_TASK_NAME,
                wl_id=wordlist.id,
                rule_id=rule.id,
                hc_attackmode="dictionary",
                hc_mask=None,
            )
            db.session.add(dictionary_rule_task)
            db.session.commit()

        domain = Domains.query.filter_by(name=E2E_DOMAIN_NAME).first()
        if not domain:
            domain = Domains(name=E2E_DOMAIN_NAME)
            db.session.add(domain)
            db.session.commit()

        hashfile = Hashfiles.query.filter_by(
            name=E2E_SAMPLE_HASHFILE_NAME,
            domain_id=domain.id,
        ).first()
        if not hashfile:
            hashfile = Hashfiles(name=E2E_SAMPLE_HASHFILE_NAME, domain_id=domain.id)
            db.session.add(hashfile)
            db.session.commit()
            if not import_hashfilehashes(
                hashfile_id=hashfile.id,
                hashfile_path=hashfile_path,
                file_type="hash_only",
                hash_type="0",
            ):
                raise RuntimeError("Failed importing E2E sample hashfile.")

        sample_job = Jobs.query.filter_by(name=E2E_SAMPLE_JOB_NAME).first()
        if not sample_job:
            sample_job = Jobs(
                name=E2E_SAMPLE_JOB_NAME,
                priority=3,
                status="Incomplete",
                domain_id=domain.id,
                owner_id=admin_user.id,
                hashfile_id=hashfile.id,
            )
            db.session.add(sample_job)
            db.session.commit()

        if not JobTasks.query.filter_by(job_id=sample_job.id, task_id=dictionary_task.id).first():
            job_task = JobTasks(job_id=sample_job.id, task_id=dictionary_task.id, status="Not Started")
            db.session.add(job_task)
            db.session.commit()

        values = {
            "HASHCRUSH_E2E_MODE": "external",
            "HASHCRUSH_E2E_BASE_URL": "https://127.0.0.1:8443",
            "HASHCRUSH_E2E_VERIFY_TLS": "0",
            "HASHCRUSH_E2E_USERNAME": E2E_ADMIN_USERNAME,
            "HASHCRUSH_E2E_PASSWORD": E2E_ADMIN_PASSWORD,
            "HASHCRUSH_E2E_SETUP_USERNAME": E2E_ADMIN_USERNAME,
            "HASHCRUSH_E2E_SETUP_PASSWORD": E2E_ADMIN_PASSWORD,
            "HASHCRUSH_E2E_SECOND_USERNAME": E2E_SECOND_USERNAME,
            "HASHCRUSH_E2E_SECOND_PASSWORD": E2E_SECOND_PASSWORD,
            "HASHCRUSH_E2E_SECOND_IS_ADMIN": "0",
            "HASHCRUSH_E2E_DOMAIN_ID": str(domain.id),
            "HASHCRUSH_E2E_DOMAIN_NAME": domain.name,
            "HASHCRUSH_E2E_HASHFILE_ID": str(hashfile.id),
            "HASHCRUSH_E2E_TASK_ID": str(mask_task.id),
            "HASHCRUSH_E2E_TASK_NAME": mask_task.name,
        }
        _write_e2e_env_file(env_path, values)
        values["seed_job_id"] = str(sample_job.id)
        values["dictionary_task_name"] = dictionary_task.name
        values["dictionary_rule_task_name"] = dictionary_rule_task.name
        values["wordlist_path"] = wordlist_path
        values["rule_path"] = rule_path
        return values


def _print_test_environment_summary(values: dict[str, str]) -> None:
    print("\nSeeded disposable E2E/live-test data")
    print(f"- admin username: {values['HASHCRUSH_E2E_USERNAME']}")
    print(f"- admin password: {values['HASHCRUSH_E2E_PASSWORD']}")
    print(f"- second username: {values['HASHCRUSH_E2E_SECOND_USERNAME']}")
    print(f"- second password: {values['HASHCRUSH_E2E_SECOND_PASSWORD']}")
    print(f"- domain id/name: {values['HASHCRUSH_E2E_DOMAIN_ID']} / {values['HASHCRUSH_E2E_DOMAIN_NAME']}")
    print(f"- hashfile id: {values['HASHCRUSH_E2E_HASHFILE_ID']}")
    print(f"- task id/name: {values['HASHCRUSH_E2E_TASK_ID']} / {values['HASHCRUSH_E2E_TASK_NAME']}")
    print(f"- sample dictionary task: {values['dictionary_task_name']}")
    print(f"- sample dictionary+rule task: {values['dictionary_rule_task_name']}")
    print(f"- sample job id: {values['seed_job_id']}")
    print(f"- wrote {ENV_TEST_PATH} with ready-to-use E2E variables")
    print(f"- sample wordlist path: {values['wordlist_path']}")
    print(f"- sample rule path: {values['rule_path']}")


def _existing_install_values() -> dict[str, str | None]:
    return {
        "hashcat_bin": _read_existing_app_value(CONFIG_PATH, "hashcat_bin"),
        "wordlists_path": _read_existing_app_value(CONFIG_PATH, "wordlists_path"),
        "rules_path": _read_existing_app_value(CONFIG_PATH, "rules_path"),
        "runtime_path": _read_existing_app_value(CONFIG_PATH, "runtime_path"),
        "ssl_cert_path": _read_existing_app_value(CONFIG_PATH, "ssl_cert_path"),
        "ssl_key_path": _read_existing_app_value(CONFIG_PATH, "ssl_key_path"),
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install and bootstrap HashCrush.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--test",
        dest="test_mode",
        action="store_true",
        help="Rebuild a disposable local live-testing environment and write .env.test.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    existing_values = _existing_install_values()

    _run_root_guard()
    _install_dependencies()

    if args.test_mode:
        print(
            "\nWARNING: hashcrush.py setup --test is destructive. "
            "It rebuilds the local hashcrush database, overwrites config.conf, "
            "and seeds dummy live-test credentials."
        )
        install_config = _collect_test_install_config(existing_values)
    else:
        install_config = _collect_interactive_install_config(existing_values)

    print("\nCreating local PostgreSQL database")
    _bootstrap_local_postgres(
        install_config["db_name"],
        install_config["db_username"],
        install_config["db_password"],
        install_config["db_port"],
    )

    secret_key = secrets.token_urlsafe(64)
    _write_config_atomic(
        CONFIG_PATH,
        install_config["db_server"],
        install_config["db_port"],
        install_config["db_name"],
        install_config["db_username"],
        install_config["db_password"],
        secret_key,
        install_config["hashcat_bin"],
        DEFAULT_HASHCAT_STATUS_TIMER,
        install_config["wordlists_path"],
        install_config["rules_path"],
        install_config["runtime_path"],
        install_config["ssl_cert_path"],
        install_config["ssl_key_path"],
    )
    print(f"Writing hashcrush config at: {CONFIG_PATH}")
    print("Generated a new app secret_key and stored it in config.")
    print(f"Set db_host={install_config['db_server']}")
    print(f"Set db_port={install_config['db_port']}")
    print(f"Set db_name={install_config['db_name']}")
    print(f"Set db_username={install_config['db_username']}")
    print(f"Set hashcat_bin={install_config['hashcat_bin']}")
    print(f"Set hashcat_status_timer={DEFAULT_HASHCAT_STATUS_TIMER}")
    print(f"Set wordlists_path={install_config['wordlists_path']}")
    print(f"Set rules_path={install_config['rules_path']}")
    print(f"Set runtime_path={install_config['runtime_path']}")
    print(f"Set ssl_cert_path={install_config['ssl_cert_path']}")
    print(f"Set ssl_key_path={install_config['ssl_key_path']}")

    print("Building database schema")
    _build_database_schema()

    _generate_ssl_certificates(
        install_config["runtime_path"],
        install_config["ssl_cert_path"],
        install_config["ssl_key_path"],
    )

    if args.test_mode:
        seeded_values = _seed_test_environment(
            install_config["runtime_path"],
            ENV_TEST_PATH,
        )
        _print_test_environment_summary(seeded_values)
        print("You can now run the live test flow with: ./tests/test-all.sh")
    else:
        print(
            "You can now start your instance of hashcrush by running the following command: ./hashcrush.py"
        )
    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
