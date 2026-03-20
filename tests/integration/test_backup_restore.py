"""Integration test for PostgreSQL backup/restore workflow."""
# ruff: noqa: F403,F405

import hashlib
import os
import shutil
import subprocess
import tarfile
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool

from tests.integration.support import *


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _require_postgres_client_tools():
    missing = [
        tool for tool in ("pg_dump", "pg_restore") if shutil.which(tool) is None
    ]
    if missing:
        pytest.fail(
            "PostgreSQL client tools are required for backup/restore validation: "
            + ", ".join(missing)
        )


def _schema_name_from_database_uri(database_uri: str) -> str:
    options = str(make_url(database_uri).query.get("options") or "")
    marker = "-csearch_path="
    if marker not in options:
        raise AssertionError(f"Expected schema-scoped test URI, got options={options!r}")
    return options.split(marker, 1)[1]


def _base_database_uri(database_uri: str) -> str:
    url = make_url(database_uri)
    query = dict(url.query)
    query.pop("options", None)
    return url.set(query=query).render_as_string(hide_password=False)


def _pg_client_args(database_uri: str) -> tuple[list[str], dict[str, str]]:
    url = make_url(database_uri)
    args = []
    if url.host:
        args.extend(["--host", url.host])
    if url.port:
        args.extend(["--port", str(url.port)])
    if url.username:
        args.extend(["--username", url.username])
    if url.database:
        args.extend(["--dbname", url.database])
    env = dict(os.environ)
    if url.password:
        env["PGPASSWORD"] = url.password
    return args, env


def _drop_schema(base_uri: str, schema_name: str) -> None:
    engine = create_engine(base_uri, isolation_level="AUTOCOMMIT", poolclass=NullPool)
    try:
        with engine.connect() as connection:
            connection.execute(
                text(f'DROP SCHEMA IF EXISTS "{schema_name}" CASCADE')
            )
    finally:
        engine.dispose()


@pytest.mark.security
def test_postgres_backup_restore_roundtrip(tmp_path):
    _require_postgres_client_tools()

    database_uri = create_managed_postgres_database()
    base_uri = _base_database_uri(database_uri)
    schema_name = _schema_name_from_database_uri(database_uri)

    runtime_path = tmp_path / "runtime"
    storage_path = tmp_path / "storage"
    ssl_dir = tmp_path / "ssl"
    for subdir in ("tmp", "hashes", "outfiles"):
        (runtime_path / subdir).mkdir(parents=True, exist_ok=True)
    for subdir in ("wordlists", "rules"):
        (storage_path / subdir).mkdir(parents=True, exist_ok=True)
    ssl_dir.mkdir(parents=True, exist_ok=True)
    (ssl_dir / "cert.pem").write_text("cert", encoding="utf-8")
    (ssl_dir / "key.pem").write_text("key", encoding="utf-8")

    source_app = create_app(
        testing=True,
        config_overrides={
            "SECRET_KEY": "backup-restore-secret",
            "DATA_ENCRYPTION_KEY": TEST_DATA_ENCRYPTION_KEY,
            "SQLALCHEMY_DATABASE_URI": database_uri,
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "SQLALCHEMY_ENGINE_OPTIONS": sqlalchemy_engine_options(),
            "ENABLE_LOCAL_EXECUTOR": False,
            "RUNTIME_PATH": str(runtime_path),
            "STORAGE_PATH": str(storage_path),
            "SSL_CERT_PATH": str(ssl_dir / "cert.pem"),
            "SSL_KEY_PATH": str(ssl_dir / "key.pem"),
        },
    )

    with source_app.app_context():
        from hashcrush.db_upgrade import CURRENT_SCHEMA_VERSION, upgrade_database

        upgrade_database()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="Backup Domain")
        db.session.add(domain)
        db.session.commit()

        wordlist_path = storage_path / "wordlists" / "backup-wordlist.txt"
        wordlist_path.write_text("password\nletmein\n", encoding="utf-8")
        rule_path = storage_path / "rules" / "backup.rule"
        rule_path.write_text(":\n", encoding="utf-8")

        wordlist = Wordlists(
            name="backup-wordlist",
            type="static",
            path=str(wordlist_path),
            size=wordlist_path.stat().st_size,
            checksum=_sha256_text(wordlist_path.read_text(encoding="utf-8")),
        )
        rule = Rules(
            name="backup-rule",
            path=str(rule_path),
            size=rule_path.stat().st_size,
            checksum=_sha256_text(rule_path.read_text(encoding="utf-8")),
        )
        db.session.add_all([wordlist, rule])
        db.session.commit()

        task = Tasks(
            name="backup-task",
            hc_attackmode="dictionary",
            wl_id=wordlist.id,
            rule_id=rule.id,
            hc_mask=None,
        )
        db.session.add(task)
        db.session.commit()

        hashfile = Hashfiles(name="backup-hashes.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        hash_row = _seed_hash(
            "5f4dcc3b5aa765d61d8327deb882cf99",
            hash_type=0,
            cracked=True,
            plaintext="password",
        )
        _seed_hashfile_hash(hash_id=hash_row.id, hashfile_id=hashfile.id, username="alice")

        job = Jobs(
            name="Backup Job",
            status="Queued",
            domain_id=domain.id,
            owner_id=admin.id,
            hashfile_id=hashfile.id,
        )
        db.session.add(job)
        db.session.commit()
        db.session.add(
            JobTasks(job_id=job.id, task_id=task.id, status="Not Started", position=0)
        )
        db.session.commit()

        schema_version = db.session.get(SchemaVersion, 1)
        assert schema_version is not None
        assert schema_version.version == CURRENT_SCHEMA_VERSION

        db.session.remove()
        db.engine.dispose()

    backup_dir = tmp_path / "backup"
    backup_dir.mkdir(parents=True, exist_ok=True)
    dump_path = backup_dir / "hashcrush.dump"
    storage_archive = backup_dir / "storage.tar.gz"
    with tarfile.open(storage_archive, "w:gz") as archive:
        archive.add(storage_path, arcname="storage")

    client_args, client_env = _pg_client_args(base_uri)
    subprocess.run(
        [
            "pg_dump",
            "--format=custom",
            f"--schema={schema_name}",
            f"--file={dump_path}",
            *client_args,
        ],
        check=True,
        env=client_env,
    )

    shutil.rmtree(storage_path)
    _drop_schema(base_uri, schema_name)

    subprocess.run(
        [
            "pg_restore",
            "--clean",
            "--if-exists",
            *client_args,
            str(dump_path),
        ],
        check=True,
        env=client_env,
    )
    with tarfile.open(storage_archive, "r:gz") as archive:
        archive.extractall(path=tmp_path, filter="data")

    restored_app = create_app(
        testing=True,
        config_overrides={
            "SECRET_KEY": "backup-restore-secret",
            "DATA_ENCRYPTION_KEY": TEST_DATA_ENCRYPTION_KEY,
            "SQLALCHEMY_DATABASE_URI": database_uri,
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "SQLALCHEMY_ENGINE_OPTIONS": sqlalchemy_engine_options(),
            "ENABLE_LOCAL_EXECUTOR": False,
            "RUNTIME_PATH": str(runtime_path),
            "STORAGE_PATH": str(storage_path),
            "SSL_CERT_PATH": str(ssl_dir / "cert.pem"),
            "SSL_KEY_PATH": str(ssl_dir / "key.pem"),
        },
    )

    with restored_app.app_context():
        from hashcrush.db_upgrade import CURRENT_SCHEMA_VERSION
        from hashcrush.utils.utils import (
            decode_ciphertext_from_storage,
            decode_plaintext_from_storage,
            decode_username_from_storage,
        )

        assert _count_rows(Users) == 1
        assert _count_rows(Domains) == 1
        assert _count_rows(Hashfiles) == 1
        assert _count_rows(Hashes) == 1
        assert _count_rows(HashfileHashes) == 1
        assert _count_rows(Wordlists) == 1
        assert _count_rows(Rules) == 1
        assert _count_rows(Tasks) == 1
        assert _count_rows(Jobs) == 1
        assert _count_rows(JobTasks) == 1

        schema_version = db.session.get(SchemaVersion, 1)
        assert schema_version is not None
        assert schema_version.version == CURRENT_SCHEMA_VERSION

        restored_hash = _first_row(Hashes)
        restored_link = _first_row(HashfileHashes)
        restored_wordlist = _first_row(Wordlists)
        restored_rule = _first_row(Rules)

        assert decode_ciphertext_from_storage(restored_hash.ciphertext) == (
            "5f4dcc3b5aa765d61d8327deb882cf99"
        )
        assert decode_plaintext_from_storage(restored_hash.plaintext) == "password"
        assert decode_username_from_storage(restored_link.username) == "alice"
        assert Path(restored_wordlist.path).read_text(encoding="utf-8") == "password\nletmein\n"
        assert Path(restored_rule.path).read_text(encoding="utf-8") == ":\n"
