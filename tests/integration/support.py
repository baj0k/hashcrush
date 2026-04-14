"""Shared helpers for integration tests."""
# ruff: noqa: F401

import importlib.util
import io
import json
import time
from configparser import ConfigParser
from pathlib import Path

import pytest
from sqlalchemy import func, inspect, select
from sqlalchemy.exc import IntegrityError

from hashcrush import create_app
from hashcrush.config import sanitize_config_input
from hashcrush.domains.service import (
    extract_domain_name_from_username,
    get_or_create_domain_by_name,
)
from hashcrush.forms_utils import normalize_text_input
from hashcrush.models import (
    AuditLog,
    Domains,
    Hashes,
    HashPublicExposure,
    HashfileHashes,
    Hashfiles,
    Jobs,
    JobTasks,
    Rules,
    SchemaVersion,
    TaskGroups,
    Tasks,
    UploadOperations,
    Users,
    Wordlists,
    db,
)
from hashcrush.searches.token_index import (
    sync_hash_search_tokens,
    sync_hashfile_hash_search_tokens,
)
from hashcrush.users.routes import bcrypt
from hashcrush.utils.utils import (
    decode_ciphertext_from_storage,
    decode_username_from_storage,
    encode_ciphertext_for_storage,
    encode_plaintext_for_storage,
    encode_username_for_storage,
    get_account_identity_digest,
    get_ciphertext_search_digest,
    get_linecount,
    get_plaintext_search_digest,
    get_username_search_digest,
    import_hashfilehashes,
    validate_hash_only_hashfile,
    validate_netntlm_hashfile,
    validate_user_hash_hashfile,
)
from tests.db_runtime import (
    create_managed_postgres_database,
    sqlalchemy_engine_options,
)

TEST_DATA_ENCRYPTION_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="


def _integrity_error():
    return IntegrityError(
        "mock statement", {"key": "value"}, Exception("mock integrity error")
    )


def _build_app(extra_overrides: dict | None = None):
    database_uri = create_managed_postgres_database()
    base_overrides = {
        "SECRET_KEY": "phase1-test-secret-key-for-hashcrush",
        "DATA_ENCRYPTION_KEY": TEST_DATA_ENCRYPTION_KEY,
        "SQLALCHEMY_DATABASE_URI": database_uri,
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "SQLALCHEMY_ENGINE_OPTIONS": sqlalchemy_engine_options(),
        "WTF_CSRF_ENABLED": False,
    }
    if extra_overrides:
        base_overrides.update(extra_overrides)
    return create_app(
        testing=True,
        config_overrides=base_overrides,
    )


def _load_cli_module():
    project_root = Path(__file__).resolve().parents[2]
    script_path = project_root / "hashcrush.py"
    spec = importlib.util.spec_from_file_location("hashcrush_cli_script", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def _load_bootstrap_module():
    project_root = Path(__file__).resolve().parents[2]
    script_path = project_root / "bootstrap_cli.py"
    spec = importlib.util.spec_from_file_location("hashcrush_bootstrap_script", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def _seed_admin_user() -> Users:
    valid_password_hash = bcrypt.generate_password_hash("test-admin-password").decode(
        "utf-8"
    )
    user = Users(
        username="admin",
        password=valid_password_hash,
        admin=True,
    )
    db.session.add(user)
    db.session.commit()
    return user


def _seed_user(
    username: str, password: str = "test-user-password", admin: bool = False
) -> Users:
    valid_password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
    user = Users(
        username=username,
        password=valid_password_hash,
        admin=admin,
    )
    db.session.add(user)
    db.session.commit()
    return user


def _seed_settings() -> None:
    return None


def _login_client_as_user(client, user: Users):
    with client.session_transaction() as session:
        session["_user_id"] = str(user.id)
        session["_fresh"] = True


def _latest_audit_entry() -> AuditLog | None:
    return db.session.scalar(select(AuditLog).order_by(AuditLog.id.desc()))


def _wait_for_upload_operation(
    client,
    status_url: str,
    *,
    attempts: int = 80,
    delay_seconds: float = 0.05,
):
    response = None
    for _ in range(attempts):
        response = client.get(status_url)
        assert response.status_code == 200
        payload = response.get_json()
        assert isinstance(payload, dict)
        if payload.get("complete"):
            return payload
        time.sleep(delay_seconds)
    pytest.fail(
        f"Upload operation did not complete after {attempts} poll attempt(s): {status_url}"
    )


def _count_rows(model, *criteria, **filters) -> int:
    stmt = select(func.count()).select_from(model)
    if filters:
        stmt = stmt.filter_by(**filters)
    if criteria:
        stmt = stmt.where(*criteria)
    return int(db.session.scalar(stmt) or 0)


def _first_row(model, *criteria, order_by=None, **filters):
    stmt = select(model)
    if filters:
        stmt = stmt.filter_by(**filters)
    if criteria:
        stmt = stmt.where(*criteria)
    if order_by is not None:
        if isinstance(order_by, list | tuple):
            stmt = stmt.order_by(*order_by)
        else:
            stmt = stmt.order_by(order_by)
    return db.session.scalar(stmt)


def _all_rows(model, *criteria, order_by=None, **filters):
    stmt = select(model)
    if filters:
        stmt = stmt.filter_by(**filters)
    if criteria:
        stmt = stmt.where(*criteria)
    if order_by is not None:
        if isinstance(order_by, list | tuple):
            stmt = stmt.order_by(*order_by)
        else:
            stmt = stmt.order_by(order_by)
    return db.session.execute(stmt).scalars().all()


def _seed_hash(
    ciphertext: str,
    *,
    hash_type: int = 1000,
    cracked: bool = False,
    plaintext: str | None = None,
    sub_ciphertext: str | None = None,
) -> Hashes:
    row = Hashes(
        sub_ciphertext=sub_ciphertext or (get_ciphertext_search_digest(ciphertext) or ""),
        ciphertext=encode_ciphertext_for_storage(ciphertext),
        hash_type=hash_type,
        cracked=cracked,
        plaintext=encode_plaintext_for_storage(plaintext) if plaintext is not None else None,
        plaintext_digest=get_plaintext_search_digest(plaintext) if plaintext is not None else None,
    )
    db.session.add(row)
    db.session.commit()
    sync_hash_search_tokens([row.id])
    return row


def _seed_hashfile_hash(
    *,
    hash_id: int,
    hashfile_id: int,
    username: str | None = None,
    domain_id: int | None = None,
) -> HashfileHashes:
    normalized_username = username or ""
    encoded_username = ""
    username_digest = ""
    if username is not None:
        encoded_username = encode_username_for_storage(normalized_username)
        username_digest = get_username_search_digest(normalized_username) or ""
    resolved_domain_id = domain_id
    if resolved_domain_id is None:
        inferred_domain_name = extract_domain_name_from_username(username)
        if inferred_domain_name:
            inferred_domain = get_or_create_domain_by_name(inferred_domain_name)
            resolved_domain_id = inferred_domain.id if inferred_domain else None
        else:
            hashfile = db.session.get(Hashfiles, hashfile_id)
            resolved_domain_id = hashfile.domain_id if hashfile is not None else None
    row = HashfileHashes(
        hash_id=hash_id,
        hashfile_id=hashfile_id,
        domain_id=resolved_domain_id,
        username=encoded_username,
        username_digest=username_digest,
        account_digest=get_account_identity_digest(
            (
                db.session.get(Domains, resolved_domain_id).name
                if resolved_domain_id is not None
                else None
            ),
            normalized_username if username is not None else None,
        ),
    )
    db.session.add(row)
    db.session.commit()
    sync_hashfile_hash_search_tokens([row.id])
    return row



__all__ = [name for name in globals() if not name.startswith("__")]
