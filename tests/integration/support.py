"""Shared helpers for integration tests."""
# ruff: noqa: F401

import importlib.util
import io
import json
from configparser import ConfigParser
from pathlib import Path

import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError

from hashcrush import create_app
from hashcrush.config import sanitize_config_input
from hashcrush.forms_utils import normalize_text_input
from hashcrush.models import (
    AuditLog,
    Domains,
    Hashes,
    HashfileHashes,
    Hashfiles,
    Jobs,
    JobTasks,
    Rules,
    SchemaVersion,
    Settings,
    TaskGroups,
    Tasks,
    Users,
    Wordlists,
    db,
)
from hashcrush.users.routes import bcrypt
from hashcrush.utils.utils import (
    encode_plaintext_for_storage,
    get_linecount,
    import_hashfilehashes,
    validate_hash_only_hashfile,
    validate_netntlm_hashfile,
    validate_user_hash_hashfile,
)


def _integrity_error():
    return IntegrityError(
        "mock statement", {"key": "value"}, Exception("mock integrity error")
    )


def _build_app(extra_overrides: dict | None = None):
    base_overrides = {
        "SECRET_KEY": "phase1-test-secret-key-for-hashcrush",
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "WTF_CSRF_ENABLED": False,
        "AUTO_SETUP_DEFAULTS": False,
        "ENABLE_SCHEDULER": False,
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


def _seed_settings() -> Settings:
    settings = Settings(
        retention_period=0,
        enabled_job_weights=False,
    )
    db.session.add(settings)
    db.session.commit()
    return settings


def _login_client_as_user(client, user: Users):
    with client.session_transaction() as session:
        session["_user_id"] = str(user.id)
        session["_fresh"] = True


def _latest_audit_entry() -> AuditLog | None:
    return AuditLog.query.order_by(AuditLog.id.desc()).first()



__all__ = [name for name in globals() if not name.startswith("__")]
