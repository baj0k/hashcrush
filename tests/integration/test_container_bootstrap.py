"""Integration tests for container bootstrap helpers."""

from pathlib import Path

from hashcrush.db_upgrade import UpgradeResult

from tests.integration.support import *


def _build_sqlite_bootstrap_app(tmp_path: Path):
    runtime_path = tmp_path / "runtime"
    storage_path = tmp_path / "storage"
    return create_app(
        testing=True,
        config_overrides={
            "SECRET_KEY": "container-bootstrap-test-secret-key",
            "DATA_ENCRYPTION_KEY": TEST_DATA_ENCRYPTION_KEY,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'bootstrap.sqlite'}",
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "WTF_CSRF_ENABLED": False,
            "ENABLE_LOCAL_EXECUTOR": False,
            "SKIP_RUNTIME_BOOTSTRAP": True,
            "RUNTIME_PATH": str(runtime_path),
            "STORAGE_PATH": str(storage_path),
        },
    )


@pytest.mark.security
def test_container_bootstrap_creates_runtime_and_storage_dirs(tmp_path):
    from hashcrush.container_bootstrap import ensure_runtime_and_storage_dirs

    runtime_path = tmp_path / "runtime"
    storage_path = tmp_path / "storage"

    ensure_runtime_and_storage_dirs(str(runtime_path), str(storage_path))

    assert (runtime_path / "tmp").is_dir()
    assert (runtime_path / "hashes").is_dir()
    assert (runtime_path / "outfiles").is_dir()
    assert (storage_path / "wordlists").is_dir()
    assert (storage_path / "rules").is_dir()


@pytest.mark.security
def test_container_bootstrap_seeds_schema_admin_and_default_tasks(tmp_path, monkeypatch):
    from hashcrush.container_bootstrap import (
        bootstrap_instance,
        ensure_runtime_and_storage_dirs,
    )

    runtime_path = tmp_path / "runtime"
    storage_path = tmp_path / "storage"
    ensure_runtime_and_storage_dirs(str(runtime_path), str(storage_path))
    app = _build_sqlite_bootstrap_app(tmp_path)
    with app.app_context():
        db.create_all()
    monkeypatch.setattr(
        "hashcrush.container_bootstrap.upgrade_database",
        lambda dry_run=False: UpgradeResult(
            starting_version=0,
            target_version=6,
            applied_steps=(),
            initialized_empty_schema=True,
            dry_run=dry_run,
        ),
    )
    monkeypatch.setattr(
        "hashcrush.container_bootstrap.migrate_sensitive_storage_rows",
        lambda: 0,
    )

    target_version, migrated_rows = bootstrap_instance(
        app,
        "admin",
        "ContainerAdminPassword!2026",
    )

    with app.app_context():
        assert target_version >= 1
        assert migrated_rows == 0
        assert _count_rows(Settings) == 1
        assert _count_rows(Users, admin=True) == 1
        assert _count_rows(Tasks) >= 10


@pytest.mark.security
def test_container_bootstrap_is_idempotent_for_existing_admin_and_tasks(
    tmp_path, monkeypatch
):
    from hashcrush.container_bootstrap import (
        bootstrap_instance,
        ensure_runtime_and_storage_dirs,
    )

    runtime_path = tmp_path / "runtime"
    storage_path = tmp_path / "storage"
    ensure_runtime_and_storage_dirs(str(runtime_path), str(storage_path))
    app = _build_sqlite_bootstrap_app(tmp_path)
    with app.app_context():
        db.create_all()
    monkeypatch.setattr(
        "hashcrush.container_bootstrap.upgrade_database",
        lambda dry_run=False: UpgradeResult(
            starting_version=0,
            target_version=6,
            applied_steps=(),
            initialized_empty_schema=True,
            dry_run=dry_run,
        ),
    )
    monkeypatch.setattr(
        "hashcrush.container_bootstrap.migrate_sensitive_storage_rows",
        lambda: 0,
    )

    bootstrap_instance(app, "admin", "ContainerAdminPassword!2026")
    bootstrap_instance(app, "admin", "ContainerAdminPassword!2026")

    with app.app_context():
        assert _count_rows(Settings) == 1
        assert _count_rows(Users, admin=True) == 1
        assert _count_rows(TaskGroups, name="maskmode 1-10") == 1
