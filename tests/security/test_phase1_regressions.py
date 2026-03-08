import importlib.util
import json
from pathlib import Path

import pytest

from hashcrush import create_app
from hashcrush.models import (
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    Rules,
    Settings,
    TaskGroups,
    Tasks,
    Users,
    Wordlists,
    db,
)
from hashcrush.users.routes import bcrypt


def _build_app():
    return create_app(
        testing=True,
        config_overrides={
            "SECRET_KEY": "phase1-test-secret",
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "WTF_CSRF_ENABLED": False,
            "AUTO_SETUP_DEFAULTS": False,
            "ENABLE_SCHEDULER": False,
        },
    )


def _load_cli_module():
    project_root = Path(__file__).resolve().parents[2]
    script_path = project_root / "hashcrush.py"
    spec = importlib.util.spec_from_file_location("hashcrush_cli_script", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def _seed_admin_user() -> Users:
    valid_password_hash = bcrypt.generate_password_hash("test-admin-password").decode("utf-8")
    user = Users(
        first_name="Admin",
        last_name="User",
        email_address="admin@example.com",
        password=valid_password_hash,
        admin=True,
        api_key="admin-api-key",
    )
    db.session.add(user)
    db.session.commit()
    return user


def _seed_settings() -> Settings:
    settings = Settings(
        retention_period=0,
        max_runtime_jobs=0,
        max_runtime_tasks=0,
        enabled_job_weights=False,
    )
    db.session.add(settings)
    db.session.commit()
    return settings


def _login_client_as_user(client, user: Users):
    with client.session_transaction() as session:
        session["_user_id"] = str(user.id)
        session["_fresh"] = True


@pytest.mark.security
def test_ensure_settings_cli_adds_settings_only_when_missing():
    cli_module = _load_cli_module()
    app = _build_app()
    with app.app_context():
        db.create_all()
        assert Settings.query.count() == 0

        cli_module.ensure_settings_cli(db)
        assert Settings.query.count() == 1

        cli_module.ensure_settings_cli(db)
        assert Settings.query.count() == 1


@pytest.mark.security
def test_analytics_download_rejects_invalid_customer_id_and_uses_hashfile_id_in_filename():
    app = _build_app()
    with app.app_context():
        db.create_all()
        user = _seed_admin_user()
        _seed_settings()
        customer = Customers(name="ACME")
        db.session.add(customer)
        db.session.commit()
        hashfile = Hashfiles(name="sample.txt", customer_id=customer.id, owner_id=user.id)
        db.session.add(hashfile)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, user)

        invalid = client.get("/analytics/download?type=found&customer_id=../../etc/passwd")
        assert invalid.status_code == 302
        assert invalid.headers["Location"].endswith("/analytics")

        valid = client.get(
            f"/analytics/download?type=found&customer_id={customer.id}&hashfile_id={hashfile.id}"
        )
        assert valid.status_code == 200
        content_disposition = valid.headers.get("Content-Disposition", "")
        assert f"found_{customer.id}_{hashfile.id}.txt" in content_disposition


@pytest.mark.security
def test_hashfiles_delete_removes_orphan_hashes():
    app = _build_app()
    with app.app_context():
        db.create_all()
        user = _seed_admin_user()
        _seed_settings()

        customer = Customers(name="ACME")
        db.session.add(customer)
        db.session.commit()

        hashfile = Hashfiles(name="to-delete.txt", customer_id=customer.id, owner_id=user.id)
        db.session.add(hashfile)
        db.session.commit()

        hash_row = Hashes(
            sub_ciphertext="deadbeefdeadbeefdeadbeefdeadbeef",
            ciphertext="11223344556677889900aabbccddeeff",
            hash_type=1000,
            cracked=False,
            plaintext=None,
        )
        db.session.add(hash_row)
        db.session.commit()

        link = HashfileHashes(hash_id=hash_row.id, hashfile_id=hashfile.id)
        db.session.add(link)
        db.session.commit()

        hash_row_id = hash_row.id

        client = app.test_client()
        _login_client_as_user(client, user)

        response = client.get(f"/hashfiles/delete/{hashfile.id}")
        assert response.status_code == 302

        assert Hashfiles.query.filter_by(id=hashfile.id).count() == 0
        assert HashfileHashes.query.filter_by(hashfile_id=hashfile.id).count() == 0
        assert Hashes.query.filter_by(id=hash_row_id).count() == 0


@pytest.mark.security
def test_add_default_tasks_seeds_bruteforce_mask_set_and_group():
    from hashcrush.setup import add_default_tasks

    app = _build_app()
    with app.app_context():
        db.create_all()
        _seed_admin_user()

        add_default_tasks(db)

        seeded_tasks = Tasks.query.order_by(Tasks.id.asc()).all()
        assert len(seeded_tasks) == 10
        expected_masks = ['?a' * length for length in range(1, 11)]
        expected_names = [f'{mask} [{length}]' for length, mask in enumerate(expected_masks, start=1)]
        assert [task.hc_mask for task in seeded_tasks] == expected_masks
        assert [task.name for task in seeded_tasks] == expected_names
        assert all(task.hc_attackmode == 'maskmode' for task in seeded_tasks)

        task_group = TaskGroups.query.filter_by(name='bruteforce 1-10').first()
        assert task_group is not None
        assert task_group.owner_id == 1
        assert json.loads(task_group.tasks) == [task.id for task in seeded_tasks]


@pytest.mark.security
def test_runtime_bootstrap_creates_required_directories(tmp_path):
    from hashcrush import _ensure_runtime_directories

    root_path = tmp_path / "runtime-root"
    _ensure_runtime_directories(str(root_path))

    assert (root_path / "control" / "tmp").is_dir()
    assert (root_path / "control" / "hashes").is_dir()
    assert (root_path / "control" / "outfiles").is_dir()
    assert (root_path / "ssl").is_dir()


@pytest.mark.security
def test_setup_defaults_no_longer_seeds_rules_or_wordlists():
    from hashcrush import setup_defaults_if_needed

    app = _build_app()
    with app.app_context():
        db.create_all()

        setup_defaults_if_needed()

        assert Rules.query.count() == 0
        assert Wordlists.query.count() == 0


@pytest.mark.security
def test_rules_selectable_files_support_nested_folders(tmp_path):
    from hashcrush.rules.routes import _list_selectable_files, _resolve_selected_file

    rules_root = tmp_path / "rules"
    nested_dir = rules_root / "example_folder1"
    nested_dir.mkdir(parents=True, exist_ok=True)
    nested_file = nested_dir / "best64.rule"
    nested_file.write_text("X", encoding="utf-8")
    non_rule_file = nested_dir / "not_a_rule.txt"
    non_rule_file.write_text("Z", encoding="utf-8")
    hidden_dir = rules_root / ".hidden"
    hidden_dir.mkdir(parents=True, exist_ok=True)
    hidden_file = hidden_dir / "secret.rule"
    hidden_file.write_text("Y", encoding="utf-8")

    selectable_files, truncated = _list_selectable_files(str(rules_root))
    assert truncated is False
    assert ("example_folder1/best64.rule", "example_folder1/best64.rule") in selectable_files
    assert ("example_folder1/not_a_rule.txt", "example_folder1/not_a_rule.txt") not in selectable_files
    assert (".hidden/secret.rule", ".hidden/secret.rule") not in selectable_files

    resolved_nested = _resolve_selected_file("example_folder1/best64.rule", str(rules_root))
    assert resolved_nested == str(nested_file.resolve())
    assert _resolve_selected_file(".hidden/secret.rule", str(rules_root)) == str(hidden_file.resolve())
    assert _resolve_selected_file("../etc/passwd", str(rules_root)) is None
    missing_files, missing_truncated = _list_selectable_files(str(rules_root / "does-not-exist"))
    assert missing_files == []
    assert missing_truncated is False


@pytest.mark.security
def test_wordlists_selectable_files_support_nested_folders(tmp_path):
    from hashcrush.wordlists.routes import _list_selectable_files, _resolve_selected_file

    wordlists_root = tmp_path / "wordlists"
    nested_dir = wordlists_root / "example_folder1"
    nested_dir.mkdir(parents=True, exist_ok=True)
    nested_file = nested_dir / "rockyou.txt"
    nested_file.write_text("password", encoding="utf-8")
    nested_tar_file = nested_dir / "rockyou.txt.tar.gz"
    nested_tar_file.write_text("compressed-placeholder", encoding="utf-8")
    disallowed_file = nested_dir / "ignore.csv"
    disallowed_file.write_text("x,y", encoding="utf-8")
    hidden_dir = wordlists_root / ".hidden"
    hidden_dir.mkdir(parents=True, exist_ok=True)
    hidden_file = hidden_dir / "secret.txt"
    hidden_file.write_text("secret", encoding="utf-8")

    selectable_files, truncated = _list_selectable_files(str(wordlists_root))
    assert truncated is False
    assert ("example_folder1/rockyou.txt", "example_folder1/rockyou.txt") in selectable_files
    assert ("example_folder1/rockyou.txt.tar.gz", "example_folder1/rockyou.txt.tar.gz") not in selectable_files
    assert ("example_folder1/ignore.csv", "example_folder1/ignore.csv") not in selectable_files
    assert (".hidden/secret.txt", ".hidden/secret.txt") not in selectable_files

    resolved_nested = _resolve_selected_file("example_folder1/rockyou.txt", str(wordlists_root))
    assert resolved_nested == str(nested_file.resolve())
    resolved_nested_tar = _resolve_selected_file("example_folder1/rockyou.txt.tar.gz", str(wordlists_root))
    assert resolved_nested_tar is None
    assert _resolve_selected_file("example_folder1/ignore.csv", str(wordlists_root)) is None
    assert _resolve_selected_file(".hidden/secret.txt", str(wordlists_root)) == str(hidden_file.resolve())
    assert _resolve_selected_file("../etc/passwd", str(wordlists_root)) is None
    missing_files, missing_truncated = _list_selectable_files(str(wordlists_root / "does-not-exist"))
    assert missing_files == []
    assert missing_truncated is False
