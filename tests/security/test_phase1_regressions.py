from configparser import ConfigParser
import importlib.util
import io
import json
from pathlib import Path

import pytest
from sqlalchemy import inspect

from hashcrush import create_app
from hashcrush.config import sanitize_config_input
from hashcrush.models import (
    Domains,
    Hashes,
    HashfileHashes,
    Hashfiles,
    Jobs,
    JobTasks,
    Rules,
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
    validate_hash_only_hashfile,
    validate_netntlm_hashfile,
    validate_user_hash_hashfile,
)


def _build_app(extra_overrides: dict | None = None):
    base_overrides = {
        "SECRET_KEY": "phase1-test-secret",
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


def _seed_admin_user() -> Users:
    valid_password_hash = bcrypt.generate_password_hash("test-admin-password").decode("utf-8")
    user = Users(
        username="admin",
        password=valid_password_hash,
        admin=True,
    )
    db.session.add(user)
    db.session.commit()
    return user


def _seed_user(username: str, password: str = "test-user-password", admin: bool = False) -> Users:
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
def test_cli_resolve_ssl_context_uses_configured_paths(tmp_path):
    cli_module = _load_cli_module()
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_text("certificate", encoding="utf-8")
    key_path.write_text("private-key", encoding="utf-8")

    class _App:
        config = {
            "SSL_CERT_PATH": str(cert_path),
            "SSL_KEY_PATH": str(key_path),
        }

    resolved = cli_module._resolve_ssl_context(_App())
    assert resolved == (str(cert_path.resolve()), str(key_path.resolve()))


@pytest.mark.security
def test_cli_resolve_ssl_context_rejects_missing_files(tmp_path):
    cli_module = _load_cli_module()
    missing_cert = tmp_path / "missing-cert.pem"
    missing_key = tmp_path / "missing-key.pem"

    class _App:
        config = {
            "SSL_CERT_PATH": str(missing_cert),
            "SSL_KEY_PATH": str(missing_key),
        }

    with pytest.raises(RuntimeError, match="SSL certificate file not found"):
        cli_module._resolve_ssl_context(_App())


@pytest.mark.security
def test_sanitize_config_input_handles_delete_backspace_artifacts():
    raw_value = "hj\x7f\x7f\x7f\x7fhashcrush"
    cleaned = sanitize_config_input(raw_value)
    assert cleaned == "hashcrush"

    mixed = "ab\x08c\x01\x02d"
    assert sanitize_config_input(mixed) == "acd"


@pytest.mark.security
def test_analytics_download_rejects_invalid_domain_id_and_uses_hashfile_id_in_filename():
    app = _build_app()
    with app.app_context():
        db.create_all()
        user = _seed_admin_user()
        _seed_settings()
        domain = Domains(name="ACME")
        db.session.add(domain)
        db.session.commit()
        hashfile = Hashfiles(name="sample.txt", domain_id=domain.id, owner_id=user.id)
        db.session.add(hashfile)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, user)

        invalid = client.get("/analytics/download?type=found&domain_id=../../etc/passwd")
        assert invalid.status_code == 302
        assert invalid.headers["Location"].endswith("/analytics")

        valid = client.get(
            f"/analytics/download?type=found&domain_id={domain.id}&hashfile_id={hashfile.id}"
        )
        assert valid.status_code == 200
        content_disposition = valid.headers.get("Content-Disposition", "")
        assert f"found_{domain.id}_{hashfile.id}.txt" in content_disposition


@pytest.mark.security
def test_hashfiles_delete_removes_orphan_hashes():
    app = _build_app()
    with app.app_context():
        db.create_all()
        user = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="ACME")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="to-delete.txt", domain_id=domain.id, owner_id=user.id)
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

        response = client.post(f"/hashfiles/delete/{hashfile.id}")
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


@pytest.mark.security
def test_runtime_bootstrap_uses_configured_runtime_root(tmp_path):
    from hashcrush import _ensure_runtime_directories

    root_path = tmp_path / "app-root"
    runtime_path = tmp_path / "custom-runtime"
    _ensure_runtime_directories(str(root_path), str(runtime_path))

    assert (runtime_path / "tmp").is_dir()
    assert (runtime_path / "hashes").is_dir()
    assert (runtime_path / "outfiles").is_dir()


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
    (hidden_dir / "secret.rule").write_text("Y", encoding="utf-8")

    selectable_files, truncated = _list_selectable_files(str(rules_root))
    assert truncated is False
    assert ("example_folder1/best64.rule", "example_folder1/best64.rule") in selectable_files
    assert ("example_folder1/not_a_rule.txt", "example_folder1/not_a_rule.txt") not in selectable_files
    assert (".hidden/secret.rule", ".hidden/secret.rule") not in selectable_files

    resolved_nested = _resolve_selected_file("example_folder1/best64.rule", str(rules_root))
    assert resolved_nested == str(nested_file.resolve())
    assert _resolve_selected_file(".hidden/secret.rule", str(rules_root)) is None
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
    (hidden_dir / "secret.txt").write_text("secret", encoding="utf-8")

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
    assert _resolve_selected_file(".hidden/secret.txt", str(wordlists_root)) is None
    assert _resolve_selected_file("../etc/passwd", str(wordlists_root)) is None
    missing_files, missing_truncated = _list_selectable_files(str(wordlists_root / "does-not-exist"))
    assert missing_files == []
    assert missing_truncated is False


@pytest.mark.security
def test_plaintext_storage_migration_normalizes_legacy_rows():
    from hashcrush.utils.utils import (
        decode_plaintext_from_storage,
        encode_plaintext_for_storage,
        migrate_plaintext_storage_rows,
    )

    app = _build_app()
    with app.app_context():
        db.create_all()

        legacy = Hashes(
            sub_ciphertext="11111111111111111111111111111111",
            ciphertext="legacy-cipher",
            hash_type=1000,
            cracked=True,
            plaintext="PASSWORD",
        )
        canonical_value = encode_plaintext_for_storage("Summer2026!")
        canonical = Hashes(
            sub_ciphertext="22222222222222222222222222222222",
            ciphertext="canonical-cipher",
            hash_type=1000,
            cracked=True,
            plaintext=canonical_value,
        )
        db.session.add_all([legacy, canonical])
        db.session.commit()

        migrated_rows = migrate_plaintext_storage_rows()
        assert migrated_rows == 1

        legacy_row = Hashes.query.get(legacy.id)
        canonical_row = Hashes.query.get(canonical.id)

        assert legacy_row.plaintext == encode_plaintext_for_storage("PASSWORD")
        assert decode_plaintext_from_storage(legacy_row.plaintext) == "PASSWORD"
        assert canonical_row.plaintext == canonical_value
        assert decode_plaintext_from_storage(canonical_row.plaintext) == "Summer2026!"


@pytest.mark.security
def test_executor_import_stores_plaintext_in_hex_format(tmp_path):
    from hashcrush.executor.service import LocalExecutorService
    from hashcrush.utils.utils import encode_plaintext_for_storage, get_md5_hash

    app = _build_app()
    with app.app_context():
        db.create_all()
        user = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="ACME")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="input.txt", domain_id=domain.id, owner_id=user.id)
        db.session.add(hashfile)
        db.session.commit()

        hash_row = Hashes(
            sub_ciphertext=get_md5_hash("abc123"),
            ciphertext="abc123",
            hash_type=1000,
            cracked=False,
            plaintext=None,
        )
        db.session.add(hash_row)
        db.session.commit()

        db.session.add(HashfileHashes(hash_id=hash_row.id, hashfile_id=hashfile.id))
        db.session.commit()

        task = Tasks(
            name="mask",
            hc_attackmode="maskmode",
            owner_id=user.id,
            wl_id=None,
            rule_id=None,
            hc_mask="?a",
        )
        db.session.add(task)
        db.session.commit()

        job = Jobs(
            name="job-1",
            status="Running",
            domain_id=domain.id,
            owner_id=user.id,
            hashfile_id=hashfile.id,
        )
        db.session.add(job)
        db.session.commit()

        job_task = JobTasks(job_id=job.id, task_id=task.id, status="Running")
        db.session.add(job_task)
        db.session.commit()

        crack_path = tmp_path / "cracked.txt"
        crack_path.write_text("abc123:Pa$$w0rd\n", encoding="latin-1")

        service = LocalExecutorService(app)
        imported_count = service._import_crack_file_for_task(job_task, str(crack_path))
        assert imported_count == 1

        imported_hash = Hashes.query.get(hash_row.id)
        assert imported_hash.cracked is True
        assert imported_hash.plaintext == encode_plaintext_for_storage("Pa$$w0rd")


@pytest.mark.security
def test_executor_canceled_flow_imports_recovered_hashes(tmp_path, monkeypatch):
    from hashcrush.executor.service import ActiveTask, LocalExecutorService
    from hashcrush.utils.utils import encode_plaintext_for_storage, get_md5_hash

    class _DoneProcess:
        def __init__(self):
            self.returncode = 1

        def poll(self):
            return self.returncode

    monkeypatch.setattr(
        "hashcrush.executor.service.update_job_task_status",
        lambda job_task_id, status: None,
    )

    app = _build_app()
    with app.app_context():
        db.create_all()
        user = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="ACME")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="input.txt", domain_id=domain.id, owner_id=user.id)
        db.session.add(hashfile)
        db.session.commit()

        hash_row = Hashes(
            sub_ciphertext=get_md5_hash("abc123"),
            ciphertext="abc123",
            hash_type=1000,
            cracked=False,
            plaintext=None,
        )
        db.session.add(hash_row)
        db.session.commit()

        db.session.add(HashfileHashes(hash_id=hash_row.id, hashfile_id=hashfile.id))
        db.session.commit()

        task = Tasks(
            name="mask",
            hc_attackmode="maskmode",
            owner_id=user.id,
            wl_id=None,
            rule_id=None,
            hc_mask="?a",
        )
        db.session.add(task)
        db.session.commit()

        job = Jobs(
            name="job-1",
            status="Running",
            domain_id=domain.id,
            owner_id=user.id,
            hashfile_id=hashfile.id,
        )
        db.session.add(job)
        db.session.commit()

        job_task = JobTasks(job_id=job.id, task_id=task.id, status="Canceled")
        db.session.add(job_task)
        db.session.commit()

        crack_path = tmp_path / "cracked.txt"
        crack_path.write_text("abc123:RecoveredDuringCancel\n", encoding="latin-1")
        output_path = tmp_path / "hashcat_output.txt"
        output_path.write_text("Status...........: Aborted\n", encoding="utf-8")
        hash_path = tmp_path / "hashes.txt"
        hash_path.write_text("abc123\n", encoding="utf-8")
        output_file = output_path.open("a", encoding="utf-8")

        service = LocalExecutorService(app)
        service._active = ActiveTask(
            job_task_id=job_task.id,
            process=_DoneProcess(),
            output_file=output_file,
            output_path=str(output_path),
            hash_path=str(hash_path),
            crack_path=str(crack_path),
            last_progress_log_at=0.0,
            last_import_at=0.0,
        )

        service._monitor_active_task()

        imported_hash = Hashes.query.get(hash_row.id)
        assert imported_hash.cracked is True
        assert imported_hash.plaintext == encode_plaintext_for_storage("RecoveredDuringCancel")


@pytest.mark.security
def test_recover_orphaned_tasks_imports_crackfile_before_requeue(tmp_path):
    from hashcrush.executor.service import LocalExecutorService
    from hashcrush.utils.utils import encode_plaintext_for_storage, get_md5_hash

    app = _build_app({"RUNTIME_PATH": str(tmp_path)})
    with app.app_context():
        db.create_all()
        user = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="recover-domain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="recover.txt", domain_id=domain.id, owner_id=user.id)
        db.session.add(hashfile)
        db.session.commit()

        hash_row = Hashes(
            sub_ciphertext=get_md5_hash("orphan-hash"),
            ciphertext="orphan-hash",
            hash_type=1000,
            cracked=False,
            plaintext=None,
        )
        db.session.add(hash_row)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=hash_row.id, hashfile_id=hashfile.id))
        db.session.commit()

        task = Tasks(
            name="recover-task",
            hc_attackmode="maskmode",
            owner_id=user.id,
            wl_id=None,
            rule_id=None,
            hc_mask="?a",
        )
        db.session.add(task)
        db.session.commit()

        job = Jobs(
            name="recover-job",
            status="Running",
            domain_id=domain.id,
            owner_id=user.id,
            hashfile_id=hashfile.id,
        )
        db.session.add(job)
        db.session.commit()

        orphan = JobTasks(job_id=job.id, task_id=task.id, status="Running")
        db.session.add(orphan)
        db.session.commit()

        outfiles_dir = tmp_path / "outfiles"
        outfiles_dir.mkdir(parents=True, exist_ok=True)
        crack_path = outfiles_dir / f"hc_cracked_{job.id}_{task.id}.txt"
        crack_path.write_text("orphan-hash:RecoveredAfterCrash\n", encoding="latin-1")

        service = LocalExecutorService(app)
        service._recover_orphaned_tasks()

        db.session.refresh(orphan)
        db.session.refresh(job)
        imported_hash = Hashes.query.get(hash_row.id)
        assert orphan.status == "Queued"
        assert job.status == "Queued"
        assert imported_hash.cracked is True
        assert imported_hash.plaintext == encode_plaintext_for_storage("RecoveredAfterCrash")


@pytest.mark.security
def test_executor_running_checkpoint_imports_cracks(tmp_path):
    from hashcrush.executor.service import ActiveTask, LocalExecutorService
    from hashcrush.utils.utils import encode_plaintext_for_storage, get_md5_hash

    class _RunningProcess:
        returncode = None

        @staticmethod
        def poll():
            return None

    app = _build_app(
        {
            "RUNTIME_PATH": str(tmp_path),
            "CRACK_IMPORT_INTERVAL_SECONDS": 1,
        }
    )
    with app.app_context():
        db.create_all()
        user = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="checkpoint-domain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="checkpoint.txt", domain_id=domain.id, owner_id=user.id)
        db.session.add(hashfile)
        db.session.commit()

        hash_row = Hashes(
            sub_ciphertext=get_md5_hash("checkpoint-hash"),
            ciphertext="checkpoint-hash",
            hash_type=1000,
            cracked=False,
            plaintext=None,
        )
        db.session.add(hash_row)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=hash_row.id, hashfile_id=hashfile.id))
        db.session.commit()

        task = Tasks(
            name="checkpoint-task",
            hc_attackmode="maskmode",
            owner_id=user.id,
            wl_id=None,
            rule_id=None,
            hc_mask="?a",
        )
        db.session.add(task)
        db.session.commit()

        job = Jobs(
            name="checkpoint-job",
            status="Running",
            domain_id=domain.id,
            owner_id=user.id,
            hashfile_id=hashfile.id,
        )
        db.session.add(job)
        db.session.commit()

        running_task = JobTasks(job_id=job.id, task_id=task.id, status="Running")
        db.session.add(running_task)
        db.session.commit()

        outfiles_dir = tmp_path / "outfiles"
        outfiles_dir.mkdir(parents=True, exist_ok=True)
        crack_path = outfiles_dir / f"hc_cracked_{job.id}_{task.id}.txt"
        crack_path.write_text("checkpoint-hash:RecoveredDuringRun\n", encoding="latin-1")
        output_path = outfiles_dir / f"hcoutput_{job.id}_{running_task.id}.txt"
        output_path.write_text(
            "Status...........: Running\nProgress.........: 1/10 (10.00%)\n",
            encoding="utf-8",
        )
        hash_path = tmp_path / "hashes" / f"hashfile_{job.id}_{task.id}.txt"
        hash_path.parent.mkdir(parents=True, exist_ok=True)
        hash_path.write_text("checkpoint-hash\n", encoding="utf-8")
        output_file = output_path.open("a", encoding="utf-8")

        service = LocalExecutorService(app)
        service._active = ActiveTask(
            job_task_id=running_task.id,
            process=_RunningProcess(),
            output_file=output_file,
            output_path=str(output_path),
            hash_path=str(hash_path),
            crack_path=str(crack_path),
            last_progress_log_at=0.0,
            last_import_at=0.0,
        )

        service._monitor_active_task()

        imported_hash = Hashes.query.get(hash_row.id)
        assert imported_hash.cracked is True
        assert imported_hash.plaintext == encode_plaintext_for_storage("RecoveredDuringRun")


@pytest.mark.security
def test_hashcat_exit_code_one_is_success_when_status_indicates_exhausted(tmp_path):
    from hashcrush.executor.service import _is_successful_hashcat_exit, _parse_hashcat_status

    output_path = tmp_path / "hashcat_status.txt"
    output_path.write_text(
        "Status...........: Exhausted\n"
        "Recovered........: 0/1000 (0.00%) Digests (total), 0/1000 (0.00%) Digests (new)\n"
        "Progress.........: 7737809375/7737809375 (100.00%)\n",
        encoding="utf-8",
    )

    status = _parse_hashcat_status(str(output_path))
    assert status.get("Status") == "Exhausted"
    assert _is_successful_hashcat_exit(1, status) is True


@pytest.mark.security
def test_hashcat_exit_code_one_without_completion_signal_is_failure():
    from hashcrush.executor.service import _is_successful_hashcat_exit

    status = {"Status": "Aborted", "Progress": "1/10 (10.00%)"}
    assert _is_successful_hashcat_exit(1, status) is False


@pytest.mark.security
def test_jobs_list_displays_eta_and_percent_done_for_active_job():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="Telemetry Domain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="telemetry.txt", domain_id=domain.id, owner_id=admin.id)
        db.session.add(hashfile)
        db.session.commit()

        task = Tasks(
            name="telemetry-task",
            hc_attackmode="maskmode",
            owner_id=admin.id,
            wl_id=None,
            rule_id=None,
            hc_mask="?a?a",
        )
        db.session.add(task)
        db.session.commit()

        job = Jobs(
            name="telemetry-job",
            status="Running",
            domain_id=domain.id,
            owner_id=admin.id,
            hashfile_id=hashfile.id,
        )
        db.session.add(job)
        db.session.commit()

        progress_payload = json.dumps(
            {
                "Time_Estimated": "ETA_TEST_VALUE",
                "Progress": "127063228416/735091890625 (17.29%)",
            }
        )
        db.session.add(
            JobTasks(
                job_id=job.id,
                task_id=task.id,
                status="Running",
                progress=progress_payload,
            )
        )
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.get("/jobs")
        assert response.status_code == 200
        assert b"% Done" in response.data
        assert b"ETA" in response.data
        assert b"17.29%" in response.data
        assert b"ETA_TEST_VALUE" in response.data


@pytest.mark.security
def test_dashboard_displays_eta_and_percent_done_columns_for_tasks():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="Dashboard Domain")
        db.session.add(domain)
        db.session.commit()

        task = Tasks(
            name="dashboard-task",
            hc_attackmode="maskmode",
            owner_id=admin.id,
            wl_id=None,
            rule_id=None,
            hc_mask="?a?a",
        )
        db.session.add(task)
        db.session.commit()

        running_job = Jobs(
            name="dashboard-running",
            status="Running",
            domain_id=domain.id,
            owner_id=admin.id,
        )
        queued_job = Jobs(
            name="dashboard-queued",
            status="Queued",
            domain_id=domain.id,
            owner_id=admin.id,
        )
        db.session.add_all([running_job, queued_job])
        db.session.commit()

        running_progress = json.dumps(
            {
                "Time_Estimated": "DASHBOARD_ETA",
                "Progress": "500/1000 (50.00%)",
            }
        )
        db.session.add(
            JobTasks(
                job_id=running_job.id,
                task_id=task.id,
                status="Running",
                progress=running_progress,
            )
        )
        db.session.add(
            JobTasks(
                job_id=queued_job.id,
                task_id=task.id,
                status="Queued",
                progress=None,
            )
        )
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.get("/")
        assert response.status_code == 200
        assert b"% Done" in response.data
        assert b"ETA" in response.data
        assert b"50.00%" in response.data
        assert b"DASHBOARD_ETA" in response.data


@pytest.mark.security
def test_jobs_assigned_hashfile_validates_domain_and_visibility():
    app = _build_app()
    with app.app_context():
        db.create_all()
        _seed_settings()
        owner = _seed_user("owner")
        other = _seed_user("other")

        domain_a = Domains(name="Domain A")
        domain_b = Domains(name="Domain B")
        db.session.add_all([domain_a, domain_b])
        db.session.commit()

        job = Jobs(
            name="scoped-job",
            status="Incomplete",
            domain_id=domain_a.id,
            owner_id=owner.id,
        )
        db.session.add(job)
        db.session.commit()

        valid_hashfile = Hashfiles(name="valid.txt", domain_id=domain_a.id, owner_id=owner.id)
        wrong_owner_hashfile = Hashfiles(name="other-owner.txt", domain_id=domain_a.id, owner_id=other.id)
        wrong_domain_hashfile = Hashfiles(name="other-domain.txt", domain_id=domain_b.id, owner_id=owner.id)
        db.session.add_all([valid_hashfile, wrong_owner_hashfile, wrong_domain_hashfile])
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, owner)

        response_wrong_owner = client.post(
            f"/jobs/{job.id}/assigned_hashfile/",
            data={"hashfile_id": str(wrong_owner_hashfile.id)},
        )
        assert response_wrong_owner.status_code == 302
        assert Jobs.query.get(job.id).hashfile_id is None

        response_wrong_domain = client.post(
            f"/jobs/{job.id}/assigned_hashfile/",
            data={"hashfile_id": str(wrong_domain_hashfile.id)},
        )
        assert response_wrong_domain.status_code == 302
        assert Jobs.query.get(job.id).hashfile_id is None

        response_valid = client.post(
            f"/jobs/{job.id}/assigned_hashfile/",
            data={"hashfile_id": str(valid_hashfile.id)},
        )
        assert response_valid.status_code == 302
        assert Jobs.query.get(job.id).hashfile_id == valid_hashfile.id


@pytest.mark.security
def test_domains_delete_blocks_when_active_jobs_exist():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="Protected Domain")
        db.session.add(domain)
        db.session.commit()

        active_job = Jobs(
            name="active-job",
            status="Running",
            domain_id=domain.id,
            owner_id=admin.id,
        )
        db.session.add(active_job)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(f"/domains/delete/{domain.id}")
        assert response.status_code == 302
        assert Domains.query.get(domain.id) is not None
        assert Jobs.query.get(active_job.id) is not None


@pytest.mark.security
def test_domains_delete_removes_inactive_jobs_and_orphans():
    from hashcrush.utils.utils import get_md5_hash

    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="Cleanup Domain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="cleanup.txt", domain_id=domain.id, owner_id=admin.id)
        db.session.add(hashfile)
        db.session.commit()

        orphan_hash = Hashes(
            sub_ciphertext=get_md5_hash("cleanup-hash"),
            ciphertext="cleanup-hash",
            hash_type=1000,
            cracked=False,
            plaintext=None,
        )
        db.session.add(orphan_hash)
        db.session.commit()

        db.session.add(HashfileHashes(hash_id=orphan_hash.id, hashfile_id=hashfile.id))
        db.session.commit()

        inactive_job = Jobs(
            name="completed-job",
            status="Completed",
            domain_id=domain.id,
            owner_id=admin.id,
            hashfile_id=hashfile.id,
        )
        db.session.add(inactive_job)
        db.session.commit()

        cleanup_task = Tasks(
            name="cleanup-task",
            hc_attackmode="maskmode",
            owner_id=admin.id,
            wl_id=None,
            rule_id=None,
            hc_mask="?a",
        )
        db.session.add(cleanup_task)
        db.session.commit()

        db.session.add(JobTasks(job_id=inactive_job.id, task_id=cleanup_task.id, status="Completed"))
        db.session.commit()

        domain_id = domain.id
        inactive_job_id = inactive_job.id
        hashfile_id = hashfile.id
        orphan_hash_id = orphan_hash.id

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(f"/domains/delete/{domain_id}")
        assert response.status_code == 302

        assert Domains.query.get(domain_id) is None
        assert Jobs.query.get(inactive_job_id) is None
        assert Hashfiles.query.get(hashfile_id) is None
        assert HashfileHashes.query.filter_by(hashfile_id=hashfile_id).count() == 0
        assert Hashes.query.get(orphan_hash_id) is None


@pytest.mark.security
def test_settings_page_renders_without_csrf_template_failure():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.get("/settings")
        assert response.status_code == 200
        assert b"csrf_token" in response.data
        assert b"database.host" in response.data
        assert b"app.hashcat_bin" in response.data
        assert b"Default When Empty" in response.data


@pytest.mark.security
def test_settings_hashcrush_config_update_persists_values(tmp_path):
    config_path = tmp_path / "config.conf"
    config_path.write_text(
        "[database]\n"
        "host = old-db-host\n"
        "username = old-db-user\n"
        "password = old-db-pass\n\n"
        "[app]\n"
        "hashcat_bin = hashcat\n"
        "hashcat_status_timer = 5\n",
        encoding="utf-8",
    )

    app = _build_app({"HASHCRUSH_CONFIG_PATH": str(config_path)})
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            "/settings/hashcrush_config",
            data={
                "cfg__database__host": "new-db-host",
                "cfg__database__username": "new-db-user",
                "cfg__database__password": "hj\x7f\x7fhashcrush",
                "cfg__app__hashcat_bin": "/usr/bin/hashcat",
                "cfg__app__hashcat_status_timer": "10",
                "cfg__app__runtime_path": "/tmp/hashcrush-runtime-custom",
            },
        )
        assert response.status_code == 302

        parser = ConfigParser(interpolation=None)
        parser.read(config_path)

        assert parser.get("database", "host") == "new-db-host"
        assert parser.get("database", "username") == "new-db-user"
        assert parser.get("database", "password") == "hashcrush"
        assert parser.get("app", "hashcat_bin") == "/usr/bin/hashcat"
        assert parser.get("app", "hashcat_status_timer") == "10"
        assert parser.get("app", "runtime_path") == "/tmp/hashcrush-runtime-custom"


@pytest.mark.security
def test_login_throttle_blocks_repeated_failures():
    app = _build_app(
        {
            "AUTH_THROTTLE_ENABLED": True,
            "AUTH_THROTTLE_MAX_ATTEMPTS": 2,
            "AUTH_THROTTLE_WINDOW_SECONDS": 300,
            "AUTH_THROTTLE_LOCKOUT_SECONDS": 60,
        }
    )
    with app.app_context():
        db.create_all()
        _seed_admin_user()
        _seed_settings()

        client = app.test_client()

        first = client.post("/login", data={"username": "admin", "password": "wrong-password"})
        assert first.status_code == 200

        second = client.post("/login", data={"username": "admin", "password": "wrong-password"})
        assert second.status_code == 200

        blocked = client.post("/login", data={"username": "admin", "password": "wrong-password"})
        assert blocked.status_code == 429
        assert blocked.headers.get("Retry-After") is not None

        blocked_valid = client.post(
            "/login",
            data={"username": "admin", "password": "test-admin-password"},
        )
        assert blocked_valid.status_code == 429


@pytest.mark.security
def test_login_throttle_can_be_disabled():
    app = _build_app(
        {
            "AUTH_THROTTLE_ENABLED": False,
            "AUTH_THROTTLE_MAX_ATTEMPTS": 1,
            "AUTH_THROTTLE_WINDOW_SECONDS": 300,
            "AUTH_THROTTLE_LOCKOUT_SECONDS": 60,
        }
    )
    with app.app_context():
        db.create_all()
        _seed_admin_user()
        _seed_settings()

        client = app.test_client()

        first = client.post("/login", data={"username": "admin", "password": "wrong-password"})
        second = client.post("/login", data={"username": "admin", "password": "wrong-password"})
        assert first.status_code == 200
        assert second.status_code == 200


@pytest.mark.security
def test_hashfile_validator_rejects_overlong_lines(tmp_path):
    app = _build_app({"HASHFILE_MAX_LINE_LENGTH": 10})
    with app.app_context():
        db.create_all()

        path = tmp_path / "long-line.txt"
        path.write_text("12345678901\n", encoding="utf-8")
        error = validate_hash_only_hashfile(str(path), "0")
        assert isinstance(error, str)
        assert "too long" in error.lower()


@pytest.mark.security
def test_hashfile_validator_rejects_oversized_files(tmp_path):
    app = _build_app({"HASHFILE_MAX_TOTAL_BYTES": 10})
    with app.app_context():
        db.create_all()

        path = tmp_path / "oversized.txt"
        path.write_text("0123456789abcdef\n", encoding="utf-8")
        error = validate_user_hash_hashfile(str(path))
        assert isinstance(error, str)
        assert "too large" in error.lower()


@pytest.mark.security
def test_hashfile_validator_rejects_too_many_lines(tmp_path):
    app = _build_app({"HASHFILE_MAX_TOTAL_LINES": 2})
    with app.app_context():
        db.create_all()

        path = tmp_path / "too-many-lines.txt"
        path.write_text(
            "0123456789abcdef0123456789abcdef\n"
            "fedcba9876543210fedcba9876543210\n"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
            encoding="utf-8",
        )
        error = validate_hash_only_hashfile(str(path), "0")
        assert isinstance(error, str)
        assert "too many lines" in error.lower()


@pytest.mark.security
def test_netntlm_validator_still_rejects_duplicate_user_host(tmp_path):
    app = _build_app()
    with app.app_context():
        db.create_all()

        path = tmp_path / "duplicate-netntlm.txt"
        path.write_text(
            "alice::WORKSTATION:1122334455667788:99aabbccddeeff00:0101000000000000\n"
            "alice::WORKSTATION:ffeeddccbbaa9988:0011223344556677:0101000000000000\n",
            encoding="utf-8",
        )
        error = validate_netntlm_hashfile(str(path))
        assert isinstance(error, str)
        assert "duplicate" in error.lower()


@pytest.mark.security
def test_dynamic_wordlist_update_is_scoped_to_requesting_user_data(tmp_path):
    app = _build_app()
    with app.app_context():
        db.create_all()
        owner = _seed_user("owner-user", password="owner-user-password", admin=False)
        other = _seed_user("other-user", password="other-user-password", admin=False)
        _seed_settings()

        domain = Domains(name="ScopeDomain")
        db.session.add(domain)
        db.session.commit()

        owner_hashfile = Hashfiles(name="owner.txt", domain_id=domain.id, owner_id=owner.id)
        other_hashfile = Hashfiles(name="other.txt", domain_id=domain.id, owner_id=other.id)
        db.session.add(owner_hashfile)
        db.session.add(other_hashfile)
        db.session.commit()

        owner_hash = Hashes(
            sub_ciphertext="11111111111111111111111111111111",
            ciphertext="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            hash_type=1000,
            cracked=True,
            plaintext=encode_plaintext_for_storage("owner-secret"),
        )
        other_hash = Hashes(
            sub_ciphertext="22222222222222222222222222222222",
            ciphertext="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            hash_type=1000,
            cracked=True,
            plaintext=encode_plaintext_for_storage("other-secret"),
        )
        db.session.add(owner_hash)
        db.session.add(other_hash)
        db.session.commit()

        db.session.add(HashfileHashes(hash_id=owner_hash.id, hashfile_id=owner_hashfile.id))
        db.session.add(HashfileHashes(hash_id=other_hash.id, hashfile_id=other_hashfile.id))
        db.session.commit()

        dynamic_wordlist_path = tmp_path / "dynamic-wordlist.txt"
        dynamic_wordlist = Wordlists(
            name="dynamic-owner",
            owner_id=owner.id,
            type="dynamic",
            path=str(dynamic_wordlist_path),
            size=0,
            checksum="0" * 64,
        )
        db.session.add(dynamic_wordlist)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, owner)

        response = client.post(f"/wordlists/update/{dynamic_wordlist.id}")
        assert response.status_code == 302

        contents = dynamic_wordlist_path.read_text(encoding="utf-8")
        assert "owner-secret" in contents
        assert "other-secret" not in contents


@pytest.mark.security
def test_task_group_assigned_tasks_blocks_non_owner_access():
    app = _build_app()
    with app.app_context():
        db.create_all()
        owner = _seed_user("tg-owner", password="owner-user-password", admin=False)
        attacker = _seed_user("tg-attacker", password="attacker-user-password", admin=False)
        _seed_settings()

        task_group = TaskGroups(name="owner-group", owner_id=owner.id, tasks=json.dumps([]))
        db.session.add(task_group)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, attacker)

        response = client.get(f"/task_groups/assigned_tasks/{task_group.id}")
        assert response.status_code == 302


@pytest.mark.security
def test_task_group_mutation_blocks_non_owner():
    app = _build_app()
    with app.app_context():
        db.create_all()
        owner = _seed_user("tg-owner", password="owner-user-password", admin=False)
        attacker = _seed_user("tg-attacker", password="attacker-user-password", admin=False)
        _seed_settings()

        task = Tasks(
            name="owner-task",
            hc_attackmode="maskmode",
            owner_id=owner.id,
            wl_id=None,
            rule_id=None,
            hc_mask="?a?a",
        )
        task_group = TaskGroups(name="owner-group", owner_id=owner.id, tasks=json.dumps([]))
        db.session.add(task)
        db.session.add(task_group)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, attacker)

        response = client.post(
            f"/task_groups/assigned_tasks/{task_group.id}/add_task/{task.id}"
        )
        assert response.status_code == 302

        db.session.refresh(task_group)
        assert json.loads(task_group.tasks) == []


@pytest.mark.security
def test_analytics_download_scopes_non_admin_to_owned_hashfiles():
    app = _build_app()
    with app.app_context():
        db.create_all()
        owner = _seed_user("analytics-owner", password="owner-user-password", admin=False)
        other = _seed_user("analytics-other", password="other-user-password", admin=False)
        _seed_settings()

        domain = Domains(name="SharedDomain")
        db.session.add(domain)
        db.session.commit()

        owner_hashfile = Hashfiles(name="owner.txt", domain_id=domain.id, owner_id=owner.id)
        other_hashfile = Hashfiles(name="other.txt", domain_id=domain.id, owner_id=other.id)
        db.session.add_all([owner_hashfile, other_hashfile])
        db.session.commit()

        owner_hash = Hashes(
            sub_ciphertext="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ciphertext="owner-ciphertext",
            hash_type=1000,
            cracked=True,
            plaintext=encode_plaintext_for_storage("owner-password"),
        )
        other_hash = Hashes(
            sub_ciphertext="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ciphertext="other-ciphertext",
            hash_type=1000,
            cracked=True,
            plaintext=encode_plaintext_for_storage("other-password"),
        )
        db.session.add_all([owner_hash, other_hash])
        db.session.commit()

        db.session.add(HashfileHashes(hash_id=owner_hash.id, hashfile_id=owner_hashfile.id))
        db.session.add(HashfileHashes(hash_id=other_hash.id, hashfile_id=other_hashfile.id))
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, owner)

        response = client.get("/analytics/download?type=found")
        assert response.status_code == 200
        content = response.data.decode("utf-8")
        assert "owner-ciphertext" in content
        assert "other-ciphertext" not in content


@pytest.mark.security
def test_search_hash_id_lookup_scopes_non_admin_to_owned_hashfiles():
    app = _build_app()
    with app.app_context():
        db.create_all()
        owner = _seed_user("search-owner", password="owner-user-password", admin=False)
        other = _seed_user("search-other", password="other-user-password", admin=False)
        _seed_settings()

        domain = Domains(name="SharedDomain")
        db.session.add(domain)
        db.session.commit()

        owner_hashfile = Hashfiles(name="owner.txt", domain_id=domain.id, owner_id=owner.id)
        other_hashfile = Hashfiles(name="other.txt", domain_id=domain.id, owner_id=other.id)
        db.session.add_all([owner_hashfile, other_hashfile])
        db.session.commit()

        owner_hash = Hashes(
            sub_ciphertext="cccccccccccccccccccccccccccccccc",
            ciphertext="owner-search-ciphertext",
            hash_type=1000,
            cracked=False,
            plaintext=None,
        )
        other_hash = Hashes(
            sub_ciphertext="dddddddddddddddddddddddddddddddd",
            ciphertext="other-search-ciphertext",
            hash_type=1000,
            cracked=False,
            plaintext=None,
        )
        db.session.add_all([owner_hash, other_hash])
        db.session.commit()

        db.session.add(HashfileHashes(hash_id=owner_hash.id, hashfile_id=owner_hashfile.id))
        db.session.add(HashfileHashes(hash_id=other_hash.id, hashfile_id=other_hashfile.id))
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, owner)

        response = client.get(f"/search?hash_id={other_hash.id}")
        assert response.status_code == 200
        assert b"other-search-ciphertext" not in response.data


@pytest.mark.security
def test_task_group_export_only_includes_current_user_owned_items():
    app = _build_app()
    with app.app_context():
        db.create_all()
        owner = _seed_user("tg-export-owner", password="owner-user-password", admin=False)
        other = _seed_user("tg-export-other", password="other-user-password", admin=False)
        _seed_settings()

        owner_task = Tasks(
            name="owner-mask",
            hc_attackmode="maskmode",
            owner_id=owner.id,
            wl_id=None,
            rule_id=None,
            hc_mask="?a?a",
        )
        other_task = Tasks(
            name="other-mask",
            hc_attackmode="maskmode",
            owner_id=other.id,
            wl_id=None,
            rule_id=None,
            hc_mask="?a?a?a",
        )
        db.session.add_all([owner_task, other_task])
        db.session.commit()

        owner_group = TaskGroups(name="owner-group", owner_id=owner.id, tasks=json.dumps([owner_task.id]))
        other_group = TaskGroups(name="other-group", owner_id=other.id, tasks=json.dumps([other_task.id]))
        db.session.add_all([owner_group, other_group])
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, owner)

        response = client.get("/task_groups/export")
        assert response.status_code == 200

        payload = json.loads(response.data.decode("utf-8"))
        exported_task_names = [entry["name"] for entry in payload["tasks"]]
        exported_group_names = [entry["name"] for entry in payload["task_groups"]]

        assert "owner-mask" in exported_task_names
        assert "other-mask" not in exported_task_names
        assert "owner-group" in exported_group_names
        assert "other-group" not in exported_group_names


@pytest.mark.security
def test_task_group_import_creates_tasks_and_groups():
    app = _build_app()
    with app.app_context():
        db.create_all()
        owner = _seed_user("tg-import-owner", password="owner-user-password", admin=False)
        _seed_settings()

        wordlist = Wordlists(
            name="rockyou",
            owner_id=owner.id,
            type="static",
            path="/tmp/rockyou.txt",
            size=1,
            checksum="0" * 64,
        )
        rule = Rules(
            name="best64",
            owner_id=owner.id,
            path="/tmp/best64.rule",
            size=1,
            checksum="1" * 64,
        )
        db.session.add_all([wordlist, rule])
        db.session.commit()

        import_payload = {
            "version": 1,
            "tasks": [
                {
                    "name": "import-dict",
                    "hc_attackmode": "dictionary",
                    "wordlist_name": "rockyou",
                    "rule_name": "best64",
                },
                {
                    "name": "import-mask",
                    "hc_attackmode": "maskmode",
                    "hc_mask": "?a?a?a",
                },
            ],
            "task_groups": [
                {
                    "name": "import-group",
                    "tasks": ["import-dict", "import-mask"],
                }
            ],
        }

        client = app.test_client()
        _login_client_as_user(client, owner)
        response = client.post(
            "/task_groups/import",
            data={
                "import_file": (
                    io.BytesIO(json.dumps(import_payload).encode("utf-8")),
                    "task_groups.json",
                )
            },
            content_type="multipart/form-data",
        )
        assert response.status_code == 302

        imported_dict_task = Tasks.query.filter_by(name="import-dict", owner_id=owner.id).first()
        imported_mask_task = Tasks.query.filter_by(name="import-mask", owner_id=owner.id).first()
        imported_group = TaskGroups.query.filter_by(name="import-group", owner_id=owner.id).first()

        assert imported_dict_task is not None
        assert imported_dict_task.wl_id == wordlist.id
        assert imported_dict_task.rule_id == rule.id
        assert imported_dict_task.hc_attackmode == "dictionary"
        assert imported_mask_task is not None
        assert imported_mask_task.hc_mask == "?a?a?a"
        assert imported_group is not None
        assert set(json.loads(imported_group.tasks)) == {imported_dict_task.id, imported_mask_task.id}


@pytest.mark.security
def test_production_session_cookie_defaults_are_hardened():
    app = create_app(
        testing=False,
        config_overrides={
            "SECRET_KEY": "phase1-test-secret",
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "AUTO_SETUP_DEFAULTS": False,
            "ENABLE_SCHEDULER": False,
            "ENABLE_LOCAL_EXECUTOR": False,
            "SKIP_RUNTIME_BOOTSTRAP": True,
            "AUTO_MIGRATE_PLAINTEXT_STORAGE": False,
            "SESSION_COOKIE_SECURE": None,
        },
    )

    assert app.config["SESSION_COOKIE_SECURE"] is True
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"


@pytest.mark.security
def test_wordlist_and_job_mutation_routes_return_404_for_invalid_ids():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response_wordlist_delete = client.post("/wordlists/delete/999999")
        assert response_wordlist_delete.status_code == 404

        response_wordlist_update = client.post("/wordlists/update/999999")
        assert response_wordlist_update.status_code == 404

        response_job_delete = client.post("/jobs/delete/999999")
        assert response_job_delete.status_code == 404


@pytest.mark.security
def test_users_delete_blocks_last_admin_account():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(f"/users/delete/{admin.id}")
        assert response.status_code == 302
        assert Users.query.get(admin.id) is not None
        assert Users.query.filter_by(admin=True).count() == 1


@pytest.mark.security
def test_users_delete_blocks_self_delete_even_when_other_admin_exists():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_user("admin2", password="test-admin-password-2", admin=True)
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(f"/users/delete/{admin.id}")
        assert response.status_code == 302
        assert Users.query.get(admin.id) is not None
        assert Users.query.filter_by(admin=True).count() == 2


@pytest.mark.security
def test_users_delete_allows_deleting_other_admin_when_not_last_admin():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        other_admin = _seed_user("admin2", password="test-admin-password-2", admin=True)
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(f"/users/delete/{other_admin.id}")
        assert response.status_code == 302
        assert Users.query.get(other_admin.id) is None
        assert Users.query.filter_by(admin=True).count() == 1


@pytest.mark.security
def test_admin_reset_blocks_self_reset_flow():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()
        original_hash = admin.password

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            f"/admin_reset_password/{admin.id}",
            data={
                "new_password": "different-password-123",
                "confirm_password": "different-password-123",
            },
        )
        assert response.status_code == 302

        db.session.refresh(admin)
        assert admin.password == original_hash


@pytest.mark.security
def test_admin_reset_still_updates_other_user_password():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        target_user = _seed_user("target-user", password="old-user-password", admin=False)
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            f"/admin_reset_password/{target_user.id}",
            data={
                "new_password": "new-user-password-123",
                "confirm_password": "new-user-password-123",
            },
        )
        assert response.status_code == 302

        db.session.refresh(target_user)
        assert bcrypt.check_password_hash(target_user.password, "new-user-password-123")


@pytest.mark.security
def test_mutating_routes_reject_get_requests():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="MethodCheck")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="method-check.txt", domain_id=domain.id, owner_id=admin.id)
        db.session.add(hashfile)
        db.session.commit()

        job = Jobs(name="method-check-job", status="Ready", domain_id=domain.id, owner_id=admin.id, hashfile_id=hashfile.id)
        db.session.add(job)
        db.session.commit()

        task = Tasks(
            name="method-check-task",
            hc_attackmode="maskmode",
            owner_id=admin.id,
            wl_id=None,
            rule_id=None,
            hc_mask="?a?a",
        )
        db.session.add(task)
        db.session.commit()

        task_group = TaskGroups(name="method-check-group", owner_id=admin.id, tasks=json.dumps([task.id]))
        db.session.add(task_group)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        assert client.get(f"/hashfiles/delete/{hashfile.id}").status_code == 405
        assert client.get("/wordlists/update/999999").status_code == 405
        assert client.get(f"/jobs/start/{job.id}").status_code == 405
        assert client.get(f"/jobs/{job.id}/assign_task/{task.id}").status_code == 405
        assert client.get(
            f"/task_groups/assigned_tasks/{task_group.id}/add_task/{task.id}"
        ).status_code == 405
        assert client.get(f"/rules/delete/999999").status_code == 405
        assert client.get("/logout").status_code == 405


@pytest.mark.security
def test_database_constraints_and_indexes_exist_on_core_link_tables():
    app = _build_app()
    with app.app_context():
        db.create_all()
        inspector = inspect(db.engine)

        hashfile_hashes_indexes = {entry["name"] for entry in inspector.get_indexes("hashfile_hashes")}
        assert "ix_hashfile_hashes_hashfile_id" in hashfile_hashes_indexes
        assert "ix_hashfile_hashes_hash_id" in hashfile_hashes_indexes

        job_tasks_indexes = {entry["name"] for entry in inspector.get_indexes("job_tasks")}
        assert "ix_job_tasks_status_priority_id" in job_tasks_indexes

        hashfile_hashes_fks = {
            (tuple(entry["constrained_columns"]), entry["referred_table"])
            for entry in inspector.get_foreign_keys("hashfile_hashes")
        }
        assert (("hash_id",), "hashes") in hashfile_hashes_fks
        assert (("hashfile_id",), "hashfiles") in hashfile_hashes_fks

        job_tasks_fks = {
            (tuple(entry["constrained_columns"]), entry["referred_table"])
            for entry in inspector.get_foreign_keys("job_tasks")
        }
        assert (("job_id",), "jobs") in job_tasks_fks
        assert (("task_id",), "tasks") in job_tasks_fks
