"""Integration tests for executor behavior and runtime recovery."""
# ruff: noqa: F403,F405
from tests.integration.support import *


@pytest.mark.security
def test_plaintext_storage_migration_encrypts_legacy_rows():
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
        assert migrated_rows >= 1

        legacy_row = db.session.get(Hashes, legacy.id)
        canonical_row = db.session.get(Hashes, canonical.id)

        assert legacy_row.plaintext != "PASSWORD"
        assert decode_plaintext_from_storage(legacy_row.plaintext) == "PASSWORD"
        assert canonical_row.plaintext == canonical_value
        assert decode_plaintext_from_storage(canonical_row.plaintext) == "Summer2026!"

@pytest.mark.security
def test_executor_import_stores_plaintext_encrypted_at_rest(tmp_path):
    from hashcrush.executor.service import LocalExecutorService
    from hashcrush.utils.utils import decode_plaintext_from_storage, get_md5_hash

    app = _build_app()
    with app.app_context():
        db.create_all()
        user = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="ACME")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="input.txt", domain_id=domain.id)
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

        imported_hash = db.session.get(Hashes, hash_row.id)
        assert imported_hash.cracked is True
        assert imported_hash.plaintext != "Pa$$w0rd"
        assert decode_plaintext_from_storage(imported_hash.plaintext) == "Pa$$w0rd"


@pytest.mark.security
def test_executor_import_refreshes_dynamic_wordlists_when_new_plaintexts_are_found(tmp_path):
    from hashcrush.executor.service import LocalExecutorService
    from hashcrush.utils.utils import get_md5_hash

    app = _build_app(
        {
            "STORAGE_PATH": str(tmp_path / "storage"),
        }
    )
    with app.app_context():
        db.create_all()
        user = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="DynamicDomain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="input.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        hash_row = Hashes(
            sub_ciphertext=get_md5_hash("dynamic-hash"),
            ciphertext="dynamic-hash",
            hash_type=1000,
            cracked=False,
            plaintext=None,
        )
        db.session.add(hash_row)
        db.session.commit()

        db.session.add(HashfileHashes(hash_id=hash_row.id, hashfile_id=hashfile.id))
        db.session.commit()

        dynamic_wordlist_path = tmp_path / "storage" / "wordlists" / "dynamic.txt"
        dynamic_wordlist_path.parent.mkdir(parents=True, exist_ok=True)
        dynamic_wordlist = Wordlists(
            name="dynamic",
            type="dynamic",
            path=str(dynamic_wordlist_path),
            size=0,
            checksum="0" * 64,
        )
        db.session.add(dynamic_wordlist)
        db.session.commit()

        task = Tasks(
            name="mask",
            hc_attackmode="maskmode",
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
        crack_path.write_text("dynamic-hash:RecoveredDynamicSecret\n", encoding="latin-1")

        service = LocalExecutorService(app)
        imported_count = service._import_crack_file_for_task(job_task, str(crack_path))
        assert imported_count == 1

        assert dynamic_wordlist_path.read_text(encoding="utf-8") == "RecoveredDynamicSecret\n"
        db.session.refresh(dynamic_wordlist)
        assert dynamic_wordlist.size == 1

@pytest.mark.security
def test_executor_canceled_flow_imports_recovered_hashes(tmp_path, monkeypatch):
    from hashcrush.executor.service import ActiveTask, LocalExecutorService
    from hashcrush.utils.utils import decode_plaintext_from_storage, get_md5_hash

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

        hashfile = Hashfiles(name="input.txt", domain_id=domain.id)
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

        imported_hash = db.session.get(Hashes, hash_row.id)
        assert imported_hash.cracked is True
        assert decode_plaintext_from_storage(imported_hash.plaintext) == "RecoveredDuringCancel"

@pytest.mark.security
def test_recover_orphaned_tasks_imports_crackfile_before_requeue(tmp_path):
    from hashcrush.executor.service import LocalExecutorService
    from hashcrush.utils.utils import decode_plaintext_from_storage, get_md5_hash

    app = _build_app({"RUNTIME_PATH": str(tmp_path)})
    with app.app_context():
        db.create_all()
        user = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="recover-domain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="recover.txt", domain_id=domain.id)
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
        imported_hash = db.session.get(Hashes, hash_row.id)
        assert orphan.status == "Queued"
        assert job.status == "Queued"
        assert imported_hash.cracked is True
        assert decode_plaintext_from_storage(imported_hash.plaintext) == "RecoveredAfterCrash"

@pytest.mark.security
def test_executor_running_checkpoint_imports_cracks(tmp_path):
    from hashcrush.executor.service import ActiveTask, LocalExecutorService
    from hashcrush.utils.utils import decode_plaintext_from_storage, get_md5_hash

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

        hashfile = Hashfiles(name="checkpoint.txt", domain_id=domain.id)
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
        crack_path.write_text(
            "checkpoint-hash:RecoveredDuringRun\n", encoding="latin-1"
        )
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

        imported_hash = db.session.get(Hashes, hash_row.id)
        assert imported_hash.cracked is True
        assert decode_plaintext_from_storage(imported_hash.plaintext) == "RecoveredDuringRun"

@pytest.mark.security
def test_hashcat_exit_code_one_is_success_when_status_indicates_exhausted(tmp_path):
    from hashcrush.executor.service import (
        _is_successful_hashcat_exit,
        _parse_hashcat_status,
    )

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
def test_recover_orphaned_paused_task_cleans_stale_pid_and_keeps_status(tmp_path):
    from hashcrush.executor.service import LocalExecutorService
    from hashcrush.utils.utils import decode_plaintext_from_storage, get_md5_hash

    app = _build_app({"RUNTIME_PATH": str(tmp_path)})
    with app.app_context():
        db.create_all()
        user = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="paused-recover-domain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="paused-recover.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        hash_row = Hashes(
            sub_ciphertext=get_md5_hash("paused-orphan-hash"),
            ciphertext="paused-orphan-hash",
            hash_type=1000,
            cracked=False,
            plaintext=None,
        )
        db.session.add(hash_row)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=hash_row.id, hashfile_id=hashfile.id))
        db.session.commit()

        task = Tasks(
            name="paused-recover-task",
            hc_attackmode="maskmode",
            wl_id=None,
            rule_id=None,
            hc_mask="?a",
        )
        db.session.add(task)
        db.session.commit()

        job = Jobs(
            name="paused-recover-job",
            status="Paused",
            domain_id=domain.id,
            owner_id=user.id,
            hashfile_id=hashfile.id,
        )
        db.session.add(job)
        db.session.commit()

        orphan = JobTasks(
            job_id=job.id, task_id=task.id, status="Paused", worker_pid=987654
        )
        db.session.add(orphan)
        db.session.commit()

        outfiles_dir = tmp_path / "outfiles"
        outfiles_dir.mkdir(parents=True, exist_ok=True)
        crack_path = outfiles_dir / f"hc_cracked_{job.id}_{task.id}.txt"
        crack_path.write_text(
            "paused-orphan-hash:RecoveredWhilePaused\n", encoding="latin-1"
        )

        service = LocalExecutorService(app)
        service._recover_orphaned_tasks()

        db.session.refresh(orphan)
        imported_hash = db.session.get(Hashes, hash_row.id)
        assert orphan.status == "Paused"
        assert orphan.worker_pid is None
        assert imported_hash.cracked is True
        assert decode_plaintext_from_storage(imported_hash.plaintext) == "RecoveredWhilePaused"
