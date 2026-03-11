"""Integration tests for CLI bootstrap, setup, schema, and runtime bootstrap."""
# ruff: noqa: F403,F405
from sqlalchemy import text

from tests.integration.support import *


@pytest.mark.security
def test_ensure_settings_cli_adds_settings_only_when_missing():
    cli_module = _load_cli_module()
    app = _build_app()
    with app.app_context():
        db.create_all()
        assert _count_rows(Settings) == 0

        cli_module.ensure_settings_cli(db)
        assert _count_rows(Settings) == 1

        cli_module.ensure_settings_cli(db)
        assert _count_rows(Settings) == 1

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
def test_setup_parse_args_accepts_test_flag():
    bootstrap_module = _load_bootstrap_module()
    assert bootstrap_module.parse_args(["--test"]).test_mode is True

@pytest.mark.security
def test_hashcrush_cli_setup_subcommand_delegates_to_bootstrap(monkeypatch):
    cli_module = _load_cli_module()
    captured = {}

    class _BootstrapModule:
        @staticmethod
        def main(argv=None):
            captured["argv"] = argv
            return 23

    monkeypatch.setattr(cli_module, "_load_bootstrap_cli", lambda: _BootstrapModule())

    result = cli_module.cli(["hashcrush.py", "setup", "--test"])

    assert result == 23
    assert captured["argv"] == ["--test"]

@pytest.mark.security
def test_hashcrush_cli_upgrade_subcommand_runs_schema_upgrade(monkeypatch):
    cli_module = _load_cli_module()
    from hashcrush.db_upgrade import (
        CURRENT_SCHEMA_VERSION,
        MigrationStep,
        UpgradeResult,
    )

    captured = {}
    app = _build_app()

    def fake_upgrade_database(*, dry_run=False):
        captured["dry_run"] = dry_run
        return UpgradeResult(
            starting_version=0,
            target_version=CURRENT_SCHEMA_VERSION,
            applied_steps=(
                MigrationStep(
                    version=1,
                    name="baseline_current_schema",
                    summary="Adopt the current schema and start tracking in-place upgrades.",
                    upgrade=lambda: None,
                ),
            ),
            initialized_empty_schema=True,
            dry_run=dry_run,
        )

    monkeypatch.setattr(cli_module, "_load_create_app", lambda: (lambda config_overrides=None: app))
    monkeypatch.setattr("hashcrush.db_upgrade.upgrade_database", fake_upgrade_database)

    result = cli_module.cli(["hashcrush.py", "upgrade", "--dry-run"])

    assert result == 0
    assert captured["dry_run"] is True

@pytest.mark.security
def test_hashcrush_cli_rejects_unknown_root_command():
    cli_module = _load_cli_module()

    with pytest.raises(SystemExit) as exc_info:
        cli_module.cli(["hashcrush.py", "legacy-mode"])

    assert exc_info.value.code == 2

@pytest.mark.security
def test_setup_seed_test_environment_creates_dummy_fixture_set(tmp_path, monkeypatch):
    bootstrap_module = _load_bootstrap_module()
    app = _build_app()
    runtime_path = tmp_path / "runtime"
    env_path = tmp_path / ".env.test"

    with app.app_context():
        db.create_all()

    monkeypatch.setattr(bootstrap_module, "_build_seed_app", lambda: app)

    values = bootstrap_module._seed_test_environment(str(runtime_path), str(env_path))

    with app.app_context():
        assert _count_rows(Users, username=bootstrap_module.E2E_ADMIN_USERNAME) == 1
        assert _count_rows(Users, username=bootstrap_module.E2E_SECOND_USERNAME) == 1
        assert _count_rows(Domains, name=bootstrap_module.E2E_DOMAIN_NAME) == 1
        assert _count_rows(Hashfiles, name=bootstrap_module.E2E_SAMPLE_HASHFILE_NAME) == 1
        assert _count_rows(Tasks, name=bootstrap_module.E2E_DICTIONARY_TASK_NAME) == 1
        assert _count_rows(Tasks, name=bootstrap_module.E2E_DICTIONARY_RULE_TASK_NAME) == 1
        assert _count_rows(Jobs, name=bootstrap_module.E2E_SAMPLE_JOB_NAME) == 1
        assert _count_rows(Wordlists, name=bootstrap_module.E2E_WORDLIST_NAME) == 1
        assert _count_rows(Rules, name=bootstrap_module.E2E_RULE_NAME) == 1

    env_text = env_path.read_text(encoding="utf-8")
    assert "HASHCRUSH_E2E_USERNAME=\"admin\"" in env_text
    assert bootstrap_module.E2E_ADMIN_PASSWORD in env_text
    assert values["HASHCRUSH_E2E_DOMAIN_NAME"] == bootstrap_module.E2E_DOMAIN_NAME
    assert values["HASHCRUSH_E2E_TASK_NAME"] == bootstrap_module.E2E_MASK_TASK_NAME

@pytest.mark.security
def test_upgrade_database_initializes_empty_schema_and_tracks_version():
    app = _build_app()
    with app.app_context():
        from hashcrush.db_upgrade import CURRENT_SCHEMA_VERSION, upgrade_database

        result = upgrade_database()

        state = db.session.get(SchemaVersion, 1)
        assert result.starting_version == 0
        assert result.initialized_empty_schema is True
        assert state is not None
        assert state.version == CURRENT_SCHEMA_VERSION

@pytest.mark.security
def test_upgrade_database_rejects_unversioned_non_empty_schema():
    app = _build_app()
    with app.app_context():
        from hashcrush.db_upgrade import upgrade_database

        db.create_all()
        user = _seed_admin_user()
        _seed_settings()
        domain = Domains(name="legacy-domain")
        db.session.add(domain)
        db.session.commit()

        SchemaVersion.__table__.drop(bind=db.engine)

        with pytest.raises(RuntimeError, match="non-empty database without schema version tracking"):
            upgrade_database()

        assert not inspect(db.engine).has_table(SchemaVersion.__tablename__)
        assert _count_rows(Users, id=user.id) == 1
        assert _count_rows(Domains, name="legacy-domain") == 1

@pytest.mark.security
def test_upgrade_database_migrates_v1_schema_forward_to_current_version():
    app = _build_app()
    with app.app_context():
        from hashcrush.db_upgrade import CURRENT_SCHEMA_VERSION, upgrade_database

        db.create_all()
        state = SchemaVersion(id=1, version=1, app_version="1.0")
        db.session.add(state)
        db.session.commit()
        AuditLog.__table__.drop(bind=db.engine)

        result = upgrade_database()

        assert inspect(db.engine).has_table(AuditLog.__tablename__)
        assert [step.version for step in result.applied_steps] == [2, 3, 4]
        assert db.session.get(SchemaVersion, 1).version == CURRENT_SCHEMA_VERSION

@pytest.mark.security
def test_upgrade_database_migrates_v2_schema_forward_to_current_version():
    app = _build_app()
    with app.app_context():
        from hashcrush.db_upgrade import CURRENT_SCHEMA_VERSION, upgrade_database

        db.create_all()
        db.session.execute(
            text(
                'ALTER TABLE "settings" ADD COLUMN "retention_period" INTEGER NOT NULL DEFAULT 0'
            )
        )
        db.session.execute(
            text(
                'ALTER TABLE "settings" ADD COLUMN "enabled_job_weights" BOOLEAN NOT NULL DEFAULT 0'
            )
        )
        db.session.add(SchemaVersion(id=1, version=2, app_version="1.0"))
        db.session.commit()

        result = upgrade_database()

        settings_columns = {
            column["name"] for column in inspect(db.engine).get_columns("settings")
        }
        assert "retention_period" not in settings_columns
        assert "enabled_job_weights" not in settings_columns
        assert [step.version for step in result.applied_steps] == [3, 4]
        assert db.session.get(SchemaVersion, 1).version == CURRENT_SCHEMA_VERSION

@pytest.mark.security
def test_upgrade_database_migrates_v3_schema_to_v4_job_task_positions():
    app = _build_app()
    with app.app_context():
        from hashcrush.db_upgrade import CURRENT_SCHEMA_VERSION, upgrade_database

        db.create_all()
        _seed_settings()
        admin = _seed_admin_user()
        domain = Domains(name="upgrade-domain")
        db.session.add(domain)
        db.session.commit()

        task_a = Tasks(name="upgrade-task-a", hc_attackmode="maskmode", hc_mask="?a")
        task_b = Tasks(name="upgrade-task-b", hc_attackmode="maskmode", hc_mask="?a?a")
        db.session.add_all([task_a, task_b])
        db.session.commit()

        job = Jobs(
            name="upgrade-job",
            status="Incomplete",
            domain_id=domain.id,
            owner_id=admin.id,
        )
        db.session.add(job)
        db.session.commit()

        db.session.add_all(
            [
                JobTasks(job_id=job.id, task_id=task_a.id, status="Not Started"),
                JobTasks(job_id=job.id, task_id=task_b.id, status="Not Started"),
            ]
        )
        db.session.add(SchemaVersion(id=1, version=3, app_version="1.0"))
        db.session.commit()
        db.session.execute(text("UPDATE job_tasks SET position = 0"))
        db.session.execute(text("DROP INDEX IF EXISTS ix_job_tasks_job_id_position"))
        db.session.commit()

        result = upgrade_database()

        persisted = _all_rows(
            JobTasks,
            job_id=job.id,
            order_by=(JobTasks.position.asc(), JobTasks.id.asc()),
        )
        index_names = {
            index["name"] for index in inspect(db.engine).get_indexes("job_tasks")
        }
        assert [step.version for step in result.applied_steps] == [4]
        assert [row.position for row in persisted] == [0, 1]
        assert "ix_job_tasks_job_id_position" in index_names
        assert db.session.get(SchemaVersion, 1).version == CURRENT_SCHEMA_VERSION

@pytest.mark.security
def test_sanitize_config_input_handles_delete_backspace_artifacts():
    raw_value = "hj\x7f\x7f\x7f\x7fhashcrush"
    cleaned = sanitize_config_input(raw_value)
    assert cleaned == "hashcrush"

    mixed = "ab\x08c\x01\x02d"
    assert sanitize_config_input(mixed) == "acd"

@pytest.mark.security
def test_normalize_text_input_trims_and_rejects_whitespace_only_values():
    assert normalize_text_input("  hashcrush  ") == "hashcrush"
    assert normalize_text_input("   ") == ""
    assert normalize_text_input(None) is None

@pytest.mark.security
def test_add_default_tasks_seeds_maskmode_mask_set_and_group():
    from hashcrush.setup import add_default_tasks

    app = _build_app()
    with app.app_context():
        db.create_all()
        _seed_admin_user()

        add_default_tasks(db)

        seeded_tasks = _all_rows(Tasks, order_by=Tasks.id.asc())
        assert len(seeded_tasks) == 10
        expected_masks = ["?a" * length for length in range(1, 11)]
        expected_names = [
            f"{mask} [{length}]" for length, mask in enumerate(expected_masks, start=1)
        ]
        assert [task.hc_mask for task in seeded_tasks] == expected_masks
        assert [task.name for task in seeded_tasks] == expected_names
        assert all(task.hc_attackmode == "maskmode" for task in seeded_tasks)

        task_group = _first_row(TaskGroups, name="maskmode 1-10")
        assert task_group is not None
        assert json.loads(task_group.tasks) == [task.id for task in seeded_tasks]

@pytest.mark.security
def test_add_default_tasks_no_longer_depend_on_admin_id():
    from hashcrush.setup import add_default_tasks

    app = _build_app()
    with app.app_context():
        db.create_all()
        _seed_user(
            "placeholder-user", password="placeholder-user-password", admin=False
        )
        _seed_user("actual-admin", password="actual-admin-password", admin=True)
        _seed_settings()

        add_default_tasks(db)

        seeded_tasks = _all_rows(Tasks, order_by=Tasks.id.asc())
        assert seeded_tasks
        task_group = _first_row(TaskGroups, name="maskmode 1-10")
        assert task_group is not None
        assert json.loads(task_group.tasks) == [task.id for task in seeded_tasks]

@pytest.mark.security
def test_setup_admin_password_flow_uses_existing_admin_when_admin_is_not_id_one():
    from hashcrush.setup import add_admin_user

    app = _build_app()
    with app.app_context():
        db.create_all()
        placeholder = _seed_user(
            "placeholder-user", password="placeholder-user-password", admin=False
        )
        add_admin_user(db, bcrypt)
        admin = _first_row(Users, admin=True)
        assert admin is not None
        assert admin.id != placeholder.id

        client = app.test_client()
        get_response = client.get(
            "/setup/admin-pass",
            environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert get_response.status_code == 200
        assert b"admin" in get_response.data

        response = client.post(
            "/setup/admin-pass",
            data={
                "username": "renamed-admin",
                "password": "longer-admin-pass",
                "confirm_password": "longer-admin-pass",
            },
            environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert response.status_code == 302

        db.session.refresh(admin)
        db.session.refresh(placeholder)
        assert admin.username == "renamed-admin"
        assert bcrypt.check_password_hash(admin.password, "longer-admin-pass")
        assert placeholder.username == "placeholder-user"

@pytest.mark.security
def test_setup_admin_password_flow_trims_username_input():
    from hashcrush.setup import add_admin_user

    app = _build_app()
    with app.app_context():
        db.create_all()
        add_admin_user(db, bcrypt)
        admin = _first_row(Users, admin=True)
        assert admin is not None

        client = app.test_client()
        response = client.post(
            "/setup/admin-pass",
            data={
                "username": "  trimmed-admin  ",
                "password": "longer-admin-pass",
                "confirm_password": "longer-admin-pass",
            },
            environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert response.status_code == 302

        db.session.refresh(admin)
        assert admin.username == "trimmed-admin"

@pytest.mark.security
def test_setup_admin_password_flow_handles_duplicate_username_cleanly():
    from hashcrush.setup import add_admin_user

    app = _build_app()
    with app.app_context():
        db.create_all()
        existing_user = _seed_user(
            "existing-user", password="existing-user-password", admin=False
        )
        add_admin_user(db, bcrypt)
        admin = _first_row(Users, admin=True)
        assert admin is not None
        assert admin.id != existing_user.id

        client = app.test_client()
        response = client.post(
            "/setup/admin-pass",
            data={
                "username": "existing-user",
                "password": "longer-admin-pass",
                "confirm_password": "longer-admin-pass",
            },
            environ_overrides={"REMOTE_ADDR": "127.0.0.1"},
        )
        assert response.status_code == 200
        assert (
            b"Admin account could not be updated because that username already exists."
            in response.data
        )

        db.session.refresh(admin)
        assert admin.username == "admin"

@pytest.mark.security
def test_schema_declares_expected_constraints_and_indexes():
    app = _build_app()
    with app.app_context():
        db.create_all()
        inspector = inspect(db.engine)

        jobs_indexes = {row["name"] for row in inspector.get_indexes("jobs")}
        assert {
            "ix_jobs_status_priority_queued_at",
            "ix_jobs_owner_id_created_at",
            "ix_jobs_domain_id_status",
            "ix_jobs_hashfile_id",
        }.issubset(jobs_indexes)

        job_tasks_indexes = {row["name"] for row in inspector.get_indexes("job_tasks")}
        assert {
            "ix_job_tasks_status_priority_id",
            "ix_job_tasks_job_id_status",
            "ix_job_tasks_task_id",
        }.issubset(job_tasks_indexes)

        hashfiles_indexes = {row["name"] for row in inspector.get_indexes("hashfiles")}
        assert {
            "ix_hashfiles_uploaded_at",
            "ix_hashfiles_domain_id_uploaded_at",
        }.issubset(hashfiles_indexes)

        tasks_indexes = {row["name"] for row in inspector.get_indexes("tasks")}
        assert {
            "ix_tasks_wl_id",
            "ix_tasks_rule_id",
        }.issubset(tasks_indexes)

        wordlists_indexes = {row["name"] for row in inspector.get_indexes("wordlists")}
        assert "ix_wordlists_type_last_updated" in wordlists_indexes

        tasks_foreign_keys = {
            tuple(row["constrained_columns"]): (
                row["referred_table"],
                row.get("options", {}).get("ondelete"),
            )
            for row in inspector.get_foreign_keys("tasks")
        }
        assert tasks_foreign_keys[("wl_id",)] == ("wordlists", "RESTRICT")
        assert tasks_foreign_keys[("rule_id",)] == ("rules", "RESTRICT")

        jobs_foreign_keys = {
            tuple(row["constrained_columns"]): (
                row["referred_table"],
                row.get("options", {}).get("ondelete"),
            )
            for row in inspector.get_foreign_keys("jobs")
        }
        assert jobs_foreign_keys[("hashfile_id",)] == ("hashfiles", "RESTRICT")
        assert jobs_foreign_keys[("domain_id",)] == ("domains", "RESTRICT")
        assert jobs_foreign_keys[("owner_id",)] == ("users", "RESTRICT")

        job_tasks_foreign_keys = {
            tuple(row["constrained_columns"]): (
                row["referred_table"],
                row.get("options", {}).get("ondelete"),
            )
            for row in inspector.get_foreign_keys("job_tasks")
        }
        assert job_tasks_foreign_keys[("job_id",)] == ("jobs", "RESTRICT")
        assert job_tasks_foreign_keys[("task_id",)] == ("tasks", "RESTRICT")

        hashfiles_foreign_keys = {
            tuple(row["constrained_columns"]): (
                row["referred_table"],
                row.get("options", {}).get("ondelete"),
            )
            for row in inspector.get_foreign_keys("hashfiles")
        }
        assert hashfiles_foreign_keys[("domain_id",)] == ("domains", "RESTRICT")

        hashfile_hashes_foreign_keys = {
            tuple(row["constrained_columns"]): (
                row["referred_table"],
                row.get("options", {}).get("ondelete"),
            )
            for row in inspector.get_foreign_keys("hashfile_hashes")
        }
        assert hashfile_hashes_foreign_keys[("hashfile_id",)] == (
            "hashfiles",
            "RESTRICT",
        )

        task_groups_columns = {
            row["name"]: str(row["type"]).upper()
            for row in inspector.get_columns("task_groups")
        }
        assert "TEXT" in task_groups_columns["tasks"]

@pytest.mark.security
def test_create_app_bootstraps_schema_for_empty_database(tmp_path):
    db_path = tmp_path / "bootstrap.db"
    app = create_app(
        testing=False,
        config_overrides={
            "SECRET_KEY": "phase1-test-secret",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_path}",
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "AUTO_SETUP_DEFAULTS": False,
            "ENABLE_LOCAL_EXECUTOR": False,
            "SKIP_RUNTIME_BOOTSTRAP": True,
            "AUTO_NORMALIZE_PLAINTEXT_STORAGE": False,
        },
    )

    with app.app_context():
        inspector = inspect(db.engine)
        table_names = set(inspector.get_table_names())
        assert {
            "users",
            "settings",
            "jobs",
            "job_tasks",
            "domains",
            "hashfiles",
            "hashfile_hashes",
            "rules",
            "wordlists",
            "tasks",
            "task_groups",
            "hashes",
            "auth_throttle",
        }.issubset(table_names)

@pytest.mark.security
def test_create_app_rejects_unversioned_non_empty_database(tmp_path):
    db_path = tmp_path / "legacy-untracked.db"
    bootstrap_app = create_app(
        testing=True,
        config_overrides={
            "SECRET_KEY": "phase1-test-secret",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_path}",
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "AUTO_SETUP_DEFAULTS": False,
            "ENABLE_LOCAL_EXECUTOR": False,
            "SKIP_RUNTIME_BOOTSTRAP": True,
            "AUTO_NORMALIZE_PLAINTEXT_STORAGE": False,
        },
    )

    with bootstrap_app.app_context():
        db.create_all()
        db.session.add(Domains(name="legacy-domain"))
        db.session.commit()
        SchemaVersion.__table__.drop(bind=db.engine)

    with pytest.raises(RuntimeError, match="non-empty database without schema version tracking"):
        create_app(
            testing=False,
            config_overrides={
                "SECRET_KEY": "phase1-test-secret",
                "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_path}",
                "SQLALCHEMY_TRACK_MODIFICATIONS": False,
                "AUTO_SETUP_DEFAULTS": False,
                "ENABLE_LOCAL_EXECUTOR": False,
                "SKIP_RUNTIME_BOOTSTRAP": True,
                "AUTO_NORMALIZE_PLAINTEXT_STORAGE": False,
            },
        )

@pytest.mark.security
def test_schema_unique_constraints_reject_duplicate_names_and_paths():
    from sqlalchemy.exc import IntegrityError

    app = _build_app()
    with app.app_context():
        db.create_all()
        user = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="unique-domain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="input.txt", domain_id=domain.id)
        wordlist = Wordlists(
            name="rockyou",
            type="static",
            path="/tmp/rockyou.txt",
            size=1,
            checksum="0" * 64,
        )
        rule = Rules(
            name="best64",
            path="/tmp/best64.rule",
            size=1,
            checksum="1" * 64,
        )
        task = Tasks(
            name="mask-1",
            hc_attackmode="maskmode",
            wl_id=None,
            rule_id=None,
            hc_mask="?a",
        )
        task_group = TaskGroups(name="mask-group", tasks="[]")
        job = Jobs(
            name="unique-job",
            status="Ready",
            domain_id=domain.id,
            owner_id=user.id,
            hashfile_id=None,
        )
        db.session.add_all([hashfile, wordlist, rule, task, task_group, job])
        db.session.commit()

        duplicate_cases = [
            Domains(name="unique-domain"),
            Wordlists(
                name="rockyou",
                type="static",
                path="/tmp/other-rockyou.txt",
                size=1,
                checksum="2" * 64,
            ),
            Wordlists(
                name="other-wordlist",
                type="static",
                path="/tmp/rockyou.txt",
                size=1,
                checksum="3" * 64,
            ),
            Rules(
                name="best64", path="/tmp/other-best64.rule", size=1, checksum="4" * 64
            ),
            Rules(
                name="other-rule", path="/tmp/best64.rule", size=1, checksum="5" * 64
            ),
            Tasks(
                name="mask-1",
                hc_attackmode="maskmode",
                wl_id=None,
                rule_id=None,
                hc_mask="?a?a",
            ),
            TaskGroups(name="mask-group", tasks="[]"),
            Jobs(
                name="unique-job",
                status="Ready",
                domain_id=domain.id,
                owner_id=user.id,
                hashfile_id=hashfile.id,
            ),
        ]

        for duplicate in duplicate_cases:
            db.session.add(duplicate)
            with pytest.raises(IntegrityError):
                db.session.commit()
            db.session.rollback()

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

        assert _count_rows(Rules) == 0
        assert _count_rows(Wordlists) == 0

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
    assert (
        "example_folder1/best64.rule",
        "example_folder1/best64.rule",
    ) in selectable_files
    assert (
        "example_folder1/not_a_rule.txt",
        "example_folder1/not_a_rule.txt",
    ) not in selectable_files
    assert (".hidden/secret.rule", ".hidden/secret.rule") not in selectable_files

    resolved_nested = _resolve_selected_file(
        "example_folder1/best64.rule", str(rules_root)
    )
    assert resolved_nested == str(nested_file.resolve())
    assert (
        _resolve_selected_file("example_folder1/not_a_rule.txt", str(rules_root))
        is None
    )
    assert _resolve_selected_file(".hidden/secret.rule", str(rules_root)) is None
    assert _resolve_selected_file("../etc/passwd", str(rules_root)) is None
    missing_files, missing_truncated = _list_selectable_files(
        str(rules_root / "does-not-exist")
    )
    assert missing_files == []
    assert missing_truncated is False

@pytest.mark.security
def test_wordlists_selectable_files_support_nested_folders(tmp_path):
    from hashcrush.wordlists.routes import (
        _list_selectable_files,
        _resolve_selected_file,
    )

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
    assert (
        "example_folder1/rockyou.txt",
        "example_folder1/rockyou.txt",
    ) in selectable_files
    assert (
        "example_folder1/rockyou.txt.tar.gz",
        "example_folder1/rockyou.txt.tar.gz",
    ) not in selectable_files
    assert (
        "example_folder1/ignore.csv",
        "example_folder1/ignore.csv",
    ) not in selectable_files
    assert (".hidden/secret.txt", ".hidden/secret.txt") not in selectable_files

    resolved_nested = _resolve_selected_file(
        "example_folder1/rockyou.txt", str(wordlists_root)
    )
    assert resolved_nested == str(nested_file.resolve())
    resolved_nested_tar = _resolve_selected_file(
        "example_folder1/rockyou.txt.tar.gz", str(wordlists_root)
    )
    assert resolved_nested_tar is None
    assert (
        _resolve_selected_file("example_folder1/ignore.csv", str(wordlists_root))
        is None
    )
    assert _resolve_selected_file(".hidden/secret.txt", str(wordlists_root)) is None
    assert _resolve_selected_file("../etc/passwd", str(wordlists_root)) is None
    missing_files, missing_truncated = _list_selectable_files(
        str(wordlists_root / "does-not-exist")
    )
    assert missing_files == []
    assert missing_truncated is False

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
        assert b"database.uri" in response.data
        assert b"database.host" in response.data
        assert b"app.hashcat_bin" in response.data
        assert b"Default When Empty" in response.data

@pytest.mark.security
def test_settings_hashcrush_config_update_persists_values(tmp_path):
    config_path = tmp_path / "config.conf"
    config_path.write_text(
        "[database]\n"
        "uri = \n"
        "host = old-db-host\n"
        "port = 5432\n"
        "name = old-db-name\n"
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
                "cfg__database__uri": "",
                "cfg__database__host": "new-db-host",
                "cfg__database__port": "5433",
                "cfg__database__name": "new-db-name",
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

        assert parser.get("database", "uri", fallback="") == ""
        assert parser.get("database", "host") == "new-db-host"
        assert parser.get("database", "port") == "5433"
        assert parser.get("database", "name") == "new-db-name"
        assert parser.get("database", "username") == "new-db-user"
        assert parser.get("database", "password") == "hashcrush"
        assert parser.get("app", "hashcat_bin") == "/usr/bin/hashcat"
        assert parser.get("app", "hashcat_status_timer") == "10"
        assert parser.get("app", "runtime_path") == "/tmp/hashcrush-runtime-custom"

@pytest.mark.security
def test_config_prefers_database_uri_from_config(tmp_path, monkeypatch):
    config_path = tmp_path / "config.conf"
    config_path.write_text(
        "[database]\n"
        "uri = postgresql+psycopg://config-user:config-pass@db.example:5432/hashcrush\n\n"
        "[app]\n"
        "secret_key = test-secret\n",
        encoding="utf-8",
    )

    monkeypatch.delenv("HASHCRUSH_DATABASE_URI", raising=False)
    monkeypatch.setenv("HASHCRUSH_CONFIG_PATH", str(config_path))

    project_root = Path(__file__).resolve().parents[2]
    script_path = project_root / "hashcrush" / "config.py"
    spec = importlib.util.spec_from_file_location(
        "hashcrush_config_uri_test_module", script_path
    )
    config_module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(config_module)

    assert (
        config_module.Config.SQLALCHEMY_DATABASE_URI
        == "postgresql+psycopg://config-user:config-pass@db.example:5432/hashcrush"
    )

@pytest.mark.security
def test_config_builds_postgresql_uri_from_discrete_fields(tmp_path, monkeypatch):
    config_path = tmp_path / "config.conf"
    config_path.write_text(
        "[database]\n"
        "host = db.internal\n"
        "port = 5433\n"
        "name = hashcrush_app\n"
        "username = app-user\n"
        "password = app-pass\n\n"
        "[app]\n"
        "secret_key = test-secret\n",
        encoding="utf-8",
    )

    monkeypatch.delenv("HASHCRUSH_DATABASE_URI", raising=False)
    monkeypatch.setenv("HASHCRUSH_CONFIG_PATH", str(config_path))

    project_root = Path(__file__).resolve().parents[2]
    script_path = project_root / "hashcrush" / "config.py"
    spec = importlib.util.spec_from_file_location(
        "hashcrush_config_discrete_test_module", script_path
    )
    config_module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(config_module)

    assert (
        config_module.Config.SQLALCHEMY_DATABASE_URI
        == "postgresql+psycopg://app-user:app-pass@db.internal:5433/hashcrush_app"
    )

@pytest.mark.security
def test_bootstrap_local_postgres_invokes_psql(monkeypatch):
    bootstrap_module = _load_bootstrap_module()
    captured = {}

    def fake_run(command, *, input=None, check=None):
        captured["command"] = command
        captured["input"] = input.decode("utf-8")
        captured["check"] = check
        return None

    monkeypatch.setattr(bootstrap_module.subprocess, "run", fake_run)

    bootstrap_module._bootstrap_local_postgres(
        "hashcrush",
        "hashcrush",
        "strong-password",
        "5432",
    )

    assert captured["command"] == [
        "sudo",
        "-u",
        "postgres",
        "psql",
        "-v",
        "ON_ERROR_STOP=1",
        "-p",
        "5432",
        "-d",
        "postgres",
    ]
    assert 'DROP DATABASE IF EXISTS "hashcrush";' in captured["input"]
    assert 'CREATE ROLE "hashcrush" LOGIN PASSWORD \'strong-password\';' in captured["input"]
    assert captured["check"] is True

@pytest.mark.security
def test_get_linecount_handles_newline_edge_cases(tmp_path):
    file_with_newline = tmp_path / "one-line-newline.txt"
    file_with_newline.write_text("line1\n", encoding="utf-8")
    assert get_linecount(str(file_with_newline)) == 1

    file_without_newline = tmp_path / "two-lines-no-final-newline.txt"
    file_without_newline.write_text("line1\nline2", encoding="utf-8")
    assert get_linecount(str(file_without_newline)) == 2

    empty_file = tmp_path / "empty.txt"
    empty_file.write_text("", encoding="utf-8")
    assert get_linecount(str(empty_file)) == 0

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
def test_import_user_hash_dcc2_preserves_username_association(tmp_path):
    app = _build_app()
    with app.app_context():
        db.create_all()
        _seed_admin_user()
        _seed_settings()

        domain = Domains(name="ImportDomain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="dcc2.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        hash_line = "alice:$DCC2$10240#alice#6f1f1524858772cc7f3a5ecf4dbf45f6\n"
        hash_path = tmp_path / "user_hash_dcc2.txt"
        hash_path.write_text(hash_line, encoding="utf-8")

        assert import_hashfilehashes(
            hashfile_id=hashfile.id,
            hashfile_path=str(hash_path),
            file_type="user_hash",
            hash_type="2100",
        )

        association = _first_row(HashfileHashes, hashfile_id=hashfile.id)
        assert association is not None
        assert bytes.fromhex(association.username).decode("latin-1") == "alice"

        imported_hash = db.session.get(Hashes, association.hash_id)
        assert imported_hash is not None
        assert imported_hash.ciphertext.startswith("$DCC2$10240#alice#")

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
def test_production_session_cookie_defaults_are_hardened():
    app = create_app(
        testing=False,
        config_overrides={
            "SECRET_KEY": "phase1-test-secret",
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "AUTO_SETUP_DEFAULTS": False,
            "ENABLE_LOCAL_EXECUTOR": False,
            "SKIP_RUNTIME_BOOTSTRAP": True,
            "AUTO_NORMALIZE_PLAINTEXT_STORAGE": False,
            "SESSION_COOKIE_SECURE": None,
        },
    )

    assert app.config["SESSION_COOKIE_SECURE"] is True
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"

@pytest.mark.security
def test_database_constraints_and_indexes_exist_on_core_link_tables():
    app = _build_app()
    with app.app_context():
        db.create_all()
        inspector = inspect(db.engine)

        hashfile_hashes_indexes = {
            entry["name"] for entry in inspector.get_indexes("hashfile_hashes")
        }
        assert "ix_hashfile_hashes_hashfile_id" in hashfile_hashes_indexes
        assert "ix_hashfile_hashes_hash_id" in hashfile_hashes_indexes

        job_tasks_indexes = {
            entry["name"] for entry in inspector.get_indexes("job_tasks")
        }
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

        hashfile_hashes_unique = {
            tuple(entry["column_names"])
            for entry in inspector.get_unique_constraints("hashfile_hashes")
        }
        assert ("hashfile_id", "hash_id", "username") in hashfile_hashes_unique

        job_tasks_unique = {
            tuple(entry["column_names"])
            for entry in inspector.get_unique_constraints("job_tasks")
        }
        assert ("job_id", "task_id") in job_tasks_unique

        hashes_unique = {
            tuple(entry["column_names"])
            for entry in inspector.get_unique_constraints("hashes")
        }
        assert ("hash_type", "sub_ciphertext") in hashes_unique

        assert "auth_throttle" in inspector.get_table_names()
