"""Integration tests for shared tasks, task groups, rules, and wordlists."""
# ruff: noqa: F403,F405
from tests.integration.support import *


@pytest.mark.security
def test_tasks_add_rejects_bruteforce_attackmode():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            "/tasks/add",
            data={
                "name": "bruteforce-task",
                "hc_attackmode": "bruteforce",
                "wl_id": "",
                "rule_id": "None",
                "mask": "",
            },
        )
        assert response.status_code == 200

        task = Tasks.query.filter_by(name="bruteforce-task").first()
        assert task is None

@pytest.mark.security
def test_tasks_add_handles_integrity_error_cleanly(monkeypatch):
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        wordlist = Wordlists(
            name="shared-wordlist",
            type="static",
            path="/tmp/shared-wordlist.txt",
            size=1,
            checksum="2" * 64,
        )
        db.session.add(wordlist)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        monkeypatch.setattr(
            "hashcrush.tasks.routes.db.session.commit",
            lambda: (_ for _ in ()).throw(_integrity_error()),
        )

        response = client.post(
            "/tasks/add",
            data={
                "name": "conflict-task",
                "hc_attackmode": "dictionary",
                "wl_id": str(wordlist.id),
                "rule_id": "None",
                "mask": "",
            },
        )
        assert response.status_code == 200
        assert b"Task could not be saved" in response.data
        assert Tasks.query.count() == 0

@pytest.mark.security
def test_task_groups_add_handles_integrity_error_cleanly(monkeypatch):
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, admin)

        monkeypatch.setattr(
            "hashcrush.task_groups.routes.db.session.commit",
            lambda: (_ for _ in ()).throw(_integrity_error()),
        )

        response = client.post(
            "/task_groups/add",
            data={
                "name": "conflict-group",
            },
        )
        assert response.status_code == 200
        assert b"Task group could not be created" in response.data
        assert TaskGroups.query.count() == 0

@pytest.mark.security
def test_wordlists_add_handles_integrity_error_cleanly(tmp_path, monkeypatch):
    app = _build_app({"WORDLISTS_PATH": str(tmp_path)})
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        wordlist_path = tmp_path / "wordlist.txt"
        wordlist_path.write_text("password\n", encoding="utf-8")

        client = app.test_client()
        _login_client_as_user(client, admin)

        monkeypatch.setattr(
            "hashcrush.wordlists.routes.db.session.commit",
            lambda: (_ for _ in ()).throw(_integrity_error()),
        )

        response = client.post(
            "/wordlists/add",
            data={
                "name": "conflict-wordlist",
                "existing_file": "wordlist.txt",
            },
        )
        assert response.status_code == 200
        assert b"Wordlist could not be registered" in response.data
        assert Wordlists.query.count() == 0

@pytest.mark.security
def test_rules_add_handles_integrity_error_cleanly(tmp_path, monkeypatch):
    app = _build_app({"RULES_PATH": str(tmp_path)})
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        rule_path = tmp_path / "best.rule"
        rule_path.write_text(":\n", encoding="utf-8")

        client = app.test_client()
        _login_client_as_user(client, admin)

        monkeypatch.setattr(
            "hashcrush.rules.routes.db.session.commit",
            lambda: (_ for _ in ()).throw(_integrity_error()),
        )

        response = client.post(
            "/rules/add",
            data={
                "name": "conflict-rule",
                "existing_file": "best.rule",
            },
        )
        assert response.status_code == 200
        assert b"Rule file could not be registered" in response.data
        assert Rules.query.count() == 0

@pytest.mark.security
def test_dynamic_wordlist_update_uses_all_cracked_data_for_shared_wordlists(tmp_path):
    app = _build_app()
    with app.app_context():
        db.create_all()
        _seed_user("owner-user", password="owner-user-password", admin=False)
        _seed_user("other-user", password="other-user-password", admin=False)
        _seed_settings()

        domain = Domains(name="ScopeDomain")
        db.session.add(domain)
        db.session.commit()

        owner_hashfile = Hashfiles(name="owner.txt", domain_id=domain.id)
        other_hashfile = Hashfiles(name="other.txt", domain_id=domain.id)
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

        db.session.add(
            HashfileHashes(hash_id=owner_hash.id, hashfile_id=owner_hashfile.id)
        )
        db.session.add(
            HashfileHashes(hash_id=other_hash.id, hashfile_id=other_hashfile.id)
        )
        db.session.commit()

        dynamic_wordlist_path = tmp_path / "dynamic-wordlist.txt"
        dynamic_wordlist = Wordlists(
            name="dynamic-owner",
            type="dynamic",
            path=str(dynamic_wordlist_path),
            size=0,
            checksum="0" * 64,
        )
        db.session.add(dynamic_wordlist)
        db.session.commit()

        admin = _seed_admin_user()
        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(f"/wordlists/update/{dynamic_wordlist.id}")
        assert response.status_code == 302

        contents = dynamic_wordlist_path.read_text(encoding="utf-8")
        assert "owner-secret" in contents
        assert "other-secret" in contents
        entry = _latest_audit_entry()
        assert entry is not None
        assert entry.event_type == "wordlist.update_dynamic"
        assert entry.target_id == str(dynamic_wordlist.id)

@pytest.mark.security
def test_task_group_export_includes_shared_items():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_user("tg-export-other", password="other-user-password", admin=False)
        _seed_settings()

        owner_task = Tasks(
            name="owner-mask",
            hc_attackmode="maskmode",
            wl_id=None,
            rule_id=None,
            hc_mask="?a?a",
        )
        other_task = Tasks(
            name="other-mask",
            hc_attackmode="maskmode",
            wl_id=None,
            rule_id=None,
            hc_mask="?a?a?a",
        )
        db.session.add_all([owner_task, other_task])
        db.session.commit()

        owner_group = TaskGroups(name="owner-group", tasks=json.dumps([owner_task.id]))
        other_group = TaskGroups(name="other-group", tasks=json.dumps([other_task.id]))
        db.session.add_all([owner_group, other_group])
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.get("/task_groups/export")
        assert response.status_code == 200

        payload = json.loads(response.data.decode("utf-8"))
        exported_task_names = [entry["name"] for entry in payload["tasks"]]
        exported_group_names = [entry["name"] for entry in payload["task_groups"]]

        assert payload["exported_by"] == admin.username
        assert "owner" not in payload
        assert "owner-mask" in exported_task_names
        assert "other-mask" in exported_task_names
        assert "owner-group" in exported_group_names
        assert "other-group" in exported_group_names

@pytest.mark.security
def test_task_group_export_requires_admin():
    app = _build_app()
    with app.app_context():
        db.create_all()
        user = _seed_user(
            "tg-export-viewer", password="viewer-user-password", admin=False
        )
        _seed_settings()

        task = Tasks(
            name="tg-export-task",
            hc_attackmode="maskmode",
            wl_id=None,
            rule_id=None,
            hc_mask="?a?a",
        )
        db.session.add(task)
        db.session.commit()
        task_group = TaskGroups(name="tg-export-group", tasks=json.dumps([task.id]))
        db.session.add(task_group)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, user)

        page_response = client.get("/task_groups")
        assert page_response.status_code == 200
        assert b"Export JSON" not in page_response.data

        export_response = client.get("/task_groups/export", follow_redirects=True)
        assert export_response.status_code == 200
        assert b"Permission Denied" in export_response.data
        assert export_response.headers.get("Content-Disposition") is None

@pytest.mark.security
def test_task_group_import_creates_tasks_and_groups():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

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
        _login_client_as_user(client, admin)
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

        imported_dict_task = Tasks.query.filter_by(name="import-dict").first()
        imported_mask_task = Tasks.query.filter_by(name="import-mask").first()
        imported_group = TaskGroups.query.filter_by(name="import-group").first()

        assert imported_dict_task is not None
        assert imported_dict_task.wl_id == wordlist.id
        assert imported_dict_task.rule_id == rule.id
        assert imported_dict_task.hc_attackmode == "dictionary"
        assert imported_mask_task is not None
        assert imported_mask_task.hc_mask == "?a?a?a"
        assert imported_group is not None
        assert set(json.loads(imported_group.tasks)) == {
            imported_dict_task.id,
            imported_mask_task.id,
        }

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
def test_tasks_add_maskmode_requires_non_empty_mask():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            "/tasks/add",
            data={
                "name": "mask-empty-task",
                "hc_attackmode": "maskmode",
                "wl_id": "",
                "rule_id": "None",
                "mask": "   ",
            },
        )
        assert response.status_code == 200
        assert Tasks.query.filter_by(name="mask-empty-task").first() is None

@pytest.mark.security
def test_task_edit_allows_same_name_and_clears_mask_when_switching_to_dictionary():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        wordlist = Wordlists(
            name="wl",
            type="static",
            path="/tmp/wl.txt",
            size=1,
            checksum="abc123",
        )
        db.session.add(wordlist)
        db.session.commit()

        task = Tasks(
            name="same-name-task",
            hc_attackmode="maskmode",
            wl_id=None,
            rule_id=None,
            hc_mask="?a?a",
        )
        db.session.add(task)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            f"/tasks/edit/{task.id}",
            data={
                "name": task.name,
                "hc_attackmode": "dictionary",
                "wl_id": str(wordlist.id),
                "rule_id": "None",
                "mask": "",
            },
        )
        assert response.status_code == 302

        db.session.refresh(task)
        assert task.hc_attackmode == "dictionary"
        assert task.wl_id == wordlist.id
        assert task.rule_id is None
        assert task.hc_mask is None

@pytest.mark.security
def test_tasks_add_allows_admin_to_use_shared_wordlists_and_rules():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        wordlist = Wordlists(
            name="shared-wordlist",
            type="static",
            path="/tmp/shared-wordlist.txt",
            size=1,
            checksum="2" * 64,
        )
        rule = Rules(
            name="shared-rule",
            path="/tmp/shared.rule",
            size=1,
            checksum="3" * 64,
        )
        db.session.add_all([wordlist, rule])
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            "/tasks/add",
            data={
                "name": "shared-dictionary-task",
                "hc_attackmode": "dictionary",
                "wl_id": str(wordlist.id),
                "rule_id": str(rule.id),
                "mask": "",
            },
        )
        assert response.status_code == 302

        task = Tasks.query.filter_by(name="shared-dictionary-task").first()
        assert task is not None
        assert task.wl_id == wordlist.id
        assert task.rule_id == rule.id
        entry = _latest_audit_entry()
        assert entry is not None
        assert entry.event_type == "task.create"
        assert entry.target_id == str(task.id)

@pytest.mark.security
def test_tasks_list_modal_does_not_match_task_group_membership_by_substring():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        seeded_tasks = []
        for index in range(1, 12):
            task = Tasks(
                name=f"modal-task-{index}",
                hc_attackmode="maskmode",
                wl_id=None,
                rule_id=None,
                hc_mask="?a",
            )
            db.session.add(task)
            seeded_tasks.append(task)
        db.session.commit()

        task_one = seeded_tasks[0]
        task_two = seeded_tasks[1]
        task_eleven = seeded_tasks[10]

        task_group = TaskGroups(
            name="substring-group",
            tasks=json.dumps([task_eleven.id]),
        )
        db.session.add(task_group)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.get("/tasks")
        assert response.status_code == 200

        html = response.get_data(as_text=True)
        task_one_modal_start = html.index(f'id="infoModal{task_one.id}"')
        task_two_modal_start = html.index(f'id="infoModal{task_two.id}"')
        task_one_modal = html[task_one_modal_start:task_two_modal_start]

        assert "substring-group" not in task_one_modal
