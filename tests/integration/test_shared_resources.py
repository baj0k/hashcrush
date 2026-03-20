"""Integration tests for shared tasks, task groups, rules, and wordlists."""
# ruff: noqa: F403,F405
import re
from urllib.parse import parse_qs, urlsplit

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

        task = _first_row(Tasks, name="bruteforce-task")
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
        assert _count_rows(Tasks) == 0

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
        assert _count_rows(TaskGroups) == 0

@pytest.mark.security
def test_wordlists_add_uploads_static_wordlist_to_managed_runtime(tmp_path):
    app = _build_app(
        {
            "RUNTIME_PATH": str(tmp_path / "runtime"),
            "STORAGE_PATH": str(tmp_path / "storage"),
        }
    )
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            "/wordlists/add",
            data={
                "name": "uploaded-wordlist",
                "upload": (io.BytesIO(b"password\nletmein\n"), "uploaded.txt"),
            },
        )

        assert response.status_code == 302
        wordlist = _first_row(Wordlists, name="uploaded-wordlist")
        assert wordlist is not None
        assert wordlist.type == "static"
        assert wordlist.path.startswith(
            str((tmp_path / "storage" / "wordlists").resolve())
        )
        assert Path(wordlist.path).read_text(encoding="utf-8") == "password\nletmein\n"


@pytest.mark.security
def test_wordlists_add_supports_async_processing_progress(tmp_path):
    app = _build_app(
        {
            "RUNTIME_PATH": str(tmp_path / "runtime"),
            "STORAGE_PATH": str(tmp_path / "storage"),
        }
    )
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            "/wordlists/add",
            data={
                "name": "async-wordlist",
                "upload": (io.BytesIO(b"password\nletmein\n"), "async.txt"),
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
        )

        assert response.status_code == 202
        start_payload = response.get_json()
        assert isinstance(start_payload, dict)
        assert start_payload["state"] in {"queued", "running"}
        assert start_payload["status_url"].startswith("/uploads/operations/")
        operation_id = start_payload["operation_id"]

        persisted_operation = db.session.get(UploadOperations, operation_id)
        assert persisted_operation is not None
        assert persisted_operation.owner_user_id == admin.id

        final_payload = _wait_for_upload_operation(client, start_payload["status_url"])
        assert final_payload["success"] is True
        assert final_payload["redirect_url"] == "/wordlists"

        db.session.expire_all()
        persisted_operation = db.session.get(UploadOperations, operation_id)
        assert persisted_operation is not None
        assert persisted_operation.state == "succeeded"

        wordlist = _first_row(Wordlists, name="async-wordlist")
        assert wordlist is not None
        assert Path(wordlist.path).read_text(encoding="utf-8") == "password\nletmein\n"

        entry = _latest_audit_entry()
        assert entry is not None
        assert entry.event_type == "wordlist.create"
        assert entry.actor_username == "admin"


@pytest.mark.security
def test_wordlists_add_form_includes_upload_progress_status_panel():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.get("/wordlists/add")
        assert response.status_code == 200
        assert b'data-upload-progress-form="true"' in response.data
        assert b"Large file uploads continue processing" in response.data


@pytest.mark.security
def test_rules_add_uploads_rule_to_managed_runtime(tmp_path):
    app = _build_app(
        {
            "RUNTIME_PATH": str(tmp_path / "runtime"),
            "STORAGE_PATH": str(tmp_path / "storage"),
        }
    )
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            "/rules/add",
            data={
                "name": "uploaded-rule",
                "upload": (io.BytesIO(b":\n"), "uploaded.rule"),
            },
        )

        assert response.status_code == 302
        rule = _first_row(Rules, name="uploaded-rule")
        assert rule is not None
        assert rule.path.startswith(str((tmp_path / "storage" / "rules").resolve()))
        assert Path(rule.path).read_text(encoding="utf-8") == ":\n"


@pytest.mark.security
def test_rules_add_supports_async_processing_progress(tmp_path):
    app = _build_app(
        {
            "RUNTIME_PATH": str(tmp_path / "runtime"),
            "STORAGE_PATH": str(tmp_path / "storage"),
        }
    )
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            "/rules/add",
            data={
                "name": "async-rule",
                "upload": (io.BytesIO(b":\n"), "async.rule"),
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
        )

        assert response.status_code == 202
        start_payload = response.get_json()
        assert isinstance(start_payload, dict)
        assert start_payload["status_url"].startswith("/uploads/operations/")

        final_payload = _wait_for_upload_operation(client, start_payload["status_url"])
        assert final_payload["success"] is True
        assert final_payload["redirect_url"] == "/rules"

        rule = _first_row(Rules, name="async-rule")
        assert rule is not None
        assert Path(rule.path).read_text(encoding="utf-8") == ":\n"

        entry = _latest_audit_entry()
        assert entry is not None
        assert entry.event_type == "rule.create"
        assert entry.actor_username == "admin"


@pytest.mark.security
def test_wordlists_add_handles_integrity_error_cleanly(tmp_path, monkeypatch):
    app = _build_app(
        {
            "RUNTIME_PATH": str(tmp_path / "runtime"),
            "STORAGE_PATH": str(tmp_path / "storage"),
        }
    )
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

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
                "upload": (io.BytesIO(b"password\n"), "wordlist.txt"),
            },
        )
        assert response.status_code == 200
        assert b"Wordlist could not be uploaded" in response.data
        assert _count_rows(Wordlists) == 0

@pytest.mark.security
def test_rules_add_handles_integrity_error_cleanly(tmp_path, monkeypatch):
    app = _build_app(
        {
            "RUNTIME_PATH": str(tmp_path / "runtime"),
            "STORAGE_PATH": str(tmp_path / "storage"),
        }
    )
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

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
                "upload": (io.BytesIO(b":\n"), "best.rule"),
            },
        )
        assert response.status_code == 200
        assert b"Rule file could not be uploaded" in response.data
        assert _count_rows(Rules) == 0

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

        imported_dict_task = _first_row(Tasks, name="import-dict")
        imported_mask_task = _first_row(Tasks, name="import-mask")
        imported_group = _first_row(TaskGroups, name="import-group")

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
        assert _first_row(Tasks, name="mask-empty-task") is None

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

        task = _first_row(Tasks, name="shared-dictionary-task")
        assert task is not None
        assert task.wl_id == wordlist.id
        assert task.rule_id == rule.id
        entry = _latest_audit_entry()
        assert entry is not None
        assert entry.event_type == "task.create"
        assert entry.target_id == str(task.id)


@pytest.mark.security
def test_tasks_add_prefills_selected_wordlist_and_rule_from_query_params():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        wordlist = Wordlists(
            name="prefill-wordlist",
            type="static",
            path="/tmp/prefill-wordlist.txt",
            size=1,
            checksum="4" * 64,
        )
        rule = Rules(
            name="prefill-rule",
            path="/tmp/prefill.rule",
            size=1,
            checksum="5" * 64,
        )
        db.session.add_all([wordlist, rule])
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.get(
            f"/tasks/add?next=/tasks&selected_wordlist_id={wordlist.id}&selected_rule_id={rule.id}"
        )

        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert re.search(
            r'<option(?=[^>]*value="dictionary")(?=[^>]*selected)[^>]*>dictionary</option>',
            html,
        )
        assert re.search(
            rf'<option(?=[^>]*value="{wordlist.id}")(?=[^>]*selected)[^>]*>{re.escape(wordlist.name)}</option>',
            html,
        )
        assert re.search(
            rf'<option(?=[^>]*value="{rule.id}")(?=[^>]*selected)[^>]*>{re.escape(rule.name)}</option>',
            html,
        )


@pytest.mark.security
def test_wordlists_add_redirects_back_to_tasks_add_with_selected_wordlist():
    app = _build_app(
        {
            "RUNTIME_PATH": "/tmp/hashcrush-runtime-wordlist-return",
            "STORAGE_PATH": "/tmp/hashcrush-storage-wordlist-return",
        }
    )
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        rule = Rules(
            name="preserved-rule",
            path="/tmp/preserved.rule",
            size=1,
            checksum="6" * 64,
        )
        db.session.add(rule)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            "/wordlists/add",
            query_string={
                "next": f"/tasks/add?next=/tasks&selected_rule_id={rule.id}",
            },
            data={
                "name": "return-wordlist",
                "upload": (io.BytesIO(b"password\n"), "return-wordlist.txt"),
            },
        )

        assert response.status_code == 302
        location = urlsplit(response.headers["Location"])
        query = parse_qs(location.query)
        wordlist = _first_row(Wordlists, name="return-wordlist")
        assert wordlist is not None
        assert location.path == "/tasks/add"
        assert query["next"] == ["/tasks"]
        assert query["selected_rule_id"] == [str(rule.id)]
        assert query["selected_wordlist_id"] == [str(wordlist.id)]


@pytest.mark.security
def test_rules_add_redirects_back_to_tasks_add_with_selected_rule():
    app = _build_app(
        {
            "RUNTIME_PATH": "/tmp/hashcrush-runtime-rule-return",
            "STORAGE_PATH": "/tmp/hashcrush-storage-rule-return",
        }
    )
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        wordlist = Wordlists(
            name="preserved-wordlist",
            type="static",
            path="/tmp/preserved-wordlist.txt",
            size=1,
            checksum="7" * 64,
        )
        db.session.add(wordlist)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            "/rules/add",
            query_string={
                "next": f"/tasks/add?next=/tasks&selected_wordlist_id={wordlist.id}",
            },
            data={
                "name": "return-rule",
                "upload": (io.BytesIO(b":\n"), "return.rule"),
            },
        )

        assert response.status_code == 302
        location = urlsplit(response.headers["Location"])
        query = parse_qs(location.query)
        rule = _first_row(Rules, name="return-rule")
        assert rule is not None
        assert location.path == "/tasks/add"
        assert query["next"] == ["/tasks"]
        assert query["selected_wordlist_id"] == [str(wordlist.id)]
        assert query["selected_rule_id"] == [str(rule.id)]

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
