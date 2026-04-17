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
def test_wordlists_add_registers_mounted_wordlist(tmp_path):
    external_root = tmp_path / "mounted-wordlists"
    external_root.mkdir(parents=True, exist_ok=True)
    external_path = external_root / "registered.txt"
    external_path.write_text("password\nletmein\n", encoding="utf-8")

    app = _build_app(
        {
            "EXTERNAL_WORDLISTS_PATH": str(external_root),
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
                "name": "registered-wordlist",
                "external_path": str(external_path),
            },
        )

        assert response.status_code == 302
        wordlist = _first_row(Wordlists, name="registered-wordlist")
        assert wordlist is not None
        assert wordlist.type == "static"
        assert wordlist.path == str(external_path.resolve())
        assert external_path.exists()


@pytest.mark.security
def test_wordlists_add_supports_async_processing_progress(tmp_path):
    external_root = tmp_path / "mounted-wordlists"
    external_root.mkdir(parents=True, exist_ok=True)
    external_path = external_root / "async.txt"
    external_path.write_text("password\nletmein\n", encoding="utf-8")

    app = _build_app(
        {
            "RUNTIME_PATH": str(tmp_path / "runtime"),
            "STORAGE_PATH": str(tmp_path / "storage"),
            "EXTERNAL_WORDLISTS_PATH": str(external_root),
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
                "external_path": str(external_path),
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
        assert final_payload["redirect_url"].startswith("/wordlists")

        db.session.expire_all()
        persisted_operation = db.session.get(UploadOperations, operation_id)
        assert persisted_operation is not None
        assert persisted_operation.state == "succeeded"

        wordlist = _first_row(Wordlists, name="async-wordlist")
        assert wordlist is not None
        assert wordlist.path == str(external_path.resolve())

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
        assert b'data-upload-progress-no-file="true"' in response.data
        assert b"Register Wordlist" in response.data


@pytest.mark.security
def test_wordlists_add_lists_mounted_wordlist_files(tmp_path):
    external_root = tmp_path / "mounted-wordlists"
    nested_root = external_root / "nested"
    nested_root.mkdir(parents=True, exist_ok=True)
    (external_root / "list10.txt").write_text("password\n", encoding="utf-8")
    (external_root / "list2.txt").write_text("letmein\n", encoding="utf-8")
    (nested_root / "inside.txt").write_text("hashcrush\n", encoding="utf-8")

    app = _build_app(
        {
            "EXTERNAL_WORDLISTS_PATH": str(external_root),
        }
    )
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, admin)

        rescan_response = client.post("/settings/rescan-mounted-folders")
        assert rescan_response.status_code == 302

        response = client.get("/wordlists/add")
        assert response.status_code == 200
        body = response.data.decode("utf-8")
        assert 'value="' + str((external_root / "list2.txt").resolve()) + '"' in body
        assert 'value="' + str((external_root / "list10.txt").resolve()) + '"' in body
        assert 'value="' + str((nested_root / "inside.txt").resolve()) + '"' in body
        assert body.index("list2.txt") < body.index("list10.txt")


@pytest.mark.security
def test_wordlists_add_registers_external_wordlist_without_copying(tmp_path):
    external_root = tmp_path / "mounted-wordlists"
    external_root.mkdir(parents=True, exist_ok=True)
    external_path = external_root / "huge-list.txt"
    external_path.write_text("password\nletmein\n", encoding="utf-8")

    app = _build_app(
        {
            "RUNTIME_PATH": str(tmp_path / "runtime"),
            "STORAGE_PATH": str(tmp_path / "storage"),
            "EXTERNAL_WORDLISTS_PATH": str(external_root),
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
                "name": "mounted-wordlist",
                "external_path": str(external_path),
            },
        )

        assert response.status_code == 302
        wordlist = _first_row(Wordlists, name="mounted-wordlist")
        assert wordlist is not None
        assert wordlist.type == "static"
        assert wordlist.path == str(external_path.resolve())
        assert external_path.exists()


@pytest.mark.security
def test_wordlists_add_rejects_external_path_outside_allowed_roots(tmp_path):
    external_root = tmp_path / "mounted-wordlists"
    external_root.mkdir(parents=True, exist_ok=True)
    disallowed_path = tmp_path / "other" / "outside.txt"
    disallowed_path.parent.mkdir(parents=True, exist_ok=True)
    disallowed_path.write_text("password\n", encoding="utf-8")

    app = _build_app(
        {
            "EXTERNAL_WORDLISTS_PATH": str(external_root),
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
                "name": "outside-wordlist",
                "external_path": str(disallowed_path),
            },
        )

        assert response.status_code == 200
        assert b"Mounted wordlist path must live under:" in response.data
        assert _first_row(Wordlists, name="outside-wordlist") is None


@pytest.mark.security
def test_wordlists_add_supports_async_external_registration(tmp_path):
    external_root = tmp_path / "mounted-wordlists"
    external_root.mkdir(parents=True, exist_ok=True)
    external_path = external_root / "async-huge-list.txt"
    external_path.write_text("password\nletmein\n", encoding="utf-8")

    app = _build_app(
        {
            "RUNTIME_PATH": str(tmp_path / "runtime"),
            "STORAGE_PATH": str(tmp_path / "storage"),
            "EXTERNAL_WORDLISTS_PATH": str(external_root),
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
                "name": "async-mounted-wordlist",
                "external_path": str(external_path),
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
        )

        assert response.status_code == 202
        start_payload = response.get_json()
        assert isinstance(start_payload, dict)
        assert start_payload["status_url"].startswith("/uploads/operations/")

        final_payload = _wait_for_upload_operation(client, start_payload["status_url"])
        assert final_payload["success"] is True
        assert final_payload["redirect_url"].startswith("/wordlists")

        wordlist = _first_row(Wordlists, name="async-mounted-wordlist")
        assert wordlist is not None
        assert wordlist.path == str(external_path.resolve())
        assert external_path.exists()


@pytest.mark.security
def test_wordlists_delete_preserves_external_mounted_files(tmp_path):
    external_root = tmp_path / "mounted-wordlists"
    external_root.mkdir(parents=True, exist_ok=True)
    external_path = external_root / "keep-me.txt"
    external_path.write_text("password\n", encoding="utf-8")

    app = _build_app(
        {
            "EXTERNAL_WORDLISTS_PATH": str(external_root),
        }
    )
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        wordlist = Wordlists(
            name="external-wordlist",
            type="static",
            path=str(external_path.resolve()),
            size=1,
            checksum="7" * 64,
        )
        db.session.add(wordlist)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(f"/wordlists/delete/{wordlist.id}")
        assert response.status_code == 302
        assert db.session.get(Wordlists, wordlist.id) is None
        assert external_path.exists()


@pytest.mark.security
def test_hashfiles_add_form_uses_upload_first_flow():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.get("/hashfiles/add")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Upload Hashfile" in html
        assert "Paste hashes manually instead" in html
        assert "Individual Hashes" not in html
        assert "File Upload" not in html


@pytest.mark.security
def test_wordlist_detail_page_shows_usage_and_dynamic_delete_notice():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        wordlist = Wordlists(
            name="dynamic-wordlist",
            type="dynamic",
            path="/tmp/dynamic-wordlist.txt",
            size=12,
            checksum="6" * 64,
        )
        task = Tasks(
            name="dynamic-wordlist-task",
            hc_attackmode="dictionary",
            wl_id=None,
            rule_id=None,
            hc_mask=None,
        )
        db.session.add_all([wordlist, task])
        db.session.commit()
        task.wl_id = wordlist.id
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.get(f"/wordlists/{wordlist.id}")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Wordlist: dynamic-wordlist" in html
        assert "This dynamic wordlist is rebuilt automatically" in html
        assert f"/tasks/{task.id}" in html
        assert "cannot be deleted from the UI" in html


@pytest.mark.security
def test_rules_add_registers_mounted_rule(tmp_path):
    external_root = tmp_path / "mounted-rules"
    external_root.mkdir(parents=True, exist_ok=True)
    external_path = external_root / "registered.rule"
    external_path.write_text(":\n", encoding="utf-8")

    app = _build_app(
        {
            "EXTERNAL_RULES_PATH": str(external_root),
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
                "name": "registered-rule",
                "external_path": str(external_path),
            },
        )

        assert response.status_code == 302
        rule = _first_row(Rules, name="registered-rule")
        assert rule is not None
        assert rule.path == str(external_path.resolve())
        assert external_path.exists()


@pytest.mark.security
def test_rules_add_supports_async_processing_progress(tmp_path):
    external_root = tmp_path / "mounted-rules"
    external_root.mkdir(parents=True, exist_ok=True)
    external_path = external_root / "async.rule"
    external_path.write_text(":\n", encoding="utf-8")

    app = _build_app(
        {
            "RUNTIME_PATH": str(tmp_path / "runtime"),
            "STORAGE_PATH": str(tmp_path / "storage"),
            "EXTERNAL_RULES_PATH": str(external_root),
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
                "external_path": str(external_path),
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
        )

        assert response.status_code == 202
        start_payload = response.get_json()
        assert isinstance(start_payload, dict)
        assert start_payload["status_url"].startswith("/uploads/operations/")

        final_payload = _wait_for_upload_operation(client, start_payload["status_url"])
        assert final_payload["success"] is True
        assert final_payload["redirect_url"].startswith("/rules")

        rule = _first_row(Rules, name="async-rule")
        assert rule is not None
        assert rule.path == str(external_path.resolve())

        entry = _latest_audit_entry()
        assert entry is not None
        assert entry.event_type == "rule.create"
        assert entry.actor_username == "admin"


@pytest.mark.security
def test_rule_detail_page_shows_associated_tasks():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        rule = Rules(
            name="detail-rule",
            path="/tmp/detail.rule",
            size=2,
            checksum="8" * 64,
        )
        task = Tasks(
            name="detail-rule-task",
            hc_attackmode="dictionary",
            wl_id=None,
            rule_id=None,
            hc_mask=None,
        )
        db.session.add_all([rule, task])
        db.session.commit()
        task.rule_id = rule.id
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.get(f"/rules/{rule.id}")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Rule: detail-rule" in html
        assert f"/tasks/{task.id}" in html
        assert "detail-rule-task" in html


@pytest.mark.security
def test_tasks_list_uses_natural_name_ordering():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        db.session.add_all(
            [
                Tasks(name="All Characters [10 chars]", hc_attackmode="maskmode", hc_mask="?a" * 10),
                Tasks(name="All Characters [2 chars]", hc_attackmode="maskmode", hc_mask="?a?a"),
                Tasks(name="All Characters [1 char]", hc_attackmode="maskmode", hc_mask="?a"),
            ]
        )
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        html = client.get("/tasks").get_data(as_text=True)
        index_one = html.index("All Characters [1 char]")
        index_two = html.index("All Characters [2 chars]")
        index_ten = html.index("All Characters [10 chars]")
        assert index_one < index_two < index_ten


@pytest.mark.security
def test_task_group_assignment_page_uses_natural_task_ordering():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        first_task = Tasks(name="All Characters [1 char]", hc_attackmode="maskmode", hc_mask="?a")
        second_task = Tasks(name="All Characters [2 chars]", hc_attackmode="maskmode", hc_mask="?a?a")
        tenth_task = Tasks(name="All Characters [10 chars]", hc_attackmode="maskmode", hc_mask="?a" * 10)
        task_group = TaskGroups(name="natural-order-group", tasks="[]")
        db.session.add_all([tenth_task, second_task, first_task, task_group])
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        html = client.get(f"/task_groups/assigned_tasks/{task_group.id}").get_data(as_text=True)
        index_one = html.index("All Characters [1 char]")
        index_two = html.index("All Characters [2 chars]")
        index_ten = html.index("All Characters [10 chars]")
        assert index_one < index_two < index_ten


@pytest.mark.security
def test_wordlists_add_handles_integrity_error_cleanly(tmp_path, monkeypatch):
    external_root = tmp_path / "mounted-wordlists"
    external_root.mkdir(parents=True, exist_ok=True)
    external_path = external_root / "wordlist.txt"
    external_path.write_text("password\n", encoding="utf-8")

    app = _build_app(
        {
            "RUNTIME_PATH": str(tmp_path / "runtime"),
            "STORAGE_PATH": str(tmp_path / "storage"),
            "EXTERNAL_WORDLISTS_PATH": str(external_root),
        }
    )
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, admin)

        monkeypatch.setattr(
            "hashcrush.wordlists.service.db.session.commit",
            lambda: (_ for _ in ()).throw(_integrity_error()),
        )

        response = client.post(
            "/wordlists/add",
            data={
                "name": "conflict-wordlist",
                "external_path": str(external_path),
            },
        )
        assert response.status_code == 200
        assert b"Wordlist could not be saved" in response.data
        assert _count_rows(Wordlists) == 0

@pytest.mark.security
def test_rules_add_handles_integrity_error_cleanly(tmp_path, monkeypatch):
    external_root = tmp_path / "mounted-rules"
    external_root.mkdir(parents=True, exist_ok=True)
    external_path = external_root / "best.rule"
    external_path.write_text(":\n", encoding="utf-8")

    app = _build_app(
        {
            "RUNTIME_PATH": str(tmp_path / "runtime"),
            "STORAGE_PATH": str(tmp_path / "storage"),
            "EXTERNAL_RULES_PATH": str(external_root),
        }
    )
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, admin)

        monkeypatch.setattr(
            "hashcrush.rules.service.db.session.commit",
            lambda: (_ for _ in ()).throw(_integrity_error()),
        )

        response = client.post(
            "/rules/add",
            data={
                "name": "conflict-rule",
                "external_path": str(external_path),
            },
        )
        assert response.status_code == 200
        assert b"Rule could not be saved" in response.data
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
def test_task_group_assignment_page_shows_searchable_available_task_picker():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        assigned_task = Tasks(
            name="assigned-task",
            hc_attackmode="maskmode",
            wl_id=None,
            rule_id=None,
            hc_mask="?a?a",
        )
        available_task = Tasks(
            name="available-task",
            hc_attackmode="dictionary",
            wl_id=None,
            rule_id=None,
            hc_mask=None,
        )
        db.session.add_all([assigned_task, available_task])
        db.session.commit()

        task_group = TaskGroups(
            name="searchable-group",
            tasks=json.dumps([assigned_task.id]),
        )
        db.session.add(task_group)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.get(f"/task_groups/assigned_tasks/{task_group.id}")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Assigned Task Order" in html
        assert "Filter Shared Tasks" in html
        assert 'data-filter-input="#task-group-available-tasks [data-filter-item]"' in html
        assert re.search(
            rf'href="/tasks/add\?next=(?:%2F|/)task_groups(?:%2F|/)assigned_tasks(?:%2F|/){task_group.id}"',
            html,
        )
        assert 'data-filter-text="available-task dictionary"' in html
        assert 'data-filter-text="assigned-task maskmode"' not in html


@pytest.mark.security
def test_task_group_detail_page_preserves_assigned_task_order():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        first_task = Tasks(
            name="first-task",
            hc_attackmode="maskmode",
            wl_id=None,
            rule_id=None,
            hc_mask="?a?a",
        )
        second_task = Tasks(
            name="second-task",
            hc_attackmode="dictionary",
            wl_id=None,
            rule_id=None,
            hc_mask=None,
        )
        db.session.add_all([first_task, second_task])
        db.session.commit()

        task_group = TaskGroups(
            name="ordered-group",
            tasks=json.dumps([second_task.id, first_task.id]),
        )
        db.session.add(task_group)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.get(f"/task_groups/{task_group.id}")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        second_position = html.index("second-task")
        first_position = html.index("first-task")
        assert second_position < first_position
        assert f"/tasks/{second_task.id}" in html
        assert f"/tasks/{first_task.id}" in html

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
def test_tasks_edit_prefills_selected_wordlist_and_rule_from_query_params():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        original_wordlist = Wordlists(
            name="original-wordlist",
            type="static",
            path="/tmp/original-wordlist.txt",
            size=1,
            checksum="a" * 64,
        )
        original_rule = Rules(
            name="original-rule",
            path="/tmp/original.rule",
            size=1,
            checksum="b" * 64,
        )
        replacement_wordlist = Wordlists(
            name="replacement-wordlist",
            type="static",
            path="/tmp/replacement-wordlist.txt",
            size=1,
            checksum="c" * 64,
        )
        replacement_rule = Rules(
            name="replacement-rule",
            path="/tmp/replacement.rule",
            size=1,
            checksum="d" * 64,
        )
        db.session.add_all(
            [original_wordlist, original_rule, replacement_wordlist, replacement_rule]
        )
        db.session.commit()

        task = Tasks(
            name="editable-task",
            hc_attackmode="dictionary",
            wl_id=original_wordlist.id,
            rule_id=original_rule.id,
        )
        db.session.add(task)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.get(
            f"/tasks/edit/{task.id}?next=/tasks&selected_wordlist_id={replacement_wordlist.id}&selected_rule_id={replacement_rule.id}"
        )

        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert re.search(
            r'<option(?=[^>]*value="dictionary")(?=[^>]*selected)[^>]*>dictionary</option>',
            html,
        )
        assert re.search(
            rf'<option(?=[^>]*value="{replacement_wordlist.id}")(?=[^>]*selected)[^>]*>{re.escape(replacement_wordlist.name)}</option>',
            html,
        )
        assert re.search(
            rf'<option(?=[^>]*value="{replacement_rule.id}")(?=[^>]*selected)[^>]*>{re.escape(replacement_rule.name)}</option>',
            html,
        )


@pytest.mark.security
def test_wordlists_add_redirects_back_to_tasks_add_with_selected_wordlist(tmp_path):
    external_root = tmp_path / "mounted-wordlists"
    external_root.mkdir(parents=True, exist_ok=True)
    external_path = external_root / "return-wordlist.txt"
    external_path.write_text("password\n", encoding="utf-8")

    app = _build_app(
        {
            "RUNTIME_PATH": str(tmp_path / "runtime"),
            "STORAGE_PATH": str(tmp_path / "storage"),
            "EXTERNAL_WORDLISTS_PATH": str(external_root),
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
                "external_path": str(external_path),
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
def test_wordlists_add_redirects_back_to_tasks_edit_with_selected_wordlist(tmp_path):
    external_root = tmp_path / "mounted-wordlists"
    external_root.mkdir(parents=True, exist_ok=True)
    external_path = external_root / "edit-return-wordlist.txt"
    external_path.write_text("password\n", encoding="utf-8")

    app = _build_app(
        {
            "RUNTIME_PATH": str(tmp_path / "runtime"),
            "STORAGE_PATH": str(tmp_path / "storage"),
            "EXTERNAL_WORDLISTS_PATH": str(external_root),
        }
    )
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        existing_wordlist = Wordlists(
            name="existing-wordlist",
            type="static",
            path="/tmp/existing-wordlist.txt",
            size=1,
            checksum="8" * 64,
        )
        rule = Rules(
            name="preserved-edit-rule",
            path="/tmp/preserved-edit.rule",
            size=1,
            checksum="9" * 64,
        )
        db.session.add_all([existing_wordlist, rule])
        db.session.commit()

        task = Tasks(
            name="edit-return-task",
            hc_attackmode="dictionary",
            wl_id=existing_wordlist.id,
            rule_id=rule.id,
        )
        db.session.add(task)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            "/wordlists/add",
            query_string={
                "next": f"/tasks/edit/{task.id}?next=/tasks&selected_rule_id={rule.id}",
            },
            data={
                "name": "edit-return-wordlist",
                "external_path": str(external_path),
            },
        )

        assert response.status_code == 302
        location = urlsplit(response.headers["Location"])
        query = parse_qs(location.query)
        wordlist = _first_row(Wordlists, name="edit-return-wordlist")
        assert wordlist is not None
        assert location.path == f"/tasks/edit/{task.id}"
        assert query["next"] == ["/tasks"]
        assert query["selected_rule_id"] == [str(rule.id)]
        assert query["selected_wordlist_id"] == [str(wordlist.id)]


@pytest.mark.security
def test_rules_add_redirects_back_to_tasks_add_with_selected_rule(tmp_path):
    external_root = tmp_path / "mounted-rules"
    external_root.mkdir(parents=True, exist_ok=True)
    external_path = external_root / "return.rule"
    external_path.write_text(":\n", encoding="utf-8")

    app = _build_app(
        {
            "RUNTIME_PATH": str(tmp_path / "runtime"),
            "STORAGE_PATH": str(tmp_path / "storage"),
            "EXTERNAL_RULES_PATH": str(external_root),
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
                "external_path": str(external_path),
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
def test_rules_add_redirects_back_to_tasks_edit_with_selected_rule(tmp_path):
    external_root = tmp_path / "mounted-rules"
    external_root.mkdir(parents=True, exist_ok=True)
    external_path = external_root / "edit-return.rule"
    external_path.write_text(":\n", encoding="utf-8")

    app = _build_app(
        {
            "RUNTIME_PATH": str(tmp_path / "runtime"),
            "STORAGE_PATH": str(tmp_path / "storage"),
            "EXTERNAL_RULES_PATH": str(external_root),
        }
    )
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        wordlist = Wordlists(
            name="preserved-edit-wordlist",
            type="static",
            path="/tmp/preserved-edit-wordlist.txt",
            size=1,
            checksum="1" * 64,
        )
        existing_rule = Rules(
            name="existing-edit-rule",
            path="/tmp/existing-edit.rule",
            size=1,
            checksum="2" * 64,
        )
        db.session.add_all([wordlist, existing_rule])
        db.session.commit()

        task = Tasks(
            name="edit-return-rule-task",
            hc_attackmode="dictionary",
            wl_id=wordlist.id,
            rule_id=existing_rule.id,
        )
        db.session.add(task)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            "/rules/add",
            query_string={
                "next": f"/tasks/edit/{task.id}?next=/tasks&selected_wordlist_id={wordlist.id}",
            },
            data={
                "name": "edit-return-rule",
                "external_path": str(external_path),
            },
        )

        assert response.status_code == 302
        location = urlsplit(response.headers["Location"])
        query = parse_qs(location.query)
        rule = _first_row(Rules, name="edit-return-rule")
        assert rule is not None
        assert location.path == f"/tasks/edit/{task.id}"
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

        response = client.get(f"/tasks/{task_one.id}")
        assert response.status_code == 200

        html = response.get_data(as_text=True)
        assert "Task: modal-task-1" in html
        assert "substring-group" not in html
        assert "modal-task-11" not in html
