"""Integration tests for authentication, authorization, and user management."""
# ruff: noqa: F403,F405
import re

from tests.integration.support import *


@pytest.mark.security
def test_load_user_rejects_non_integer_session_values():
    from hashcrush.users.routes import load_user

    assert load_user("not-an-integer") is None
    assert load_user(None) is None

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

        first = client.post(
            "/login", data={"username": "admin", "password": "wrong-password"}
        )
        assert first.status_code == 200

        second = client.post(
            "/login", data={"username": "admin", "password": "wrong-password"}
        )
        assert second.status_code == 200

        blocked = client.post(
            "/login", data={"username": "admin", "password": "wrong-password"}
        )
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

        first = client.post(
            "/login", data={"username": "admin", "password": "wrong-password"}
        )
        second = client.post(
            "/login", data={"username": "admin", "password": "wrong-password"}
        )
        assert first.status_code == 200
        assert second.status_code == 200

@pytest.mark.security
def test_login_throttle_ignores_x_forwarded_for_by_default():
    app = _build_app(
        {
            "AUTH_THROTTLE_ENABLED": True,
            "AUTH_THROTTLE_MAX_ATTEMPTS": 1,
            "AUTH_THROTTLE_WINDOW_SECONDS": 300,
            "AUTH_THROTTLE_LOCKOUT_SECONDS": 60,
            "TRUST_X_FORWARDED_FOR": False,
        }
    )
    with app.app_context():
        db.create_all()
        _seed_admin_user()
        _seed_settings()

        client = app.test_client()

        first = client.post(
            "/login",
            data={"username": "admin", "password": "wrong-password"},
            headers={"X-Forwarded-For": "1.1.1.1"},
        )
        assert first.status_code == 200

        blocked = client.post(
            "/login",
            data={"username": "admin", "password": "wrong-password"},
            headers={"X-Forwarded-For": "2.2.2.2"},
        )
        assert blocked.status_code == 429

@pytest.mark.security
def test_login_throttle_can_trust_x_forwarded_for_when_enabled():
    app = _build_app(
        {
            "AUTH_THROTTLE_ENABLED": True,
            "AUTH_THROTTLE_MAX_ATTEMPTS": 1,
            "AUTH_THROTTLE_WINDOW_SECONDS": 300,
            "AUTH_THROTTLE_LOCKOUT_SECONDS": 60,
            "TRUST_X_FORWARDED_FOR": True,
        }
    )
    with app.app_context():
        db.create_all()
        _seed_admin_user()
        _seed_settings()

        client = app.test_client()

        first = client.post(
            "/login",
            data={"username": "admin", "password": "wrong-password"},
            headers={"X-Forwarded-For": "1.1.1.1"},
        )
        assert first.status_code == 200

        second = client.post(
            "/login",
            data={"username": "admin", "password": "wrong-password"},
            headers={"X-Forwarded-For": "2.2.2.2"},
        )
        assert second.status_code == 200

        blocked = client.post(
            "/login",
            data={"username": "admin", "password": "wrong-password"},
            headers={"X-Forwarded-For": "2.2.2.2"},
        )
        assert blocked.status_code == 429

@pytest.mark.security
def test_login_csrf_allows_non_default_https_port_behind_proxy():
    app = _build_app(
        {
            "WTF_CSRF_ENABLED": True,
            "AUTH_THROTTLE_ENABLED": False,
            "TRUST_X_FORWARDED_FOR": True,
        }
    )
    with app.app_context():
        db.create_all()
        _seed_admin_user()
        _seed_settings()

        client = app.test_client()
        forwarded_headers = {
            "X-Forwarded-For": "1.1.1.1",
            "X-Forwarded-Proto": "https",
        }

        response = client.get(
            "/login",
            base_url="http://example.test:8443",
            headers=forwarded_headers,
        )
        assert response.status_code == 200

        csrf_match = re.search(
            r'<input[^>]+name="csrf_token"[^>]+value="([^"]+)"|'
            r'<input[^>]+value="([^"]+)"[^>]+name="csrf_token"',
            response.get_data(as_text=True),
        )
        assert csrf_match is not None

        login_response = client.post(
            "/login",
            base_url="http://example.test:8443",
            headers={
                **forwarded_headers,
                "Referer": "https://example.test:8443/login",
            },
            data={
                "username": "admin",
                "password": "wrong-password",
                "csrf_token": csrf_match.group(1) or csrf_match.group(2),
            },
        )
        assert login_response.status_code == 200
        assert b"The referrer does not match the host." not in login_response.data

@pytest.mark.security
def test_login_ignores_non_root_relative_next_target():
    app = _build_app({"AUTH_THROTTLE_ENABLED": False})
    with app.app_context():
        db.create_all()
        _seed_admin_user()
        _seed_settings()

        client = app.test_client()
        response = client.post(
            "/login?next=jobs",
            data={"username": "admin", "password": "test-admin-password"},
            follow_redirects=False,
        )

        assert response.status_code == 302
        assert response.headers["Location"] == "/"

@pytest.mark.security
def test_users_add_handles_integrity_error_cleanly(monkeypatch):
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, admin)

        monkeypatch.setattr(
            "hashcrush.users.routes.db.session.commit",
            lambda: (_ for _ in ()).throw(_integrity_error()),
        )

        response = client.post(
            "/users/add",
            data={
                "username": "conflict-user",
                "is_admin": "y",
                "password": "strong-password-123",
                "confirm_password": "strong-password-123",
            },
        )
        assert response.status_code == 200
        assert b"Account could not be created" in response.data
        assert _count_rows(Users) == 1

@pytest.mark.security
def test_users_add_rejects_whitespace_only_username():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            "/users/add",
            data={
                "username": "   ",
                "password": "strong-password-123",
                "confirm_password": "strong-password-123",
            },
        )
        assert response.status_code == 200
        assert _count_rows(Users) == 1

@pytest.mark.security
def test_users_delete_handles_integrity_error_cleanly(monkeypatch):
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_user("other-admin", password="other-admin-password", admin=True)
        target_user = _seed_user(
            "delete-target", password="delete-target-password", admin=False
        )
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, admin)

        monkeypatch.setattr(
            "hashcrush.users.routes.db.session.commit",
            lambda: (_ for _ in ()).throw(_integrity_error()),
        )

        response = client.post(f"/users/delete/{target_user.id}", follow_redirects=True)
        assert response.status_code == 200
        assert (
            b"Cannot delete user while they own records or while related jobs are being created"
            in response.data
        )
        assert _count_rows(Users, id=target_user.id) == 1

@pytest.mark.security
def test_shared_resource_mutation_requires_admin(tmp_path, monkeypatch):
    app = _build_app()
    with app.app_context():
        db.create_all()
        attacker = _seed_user(
            "shared-resource-user", password="shared-resource-password", admin=False
        )
        _seed_settings()

        static_wordlist = Wordlists(
            name="static-wordlist",
            type="static",
            path=str(tmp_path / "static-wordlist.txt"),
            size=1,
            checksum="1" * 64,
        )
        dynamic_wordlist = Wordlists(
            name="dynamic-wordlist",
            type="dynamic",
            path=str(tmp_path / "dynamic-wordlist.txt"),
            size=0,
            checksum="2" * 64,
        )
        rule = Rules(
            name="shared-rule",
            path=str(tmp_path / "shared.rule"),
            size=1,
            checksum="3" * 64,
        )
        task = Tasks(
            name="shared-task",
            hc_attackmode="maskmode",
            wl_id=None,
            rule_id=None,
            hc_mask="?a?a",
        )
        extra_task = Tasks(
            name="shared-task-extra",
            hc_attackmode="maskmode",
            wl_id=None,
            rule_id=None,
            hc_mask="?a?a?a",
        )
        movable_task = Tasks(
            name="shared-task-movable",
            hc_attackmode="maskmode",
            wl_id=None,
            rule_id=None,
            hc_mask="?a?a?a?a",
        )
        task_group = TaskGroups(
            name="shared-group",
            tasks=json.dumps([task.id, extra_task.id]) if task.id and extra_task.id else json.dumps([]),
        )
        db.session.add_all(
            [
                static_wordlist,
                dynamic_wordlist,
                rule,
                task,
                extra_task,
                movable_task,
            ]
        )
        db.session.commit()
        task_group.tasks = json.dumps([task.id, extra_task.id])
        db.session.add(task_group)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, attacker)

        response = client.get("/tasks/add", follow_redirects=True)
        assert response.status_code == 200
        assert b"Permission Denied" in response.data

        response = client.post(
            "/tasks/add",
            data={
                "name": "blocked-task",
                "hc_attackmode": "maskmode",
                "wl_id": "",
                "rule_id": "None",
                "mask": "?a",
            },
        )
        assert response.status_code == 302
        assert _first_row(Tasks, name="blocked-task") is None

        response = client.get(f"/tasks/edit/{task.id}")
        assert response.status_code == 302
        response = client.post(
            f"/tasks/edit/{task.id}",
            data={
                "name": "mutated-task",
                "hc_attackmode": "maskmode",
                "wl_id": "",
                "rule_id": "None",
                "mask": "?d",
            },
        )
        assert response.status_code == 302
        db.session.refresh(task)
        assert task.name == "shared-task"
        assert task.hc_mask == "?a?a"

        response = client.post(f"/tasks/delete/{task.id}")
        assert response.status_code == 302
        assert db.session.get(Tasks, task.id) is not None

        response = client.get("/task_groups/add")
        assert response.status_code == 302
        response = client.post("/task_groups/add", data={"name": "blocked-group"})
        assert response.status_code == 302
        assert _first_row(TaskGroups, name="blocked-group") is None

        response = client.post("/task_groups/import", data={})
        assert response.status_code == 302

        response = client.get(f"/task_groups/assigned_tasks/{task_group.id}")
        assert response.status_code == 302

        response = client.post(
            f"/task_groups/assigned_tasks/{task_group.id}/add_task/{movable_task.id}"
        )
        assert response.status_code == 302
        response = client.post(
            f"/task_groups/assigned_tasks/{task_group.id}/remove_task/{task.id}"
        )
        assert response.status_code == 302
        response = client.post(
            f"/task_groups/assigned_tasks/{task_group.id}/promote_task/{extra_task.id}"
        )
        assert response.status_code == 302
        response = client.post(
            f"/task_groups/assigned_tasks/{task_group.id}/demote_task/{task.id}"
        )
        assert response.status_code == 302
        response = client.post(f"/task_groups/delete/{task_group.id}")
        assert response.status_code == 302

        db.session.refresh(task_group)
        assert json.loads(task_group.tasks) == [task.id, extra_task.id]
        assert db.session.get(TaskGroups, task_group.id) is not None

        response = client.get("/wordlists/add")
        assert response.status_code == 302
        response = client.post(
            "/wordlists/add",
            data={"name": "blocked-wordlist", "upload": (io.BytesIO(b"password\n"), "test.txt")},
        )
        assert response.status_code == 302
        assert _first_row(Wordlists, name="blocked-wordlist") is None

        response = client.post(f"/wordlists/delete/{static_wordlist.id}")
        assert response.status_code == 302
        assert db.session.get(Wordlists, static_wordlist.id) is not None

        response = client.get("/rules/add")
        assert response.status_code == 302
        response = client.post(
            "/rules/add",
            data={"name": "blocked-rule", "upload": (io.BytesIO(b":\n"), "test.rule")},
        )
        assert response.status_code == 302
        assert _first_row(Rules, name="blocked-rule") is None

        response = client.post(f"/rules/delete/{rule.id}")
        assert response.status_code == 302
        assert db.session.get(Rules, rule.id) is not None

@pytest.mark.security
def test_shared_resource_lists_hide_admin_controls_for_non_admin():
    app = _build_app()
    with app.app_context():
        db.create_all()
        viewer = _seed_user("shared-viewer", password="shared-viewer-password", admin=False)
        _seed_settings()

        static_wordlist = Wordlists(
            name="list-static-wordlist",
            type="static",
            path="/tmp/list-static-wordlist.txt",
            size=1,
            checksum="4" * 64,
        )
        dynamic_wordlist = Wordlists(
            name="list-dynamic-wordlist",
            type="dynamic",
            path="/tmp/list-dynamic-wordlist.txt",
            size=1,
            checksum="5" * 64,
        )
        rule = Rules(
            name="list-rule",
            path="/tmp/list.rule",
            size=1,
            checksum="6" * 64,
        )
        task = Tasks(
            name="list-task",
            hc_attackmode="maskmode",
            wl_id=None,
            rule_id=None,
            hc_mask="?a",
        )
        task_group = TaskGroups(name="list-group", tasks=json.dumps([task.id]) if task.id else json.dumps([]))
        db.session.add_all([static_wordlist, dynamic_wordlist, rule, task])
        db.session.commit()
        task_group.tasks = json.dumps([task.id])
        db.session.add(task_group)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, viewer)

        tasks_html = client.get("/tasks").get_data(as_text=True)
        assert "/tasks/add" not in tasks_html
        assert f"/tasks/edit/{task.id}" not in tasks_html
        assert f"/tasks/delete/{task.id}" not in tasks_html

        task_groups_html = client.get("/task_groups").get_data(as_text=True)
        assert "/task_groups/add" not in task_groups_html
        assert "/task_groups/import" not in task_groups_html
        assert f"/task_groups/assigned_tasks/{task_group.id}" not in task_groups_html
        assert f"/task_groups/delete/{task_group.id}" not in task_groups_html
        assert "/task_groups/export" not in task_groups_html

        wordlists_html = client.get("/wordlists").get_data(as_text=True)
        assert "/wordlists/add" not in wordlists_html
        assert f"/wordlists/delete/{static_wordlist.id}" not in wordlists_html

        rules_html = client.get("/rules").get_data(as_text=True)
        assert "/rules/add" not in rules_html
        assert f"/rules/delete/{rule.id}" not in rules_html

@pytest.mark.security
def test_shared_resource_pages_hide_private_incomplete_job_names_from_other_users():
    app = _build_app()
    with app.app_context():
        db.create_all()
        owner = _seed_user(
            "shared-owner", password="owner-user-password", admin=False
        )
        viewer = _seed_user(
            "shared-viewer", password="viewer-user-password", admin=False
        )
        _seed_settings()

        domain = Domains(name="Shared Visibility Domain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="shared-visibility.txt", domain_id=domain.id)
        task = Tasks(
            name="shared-visibility-task",
            hc_attackmode="maskmode",
            wl_id=None,
            rule_id=None,
            hc_mask="?a?a",
        )
        db.session.add_all([hashfile, task])
        db.session.commit()

        private_job = Jobs(
            name="private-incomplete-job",
            status="Incomplete",
            domain_id=domain.id,
            hashfile_id=hashfile.id,
            owner_id=owner.id,
        )
        public_job = Jobs(
            name="public-ready-job",
            status="Ready",
            domain_id=domain.id,
            hashfile_id=hashfile.id,
            owner_id=owner.id,
        )
        db.session.add_all([private_job, public_job])
        db.session.commit()

        db.session.add_all(
            [
                JobTasks(job_id=private_job.id, task_id=task.id, status="Queued"),
                JobTasks(job_id=public_job.id, task_id=task.id, status="Queued"),
            ]
        )
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, viewer)

        tasks_html = client.get("/tasks").get_data(as_text=True)
        domains_html = client.get("/domains").get_data(as_text=True)
        hashfiles_html = client.get("/hashfiles").get_data(as_text=True)

        assert "public-ready-job" in tasks_html
        assert "public-ready-job" in domains_html
        assert "public-ready-job" in hashfiles_html

        assert "private-incomplete-job" not in tasks_html
        assert "private-incomplete-job" not in domains_html
        assert "private-incomplete-job" not in hashfiles_html

@pytest.mark.security
def test_hashfiles_page_hides_download_controls_for_non_admin():
    app = _build_app()
    with app.app_context():
        db.create_all()
        _seed_admin_user()
        user = _seed_user("hashfiles-viewer", password="viewer-password", admin=False)
        _seed_settings()

        domain = Domains(name="Hashfile Downloads Domain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="downloadable.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        user_client = app.test_client()
        _login_client_as_user(user_client, user)
        user_html = user_client.get("/hashfiles").get_data(as_text=True)
        assert (
            f"/analytics/download?type=found&domain_id={domain.id}&hashfile_id={hashfile.id}"
            not in user_html
        )
        assert (
            f"/analytics?domain_id={domain.id}&hashfile_id={hashfile.id}" in user_html
        )

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
        assert db.session.get(Users, admin.id) is not None
        assert _count_rows(Users, admin=True) == 1

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
        assert db.session.get(Users, admin.id) is not None
        assert _count_rows(Users, admin=True) == 2

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
        assert db.session.get(Users, other_admin.id) is None
        assert _count_rows(Users, admin=True) == 1

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
        target_user = _seed_user(
            "target-user", password="old-user-password", admin=False
        )
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

        hashfile = Hashfiles(name="method-check.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        job = Jobs(
            name="method-check-job",
            status="Ready",
            domain_id=domain.id,
            owner_id=admin.id,
            hashfile_id=hashfile.id,
        )
        db.session.add(job)
        db.session.commit()

        task = Tasks(
            name="method-check-task",
            hc_attackmode="maskmode",
            wl_id=None,
            rule_id=None,
            hc_mask="?a?a",
        )
        db.session.add(task)
        db.session.commit()

        task_group = TaskGroups(name="method-check-group", tasks=json.dumps([task.id]))
        db.session.add(task_group)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        assert client.get(f"/hashfiles/delete/{hashfile.id}").status_code == 405
        assert client.get(f"/jobs/start/{job.id}").status_code == 405
        assert client.get(f"/jobs/{job.id}/assign_task/{task.id}").status_code == 405
        assert (
            client.get(
                f"/task_groups/assigned_tasks/{task_group.id}/add_task/{task.id}"
            ).status_code
            == 405
        )
        assert client.get("/rules/delete/999999").status_code == 405
        assert client.get("/logout").status_code == 405

@pytest.mark.security
def test_users_delete_blocks_when_target_user_owns_records():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        target_user = _seed_user(
            "owned-user", password="owned-user-password", admin=False
        )
        _seed_settings()

        domain = Domains(name="owned-user-domain")
        db.session.add(domain)
        db.session.commit()

        owned_job = Jobs(
            name="owned-job",
            status="Ready",
            domain_id=domain.id,
            owner_id=target_user.id,
        )
        db.session.add(owned_job)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(f"/users/delete/{target_user.id}")
        assert response.status_code == 302
        assert db.session.get(Users, target_user.id) is not None
