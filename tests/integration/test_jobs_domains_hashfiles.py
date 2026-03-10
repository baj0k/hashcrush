"""Integration tests for jobs, domains, and hashfiles."""
# ruff: noqa: F403,F405
from tests.integration.support import *


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

        hashfile = Hashfiles(name="to-delete.txt", domain_id=domain.id)
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

        response = client.post(
            f"/hashfiles/delete/{hashfile.id}",
            data={"confirm_name": hashfile.name},
        )
        assert response.status_code == 302

        assert Hashfiles.query.filter_by(id=hashfile.id).count() == 0
        assert HashfileHashes.query.filter_by(hashfile_id=hashfile.id).count() == 0
        assert Hashes.query.filter_by(id=hash_row_id).count() == 0

@pytest.mark.security
def test_hashfiles_delete_requires_exact_name_confirmation():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="HashfileConfirmDomain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="confirm-me.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            f"/hashfiles/delete/{hashfile.id}",
            data={"confirm_name": "wrong-name"},
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert b"Type the hashfile name exactly to confirm deletion." in response.data
        assert Hashfiles.query.filter_by(id=hashfile.id).count() == 1

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

        hashfile = Hashfiles(name="telemetry.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        task = Tasks(
            name="telemetry-task",
            hc_attackmode="maskmode",
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
def test_dashboard_shows_stop_button_for_importing_tasks():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="ImportingDomain")
        db.session.add(domain)
        db.session.commit()

        task = Tasks(
            name="importing-dashboard-task",
            hc_attackmode="maskmode",
            wl_id=None,
            rule_id=None,
            hc_mask="?a",
        )
        db.session.add(task)
        db.session.commit()

        job = Jobs(
            name="importing-dashboard-job",
            status="Running",
            domain_id=domain.id,
            owner_id=admin.id,
        )
        db.session.add(job)
        db.session.commit()

        job_task = JobTasks(
            job_id=job.id,
            task_id=task.id,
            status="Importing",
            progress=json.dumps(
                {"Time_Estimated": "soon", "Progress": "1/1 (100.00%)"}
            ),
        )
        db.session.add(job_task)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.get("/")
        assert response.status_code == 200
        assert f"/job_task/stop/{job_task.id}".encode() in response.data

@pytest.mark.security
def test_jobs_assigned_hashfile_validates_domain_but_allows_shared_hashfiles():
    app = _build_app()
    with app.app_context():
        db.create_all()
        _seed_settings()
        owner = _seed_user("owner")
        _seed_user("other")

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

        valid_hashfile = Hashfiles(name="valid.txt", domain_id=domain_a.id)
        wrong_owner_hashfile = Hashfiles(name="other-owner.txt", domain_id=domain_a.id)
        wrong_domain_hashfile = Hashfiles(
            name="other-domain.txt", domain_id=domain_b.id
        )
        db.session.add_all(
            [valid_hashfile, wrong_owner_hashfile, wrong_domain_hashfile]
        )
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, owner)

        response_shared_hashfile = client.post(
            f"/jobs/{job.id}/assigned_hashfile/",
            data={"hashfile_id": str(wrong_owner_hashfile.id)},
        )
        assert response_shared_hashfile.status_code == 302
        assert Jobs.query.get(job.id).hashfile_id == wrong_owner_hashfile.id

        response_wrong_domain = client.post(
            f"/jobs/{job.id}/assigned_hashfile/",
            data={"hashfile_id": str(wrong_domain_hashfile.id)},
        )
        assert response_wrong_domain.status_code == 302
        assert Jobs.query.get(job.id).hashfile_id == wrong_owner_hashfile.id

        response_valid = client.post(
            f"/jobs/{job.id}/assigned_hashfile/",
            data={"hashfile_id": str(valid_hashfile.id)},
        )
        assert response_valid.status_code == 302
        assert Jobs.query.get(job.id).hashfile_id == valid_hashfile.id

@pytest.mark.security
def test_jobs_assigned_hashfile_existing_hashfile_form_includes_csrf_token():
    app = _build_app({"WTF_CSRF_ENABLED": True})
    with app.app_context():
        db.create_all()
        _seed_settings()
        owner = _seed_user("owner")

        domain = Domains(name="CSRF Domain")
        db.session.add(domain)
        db.session.commit()

        job = Jobs(
            name="csrf-job",
            status="Incomplete",
            domain_id=domain.id,
            owner_id=owner.id,
        )
        hashfile = Hashfiles(name="existing.txt", domain_id=domain.id)
        db.session.add_all([job, hashfile])
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, owner)

        response = client.get(f"/jobs/{job.id}/assigned_hashfile/")
        assert response.status_code == 200
        html = response.data.decode("utf-8")
        existing_form_html = html.split('id="nav-existing-hashfile"', 1)[1]
        assert 'name="csrf_token"' in existing_form_html

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

        response = client.post(
            f"/domains/delete/{domain.id}",
            data={"confirm_name": domain.name},
        )
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

        hashfile = Hashfiles(name="cleanup.txt", domain_id=domain.id)
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
            wl_id=None,
            rule_id=None,
            hc_mask="?a",
        )
        db.session.add(cleanup_task)
        db.session.commit()

        db.session.add(
            JobTasks(
                job_id=inactive_job.id, task_id=cleanup_task.id, status="Completed"
            )
        )
        db.session.commit()

        domain_id = domain.id
        inactive_job_id = inactive_job.id
        hashfile_id = hashfile.id
        orphan_hash_id = orphan_hash.id

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            f"/domains/delete/{domain_id}",
            data={"confirm_name": domain.name},
        )
        assert response.status_code == 302

        assert Domains.query.get(domain_id) is None
        assert Jobs.query.get(inactive_job_id) is None
        assert Hashfiles.query.get(hashfile_id) is None
        assert HashfileHashes.query.filter_by(hashfile_id=hashfile_id).count() == 0
        assert Hashes.query.get(orphan_hash_id) is None

@pytest.mark.security
def test_domains_delete_requires_exact_name_confirmation():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="Confirm Domain")
        db.session.add(domain)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            f"/domains/delete/{domain.id}",
            data={"confirm_name": "wrong-name"},
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert b"Type the domain name exactly to confirm deletion." in response.data
        assert Domains.query.get(domain.id) is not None

@pytest.mark.security
def test_domains_page_is_shared_read_and_admin_can_add_domains():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        viewer = _seed_user("domains-viewer", password="viewer-password", admin=False)
        _seed_settings()

        seed_domain = Domains(name="Existing Domain")
        db.session.add(seed_domain)
        db.session.commit()

        admin_client = app.test_client()
        _login_client_as_user(admin_client, admin)
        admin_html = admin_client.get("/domains").get_data(as_text=True)
        assert 'action="/domains/add"' in admin_html

        response = admin_client.post(
            "/domains/add",
            data={"name": "New Shared Domain"},
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert b"Domain created!" in response.data
        assert Domains.query.filter_by(name="New Shared Domain").count() == 1

        viewer_client = app.test_client()
        _login_client_as_user(viewer_client, viewer)
        viewer_response = viewer_client.get("/domains")
        viewer_html = viewer_response.get_data(as_text=True)
        assert viewer_response.status_code == 200
        assert "Existing Domain" in viewer_html
        assert "New Shared Domain" in viewer_html
        assert 'href="/domains"' in viewer_client.get("/jobs").get_data(as_text=True)

@pytest.mark.security
def test_non_admin_cannot_add_domains():
    app = _build_app()
    with app.app_context():
        db.create_all()
        viewer = _seed_user("domains-writer", password="viewer-password", admin=False)
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, viewer)

        list_response = client.get("/domains")
        assert list_response.status_code == 200
        assert 'action="/domains/add"' not in list_response.get_data(as_text=True)

        response = client.post(
            "/domains/add",
            data={"name": "Unauthorized Domain"},
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert b"Permission Denied" in response.data
        assert Domains.query.filter_by(name="Unauthorized Domain").count() == 0


@pytest.mark.security
def test_hashfiles_page_allows_admin_to_add_shared_hashfiles():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="Hashfile Upload Domain")
        db.session.add(domain)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        list_html = client.get("/hashfiles").get_data(as_text=True)
        assert 'href="/hashfiles/add"' in list_html

        response = client.post(
            "/hashfiles/add",
            data={
                "domain_id": str(domain.id),
                "file_type": "hash_only",
                "hash_type": "0",
                "hashfile": (io.BytesIO(b"5f4dcc3b5aa765d61d8327deb882cf99\n"), "shared-hashes.txt"),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )

        assert response.status_code == 200
        assert b"Hashfile created!" in response.data

        hashfile = Hashfiles.query.filter_by(name="shared-hashes.txt").first()
        assert hashfile is not None
        assert hashfile.domain_id == domain.id
        assert HashfileHashes.query.filter_by(hashfile_id=hashfile.id).count() == 1

        entry = _latest_audit_entry()
        assert entry is not None
        assert entry.event_type == "hashfile.create"
        assert entry.target_id == str(hashfile.id)
        assert '"hashfile_name": "shared-hashes.txt"' in entry.details_json


@pytest.mark.security
def test_non_admin_cannot_add_hashfiles():
    app = _build_app()
    with app.app_context():
        db.create_all()
        viewer = _seed_user("hashfile-viewer", password="viewer-password", admin=False)
        _seed_settings()

        domain = Domains(name="Shared Hashfile Domain")
        db.session.add(domain)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, viewer)

        list_response = client.get("/hashfiles")
        assert list_response.status_code == 200
        assert 'href="/hashfiles/add"' not in list_response.get_data(as_text=True)

        response = client.post(
            "/hashfiles/add",
            data={
                "domain_id": str(domain.id),
                "file_type": "hash_only",
                "hash_type": "0",
                "hashfile": (io.BytesIO(b"5f4dcc3b5aa765d61d8327deb882cf99\n"), "blocked.txt"),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )

        assert response.status_code == 200
        assert b"Permission Denied" in response.data
        assert Hashfiles.query.filter_by(name="blocked.txt").count() == 0

@pytest.mark.security
def test_job_task_move_routes_do_not_mutate_active_jobs():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="Move Guard Domain")
        db.session.add(domain)
        db.session.commit()

        task_a = Tasks(
            name="task-a",
            hc_attackmode="maskmode",
            wl_id=None,
            rule_id=None,
            hc_mask="?a",
        )
        task_b = Tasks(
            name="task-b",
            hc_attackmode="maskmode",
            wl_id=None,
            rule_id=None,
            hc_mask="?a?a",
        )
        db.session.add_all([task_a, task_b])
        db.session.commit()

        job = Jobs(
            name="active-job",
            status="Running",
            domain_id=domain.id,
            owner_id=admin.id,
        )
        db.session.add(job)
        db.session.commit()

        first = JobTasks(job_id=job.id, task_id=task_a.id, status="Running")
        second = JobTasks(job_id=job.id, task_id=task_b.id, status="Queued")
        db.session.add_all([first, second])
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(f"/jobs/{job.id}/move_task_down/{task_a.id}")
        assert response.status_code == 302

        persisted = (
            JobTasks.query.filter_by(job_id=job.id).order_by(JobTasks.id.asc()).all()
        )
        assert [row.task_id for row in persisted] == [task_a.id, task_b.id]
        assert [row.status for row in persisted] == ["Running", "Queued"]

@pytest.mark.security
def test_jobs_assign_task_group_normalizes_string_ids_and_skips_duplicates():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="TaskGroupAssignDomain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="job_hashes.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        job = Jobs(
            name="tg-job",
            status="Incomplete",
            domain_id=domain.id,
            owner_id=admin.id,
            hashfile_id=hashfile.id,
        )
        db.session.add(job)
        db.session.commit()

        task_a = Tasks(
            name="task-a",
            hc_attackmode="maskmode",
            wl_id=None,
            rule_id=None,
            hc_mask="?a",
        )
        task_b = Tasks(
            name="task-b",
            hc_attackmode="maskmode",
            wl_id=None,
            rule_id=None,
            hc_mask="?a?a",
        )
        db.session.add(task_a)
        db.session.add(task_b)
        db.session.commit()

        task_group = TaskGroups(
            name="tg-string-ids",
            tasks=json.dumps(
                [str(task_a.id), str(task_a.id), str(task_b.id), "invalid"]
            ),
        )
        db.session.add(task_group)
        db.session.commit()

        preexisting_assignment = JobTasks(
            job_id=job.id, task_id=task_a.id, status="Not Started"
        )
        db.session.add(preexisting_assignment)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)
        response = client.post(f"/jobs/{job.id}/assign_task_group/{task_group.id}")
        assert response.status_code == 302

        assigned_task_ids = [
            row.task_id
            for row in JobTasks.query.filter_by(job_id=job.id)
            .order_by(JobTasks.id.asc())
            .all()
        ]
        assert assigned_task_ids.count(task_a.id) == 1
        assert assigned_task_ids.count(task_b.id) == 1

@pytest.mark.security
def test_jobs_add_rejects_invalid_domain_selection():
    app = _build_app()
    with app.app_context():
        db.create_all()
        user = _seed_admin_user()
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, user)

        form_response = client.get("/jobs/add")
        assert form_response.status_code == 200
        assert b"New Domain" not in form_response.data

        response = client.post(
            "/jobs/add",
            data={
                "name": "blocked-domain-job",
                "priority": "3",
                "domain_id": "999999",
            },
        )
        assert response.status_code == 200
        assert b"Not a valid choice." in response.data
        assert Domains.query.count() == 0
        assert Jobs.query.count() == 0

@pytest.mark.security
def test_jobs_add_uses_existing_selected_domain():
    app = _build_app()
    with app.app_context():
        db.create_all()
        user = _seed_admin_user()
        _seed_settings()

        existing_domain = Domains(name="ExistingDomain")
        db.session.add(existing_domain)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, user)

        response = client.post(
            "/jobs/add",
            data={
                "name": "selected-domain-job",
                "priority": "3",
                "domain_id": str(existing_domain.id),
            },
        )
        assert response.status_code == 302

        job = Jobs.query.filter_by(name="selected-domain-job").first()
        assert job is not None
        assert job.domain_id == existing_domain.id
        assert Domains.query.count() == 1

@pytest.mark.security
def test_jobs_add_rejects_whitespace_only_name():
    app = _build_app()
    with app.app_context():
        db.create_all()
        user = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="WhitespaceDomain")
        db.session.add(domain)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, user)

        response = client.post(
            "/jobs/add",
            data={
                "name": "   ",
                "priority": "3",
                "domain_id": str(domain.id),
            },
        )
        assert response.status_code == 200
        assert Jobs.query.count() == 0

@pytest.mark.security
def test_jobs_add_handles_job_commit_conflict_without_mutating_domains(monkeypatch):
    app = _build_app()
    with app.app_context():
        db.create_all()
        user = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="ConflictDomain")
        db.session.add(domain)
        db.session.commit()

        monkeypatch.setattr(
            "hashcrush.jobs.routes.db.session.commit",
            lambda: (_ for _ in ()).throw(_integrity_error()),
        )

        client = app.test_client()
        _login_client_as_user(client, user)
        response = client.post(
            "/jobs/add",
            data={
                "name": "conflicting-job",
                "priority": "3",
                "domain_id": str(domain.id),
            },
        )
        assert response.status_code == 200
        assert b"Job could not be created" in response.data
        assert Jobs.query.count() == 0
        assert Domains.query.count() == 1

@pytest.mark.security
def test_jobs_assigned_hashfile_failed_import_rolls_back_hashfile_row(monkeypatch):
    app = _build_app()
    with app.app_context():
        db.create_all()
        user = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="rollback-domain")
        db.session.add(domain)
        db.session.commit()

        job = Jobs(
            name="rollback-job",
            status="Incomplete",
            domain_id=domain.id,
            owner_id=user.id,
        )
        db.session.add(job)
        db.session.commit()

        monkeypatch.setattr(
            "hashcrush.hashfiles.service.import_hashfilehashes", lambda **_: False
        )

        client = app.test_client()
        _login_client_as_user(client, user)

        response = client.post(
            f"/jobs/{job.id}/assigned_hashfile/",
            data={
                "name": "rollback.txt",
                "file_type": "hash_only",
                "hash_type": "0",
                "shadow_hash_type": "",
                "pwdump_hash_type": "",
                "netntlm_hash_type": "",
                "kerberos_hash_type": "",
                "hashfilehashes": "0123456789abcdef0123456789abcdef",
                "submit": "Next",
            },
        )
        assert response.status_code == 302

        db.session.refresh(job)
        assert job.hashfile_id is None
        assert Hashfiles.query.count() == 0
        assert HashfileHashes.query.count() == 0

@pytest.mark.security
def test_hashfiles_delete_handles_integrity_error_cleanly(monkeypatch):
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="HashfileDeleteDomain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="delete-me.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        monkeypatch.setattr(
            "hashcrush.hashfiles.routes.db.session.commit",
            lambda: (_ for _ in ()).throw(_integrity_error()),
        )

        response = client.post(
            f"/hashfiles/delete/{hashfile.id}",
            data={"confirm_name": hashfile.name},
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert (
            b"Error: Hashfile is associated with a job or changed concurrently."
            in response.data
        )
        assert Hashfiles.query.filter_by(id=hashfile.id).count() == 1

@pytest.mark.security
def test_non_owner_can_view_scheduled_jobs_but_cannot_stop_them():
    app = _build_app()
    with app.app_context():
        db.create_all()
        owner = _seed_user("job-owner", password="job-owner-password", admin=False)
        viewer = _seed_user("job-viewer", password="job-viewer-password", admin=False)
        _seed_settings()

        domain = Domains(name="VisibleDomain")
        hashfile = Hashfiles(name="visible.txt", domain_id=1)
        db.session.add(domain)
        db.session.commit()
        hashfile.domain_id = domain.id
        db.session.add(hashfile)
        db.session.commit()

        task = Tasks(
            name="visible-task",
            hc_attackmode="maskmode",
            wl_id=None,
            rule_id=None,
            hc_mask="?a",
        )
        db.session.add(task)
        db.session.commit()

        job = Jobs(
            name="queued-visible-job",
            status="Queued",
            domain_id=domain.id,
            owner_id=owner.id,
            hashfile_id=hashfile.id,
        )
        draft_job = Jobs(
            name="draft-hidden-job",
            status="Incomplete",
            domain_id=domain.id,
            owner_id=owner.id,
            hashfile_id=None,
        )
        db.session.add_all([job, draft_job])
        db.session.commit()

        job_task = JobTasks(job_id=job.id, task_id=task.id, status="Queued")
        db.session.add(job_task)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, viewer)

        home_response = client.get("/")
        assert home_response.status_code == 200
        assert b"queued-visible-job" in home_response.data

        jobs_response = client.get("/jobs")
        assert jobs_response.status_code == 200
        assert b"queued-visible-job" in jobs_response.data
        assert b"draft-hidden-job" not in jobs_response.data
        assert (
            f"/analytics?domain_id={job.domain_id}&hashfile_id={hashfile.id}".encode()
            not in jobs_response.data
        )

        tasks_response = client.get(f"/jobs/{job.id}/tasks")
        assert tasks_response.status_code == 200
        assert b"visible-task" in tasks_response.data
        assert b"Read-only view" in tasks_response.data
        assert f"/jobs/{job.id}/assign_task/".encode() not in tasks_response.data
        assert f"/jobs/{job.id}/remove_all_tasks".encode() not in tasks_response.data

        summary_response = client.get(f"/jobs/{job.id}/summary")
        assert summary_response.status_code == 200
        assert b"queued-visible-job" in summary_response.data
        assert b"Read-only view" in summary_response.data
        assert b"Only the job owner or an admin can finalize or edit this job." in summary_response.data

        draft_tasks_response = client.get(f"/jobs/{draft_job.id}/tasks")
        assert draft_tasks_response.status_code == 302

        draft_summary_response = client.get(f"/jobs/{draft_job.id}/summary")
        assert draft_summary_response.status_code == 302

        cracked_view_response = client.get(
            f"/jobs/{job.id}/assigned_hashfile/{hashfile.id}"
        )
        assert cracked_view_response.status_code == 302

        summary_post_response = client.post(
            f"/jobs/{job.id}/summary",
            data={"submit": "Complete"},
        )
        assert summary_post_response.status_code == 302

        stop_response = client.post(f"/jobs/stop/{job.id}")
        assert stop_response.status_code == 302

        db.session.refresh(job)
        assert job.status == "Queued"

@pytest.mark.security
def test_jobs_stop_preserves_completed_tasks_and_running_pid():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="stop-domain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="stop.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        task_done = Tasks(
            name="done-task",
            hc_attackmode="maskmode",
            wl_id=None,
            rule_id=None,
            hc_mask="?a",
        )
        task_run = Tasks(
            name="run-task",
            hc_attackmode="maskmode",
            wl_id=None,
            rule_id=None,
            hc_mask="?a?a",
        )
        db.session.add_all([task_done, task_run])
        db.session.commit()

        job = Jobs(
            name="stop-job",
            status="Running",
            domain_id=domain.id,
            owner_id=admin.id,
            hashfile_id=hashfile.id,
        )
        db.session.add(job)
        db.session.commit()

        completed = JobTasks(job_id=job.id, task_id=task_done.id, status="Completed")
        running = JobTasks(
            job_id=job.id, task_id=task_run.id, status="Running", worker_pid=424242
        )
        db.session.add_all([completed, running])
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(f"/jobs/stop/{job.id}")
        assert response.status_code == 302

        db.session.refresh(completed)
        db.session.refresh(running)
        assert completed.status == "Completed"
        assert running.status == "Canceled"
        assert running.worker_pid == 424242

@pytest.mark.security
def test_stop_job_task_ignores_stale_request_for_completed_task():
    app = _build_app()
    with app.app_context():
        db.create_all()
        owner = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="stale-stop-domain")
        db.session.add(domain)
        db.session.commit()

        job = Jobs(
            name="stale-stop-job",
            status="Completed",
            domain_id=domain.id,
            owner_id=owner.id,
        )
        db.session.add(job)
        db.session.commit()

        task = Tasks(
            name="stale-stop-task",
            hc_attackmode="maskmode",
            wl_id=None,
            rule_id=None,
            hc_mask="?a",
        )
        db.session.add(task)
        db.session.commit()

        job_task = JobTasks(job_id=job.id, task_id=task.id, status="Completed")
        db.session.add(job_task)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, owner)

        response = client.post(f"/job_task/stop/{job_task.id}")
        assert response.status_code == 302

        db.session.refresh(job_task)
        db.session.refresh(job)
        assert job_task.status == "Completed"
        assert job.status == "Completed"
