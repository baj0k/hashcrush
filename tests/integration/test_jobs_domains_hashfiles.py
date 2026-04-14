"""Integration tests for jobs, domains, and hashfiles."""
# ruff: noqa: F403,F405
import io
from datetime import datetime, timedelta

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

        assert _count_rows(Hashfiles, id=hashfile.id) == 0
        assert _count_rows(HashfileHashes, hashfile_id=hashfile.id) == 0
        assert _count_rows(Hashes, id=hash_row_id) == 0

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
        assert _count_rows(Hashfiles, id=hashfile.id) == 1


@pytest.mark.security
def test_hashfile_detail_page_shows_visible_jobs_and_delete_state():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="Hashfile Detail Domain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="detail-hashfile.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        job = Jobs(
            name="detail-job",
            status="Ready",
            domain_id=domain.id,
            hashfile_id=hashfile.id,
            owner_id=admin.id,
        )
        db.session.add(job)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.get(f"/hashfiles/{hashfile.id}")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Hashfile: detail-hashfile.txt" in html
        assert "detail-job" in html
        assert "Associated Jobs Blocking Deletion" in html
        assert "cannot be deleted until the jobs listed above are detached or removed" in html

@pytest.mark.security
def test_job_summary_page_shows_metadata_and_delete_controls():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="Job Detail Domain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="job-detail.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        task = Tasks(
            name="job-detail-task",
            hc_attackmode="maskmode",
            wl_id=None,
            rule_id=None,
            hc_mask="?a?a",
        )
        db.session.add(task)
        db.session.commit()

        job = Jobs(
            name="job-detail",
            status="Ready",
            domain_id=domain.id,
            hashfile_id=hashfile.id,
            owner_id=admin.id,
        )
        db.session.add(job)
        db.session.commit()

        db.session.add(
            JobTasks(job_id=job.id, task_id=task.id, status="Not Started", position=0)
        )
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.get(f"/jobs/{job.id}/summary")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Job: job-detail" in html
        assert "Owner" in html
        assert "Created At" in html
        assert "job-detail-task" in html
        assert "Delete Job" in html


@pytest.mark.security
def test_jobs_delete_requires_exact_name_when_confirmation_supplied():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="Job Confirm Domain")
        db.session.add(domain)
        db.session.commit()

        job = Jobs(
            name="confirm-job",
            status="Ready",
            domain_id=domain.id,
            owner_id=admin.id,
        )
        db.session.add(job)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            f"/jobs/delete/{job.id}",
            data={"confirm_name": "wrong-name"},
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert b"Type the job name exactly to confirm deletion." in response.data
        assert db.session.get(Jobs, job.id) is not None


@pytest.mark.security
def test_domains_list_paginates_results():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        db.session.add_all(
            [Domains(name=f"Domain {index:03d}") for index in range(1, 56)]
        )
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.get("/domains?page=2")
        assert response.status_code == 200
        assert b"Domain 001" not in response.data
        assert b"Domain 050" not in response.data
        assert b"Domain 051" in response.data
        assert b"Domain 055" in response.data
        assert b"Page 2 / 2" in response.data


@pytest.mark.security
def test_hashfiles_list_paginates_results():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="Paged Hashfile Domain")
        db.session.add(domain)
        db.session.commit()

        base_time = datetime(2026, 1, 1, 12, 0, 0)
        db.session.add_all(
            [
                Hashfiles(
                    name=f"hashfile-{index:03d}.txt",
                    domain_id=domain.id,
                    uploaded_at=base_time + timedelta(seconds=index),
                )
                for index in range(1, 56)
            ]
        )
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.get("/hashfiles?page=2")
        assert response.status_code == 200
        assert b"hashfile-055.txt" not in response.data
        assert b"hashfile-006.txt" not in response.data
        assert b"hashfile-005.txt" in response.data
        assert b"hashfile-001.txt" in response.data
        assert b"Page 2 / 2" in response.data


@pytest.mark.security
def test_jobs_list_paginates_results():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="Paged Job Domain")
        db.session.add(domain)
        db.session.commit()

        base_time = datetime(2026, 1, 1, 12, 0, 0)
        db.session.add_all(
            [
                Jobs(
                    name=f"job-{index:03d}",
                    status="Ready",
                    domain_id=domain.id,
                    owner_id=admin.id,
                    created_at=base_time + timedelta(seconds=index),
                )
                for index in range(1, 56)
            ]
        )
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.get("/jobs?page=2")
        assert response.status_code == 200
        assert b"job-055" not in response.data
        assert b"job-006" not in response.data
        assert b"job-005" in response.data
        assert b"job-001" in response.data
        assert b"Page 2 / 2" in response.data

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
                benchmark="40252.3 MH/s",
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
        assert b"40.3 GH/s" in response.data
        assert b"40252.3 MH/s" not in response.data


@pytest.mark.security
def test_tasks_add_redirects_back_to_job_builder_when_next_is_provided():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="Task Return Domain")
        db.session.add(domain)
        db.session.commit()

        job = Jobs(
            name="task-return-job",
            status="Incomplete",
            domain_id=domain.id,
            owner_id=admin.id,
        )
        db.session.add(job)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            "/tasks/add",
            data={
                "name": "task-return-task",
                "hc_attackmode": "maskmode",
                "mask": "?l?l?l?l",
                "next": f"/jobs/{job.id}/builder?tab=tasks",
                "submit": "Create",
            },
        )

        assert response.status_code == 302
        assert response.headers["Location"].endswith(f"/jobs/{job.id}/builder?tab=tasks")
        assert _count_rows(Tasks, name="task-return-task") == 1


@pytest.mark.security
def test_jobs_page_displays_active_queue_eta_and_percent_done_columns_for_tasks():
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

        response = client.get("/jobs")
        assert response.status_code == 200
        assert b"Active Queue" in response.data
        assert b"% Done" in response.data
        assert b"ETA" in response.data
        assert b"50.00%" in response.data
        assert b"DASHBOARD_ETA" in response.data

@pytest.mark.security
def test_jobs_page_shows_stop_button_for_importing_tasks():
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

        response = client.get("/jobs")
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
        assert db.session.get(Jobs, job.id).hashfile_id == wrong_owner_hashfile.id

        response_wrong_domain = client.post(
            f"/jobs/{job.id}/assigned_hashfile/",
            data={"hashfile_id": str(wrong_domain_hashfile.id)},
        )
        assert response_wrong_domain.status_code == 302
        assert db.session.get(Jobs, job.id).hashfile_id == wrong_domain_hashfile.id

        response_valid = client.post(
            f"/jobs/{job.id}/assigned_hashfile/",
            data={"hashfile_id": str(valid_hashfile.id)},
        )
        assert response_valid.status_code == 302
        assert db.session.get(Jobs, job.id).hashfile_id == valid_hashfile.id

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

        response = client.get(f"/jobs/{job.id}/builder")
        assert response.status_code == 200
        html = response.data.decode("utf-8")
        existing_form_html = html.split('id="existing-hashfile-panel"', 1)[1]
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
        assert db.session.get(Domains, domain.id) is not None
        assert db.session.get(Jobs, active_job.id) is not None

@pytest.mark.security
def test_domains_delete_blocks_when_hashfiles_or_inactive_jobs_still_reference_domain():
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

        assert db.session.get(Domains, domain_id) is not None
        assert db.session.get(Jobs, inactive_job_id) is not None
        assert db.session.get(Hashfiles, hashfile_id) is not None
        assert _count_rows(HashfileHashes, hashfile_id=hashfile_id) == 1
        assert db.session.get(Hashes, orphan_hash_id) is not None

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
        assert db.session.get(Domains, domain.id) is not None


@pytest.mark.security
def test_domain_detail_page_shows_associated_hashfiles_and_jobs():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="Domain Detail")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="domain-detail.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        job = Jobs(
            name="domain-detail-job",
            status="Ready",
            domain_id=domain.id,
            hashfile_id=hashfile.id,
            owner_id=admin.id,
        )
        db.session.add(job)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.get(f"/domains/{domain.id}")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Domain: Domain Detail" in html
        assert "domain-detail-job" in html
        assert f"/hashfiles/{hashfile.id}" in html
        assert "domain-detail.txt" in html

@pytest.mark.security
def test_domains_page_is_shared_read_and_manual_creation_is_disabled():
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
        assert 'action="/domains/add"' not in admin_html
        assert "created automatically" in admin_html

        response = admin_client.post("/domains/add", data={"name": "New Shared Domain"})
        assert response.status_code == 404
        assert _count_rows(Domains, name="New Shared Domain") == 0

        viewer_client = app.test_client()
        _login_client_as_user(viewer_client, viewer)
        viewer_response = viewer_client.get("/domains")
        viewer_html = viewer_response.get_data(as_text=True)
        assert viewer_response.status_code == 200
        assert "Existing Domain" in viewer_html
        assert 'href="/domains"' in viewer_client.get("/jobs").get_data(as_text=True)

@pytest.mark.security
def test_non_admin_sees_same_manual_domain_creation_disabled_message():
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

        response = client.post("/domains/add", data={"name": "Unauthorized Domain"})
        assert response.status_code == 404
        assert _count_rows(Domains, name="Unauthorized Domain") == 0


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
                "domain_name": domain.name,
                "file_type": "hash_only",
                "hash_type": "0",
                "hashfile": (io.BytesIO(b"5f4dcc3b5aa765d61d8327deb882cf99\n"), "shared-hashes.txt"),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )

        assert response.status_code == 200
        assert b"Hashfile created!" in response.data

        hashfile = _first_row(Hashfiles, name="shared-hashes.txt")
        assert hashfile is not None
        assert hashfile.domain_id == domain.id
        assert _count_rows(HashfileHashes, hashfile_id=hashfile.id) == 1

        entry = _latest_audit_entry()
        assert entry is not None
        assert entry.event_type == "hashfile.create"
        assert entry.target_id == str(hashfile.id)
        assert '"hashfile_name": "shared-hashes.txt"' in entry.details_json


@pytest.mark.security
def test_hashfiles_add_form_mentions_windows_pwdump_format():
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
        assert "Windows pwdump" in html
        assert "Administrator:500:LMHASH:NTHASH:::" in html


@pytest.mark.security
def test_hashfiles_add_supports_async_processing_progress():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="Async Hashfile Domain")
        db.session.add(domain)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            "/hashfiles/add",
            data={
                "domain_name": domain.name,
                "file_type": "hash_only",
                "hash_type": "0",
                "hashfile": (
                    io.BytesIO(b"5f4dcc3b5aa765d61d8327deb882cf99\n"),
                    "async-hashes.txt",
                ),
            },
            content_type="multipart/form-data",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )

        assert response.status_code == 202
        start_payload = response.get_json()
        assert isinstance(start_payload, dict)
        assert start_payload["status_url"].startswith("/uploads/operations/")

        final_payload = _wait_for_upload_operation(client, start_payload["status_url"])
        assert final_payload["success"] is True
        assert final_payload["redirect_url"] == "/hashfiles"

        hashfile = _first_row(Hashfiles, name="async-hashes.txt")
        assert hashfile is not None
        assert hashfile.domain_id == domain.id
        assert _count_rows(HashfileHashes, hashfile_id=hashfile.id) == 1

        entry = _latest_audit_entry()
        assert entry is not None
        assert entry.event_type == "hashfile.create"
        assert entry.actor_username == "admin"


@pytest.mark.security
def test_hashfiles_add_prefills_required_no_domain_fallback_category():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, admin)

        form_response = client.get("/hashfiles/add")
        assert form_response.status_code == 200
        assert (
            b"Fallback category (domain) for no-domain entries"
            in form_response.data
        )
        assert b'value="None"' in form_response.data
        assert b'data-upload-progress-form="true"' in form_response.data
        assert b"Large file uploads continue processing" in form_response.data


@pytest.mark.security
def test_hashfiles_add_uses_default_none_category_for_rows_without_domain():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            "/hashfiles/add",
            data={
                "domain_name": "None",
                "file_type": "hash_only",
                "hash_type": "0",
                "hashfile": (
                    io.BytesIO(b"5f4dcc3b5aa765d61d8327deb882cf99\n"),
                    "none-category-hashes.txt",
                ),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )

        assert response.status_code == 200
        assert b"Hashfile created!" in response.data

        hashfile = _first_row(Hashfiles, name="none-category-hashes.txt")
        assert hashfile is not None
        assert hashfile.domain_id is None
        imported_row = _first_row(HashfileHashes, hashfile_id=hashfile.id)
        assert imported_row is not None
        assert imported_row.domain_id is None


@pytest.mark.security
def test_hashfiles_add_treats_redundant_domain_username_prefix_as_none_category():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            "/hashfiles/add",
            data={
                "domain_name": "None",
                "file_type": "pwdump",
                "pwdump_hash_type": "1000",
                "hashfile": (
                    io.BytesIO(
                        (
                            "alice\\alice:500:aad3b435b51404eeaad3b435b51404ee:"
                            "31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
                        ).encode("utf-8")
                    ),
                    "redundant-domain-user.txt",
                ),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )

        assert response.status_code == 200
        assert b"Hashfile created!" in response.data

        hashfile = _first_row(Hashfiles, name="redundant-domain-user.txt")
        assert hashfile is not None
        assert hashfile.domain_id is None

        imported_row = _first_row(HashfileHashes, hashfile_id=hashfile.id)
        assert imported_row is not None
        assert imported_row.domain_id is None
        assert _first_row(Domains, name="alice") is None


@pytest.mark.security
def test_jobs_builder_hashfile_upload_can_run_async_and_redirect_to_tasks():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="Builder Async Domain")
        db.session.add(domain)
        db.session.commit()

        job = Jobs(
            name="builder-async-job",
            status="Incomplete",
            domain_id=domain.id,
            owner_id=admin.id,
        )
        db.session.add(job)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            f"/jobs/{job.id}/assigned_hashfile/",
            data={
                "file_type": "hash_only",
                "hash_type": "0",
                "domain_name": domain.name,
                "hashfile": (
                    io.BytesIO(b"5f4dcc3b5aa765d61d8327deb882cf99\n"),
                    "builder-async.txt",
                ),
            },
            content_type="multipart/form-data",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )

        assert response.status_code == 202
        start_payload = response.get_json()
        assert isinstance(start_payload, dict)
        assert start_payload["status_url"].startswith("/uploads/operations/")

        final_payload = _wait_for_upload_operation(client, start_payload["status_url"])
        assert final_payload["success"] is True
        assert final_payload["redirect_url"] == f"/jobs/{job.id}/builder?tab=tasks"

        db.session.refresh(job)
        assert job.hashfile_id is not None

        hashfile = db.session.get(Hashfiles, job.hashfile_id)
        assert hashfile is not None
        assert hashfile.name == "builder-async.txt"
        assert hashfile.domain_id == domain.id


@pytest.mark.security
def test_hashfiles_add_reuses_existing_domain_when_admin_selects_add_new():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        existing_domain = Domains(name="Existing Hashfile Domain")
        db.session.add(existing_domain)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            "/hashfiles/add",
            data={
                "domain_name": "Existing Hashfile Domain",
                "file_type": "hash_only",
                "hash_type": "0",
                "hashfile": (
                    io.BytesIO(b"5f4dcc3b5aa765d61d8327deb882cf99\n"),
                    "existing-domain-hashes.txt",
                ),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )

        assert response.status_code == 200
        assert _count_rows(Domains, name="Existing Hashfile Domain") == 1

        hashfile = _first_row(Hashfiles, name="existing-domain-hashes.txt")
        assert hashfile is not None
        assert hashfile.domain_id == existing_domain.id

        audit_events = [
            entry.event_type
            for entry in _all_rows(AuditLog, order_by=AuditLog.id.asc())
        ]
        assert audit_events.count("domain.create") == 0
        assert "hashfile.create" in audit_events


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
                "file_type": "hash_only",
                "hash_type": "0",
                "hashfile": (io.BytesIO(b"5f4dcc3b5aa765d61d8327deb882cf99\n"), "blocked.txt"),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )

        assert response.status_code == 200
        assert b"Permission Denied" in response.data
        assert _count_rows(Hashfiles, name="blocked.txt") == 0

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
            _all_rows(
                JobTasks,
                job_id=job.id,
                order_by=(JobTasks.position.asc(), JobTasks.id.asc()),
            )
        )
        assert [row.task_id for row in persisted] == [task_a.id, task_b.id]
        assert [row.status for row in persisted] == ["Running", "Queued"]

@pytest.mark.security
def test_job_task_move_routes_swap_positions_without_recreating_rows():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="Move Order Domain")
        db.session.add(domain)
        db.session.commit()

        task_a = Tasks(name="move-a", hc_attackmode="maskmode", hc_mask="?a")
        task_b = Tasks(name="move-b", hc_attackmode="maskmode", hc_mask="?a?a")
        db.session.add_all([task_a, task_b])
        db.session.commit()

        job = Jobs(
            name="move-job",
            status="Incomplete",
            domain_id=domain.id,
            owner_id=admin.id,
        )
        db.session.add(job)
        db.session.commit()

        first = JobTasks(job_id=job.id, task_id=task_a.id, status="Not Started", position=0)
        second = JobTasks(job_id=job.id, task_id=task_b.id, status="Not Started", position=1)
        db.session.add_all([first, second])
        db.session.commit()
        original_ids = {first.task_id: first.id, second.task_id: second.id}

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(f"/jobs/{job.id}/move_task_down/{task_a.id}")
        assert response.status_code == 302

        persisted = _all_rows(
            JobTasks,
            job_id=job.id,
            order_by=(JobTasks.position.asc(), JobTasks.id.asc()),
        )
        assert [row.task_id for row in persisted] == [task_b.id, task_a.id]
        assert [row.id for row in persisted] == [
            original_ids[task_b.id],
            original_ids[task_a.id],
        ]
        assert [row.position for row in persisted] == [0, 1]

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
            for row in _all_rows(
                JobTasks,
                job_id=job.id,
                order_by=(JobTasks.position.asc(), JobTasks.id.asc()),
            )
        ]
        assert assigned_task_ids.count(task_a.id) == 1
        assert assigned_task_ids.count(task_b.id) == 1

@pytest.mark.security
def test_jobs_add_does_not_require_or_offer_manual_domain_selection():
    app = _build_app()
    with app.app_context():
        db.create_all()
        user = _seed_admin_user()
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, user)

        form_response = client.get("/jobs/add")
        assert form_response.status_code == 200
        assert b"Add New Domain" not in form_response.data
        assert b"Domains are inferred from imported usernames" in form_response.data

        response = client.post(
            "/jobs/add",
            data={
                "name": "domainless-draft-job",
                "priority": "3",
            },
        )
        assert response.status_code == 302
        assert _count_rows(Domains) == 0
        job = _first_row(Jobs, name="domainless-draft-job")
        assert job is not None
        assert job.domain_id is None


@pytest.mark.security
def test_jobs_add_ignores_legacy_domain_fields_and_keeps_domain_unset():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            "/jobs/add",
            data={
                "name": "inline-domain-job",
                "priority": "3",
                "domain_id": "add_new",
                "domain_name": "Inline Job Domain",
            },
            follow_redirects=False,
        )

        assert response.status_code == 302

        domain = _first_row(Domains, name="Inline Job Domain")
        assert domain is None

        job = _first_row(Jobs, name="inline-domain-job")
        assert job is not None
        assert job.domain_id is None

        audit_events = [
            entry.event_type
            for entry in _all_rows(AuditLog, order_by=AuditLog.id.asc())
        ]
        assert "job.create" in audit_events


@pytest.mark.security
def test_job_builder_tasks_tab_uses_natural_task_ordering():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        first_task = Tasks(
            name="All Characters [1 char]",
            hc_attackmode="maskmode",
            hc_mask="?a",
        )
        second_task = Tasks(
            name="All Characters [2 chars]",
            hc_attackmode="maskmode",
            hc_mask="?a?a",
        )
        tenth_task = Tasks(
            name="All Characters [10 chars]",
            hc_attackmode="maskmode",
            hc_mask="?a" * 10,
        )
        db.session.add_all([tenth_task, second_task, first_task])
        db.session.commit()

        job = Jobs(
            name="natural-order-job",
            status="Incomplete",
            domain_id=None,
            owner_id=admin.id,
        )
        db.session.add(job)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        html = client.get(f"/jobs/{job.id}/builder?tab=tasks").get_data(as_text=True)
        index_one = html.index("All Characters [1 char]")
        index_two = html.index("All Characters [2 chars]")
        index_ten = html.index("All Characters [10 chars]")
        assert index_one < index_two < index_ten


@pytest.mark.security
def test_jobs_add_for_non_admin_ignores_legacy_domain_fields():
    app = _build_app()
    with app.app_context():
        db.create_all()
        _seed_admin_user()
        viewer = _seed_user(
            "job-domain-viewer",
            password="viewer-password",
            admin=False,
        )
        _seed_settings()

        domain = Domains(name="Shared Domain")
        db.session.add(domain)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, viewer)

        form_response = client.get("/jobs/add")
        assert form_response.status_code == 200
        assert b"Add New Domain" not in form_response.data

        response = client.post(
            "/jobs/add",
            data={
                "name": "blocked-inline-domain-job",
                "priority": "3",
                "domain_id": "add_new",
                "domain_name": "Blocked Inline Domain",
            },
        )
        assert response.status_code == 302
        assert _count_rows(Domains, name="Blocked Inline Domain") == 0
        job = _first_row(Jobs, name="blocked-inline-domain-job")
        assert job is not None
        assert job.domain_id is None

@pytest.mark.security
def test_jobs_add_creates_domainless_draft_even_when_domains_exist():
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

        job = _first_row(Jobs, name="selected-domain-job")
        assert job is not None
        assert job.domain_id is None
        assert _count_rows(Domains) == 1


@pytest.mark.security
def test_jobs_add_does_not_create_or_reuse_domains_from_legacy_fields():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        existing_domain = Domains(name="Existing Domain Name")
        db.session.add(existing_domain)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            "/jobs/add",
            data={
                "name": "reuse-inline-domain-job",
                "priority": "3",
                "domain_id": "add_new",
                "domain_name": "Existing Domain Name",
            },
            follow_redirects=False,
        )

        assert response.status_code == 302
        assert _count_rows(Domains, name="Existing Domain Name") == 1

        job = _first_row(Jobs, name="reuse-inline-domain-job")
        assert job is not None
        assert job.domain_id is None

        audit_events = [
            entry.event_type
            for entry in _all_rows(AuditLog, order_by=AuditLog.id.asc())
        ]
        assert "job.create" in audit_events

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
            },
        )
        assert response.status_code == 200
        assert _count_rows(Jobs) == 0

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
            },
        )
        assert response.status_code == 200
        assert b"Job could not be created" in response.data
        assert _count_rows(Jobs) == 0
        assert _count_rows(Domains) == 1

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
        assert response.status_code == 200
        assert b"Failed importing hashfile." in response.data

        db.session.refresh(job)
        assert job.hashfile_id is None
        assert _count_rows(Hashfiles) == 0
        assert _count_rows(HashfileHashes) == 0

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
        assert _count_rows(Hashfiles, id=hashfile.id) == 1

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
        assert home_response.status_code == 302
        assert home_response.headers["Location"].endswith("/jobs")

        jobs_response = client.get("/jobs")
        assert jobs_response.status_code == 200
        assert b"Active Queue" in jobs_response.data
        assert b"queued-visible-job" in jobs_response.data
        assert b"draft-hidden-job" not in jobs_response.data
        assert (
            f"/analytics?domain_id={job.domain_id}&hashfile_id={hashfile.id}".encode()
            not in jobs_response.data
        )

        builder_response = client.get(f"/jobs/{job.id}/builder")
        assert builder_response.status_code == 200
        assert b"visible-task" in builder_response.data
        assert b"Read-only view" in builder_response.data
        assert f"/jobs/{job.id}/assign_task/".encode() not in builder_response.data
        assert f"/jobs/{job.id}/remove_all_tasks".encode() not in builder_response.data

        tasks_response = client.get(f"/jobs/{job.id}/tasks")
        assert tasks_response.status_code == 302
        assert tasks_response.headers["Location"].endswith(f"/jobs/{job.id}/builder?tab=tasks")

        summary_response = client.get(f"/jobs/{job.id}/summary")
        assert summary_response.status_code == 200
        assert b"Job:" in summary_response.data
        assert b"Only the job owner or an admin can accept, edit, or delete this job." in summary_response.data

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
def test_hashfiles_add_rejects_oversized_request_before_processing():
    app = _build_app({"MAX_CONTENT_LENGTH": 128})
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="oversized-upload-domain")
        db.session.add(domain)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            "/hashfiles/add",
            data={
                "name": "oversized-hashfile",
                "domain_name": domain.name,
                "file_type": "hash_only",
                "hash_type": "0",
                "hashfile": (io.BytesIO(b"a" * 2048), "oversized.txt"),
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
            content_type="multipart/form-data",
        )

        assert response.status_code == 413
        payload = response.get_json()
        assert payload is not None
        assert "size limit" in payload["detail"].lower()
        assert _count_rows(Hashfiles) == 0

@pytest.mark.security
def test_jobs_start_rejects_completed_job_replay():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="completed-start-domain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="completed-start.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        hash_row = _seed_hash("5f4dcc3b5aa765d61d8327deb882cf99", hash_type=0)
        _seed_hashfile_hash(hash_id=hash_row.id, hashfile_id=hashfile.id)

        task = Tasks(
            name="completed-start-task",
            hc_attackmode="maskmode",
            wl_id=None,
            rule_id=None,
            hc_mask="?a",
        )
        db.session.add(task)
        db.session.commit()

        job = Jobs(
            name="completed-start-job",
            status="Completed",
            domain_id=domain.id,
            owner_id=admin.id,
            hashfile_id=hashfile.id,
        )
        db.session.add(job)
        db.session.commit()

        job_task = JobTasks(
            job_id=job.id,
            task_id=task.id,
            status="Completed",
            command="old-command",
        )
        db.session.add(job_task)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(f"/jobs/start/{job.id}", follow_redirects=True)

        assert response.status_code == 200
        assert b"Only ready or canceled jobs can be started." in response.data
        db.session.refresh(job)
        db.session.refresh(job_task)
        assert job.status == "Completed"
        assert job_task.status == "Completed"
        assert job_task.command == "old-command"

@pytest.mark.security
def test_jobs_start_resets_canceled_job_runtime_metadata():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="restart-domain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="restart.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        hash_row = _seed_hash("5f4dcc3b5aa765d61d8327deb882cf99", hash_type=0)
        _seed_hashfile_hash(hash_id=hash_row.id, hashfile_id=hashfile.id)

        task = Tasks(
            name="restart-task",
            hc_attackmode="maskmode",
            wl_id=None,
            rule_id=None,
            hc_mask="?a",
        )
        db.session.add(task)
        db.session.commit()

        old_started_at = datetime(2024, 1, 2, 3, 4, 5)
        old_ended_at = old_started_at + timedelta(minutes=12)
        job = Jobs(
            name="restart-job",
            status="Canceled",
            domain_id=domain.id,
            owner_id=admin.id,
            hashfile_id=hashfile.id,
            started_at=old_started_at,
            ended_at=old_ended_at,
        )
        db.session.add(job)
        db.session.commit()

        job_task = JobTasks(
            job_id=job.id,
            task_id=task.id,
            status="Canceled",
            started_at=old_started_at,
            progress='{"Progress":"old"}',
            benchmark="123 H/s",
            worker_pid=4242,
        )
        db.session.add(job_task)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(f"/jobs/start/{job.id}", follow_redirects=False)

        assert response.status_code == 302
        db.session.refresh(job)
        db.session.refresh(job_task)
        assert job.status == "Queued"
        assert job.started_at is None
        assert job.ended_at is None
        assert job.queued_at is not None
        assert job_task.status == "Queued"
        assert job_task.started_at is None
        assert job_task.progress is None
        assert job_task.benchmark is None
        assert job_task.worker_pid is None
        assert job_task.command is not None

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
