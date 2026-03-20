"""Integration tests for audit logging."""
# ruff: noqa: F403,F405
from datetime import datetime

from tests.integration.support import *


@pytest.mark.security
def test_audit_log_page_renders_entries_for_admin():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()
        db.session.add(
            AuditLog(
                actor_user_id=admin.id,
                actor_username=admin.username,
                actor_admin=True,
                actor_ip="127.0.0.1",
                event_type="job.start",
                target_type="job",
                target_id="7",
                summary="Started job sample-job.",
                details_json='{"job_name":"sample-job"}',
            )
        )
        db.session.commit()

        admin_client = app.test_client()
        _login_client_as_user(admin_client, admin)
        response = admin_client.get("/audit")
        assert response.status_code == 200
        assert b"Audit Log" in response.data
        assert b"job.start" in response.data
        assert b"sample-job" in response.data


@pytest.mark.security
def test_record_audit_event_flushes_after_commit():
    from hashcrush.audit import record_audit_event

    app = _build_app()
    with app.app_context():
        db.create_all()
        _seed_admin_user()
        db.session.add(Domains(name="audit-seed-domain"))

        record_audit_event(
            "runtime.seed",
            "bootstrap",
            target_id="seed-1",
            summary="Seeded runtime state.",
            details={"source": "test"},
        )
        assert _count_rows(AuditLog) == 0

        db.session.commit()

        entry = _latest_audit_entry()
        assert entry is not None
        assert entry.event_type == "runtime.seed"
        assert '"source": "test"' in entry.details_json


@pytest.mark.security
def test_record_audit_event_is_cleared_on_rollback():
    from hashcrush.audit import record_audit_event

    app = _build_app()
    with app.app_context():
        db.create_all()
        _seed_admin_user()
        db.session.add(Domains(name="rollback-seed-domain"))

        record_audit_event(
            "runtime.seed",
            "bootstrap",
            target_id="seed-1",
            summary="Seeded runtime state.",
            details={"source": "test"},
        )
        db.session.rollback()

        assert _count_rows(AuditLog) == 0

@pytest.mark.security
def test_audit_log_page_rejects_non_admin():
    app = _build_app()
    with app.app_context():
        db.create_all()
        _seed_admin_user()
        user = _seed_user("audited-user")
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, user)

        response = client.get("/audit")

        assert response.status_code == 403


@pytest.mark.security
def test_audit_log_page_filters_by_actor_event_target_and_date():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()
        db.session.add_all(
            [
                AuditLog(
                    actor_user_id=admin.id,
                    actor_username="alice-admin",
                    actor_admin=True,
                    actor_ip="127.0.0.1",
                    event_type="job.start",
                    target_type="job",
                    target_id="7",
                    summary="Matched audit row",
                    details_json='{"job_name":"match"}',
                    created_at=datetime(2026, 3, 10, 12, 0, 0),
                ),
                AuditLog(
                    actor_user_id=admin.id,
                    actor_username="bob-admin",
                    actor_admin=True,
                    actor_ip="127.0.0.1",
                    event_type="job.stop",
                    target_type="job",
                    target_id="8",
                    summary="Wrong actor/event",
                    details_json='{"job_name":"stop"}',
                    created_at=datetime(2026, 3, 10, 12, 30, 0),
                ),
                AuditLog(
                    actor_user_id=admin.id,
                    actor_username="alice-admin",
                    actor_admin=True,
                    actor_ip="127.0.0.1",
                    event_type="job.start",
                    target_type="task",
                    target_id="9",
                    summary="Wrong target type",
                    details_json='{"task_name":"task"}',
                    created_at=datetime(2026, 3, 11, 12, 0, 0),
                ),
            ]
        )
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.get(
            "/audit?actor=alice&event_type=job.start&target_type=job&date_from=2026-03-10&date_to=2026-03-10"
        )

        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Matched audit row" in html
        assert "Wrong actor/event" not in html
        assert "Wrong target type" not in html


@pytest.mark.security
def test_audit_log_csv_export_respects_filters():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()
        db.session.add_all(
            [
                AuditLog(
                    actor_user_id=admin.id,
                    actor_username="alice-admin",
                    actor_admin=True,
                    actor_ip="127.0.0.1",
                    event_type="job.start",
                    target_type="job",
                    target_id="7",
                    summary="Matched export row",
                    details_json='{"job_name":"match"}',
                ),
                AuditLog(
                    actor_user_id=admin.id,
                    actor_username="bob-admin",
                    actor_admin=True,
                    actor_ip="127.0.0.1",
                    event_type="job.stop",
                    target_type="job",
                    target_id="8",
                    summary="Filtered out row",
                    details_json='{"job_name":"stop"}',
                ),
            ]
        )
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.get("/audit?actor=alice&export=csv")

        assert response.status_code == 200
        assert response.headers["Content-Disposition"].startswith(
            "attachment; filename=audit_log.csv"
        )
        body = response.get_data(as_text=True)
        assert "Matched export row" in body
        assert "Filtered out row" not in body
        assert "actor_username" in body


@pytest.mark.security
def test_audit_log_page_paginates_results():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()
        db.session.add_all(
            [
                AuditLog(
                    actor_user_id=admin.id,
                    actor_username=admin.username,
                    actor_admin=True,
                    actor_ip="127.0.0.1",
                    event_type="job.start",
                    target_type="job",
                    target_id=str(index),
                    summary=f"Audit row {index}",
                    details_json="{}",
                    created_at=datetime(2026, 3, 10, 12, 0, 0),
                )
                for index in range(55)
            ]
        )
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        first_page = client.get("/audit")
        second_page = client.get("/audit?page=2")

        assert first_page.status_code == 200
        assert second_page.status_code == 200
        first_html = first_page.get_data(as_text=True)
        second_html = second_page.get_data(as_text=True)
        assert "Page 1 / 2" in first_html
        assert "Audit row 54" in first_html
        assert "Audit row 0" not in first_html
        assert "Page 2 / 2" in second_html
        assert "Audit row 0" in second_html


@pytest.mark.security
def test_audit_log_csv_export_rejects_non_admin():
    app = _build_app()
    with app.app_context():
        db.create_all()
        _seed_admin_user()
        user = _seed_user("audit-export-user")
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, user)

        response = client.get("/audit?export=csv")

        assert response.status_code == 403

@pytest.mark.security
def test_domains_add_records_audit_event():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()
        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post("/domains/add", data={"name": "Audit Domain"})

        assert response.status_code == 302
        entry = _latest_audit_entry()
        assert entry is not None
        assert entry.event_type == "domain.create"
        assert entry.summary == 'Created shared domain "Audit Domain".'
        assert '"domain_name": "Audit Domain"' in entry.details_json

@pytest.mark.security
def test_jobs_start_records_audit_event():
    app = _build_app()
    with app.app_context():
        db.create_all()
        owner = _seed_admin_user()
        _seed_settings()
        domain = Domains(name="Audit Job Domain")
        hashfile = Hashfiles(name="audit-job.txt", domain_id=1)
        task = Tasks(name="?a [1]", hc_attackmode="maskmode", hc_mask="?a")
        db.session.add(domain)
        db.session.commit()
        hashfile.domain_id = domain.id
        db.session.add_all(
            [
                hashfile,
                task,
            ]
        )
        db.session.commit()
        job = Jobs(
            name="Audit Job",
            priority=3,
            status="Ready",
            domain_id=domain.id,
            owner_id=owner.id,
            hashfile_id=hashfile.id,
        )
        db.session.add(job)
        db.session.commit()
        db.session.add(JobTasks(job_id=job.id, task_id=task.id, status="Ready"))
        hash_row = Hashes(
            sub_ciphertext="deadbeefdeadbeefdeadbeefdeadbeef",
            ciphertext="11223344556677889900aabbccddeeff",
            hash_type=1000,
            cracked=False,
            plaintext=None,
        )
        db.session.add(hash_row)
        db.session.commit()
        db.session.add(
            HashfileHashes(hash_id=hash_row.id, username="user", hashfile_id=hashfile.id)
        )
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, owner)

        response = client.post(f"/jobs/start/{job.id}")

        assert response.status_code == 302
        entry = _latest_audit_entry()
        assert entry is not None
        assert entry.event_type == "job.start"
        assert entry.target_id == str(job.id)
        assert '"job_name": "Audit Job"' in entry.details_json

@pytest.mark.security
def test_rules_add_records_audit_event(tmp_path):
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
                "name": "audit-rule",
                "upload": (io.BytesIO(b":\n"), "best.rule"),
            },
        )

        assert response.status_code == 302
        rule = _first_row(Rules, name="audit-rule")
        assert rule is not None
        entry = _latest_audit_entry()
        assert entry is not None
        assert entry.event_type == "rule.create"
        assert entry.target_id == str(rule.id)

@pytest.mark.security
def test_task_group_add_task_records_audit_event():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        task_a = Tasks(name="audit-group-task-a", hc_attackmode="maskmode", wl_id=None, rule_id=None, hc_mask="?a")
        task_b = Tasks(name="audit-group-task-b", hc_attackmode="maskmode", wl_id=None, rule_id=None, hc_mask="?d")
        db.session.add_all([task_a, task_b])
        db.session.commit()
        task_group = TaskGroups(name="audit-group", tasks=json.dumps([task_a.id]))
        db.session.add(task_group)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            f"/task_groups/assigned_tasks/{task_group.id}/add_task/{task_b.id}"
        )

        assert response.status_code == 302
        db.session.refresh(task_group)
        assert json.loads(task_group.tasks) == [task_a.id, task_b.id]
        entry = _latest_audit_entry()
        assert entry is not None
        assert entry.event_type == "task_group.add_task"
        assert entry.target_id == str(task_group.id)
