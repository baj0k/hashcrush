"""Integration tests for audit logging."""
# ruff: noqa: F403,F405
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
    app = _build_app({"RULES_PATH": str(tmp_path)})
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        rule_path = tmp_path / "best.rule"
        rule_path.write_text(":\n", encoding="utf-8")

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            "/rules/add",
            data={
                "name": "audit-rule",
                "existing_file": "best.rule",
            },
        )

        assert response.status_code == 302
        rule = Rules.query.filter_by(name="audit-rule").first()
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
