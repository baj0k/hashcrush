import json

import pytest

from hashcrush import create_app
from hashcrush.models import (
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    Jobs,
    JobTasks,
    Rules,
    Tasks,
    Users,
    Wordlists,
    db,
)


def _build_app():
    return create_app(
        testing=True,
        config_overrides={
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "WTF_CSRF_ENABLED": False,
            "AUTO_SETUP_DEFAULTS": False,
            "ENABLE_SCHEDULER": False,
            "ENABLE_LOCAL_EXECUTOR": False,
        },
    )


def _add_user(email: str, api_key: str, admin: bool = False) -> Users:
    user = Users(
        first_name="Test",
        last_name="User",
        email_address=email,
        password="x" * 60,
        admin=admin,
        api_key=api_key,
    )
    db.session.add(user)
    db.session.commit()
    return user


def _seed_job(owner: Users):
    customer = Customers(name="ACME")
    db.session.add(customer)
    db.session.commit()

    hashfile = Hashfiles(name="hf.txt", customer_id=customer.id, owner_id=owner.id)
    db.session.add(hashfile)
    db.session.commit()

    task = Tasks(name="Task1", hc_attackmode="dictionary", owner_id=owner.id, wl_id=None, rule_id=None)
    db.session.add(task)
    db.session.commit()

    job = Jobs(
        name="Job1",
        status="Running",
        customer_id=customer.id,
        owner_id=owner.id,
        hashfile_id=hashfile.id,
    )
    db.session.add(job)
    db.session.commit()

    hash_row = Hashes(sub_ciphertext="abc", ciphertext="ABC", hash_type=1000, cracked=False, plaintext=None)
    db.session.add(hash_row)
    db.session.commit()

    link = HashfileHashes(hash_id=hash_row.id, hashfile_id=hashfile.id)
    db.session.add(link)
    db.session.commit()

    job_task = JobTasks(job_id=job.id, task_id=task.id, status="Running")
    db.session.add(job_task)
    db.session.commit()

    return {
        "customer": customer,
        "hashfile": hashfile,
        "task": task,
        "job": job,
        "job_task": job_task,
    }


@pytest.mark.security
def test_job_endpoint_scopes_user_access_to_owner():
    app = _build_app()
    with app.app_context():
        db.create_all()
        owner = _add_user("owner@example.com", "owner-key")
        other = _add_user("other@example.com", "other-key")
        seeded = _seed_job(owner)

        client = app.test_client()
        forbidden = client.get(
            f"/v1/jobs/{seeded['job'].id}",
            headers={"X-API-Key": other.api_key},
        )
        assert forbidden.status_code == 403

        allowed = client.get(
            f"/v1/jobs/{seeded['job'].id}",
            headers={"X-API-Key": owner.api_key},
        )
        assert allowed.status_code == 200
        payload = allowed.get_json()
        assert payload["status"] == 200
        job_data = json.loads(payload["job"])
        assert job_data["id"] == seeded["job"].id


@pytest.mark.security
def test_hashfile_download_requires_visibility():
    app = _build_app()
    with app.app_context():
        db.create_all()
        owner = _add_user("owner@example.com", "owner-key")
        other = _add_user("other@example.com", "other-key")
        seeded = _seed_job(owner)

        client = app.test_client()
        forbidden = client.get(
            f"/v1/hashfiles/{seeded['hashfile'].id}",
            headers={"X-API-Key": other.api_key},
        )
        assert forbidden.status_code == 403

        allowed = client.get(
            f"/v1/hashfiles/{seeded['hashfile'].id}",
            headers={"X-API-Key": owner.api_key},
        )
        assert allowed.status_code == 200


@pytest.mark.security
def test_wordlist_update_requires_owner_or_admin():
    app = _build_app()
    with app.app_context():
        db.create_all()
        owner = _add_user("owner@example.com", "owner-key")
        other = _add_user("other@example.com", "other-key")
        admin = _add_user("admin@example.com", "admin-key", admin=True)

        wordlist = Wordlists(
            name="wl.txt",
            owner_id=owner.id,
            type="dynamic",
            path="hashcrush/control/wordlists/dynamic-wordlist.txt",
            size=0,
            checksum="0" * 64,
        )
        db.session.add(wordlist)
        db.session.commit()

        client = app.test_client()
        forbidden = client.get(
            f"/v1/updateWordlist/{wordlist.id}",
            headers={"X-API-Key": other.api_key},
        )
        assert forbidden.status_code == 403

        allowed_owner = client.get(
            f"/v1/updateWordlist/{wordlist.id}",
            headers={"X-API-Key": owner.api_key},
        )
        assert allowed_owner.status_code == 200

        allowed_admin = client.get(
            f"/v1/updateWordlist/{wordlist.id}",
            headers={"X-API-Key": admin.api_key},
        )
        assert allowed_admin.status_code == 200


@pytest.mark.security
def test_rules_list_requires_api_key():
    app = _build_app()
    with app.app_context():
        db.create_all()
        owner = _add_user("owner@example.com", "owner-key")
        db.session.add(
            Rules(
                name="rule1",
                owner_id=owner.id,
                path="hashcrush/control/rules/best64.rule",
                size=1,
                checksum="0" * 64,
            )
        )
        db.session.commit()

        client = app.test_client()
        unauthorized = client.get("/v1/rules")
        assert unauthorized.status_code in (301, 302, 303, 307, 308)

        authorized = client.get("/v1/rules", headers={"X-API-Key": owner.api_key})
        assert authorized.status_code == 200
        payload = authorized.get_json()
        assert payload["status"] == 200
