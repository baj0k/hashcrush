"""Integration coverage for offline HIBP NTLM dataset loading and matching."""

from __future__ import annotations

import io
import json
import os

from sqlalchemy import inspect, select

from hashcrush.db_upgrade import CURRENT_SCHEMA_VERSION, upgrade_database
from hashcrush.hibp.service import HIBP_NTLM_KIND
from hashcrush.models import (
    HashPublicExposure,
    Hashfiles,
    ReferenceDatasets,
    SchemaVersion,
    db,
)
from tests.integration.support import (
    _build_app,
    _login_client_as_user,
    _seed_admin_user,
    _seed_settings,
    _wait_for_upload_operation,
)


def _dataset_upload_payload():
    dataset_text = (
        "31D6CFE0D16AE931B73C59D7E0C089C0\n"
        "8846F7EAEE8FB117AD06BDD830B7586C\n"
    )
    return {
        "version_label": "HIBP NTLM April 2026",
        "dataset_file": (
            io.BytesIO(dataset_text.encode("utf-8")),
            "hibp-ntlm.txt",
        ),
    }


def _hashfile_upload_payload():
    return {
        "name": "Windows Pwdump Sample",
        "file_type": "pwdump",
        "pwdump_hash_type": "1000",
        "hashfile": (
            io.BytesIO(
                (
                    "DOMAIN.LOCAL\\alice:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::\n"
                    "DOMAIN.LOCAL\\bob:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
                    "DOMAIN.LOCAL\\carol:502:aad3b435b51404eeaad3b435b51404ee:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:::\n"
                ).encode("utf-8")
            ),
            "pwdump.txt",
        ),
    }


def test_admin_can_load_offline_hibp_dataset_and_scan_new_hashfile(tmp_path):
    app = _build_app(
        {
            "RUNTIME_PATH": str(tmp_path / "runtime"),
            "STORAGE_PATH": str(tmp_path / "storage"),
            "ENABLE_INLINE_UPLOAD_WORKER": True,
        }
    )

    with app.app_context():
        db.create_all()
        _seed_settings()
        admin = _seed_admin_user()
        client = app.test_client()
        _login_client_as_user(client, admin)

        dataset_response = client.post(
            "/settings/hibp_ntlm_dataset",
            data=_dataset_upload_payload(),
            content_type="multipart/form-data",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert dataset_response.status_code == 202
        dataset_payload = dataset_response.get_json()
        assert isinstance(dataset_payload, dict)
        dataset_status = _wait_for_upload_operation(client, dataset_payload["status_url"])
        assert dataset_status["success"] is True

        dataset_row = db.session.scalar(
            select(ReferenceDatasets).where(ReferenceDatasets.kind == HIBP_NTLM_KIND)
        )
        assert dataset_row is not None
        assert dataset_row.version_label == "HIBP NTLM April 2026"
        assert int(dataset_row.record_count) == 2
        assert dataset_row.path is not None

        with open(str(dataset_row.path), "r", encoding="utf-8") as handle:
            manifest_payload = json.load(handle)
        assert manifest_payload["format"] == "hibp_ntlm_lmdb"
        lmdb_path = str(manifest_payload["db_path"])
        assert os.path.isdir(lmdb_path)
        assert os.path.exists(os.path.join(lmdb_path, "data.mdb"))

        breach_response = client.get("/breach-intelligence")
        assert breach_response.status_code == 200
        assert b"Have I Been Pwned NTLM" in breach_response.data
        assert b"HIBP NTLM April 2026" in breach_response.data

        hashfile_response = client.post(
            "/hashfiles/add",
            data=_hashfile_upload_payload(),
            content_type="multipart/form-data",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert hashfile_response.status_code == 202
        hashfile_payload = hashfile_response.get_json()
        assert isinstance(hashfile_payload, dict)
        hashfile_status = _wait_for_upload_operation(client, hashfile_payload["status_url"])
        assert hashfile_status["success"] is True

        hashfile = db.session.scalar(
            select(Hashfiles).where(Hashfiles.name == "Windows Pwdump Sample")
        )
        assert hashfile is not None

        matched_exposures = db.session.execute(
            select(HashPublicExposure)
            .where(HashPublicExposure.source_kind == HIBP_NTLM_KIND)
            .where(HashPublicExposure.matched.is_(True))
        ).scalars().all()
        assert len(matched_exposures) == 2

        detail_response = client.get(f"/hashfiles/{hashfile.id}")
        assert detail_response.status_code == 200
        assert b"Publicly Exposed Hashes" in detail_response.data
        assert b"2/3" in detail_response.data

        analytics_response = client.get(f"/analytics?hashfile_id={hashfile.id}")
        assert analytics_response.status_code == 200
        assert b"Publicly Exposed Hashes" in analytics_response.data
        assert b"Accounts Using Publicly Exposed Hashes" in analytics_response.data
        assert b"HIBP NTLM April 2026" in analytics_response.data

        export_response = client.get(
            f"/analytics/download?type=public_exposures&hashfile_id={hashfile.id}"
        )
        assert export_response.status_code == 200
        export_body = export_response.data.decode("utf-8")
        assert "DOMAIN.LOCAL\\alice" in export_body
        assert "DOMAIN.LOCAL\\bob" in export_body
        assert ":45" not in export_body
        assert ":123" not in export_body


def test_loading_dataset_does_not_backfill_existing_hashes_until_requested(tmp_path):
    app = _build_app(
        {
            "RUNTIME_PATH": str(tmp_path / "runtime"),
            "STORAGE_PATH": str(tmp_path / "storage"),
            "ENABLE_INLINE_UPLOAD_WORKER": True,
        }
    )

    with app.app_context():
        db.create_all()
        _seed_settings()
        admin = _seed_admin_user()
        client = app.test_client()
        _login_client_as_user(client, admin)

        hashfile_response = client.post(
            "/hashfiles/add",
            data=_hashfile_upload_payload(),
            content_type="multipart/form-data",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert hashfile_response.status_code == 202
        hashfile_payload = hashfile_response.get_json()
        assert isinstance(hashfile_payload, dict)
        hashfile_status = _wait_for_upload_operation(client, hashfile_payload["status_url"])
        assert hashfile_status["success"] is True

        matched_exposures = db.session.execute(
            select(HashPublicExposure)
            .where(HashPublicExposure.source_kind == HIBP_NTLM_KIND)
            .where(HashPublicExposure.matched.is_(True))
        ).scalars().all()
        assert len(matched_exposures) == 0

        dataset_response = client.post(
            "/settings/hibp_ntlm_dataset",
            data=_dataset_upload_payload(),
            content_type="multipart/form-data",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert dataset_response.status_code == 202
        dataset_payload = dataset_response.get_json()
        assert isinstance(dataset_payload, dict)
        dataset_status = _wait_for_upload_operation(client, dataset_payload["status_url"])
        assert dataset_status["success"] is True

        matched_exposures = db.session.execute(
            select(HashPublicExposure)
            .where(HashPublicExposure.source_kind == HIBP_NTLM_KIND)
            .where(HashPublicExposure.matched.is_(True))
        ).scalars().all()
        assert len(matched_exposures) == 0

        breach_response = client.get("/breach-intelligence")
        assert breach_response.status_code == 200
        assert b"Refresh Existing Hashes" in breach_response.data

        backfill_response = client.post(
            "/settings/hibp_ntlm_dataset/backfill",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert backfill_response.status_code == 202
        backfill_payload = backfill_response.get_json()
        assert isinstance(backfill_payload, dict)
        backfill_status = _wait_for_upload_operation(
            client, backfill_payload["status_url"]
        )
        assert backfill_status["success"] is True

        matched_exposures = db.session.execute(
            select(HashPublicExposure)
            .where(HashPublicExposure.source_kind == HIBP_NTLM_KIND)
            .where(HashPublicExposure.matched.is_(True))
        ).scalars().all()
        assert len(matched_exposures) == 2


def test_settings_lists_mounted_hibp_dataset_files(tmp_path):
    mounted_root = tmp_path / "mounted-hibp"
    nested_root = mounted_root / "nested"
    nested_root.mkdir(parents=True, exist_ok=True)
    (mounted_root / "hibp-ntlm.txt").write_text(
        "31D6CFE0D16AE931B73C59D7E0C089C0\n",
        encoding="utf-8",
    )
    (mounted_root / "hibp-ntlm-10.txt").write_text(
        "8846F7EAEE8FB117AD06BDD830B7586C\n",
        encoding="utf-8",
    )
    (nested_root / "hibp-ntlm-2.txt").write_text(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
        encoding="utf-8",
    )

    app = _build_app(
        {
            "HIBP_DATASETS_PATH": str(mounted_root),
        }
    )

    with app.app_context():
        db.create_all()
        _seed_settings()
        admin = _seed_admin_user()
        client = app.test_client()
        _login_client_as_user(client, admin)

        initial_response = client.get("/breach-intelligence")
        assert initial_response.status_code == 200
        assert b"No cached readable files were found under" in initial_response.data
        assert b'href="/settings#nav-data"' in initial_response.data
        assert b"<select id=\"mounted_dataset_path\"" not in initial_response.data

        rescan_response = client.post("/settings/rescan-mounted-folders")
        assert rescan_response.status_code == 302

        response = client.get("/breach-intelligence")
        assert response.status_code == 200
        body = response.data.decode("utf-8")
        assert 'value="' + str((mounted_root / "hibp-ntlm.txt").resolve()) + '"' in body
        assert 'value="' + str((mounted_root / "hibp-ntlm-10.txt").resolve()) + '"' in body
        assert 'value="' + str((nested_root / "hibp-ntlm-2.txt").resolve()) + '"' in body
        assert (
            'value="'
            + str((mounted_root / "hibp-ntlm.txt").resolve())
            + '" selected'
        ) in body
        assert "Cached list refreshed at" in body
        assert "Choose a mounted HIBP dataset file" not in body


def test_admin_can_load_offline_hibp_dataset_from_mounted_path(tmp_path):
    mounted_root = tmp_path / "mounted-hibp"
    mounted_root.mkdir(parents=True, exist_ok=True)
    dataset_path = mounted_root / "hibp-ntlm.txt"
    dataset_path.write_text(
        "31D6CFE0D16AE931B73C59D7E0C089C0\n"
        "8846F7EAEE8FB117AD06BDD830B7586C\n",
        encoding="utf-8",
    )

    app = _build_app(
        {
            "RUNTIME_PATH": str(tmp_path / "runtime"),
            "STORAGE_PATH": str(tmp_path / "storage"),
            "ENABLE_INLINE_UPLOAD_WORKER": True,
            "HIBP_DATASETS_PATH": str(mounted_root),
        }
    )

    with app.app_context():
        db.create_all()
        _seed_settings()
        admin = _seed_admin_user()
        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            "/settings/hibp_ntlm_dataset/mounted",
            data={
                "version_label": "Mounted HIBP NTLM April 2026",
                "mounted_dataset_path": str(dataset_path),
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 202
        payload = response.get_json()
        assert isinstance(payload, dict)
        status = _wait_for_upload_operation(client, payload["status_url"])
        assert status["success"] is True

        dataset_row = db.session.scalar(
            select(ReferenceDatasets).where(ReferenceDatasets.kind == HIBP_NTLM_KIND)
        )
        assert dataset_row is not None
        assert dataset_row.version_label == "Mounted HIBP NTLM April 2026"
        assert int(dataset_row.record_count) == 2
        assert dataset_row.path is not None

        with open(str(dataset_row.path), "r", encoding="utf-8") as handle:
            manifest_payload = json.load(handle)
        assert manifest_payload["format"] == "hibp_ntlm_lmdb"
        lmdb_path = str(manifest_payload["db_path"])
        assert os.path.isdir(lmdb_path)
        assert os.path.exists(os.path.join(lmdb_path, "data.mdb"))

        breach_response = client.get("/breach-intelligence")
        assert breach_response.status_code == 200
        assert str(mounted_root).encode("utf-8") in breach_response.data

        hashfile_response = client.post(
            "/hashfiles/add",
            data=_hashfile_upload_payload(),
            content_type="multipart/form-data",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert hashfile_response.status_code == 202
        hashfile_payload = hashfile_response.get_json()
        assert isinstance(hashfile_payload, dict)
        hashfile_status = _wait_for_upload_operation(client, hashfile_payload["status_url"])
        assert hashfile_status["success"] is True

        matched_exposures = db.session.execute(
            select(HashPublicExposure)
            .where(HashPublicExposure.source_kind == HIBP_NTLM_KIND)
            .where(HashPublicExposure.matched.is_(True))
        ).scalars().all()
        assert len(matched_exposures) == 2


def test_admin_cannot_load_mounted_hibp_dataset_outside_configured_root(tmp_path):
    mounted_root = tmp_path / "mounted-hibp"
    mounted_root.mkdir(parents=True, exist_ok=True)
    outside_path = tmp_path / "outside" / "hibp-ntlm.txt"
    outside_path.parent.mkdir(parents=True, exist_ok=True)
    outside_path.write_text(
        "31D6CFE0D16AE931B73C59D7E0C089C0\n",
        encoding="utf-8",
    )

    app = _build_app(
        {
            "RUNTIME_PATH": str(tmp_path / "runtime"),
            "STORAGE_PATH": str(tmp_path / "storage"),
            "ENABLE_INLINE_UPLOAD_WORKER": True,
            "HIBP_DATASETS_PATH": str(mounted_root),
        }
    )

    with app.app_context():
        db.create_all()
        _seed_settings()
        admin = _seed_admin_user()
        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            "/settings/hibp_ntlm_dataset/mounted",
            data={"mounted_dataset_path": str(outside_path)},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert response.status_code == 400
        payload = response.get_json()
        assert isinstance(payload, dict)
        assert str(mounted_root) in str(payload.get("detail") or "")


def test_upgrade_database_adds_reference_dataset_tables():
    app = _build_app()

    with app.app_context():
        db.create_all()
        schema_version = db.session.get(SchemaVersion, 1)
        if schema_version is None:
            schema_version = SchemaVersion(id=1, version=10, app_version="test")
            db.session.add(schema_version)
        schema_version.version = 10
        db.session.commit()

        HashPublicExposure.__table__.drop(bind=db.engine, checkfirst=True)
        ReferenceDatasets.__table__.drop(bind=db.engine, checkfirst=True)

        result = upgrade_database()

        assert result.target_version == CURRENT_SCHEMA_VERSION
        inspector = inspect(db.engine)
        assert inspector.has_table("reference_datasets")
        assert inspector.has_table("hash_public_exposures")
