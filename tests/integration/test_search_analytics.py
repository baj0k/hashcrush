"""Integration tests for search and analytics flows."""
# ruff: noqa: F403,F405
from tests.integration.support import *


@pytest.mark.security
def test_analytics_download_rejects_invalid_domain_id_and_uses_hashfile_id_in_filename():
    app = _build_app()
    with app.app_context():
        db.create_all()
        user = _seed_admin_user()
        _seed_settings()
        domain = Domains(name="ACME")
        db.session.add(domain)
        db.session.commit()
        hashfile = Hashfiles(name="sample.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, user)

        invalid = client.get(
            "/analytics/download?type=found&domain_id=../../etc/passwd"
        )
        assert invalid.status_code == 302
        assert invalid.headers["Location"].endswith("/analytics")

        valid = client.get(
            f"/analytics/download?type=found&domain_id={domain.id}&hashfile_id={hashfile.id}"
        )
        assert valid.status_code == 200
        content_disposition = valid.headers.get("Content-Disposition", "")
        assert f"found_{domain.id}_{hashfile.id}.txt" in content_disposition

@pytest.mark.security
def test_analytics_download_normalizes_export_type_query_param():
    app = _build_app()
    with app.app_context():
        db.create_all()
        user = _seed_admin_user()
        _seed_settings()
        domain = Domains(name="ACME-Normalized")
        db.session.add(domain)
        db.session.commit()
        hashfile = Hashfiles(name="normalized.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, user)

        response = client.get(f"/analytics/download?type= Found &domain_id={domain.id}")
        assert response.status_code == 200
        content_disposition = response.headers.get("Content-Disposition", "")
        assert f"found_{domain.id}_all.txt" in content_disposition

@pytest.mark.security
def test_analytics_page_is_global_but_downloads_require_admin():
    app = _build_app()
    with app.app_context():
        db.create_all()
        owner = _seed_user(
            "analytics-owner", password="owner-user-password", admin=False
        )
        _seed_user("analytics-other", password="other-user-password", admin=False)
        _seed_settings()

        domain = Domains(name="SharedDomain")
        db.session.add(domain)
        db.session.commit()

        owner_hashfile = Hashfiles(name="owner.txt", domain_id=domain.id)
        other_hashfile = Hashfiles(name="other.txt", domain_id=domain.id)
        db.session.add_all([owner_hashfile, other_hashfile])
        db.session.commit()

        owner_hash = Hashes(
            sub_ciphertext="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ciphertext="owner-ciphertext",
            hash_type=1000,
            cracked=True,
            plaintext=encode_plaintext_for_storage("owner-password"),
        )
        other_hash = Hashes(
            sub_ciphertext="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ciphertext="other-ciphertext",
            hash_type=1000,
            cracked=True,
            plaintext=encode_plaintext_for_storage("other-password"),
        )
        db.session.add_all([owner_hash, other_hash])
        db.session.commit()

        db.session.add(
            HashfileHashes(hash_id=owner_hash.id, hashfile_id=owner_hashfile.id)
        )
        db.session.add(
            HashfileHashes(hash_id=other_hash.id, hashfile_id=other_hashfile.id)
        )
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, owner)

        analytics_response = client.get(f"/analytics?domain_id={domain.id}")
        assert analytics_response.status_code == 200
        analytics_html = analytics_response.get_data(as_text=True)
        assert "General Stats" in analytics_html
        assert "Total Accounts:" in analytics_html
        assert "Download Charts" not in analytics_html
        assert "/analytics/download?type=found" not in analytics_html
        assert "/analytics/download?type=left" not in analytics_html

        download_response = client.get("/analytics/download?type=found")
        assert download_response.status_code == 302
        assert download_response.headers["Location"].endswith("/analytics")

@pytest.mark.security
def test_search_hash_post_is_trimmed_and_case_insensitive():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="SearchDomain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="search-hashes.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        hash_row = Hashes(
            sub_ciphertext="eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            ciphertext="ABCDEF0123456789",
            hash_type=1000,
            cracked=False,
            plaintext=None,
        )
        db.session.add(hash_row)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=hash_row.id, hashfile_id=hashfile.id))
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            "/search",
            data={
                "search_type": "hash",
                "query": "  abcdef0123456789  ",
            },
        )
        assert response.status_code == 200
        assert b"ABCDEF0123456789" in response.data

@pytest.mark.security
def test_search_password_post_matches_canonical_and_legacy_plaintext_rows():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="SearchPasswordDomain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="search-passwords.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        canonical_hash = Hashes(
            sub_ciphertext="f" * 32,
            ciphertext="canonical-ciphertext",
            hash_type=1000,
            cracked=True,
            plaintext=encode_plaintext_for_storage("CanonicalPass1!"),
        )
        legacy_hash = Hashes(
            sub_ciphertext="1" * 32,
            ciphertext="legacy-ciphertext",
            hash_type=1000,
            cracked=True,
            plaintext="LegacyPass1!",
        )
        db.session.add_all([canonical_hash, legacy_hash])
        db.session.commit()
        db.session.add(
            HashfileHashes(hash_id=canonical_hash.id, hashfile_id=hashfile.id)
        )
        db.session.add(HashfileHashes(hash_id=legacy_hash.id, hashfile_id=hashfile.id))
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        canonical_response = client.post(
            "/search",
            data={
                "search_type": "password",
                "query": "CanonicalPass1!",
            },
        )
        assert canonical_response.status_code == 200
        assert b"canonical-ciphertext" in canonical_response.data

        legacy_response = client.post(
            "/search",
            data={
                "search_type": "password",
                "query": "LegacyPass1!",
            },
        )
        assert legacy_response.status_code == 200
        assert b"legacy-ciphertext" in legacy_response.data

@pytest.mark.security
def test_search_post_rejects_whitespace_only_query():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="SearchWhitespaceDomain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="search-whitespace.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        hash_row = Hashes(
            sub_ciphertext="a" * 32,
            ciphertext="SHOULD-NOT-MATCH",
            hash_type=1000,
            cracked=False,
            plaintext=None,
        )
        db.session.add(hash_row)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=hash_row.id, hashfile_id=hashfile.id))
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            "/search",
            data={
                "search_type": "hash",
                "query": "   ",
            },
        )
        assert response.status_code == 200
        assert b"No results found" in response.data
        assert b"SHOULD-NOT-MATCH" not in response.data

@pytest.mark.security
def test_search_hash_id_lookup_is_global_for_shared_hashfiles():
    app = _build_app()
    with app.app_context():
        db.create_all()
        owner = _seed_user("search-owner", password="owner-user-password", admin=False)
        _seed_user("search-other", password="other-user-password", admin=False)
        _seed_settings()

        domain = Domains(name="SharedDomain")
        db.session.add(domain)
        db.session.commit()

        owner_hashfile = Hashfiles(name="owner.txt", domain_id=domain.id)
        other_hashfile = Hashfiles(name="other.txt", domain_id=domain.id)
        db.session.add_all([owner_hashfile, other_hashfile])
        db.session.commit()

        owner_hash = Hashes(
            sub_ciphertext="cccccccccccccccccccccccccccccccc",
            ciphertext="owner-search-ciphertext",
            hash_type=1000,
            cracked=False,
            plaintext=None,
        )
        other_hash = Hashes(
            sub_ciphertext="dddddddddddddddddddddddddddddddd",
            ciphertext="other-search-ciphertext",
            hash_type=1000,
            cracked=False,
            plaintext=None,
        )
        db.session.add_all([owner_hash, other_hash])
        db.session.commit()

        db.session.add(
            HashfileHashes(hash_id=owner_hash.id, hashfile_id=owner_hashfile.id)
        )
        db.session.add(
            HashfileHashes(hash_id=other_hash.id, hashfile_id=other_hashfile.id)
        )
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, owner)

        response = client.get(f"/search?hash_id={other_hash.id}")
        assert response.status_code == 200
        assert b"other-search-ciphertext" in response.data

@pytest.mark.security
def test_search_hash_id_lookup_rejects_invalid_query_value():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.get("/search?hash_id=../../etc/passwd")
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/search")

@pytest.mark.security
def test_search_hash_id_lookup_accepts_trimmed_numeric_value():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="TrimmedHashIdDomain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="trimmed-hash-id.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        hash_row = Hashes(
            sub_ciphertext="e" * 32,
            ciphertext="trimmed-hash-id-ciphertext",
            hash_type=1000,
            cracked=False,
            plaintext=None,
        )
        db.session.add(hash_row)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=hash_row.id, hashfile_id=hashfile.id))
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.get(f"/search?hash_id=%20{hash_row.id}%20")
        assert response.status_code == 200
        assert b"trimmed-hash-id-ciphertext" in response.data

@pytest.mark.security
def test_search_page_hides_export_controls_for_non_admin():
    app = _build_app()
    with app.app_context():
        db.create_all()
        user = _seed_user("search-viewer", password="viewer-password", admin=False)
        _seed_settings()

        domain = Domains(name="SearchExportDomain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="search-export.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        hash_row = Hashes(
            sub_ciphertext="f" * 32,
            ciphertext="search-export-ciphertext",
            hash_type=1000,
            cracked=True,
            plaintext=encode_plaintext_for_storage("ExportMe123!"),
        )
        db.session.add(hash_row)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=hash_row.id, hashfile_id=hashfile.id))
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, user)

        response = client.post(
            "/search",
            data={
                "search_type": "hash",
                "query": "search-export-ciphertext",
            },
        )
        html = response.get_data(as_text=True)
        assert response.status_code == 200
        assert "search-export-ciphertext" in html
        assert 'value="Export"' not in html
        assert "Search exports are restricted to admin accounts." in html

@pytest.mark.security
def test_search_export_requires_admin():
    app = _build_app()
    with app.app_context():
        db.create_all()
        user = _seed_user("search-exporter", password="viewer-password", admin=False)
        _seed_settings()

        domain = Domains(name="SearchExportDeniedDomain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="search-export-denied.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        hash_row = Hashes(
            sub_ciphertext="1" * 32,
            ciphertext="search-export-denied-ciphertext",
            hash_type=1000,
            cracked=True,
            plaintext=encode_plaintext_for_storage("DeniedExport123!"),
        )
        db.session.add(hash_row)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=hash_row.id, hashfile_id=hashfile.id))
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, user)

        response = client.post(
            "/search",
            data={
                "search_type": "hash",
                "query": "search-export-denied-ciphertext",
                "export": "Export",
                "export_type": "Comma",
            },
        )
        assert response.status_code == 200
        assert b"Permission Denied" in response.data
        assert b"search-export-denied-ciphertext" in response.data
        assert response.headers.get("Content-Disposition") is None

@pytest.mark.security
def test_search_export_still_works_for_admin():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="SearchExportAdminDomain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="search-export-admin.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        hash_row = Hashes(
            sub_ciphertext="2" * 32,
            ciphertext="search-export-admin-ciphertext",
            hash_type=1000,
            cracked=True,
            plaintext=encode_plaintext_for_storage("AdminExport123!"),
        )
        db.session.add(hash_row)
        db.session.commit()
        db.session.add(HashfileHashes(hash_id=hash_row.id, hashfile_id=hashfile.id))
        db.session.commit()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.post(
            "/search",
            data={
                "search_type": "hash",
                "query": "search-export-admin-ciphertext",
                "export": "Export",
                "export_type": "Comma",
            },
        )
        assert response.status_code == 200
        assert response.headers["Content-Disposition"].startswith(
            'attachment; filename=search.txt'
        )
        assert b"search-export-admin-ciphertext" in response.data
