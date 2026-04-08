"""Integration tests for search and analytics flows."""
# ruff: noqa: F403,F405
from datetime import UTC, datetime

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
        hash_row = _seed_hash("sample-ciphertext", cracked=False)
        _seed_hashfile_hash(hash_id=hash_row.id, hashfile_id=hashfile.id, username="ACME\\sample")

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
        expected_date = datetime.now(UTC).date().isoformat()
        assert (
            f"recovered_accounts_domain_{domain.id}_hashfile_{hashfile.id}_{expected_date}.txt"
            in content_disposition
        )

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
        hash_row = _seed_hash("normalized-ciphertext", cracked=False)
        _seed_hashfile_hash(hash_id=hash_row.id, hashfile_id=hashfile.id, username="ACME-Normalized\\sample")

        client = app.test_client()
        _login_client_as_user(client, user)

        response = client.get(f"/analytics/download?type= Found &domain_id={domain.id}")
        assert response.status_code == 200
        content_disposition = response.headers.get("Content-Disposition", "")
        expected_date = datetime.now(UTC).date().isoformat()
        assert (
            f"recovered_accounts_domain_{domain.id}_{expected_date}.txt"
            in content_disposition
        )

@pytest.mark.security
def test_analytics_download_found_includes_decoded_plaintext_and_username():
    app = _build_app()
    with app.app_context():
        db.create_all()
        user = _seed_admin_user()
        _seed_settings()
        domain = Domains(name="AnalyticsExportDomain")
        db.session.add(domain)
        db.session.commit()
        hashfile = Hashfiles(name="export.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        hash_row = _seed_hash(
            "analytics-export-ciphertext",
            cracked=True,
            plaintext="$HEX[506173733a313233]",
        )
        _seed_hashfile_hash(
            hash_id=hash_row.id,
            hashfile_id=hashfile.id,
            username="ACME\\Administrator",
        )

        client = app.test_client()
        _login_client_as_user(client, user)

        response = client.get(
            f"/analytics/download?type=found&domain_id={domain.id}&hashfile_id={hashfile.id}"
        )
        assert response.status_code == 200
        assert response.get_data(as_text=True) == (
            "ACME\\Administrator:analytics-export-ciphertext:Pass:123\n"
        )


@pytest.mark.security
def test_analytics_download_found_decodes_stored_plain_hex_plaintext():
    app = _build_app()
    with app.app_context():
        db.create_all()
        user = _seed_admin_user()
        _seed_settings()
        domain = Domains(name="AnalyticsPlainHexExportDomain")
        db.session.add(domain)
        db.session.commit()
        hashfile = Hashfiles(name="plainhex-export.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        hash_row = _seed_hash(
            "analytics-plainhex-ciphertext",
            cracked=True,
            plaintext="506173733a313233",
        )
        _seed_hashfile_hash(
            hash_id=hash_row.id,
            hashfile_id=hashfile.id,
            username="domain.test\\BAJOK",
        )

        client = app.test_client()
        _login_client_as_user(client, user)

        response = client.get(
            f"/analytics/download?type=found&domain_id={domain.id}&hashfile_id={hashfile.id}"
        )
        assert response.status_code == 200
        assert response.get_data(as_text=True) == (
            "domain.test\\BAJOK:analytics-plainhex-ciphertext:Pass:123\n"
        )


@pytest.mark.security
def test_analytics_download_reused_hash_accounts_includes_all_matching_rows():
    app = _build_app()
    with app.app_context():
        db.create_all()
        user = _seed_admin_user()
        _seed_settings()
        domain = Domains(name="AnalyticsReusedHashesDomain")
        db.session.add(domain)
        db.session.commit()
        hashfile = Hashfiles(name="reused-hashes.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        reused_hash = _seed_hash("shared-ciphertext", cracked=False)
        unique_hash = _seed_hash("unique-ciphertext", cracked=False)
        _seed_hashfile_hash(hash_id=reused_hash.id, hashfile_id=hashfile.id, username="alice")
        _seed_hashfile_hash(hash_id=reused_hash.id, hashfile_id=hashfile.id, username="bob")
        _seed_hashfile_hash(hash_id=unique_hash.id, hashfile_id=hashfile.id, username="charlie")

        client = app.test_client()
        _login_client_as_user(client, user)

        response = client.get(
            f"/analytics/download?type=reused_hashes&domain_id={domain.id}&hashfile_id={hashfile.id}"
        )
        assert response.status_code == 200
        assert response.get_data(as_text=True) == (
            "alice:shared-ciphertext\n"
            "bob:shared-ciphertext\n"
        )
        expected_date = datetime.now(UTC).date().isoformat()
        assert (
            f"reused_hash_accounts_domain_{domain.id}_hashfile_{hashfile.id}_{expected_date}.txt"
            in response.headers.get("Content-Disposition", "")
        )


@pytest.mark.security
def test_analytics_download_reused_password_accounts_includes_decoded_plaintext():
    app = _build_app()
    with app.app_context():
        db.create_all()
        user = _seed_admin_user()
        _seed_settings()
        domain = Domains(name="AnalyticsReusedPasswordsDomain")
        db.session.add(domain)
        db.session.commit()
        hashfile = Hashfiles(name="reused-passwords.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        first_hash = _seed_hash("shared-password-one", cracked=True, plaintext="SharedPass123!")
        second_hash = _seed_hash("shared-password-two", cracked=True, plaintext="SharedPass123!")
        unique_hash = _seed_hash("unique-password", cracked=True, plaintext="UniquePass123!")
        _seed_hashfile_hash(hash_id=first_hash.id, hashfile_id=hashfile.id, username="alice")
        _seed_hashfile_hash(hash_id=second_hash.id, hashfile_id=hashfile.id, username="bob")
        _seed_hashfile_hash(hash_id=unique_hash.id, hashfile_id=hashfile.id, username="charlie")

        client = app.test_client()
        _login_client_as_user(client, user)

        response = client.get(
            f"/analytics/download?type=reused_passwords&domain_id={domain.id}&hashfile_id={hashfile.id}"
        )
        assert response.status_code == 200
        assert response.get_data(as_text=True) == (
            "alice:shared-password-one:SharedPass123!\n"
            "bob:shared-password-two:SharedPass123!\n"
        )
        expected_date = datetime.now(UTC).date().isoformat()
        assert (
            f"reused_password_accounts_domain_{domain.id}_hashfile_{hashfile.id}_{expected_date}.txt"
            in response.headers.get("Content-Disposition", "")
        )


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

        owner_hash = _seed_hash("owner-ciphertext", cracked=True, plaintext="owner-password")
        other_hash = _seed_hash("other-ciphertext", cracked=True, plaintext="other-password")

        _seed_hashfile_hash(hash_id=owner_hash.id, hashfile_id=owner_hashfile.id)
        _seed_hashfile_hash(hash_id=other_hash.id, hashfile_id=other_hashfile.id)

        client = app.test_client()
        _login_client_as_user(client, owner)

        analytics_response = client.get(f"/analytics?domain_id={domain.id}")
        assert analytics_response.status_code == 200
        analytics_html = analytics_response.get_data(as_text=True)
        assert "Scope Stats" in analytics_html
        assert "Total Accounts" in analytics_html
        assert "Domain Posture Comparison" in analytics_html
        assert "Sensitive recovered-password detail is limited to admin accounts." in analytics_html
        assert "Most Reused Recovered Passwords" not in analytics_html
        assert "Download Charts" not in analytics_html
        assert "/analytics/download?type=found" not in analytics_html
        assert "/analytics/download?type=left" not in analytics_html
        assert "/analytics/download?type=reused_hashes" not in analytics_html
        assert "/analytics/download?type=reused_passwords" not in analytics_html

        download_response = client.get("/analytics/download?type=found")
        assert download_response.status_code == 302
        assert download_response.headers["Location"].endswith("/analytics")


@pytest.mark.security
def test_analytics_admin_view_shows_reuse_table_and_password_quality_chart():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="AnalyticsAdminDetailDomain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="analytics-admin-detail.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        reused_one = _seed_hash("reuse-one", cracked=True, plaintext="SharedPass123!")
        reused_two = _seed_hash("reuse-two", cracked=True, plaintext="SharedPass123!")
        unique = _seed_hash("unique", cracked=True, plaintext="UniquePass123!")
        _seed_hashfile_hash(hash_id=reused_one.id, hashfile_id=hashfile.id, username="alice")
        _seed_hashfile_hash(hash_id=reused_two.id, hashfile_id=hashfile.id, username="bob")
        _seed_hashfile_hash(hash_id=unique.id, hashfile_id=hashfile.id, username="charlie")

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.get(f"/analytics?domain_id={domain.id}&hashfile_id={hashfile.id}")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Recovered Password Quality" in html
        assert "Hash Reuse" in html
        assert "Password Reuse" in html
        assert "Most Reused Recovered Passwords" in html
        assert "SharedPass123!" in html
        assert "Accounts Where Password Matches Username" in html


@pytest.mark.security
def test_analytics_scope_stats_show_non_unique_hash_metrics():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="AnalyticsHashReuseDomain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="analytics-hash-reuse.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        reused_hash = _seed_hash("shared-hash-value", cracked=False)
        unique_hash = _seed_hash("unique-hash-value", cracked=False)
        _seed_hashfile_hash(hash_id=reused_hash.id, hashfile_id=hashfile.id, username="alice")
        _seed_hashfile_hash(hash_id=reused_hash.id, hashfile_id=hashfile.id, username="bob")
        _seed_hashfile_hash(hash_id=unique_hash.id, hashfile_id=hashfile.id, username="charlie")

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.get(f"/analytics?domain_id={domain.id}&hashfile_id={hashfile.id}")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Non-Unique Hash Values" in html
        assert "1 (50%)" in html
        assert "Account Rows Sharing a Hash" in html
        assert "2 (66.7%)" in html

@pytest.mark.security
def test_analytics_page_renders_upperalphanumeric_and_mixed_categories():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        domain = Domains(name="AnalyticsCategoryDomain")
        db.session.add(domain)
        db.session.commit()

        hashfile = Hashfiles(name="analytics-category.txt", domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        upper_alphanumeric = _seed_hash("upper-alpha-num", cracked=True, plaintext="UPPER123")
        mixed_special = _seed_hash("mixed-special", cracked=True, plaintext="Pass123!")
        _seed_hashfile_hash(hash_id=upper_alphanumeric.id, hashfile_id=hashfile.id)
        _seed_hashfile_hash(hash_id=mixed_special.id, hashfile_id=hashfile.id)

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.get(
            f"/analytics?domain_id={domain.id}&hashfile_id={hashfile.id}"
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "UpperAlphaNumeric: 1" in html
        assert "MixedAlphaSpecialNumeric: 1" in html


@pytest.mark.security
def test_analytics_page_uses_local_chart_renderer_assets():
    app = _build_app()
    with app.app_context():
        db.create_all()
        admin = _seed_admin_user()
        _seed_settings()

        client = app.test_client()
        _login_client_as_user(client, admin)

        response = client.get("/analytics")
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "/static/analytics.js" in html
        assert 'id="analytics-chart-data"' in html
        assert "cdn.jsdelivr.net/npm/chart.js" not in html

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

        hash_row = _seed_hash("ABCDEF0123456789", cracked=False)
        _seed_hashfile_hash(hash_id=hash_row.id, hashfile_id=hashfile.id)

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

        canonical_hash = _seed_hash(
            "canonical-ciphertext",
            cracked=True,
            plaintext="CanonicalPass1!",
        )
        legacy_hash = Hashes(
            sub_ciphertext="1" * 32,
            ciphertext="legacy-ciphertext",
            hash_type=1000,
            cracked=True,
            plaintext="LegacyPass1!",
        )
        db.session.add(legacy_hash)
        db.session.commit()
        _seed_hashfile_hash(hash_id=canonical_hash.id, hashfile_id=hashfile.id)
        _seed_hashfile_hash(hash_id=legacy_hash.id, hashfile_id=hashfile.id)

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

        hash_row = _seed_hash("SHOULD-NOT-MATCH", cracked=False)
        _seed_hashfile_hash(hash_id=hash_row.id, hashfile_id=hashfile.id)

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

        owner_hash = _seed_hash("owner-search-ciphertext", cracked=False)
        other_hash = _seed_hash("other-search-ciphertext", cracked=False)

        _seed_hashfile_hash(hash_id=owner_hash.id, hashfile_id=owner_hashfile.id)
        _seed_hashfile_hash(hash_id=other_hash.id, hashfile_id=other_hashfile.id)

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

        hash_row = _seed_hash("trimmed-hash-id-ciphertext", cracked=False)
        _seed_hashfile_hash(hash_id=hash_row.id, hashfile_id=hashfile.id)

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

        hash_row = _seed_hash(
            "search-export-ciphertext",
            cracked=True,
            plaintext="ExportMe123!",
        )
        _seed_hashfile_hash(hash_id=hash_row.id, hashfile_id=hashfile.id)

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

        hash_row = _seed_hash(
            "search-export-denied-ciphertext",
            cracked=True,
            plaintext="DeniedExport123!",
        )
        _seed_hashfile_hash(hash_id=hash_row.id, hashfile_id=hashfile.id)

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

        hash_row = _seed_hash(
            "search-export-admin-ciphertext",
            cracked=True,
            plaintext="AdminExport123!",
        )
        _seed_hashfile_hash(hash_id=hash_row.id, hashfile_id=hashfile.id)

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
