import re
import uuid
from pathlib import Path

import pytest
from playwright.sync_api import expect

from tests.e2e.support import select_domain, unique_name


@pytest.mark.e2e
def test_job_name_required_validation(page, live_server, login, e2e_fixture_data):
    login()
    page.get_by_role("link", name="Jobs").click()
    page.get_by_role("link", name="Create a New Job").click()
    expect(page.get_by_role("heading", name="Create a new Job")).to_be_visible()

    select_domain(page, e2e_fixture_data["domain_id"])
    page.get_by_role("button", name="Next").click()
    expect(page.get_by_role("heading", name="Create a new Job")).to_be_visible()


@pytest.mark.e2e
def test_job_name_xss_is_escaped(page, live_server, login, e2e_fixture_data):
    login()
    page.get_by_role("link", name="Jobs").click()
    page.get_by_role("link", name="Create a New Job").click()
    expect(page.get_by_role("heading", name="Create a new Job")).to_be_visible()

    xss_token = uuid.uuid4().hex[:6]
    xss_payload = f'<script id="x{xss_token}">1</script>'
    assert len(xss_payload) <= 50
    page.get_by_label("Job Name").fill(xss_payload)
    if page.locator("#priority").count() > 0:
        page.locator("#priority").select_option("3")
    select_domain(page, e2e_fixture_data["domain_id"])
    page.get_by_role("button", name="Next").click()
    expect(
        page.get_by_role("heading", name=re.compile(r"Assign Hashes for"))
    ).to_be_visible()

    page.goto(f"{live_server}/jobs", wait_until="domcontentloaded")
    assert page.locator(f"script#x{xss_token}").count() == 0
    expect(page.get_by_text(xss_payload, exact=True)).to_be_visible()


@pytest.mark.e2e
def test_hashfile_validation_rejects_invalid_hash(page, live_server, login, e2e_fixture_data):
    login()
    page.get_by_role("link", name="Jobs").click()
    page.get_by_role("link", name="Create a New Job").click()
    expect(page.get_by_role("heading", name="Create a new Job")).to_be_visible()

    page.get_by_label("Job Name").fill(unique_name("E2E Invalid Hash Test"))
    select_domain(page, e2e_fixture_data["domain_id"])
    page.get_by_role("button", name="Next").click()
    expect(
        page.get_by_role("heading", name=re.compile(r"Assign Hashes for"))
    ).to_be_visible()

    page.locator("select[name='file_type']").select_option("hash_only")
    page.locator("select[name='hash_type']").select_option("0")
    page.locator("textarea[name='hashfilehashes']").fill("short")
    page.get_by_role("button", name="Next").click()
    expect(page).to_have_url(re.compile(r".*/assigned_hashfile/"))
    if page.locator(".alert-danger").count() > 0:
        expect(page.locator(".alert-danger")).to_be_visible()


@pytest.mark.e2e
def test_hashfile_upload_example_file(page, live_server, login, e2e_fixture_data):
    login()
    page.get_by_role("link", name="Jobs").click()
    page.get_by_role("link", name="Create a New Job").click()
    expect(page.get_by_role("heading", name="Create a new Job")).to_be_visible()

    page.get_by_label("Job Name").fill(unique_name("E2E Upload Example Hashfile"))
    select_domain(page, e2e_fixture_data["domain_id"])
    page.get_by_role("button", name="Next").click()
    expect(
        page.get_by_role("heading", name=re.compile(r"Assign Hashes for"))
    ).to_be_visible()

    page.locator("select[name='file_type']").select_option("hash_only")
    page.locator("select[name='hash_type']").select_option("0")
    page.locator("#pills-profile-tab").click()
    example_path = Path(__file__).parent / "example_hashes.txt"
    page.set_input_files("input[name='hashfile']", str(example_path))
    page.get_by_role("button", name="Next").click()
    expect(page).to_have_url(re.compile(r".*/assigned_hashfile/\d+"))


@pytest.mark.e2e
def test_hashfile_upload_example_pwdump(page, live_server, login, e2e_fixture_data):
    login()
    page.get_by_role("link", name="Jobs").click()
    page.get_by_role("link", name="Create a New Job").click()
    expect(page.get_by_role("heading", name="Create a new Job")).to_be_visible()

    page.get_by_label("Job Name").fill(unique_name("E2E Upload Example Pwdump"))
    select_domain(page, e2e_fixture_data["domain_id"])
    page.get_by_role("button", name="Next").click()
    expect(
        page.get_by_role("heading", name=re.compile(r"Assign Hashes for"))
    ).to_be_visible()

    page.locator("select[name='file_type']").select_option("pwdump")
    page.locator("select[name='pwdump_hash_type']").select_option("1000")
    page.locator("#pills-profile-tab").click()
    example_path = Path(__file__).parent / "example_pwdump.txt"
    page.set_input_files("input[name='hashfile']", str(example_path))
    page.get_by_role("button", name="Next").click()
    expect(page).to_have_url(re.compile(r".*/assigned_hashfile/\d+"))
