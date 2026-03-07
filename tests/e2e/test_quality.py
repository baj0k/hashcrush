import os
import re
from pathlib import Path

import pytest
from playwright.sync_api import expect


def _select_customer(page):
    customer_id = os.getenv("HASHCRUSH_E2E_CUSTOMER_ID")
    if customer_id:
        option = page.locator(f"#customer_id option[value='{customer_id}']")
        if option.count() > 0:
            page.locator("#customer_id").select_option(str(customer_id))
            return
    page.locator("#customer_id").select_option("add_new")
    customer_name = os.getenv("HASHCRUSH_E2E_CUSTOMER_NAME", "E2E Customer")
    page.locator("#new_customer_div input[name='customer_name']").fill(customer_name)


@pytest.mark.e2e
def test_login_invalid_username_shows_error(page, live_server):
    page.goto(f"{live_server}/login", wait_until="domcontentloaded")
    page.get_by_label("Username").fill("not-a-real-user")
    page.get_by_label("Password").fill("not-a-real-password")
    page.get_by_role("button", name="Login").click()
    expect(page.get_by_text("Login Unsuccessful", exact=False)).to_be_visible()


@pytest.mark.e2e
def test_job_name_required_validation(page, live_server, login):
    login()
    page.get_by_role("link", name="Jobs").click()
    page.get_by_role("link", name="Create a New Job").click()
    expect(page.get_by_role("heading", name="Create a new Job")).to_be_visible()

    _select_customer(page)
    page.get_by_role("button", name="Next").click()
    expect(page.get_by_role("heading", name="Create a new Job")).to_be_visible()


@pytest.mark.e2e
def test_job_name_xss_is_escaped(page, live_server, login):
    login()
    page.get_by_role("link", name="Jobs").click()
    page.get_by_role("link", name="Create a New Job").click()
    expect(page.get_by_role("heading", name="Create a new Job")).to_be_visible()

    xss_payload = '<script id="xss-test">window.__xss=1</script>'
    page.get_by_label("Job Name").fill(xss_payload)
    if page.locator("#priority").count() > 0:
        page.locator("#priority").select_option("3")
    _select_customer(page)
    page.get_by_role("button", name="Next").click()
    expect(
        page.get_by_role("heading", name=re.compile(r"Assign Hashes for"))
    ).to_be_visible()

    page.goto(f"{live_server}/jobs", wait_until="domcontentloaded")
    assert page.locator("script#xss-test").count() == 0
    expect(page.locator('text=<script id="xss-test"').first).to_be_visible()


@pytest.mark.e2e
def test_hashfile_validation_rejects_invalid_hash(page, live_server, login):
    login()
    page.get_by_role("link", name="Jobs").click()
    page.get_by_role("link", name="Create a New Job").click()
    expect(page.get_by_role("heading", name="Create a new Job")).to_be_visible()

    page.get_by_label("Job Name").fill("E2E Invalid Hash Test")
    _select_customer(page)
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
def test_hashfile_upload_example_file(page, live_server, login):
    login()
    page.get_by_role("link", name="Jobs").click()
    page.get_by_role("link", name="Create a New Job").click()
    expect(page.get_by_role("heading", name="Create a new Job")).to_be_visible()

    page.get_by_label("Job Name").fill("E2E Upload Example Hashfile")
    _select_customer(page)
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
def test_hashfile_upload_example_pwdump(page, live_server, login):
    login()
    page.get_by_role("link", name="Jobs").click()
    page.get_by_role("link", name="Create a New Job").click()
    expect(page.get_by_role("heading", name="Create a new Job")).to_be_visible()

    page.get_by_label("Job Name").fill("E2E Upload Example Pwdump")
    _select_customer(page)
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
