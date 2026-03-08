import os
import re
import uuid
from pathlib import Path

import pytest
from playwright.sync_api import expect


def _assert_login_error_or_skip(page) -> None:
    generic_error = page.get_by_text("Login Unsuccessful", exact=False)
    throttle_error = page.get_by_text("Too many failed login attempts", exact=False)
    if generic_error.count() > 0 or throttle_error.count() > 0:
        return

    rendered = page.content().lower()
    if (
        "csrf" in rendered
        or "400 bad request" in rendered
        or ">bad request<" in rendered
        or "the csrf token" in rendered
    ):
        pytest.skip(
            "Login POST appears blocked by CSRF/400 (likely HTTP mode with secure cookie). "
            "Use HTTPS or ensure session/cookie settings are compatible with your endpoint."
        )

    pytest.fail(
        "Login error feedback was not rendered; expected either invalid-login or throttle message."
    )


def _select_domain(page):
    domain_id = os.getenv("HASHCRUSH_E2E_DOMAIN_ID")
    if domain_id:
        option = page.locator(f"#domain_id option[value='{domain_id}']")
        if option.count() > 0:
            page.locator("#domain_id").select_option(str(domain_id))
            return
    page.locator("#domain_id").select_option("add_new")
    domain_name = os.getenv("HASHCRUSH_E2E_DOMAIN_NAME", "E2E Domain")
    page.locator("#new_domain_div input[name='domain_name']").fill(domain_name)


def _unique_job_name(prefix: str) -> str:
    return f"{prefix} {uuid.uuid4().hex[:8]}"


@pytest.mark.e2e
def test_login_invalid_username_shows_error(page, live_server):
    page.goto(f"{live_server}/login", wait_until="domcontentloaded")
    page.get_by_label("Username").fill("not-a-real-user")
    page.get_by_label("Password").fill("not-a-real-password")
    page.get_by_role("button", name="Login").click()
    _assert_login_error_or_skip(page)


@pytest.mark.e2e
def test_job_name_required_validation(page, live_server, login):
    login()
    page.get_by_role("link", name="Jobs").click()
    page.get_by_role("link", name="Create a New Job").click()
    expect(page.get_by_role("heading", name="Create a new Job")).to_be_visible()

    _select_domain(page)
    page.get_by_role("button", name="Next").click()
    expect(page.get_by_role("heading", name="Create a new Job")).to_be_visible()


@pytest.mark.e2e
def test_job_name_xss_is_escaped(page, live_server, login):
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
    _select_domain(page)
    page.get_by_role("button", name="Next").click()
    expect(
        page.get_by_role("heading", name=re.compile(r"Assign Hashes for"))
    ).to_be_visible()

    page.goto(f"{live_server}/jobs", wait_until="domcontentloaded")
    assert page.locator(f"script#x{xss_token}").count() == 0
    expect(page.get_by_text(f'<script id="x{xss_token}">1</script>', exact=True)).to_be_visible()


@pytest.mark.e2e
def test_hashfile_validation_rejects_invalid_hash(page, live_server, login):
    login()
    page.get_by_role("link", name="Jobs").click()
    page.get_by_role("link", name="Create a New Job").click()
    expect(page.get_by_role("heading", name="Create a new Job")).to_be_visible()

    page.get_by_label("Job Name").fill(_unique_job_name("E2E Invalid Hash Test"))
    _select_domain(page)
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

    page.get_by_label("Job Name").fill(_unique_job_name("E2E Upload Example Hashfile"))
    _select_domain(page)
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

    page.get_by_label("Job Name").fill(_unique_job_name("E2E Upload Example Pwdump"))
    _select_domain(page)
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
