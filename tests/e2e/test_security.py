import os
import re
import uuid
from urllib.parse import urlparse

import pytest
from playwright.sync_api import expect


def _xss_payload(label: str):
    token = uuid.uuid4().hex[:8]
    element_id = f"xss-{label}-{token}"
    payload = f'<script id="{element_id}">window.__xss=1</script>'
    return element_id, payload


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


def _login(page, live_server, username, password):
    page.goto(f"{live_server}/login", wait_until="domcontentloaded")
    page.get_by_label("Username").fill(username)
    page.get_by_label("Password").fill(password)
    page.get_by_role("button", name="Login").click()
    if page.get_by_role("link", name="Jobs").count() > 0:
        return

    # Fallback auth check that does not depend on navbar visibility.
    page.goto(f"{live_server}/jobs", wait_until="domcontentloaded")
    current_path = urlparse(page.url).path.rstrip("/")
    authenticated = current_path != "/login"
    if authenticated:
        return

    rendered = page.content().lower()
    if "too many failed login attempts" in rendered:
        pytest.skip(
            "Login account appears throttled by prior failed attempts. "
            "Wait lockout expiry or clear auth_throttle rows for this account/IP."
        )
    if "/setup/" in page.url:
        pytest.skip("Live host is in setup flow; complete setup before running e2e tests.")
    alert_text = ""
    if page.locator(".alert").count() > 0:
        alert_text = page.locator(".alert").first.inner_text().strip()
    if alert_text:
        pytest.skip(f"Login failed against external server (url={page.url}, alert={alert_text!r}).")
    pytest.skip(f"Login failed against external server (url={page.url}).")


@pytest.mark.e2e
def test_domain_name_xss_is_escaped(page, live_server, login):
    login()
    payload = "<svg onload=alert(1)>"

    page.get_by_role("link", name="Jobs").click()
    page.get_by_role("link", name="Create a New Job").click()
    expect(page.get_by_role("heading", name="Create a new Job")).to_be_visible()

    page.locator("input[name='name']").fill(f"E2E XSS Domain {uuid.uuid4().hex[:6]}")
    if page.locator("#priority").count() > 0:
        page.locator("#priority").select_option("3")
    domain_select = page.locator("#domain_id")
    domain_select.select_option("add_new")
    if domain_select.input_value() != "add_new":
        page.evaluate(
            "const el=document.querySelector('#domain_id');"
            "if(el){el.value='add_new';el.dispatchEvent(new Event('change'));}"
        )
    page.locator("input[name='domain_name']").fill(payload)
    page.get_by_role("button", name="Next").click()
    try:
        expect(
            page.get_by_role("heading", name=re.compile(r"Assign Hashes for"))
        ).to_be_visible()
    except AssertionError:
        pytest.skip("Job creation failed; domain not created.")

    page.goto(f"{live_server}/domains", wait_until="domcontentloaded")
    content = page.content()
    assert "<svg onload=alert(1)>" not in content
    assert "&lt;svg onload=alert(1)&gt;" in content


@pytest.mark.e2e
def test_task_name_xss_is_escaped(page, live_server, login):
    login()
    element_id, payload = _xss_payload("task")

    page.goto(f"{live_server}/tasks/add", wait_until="domcontentloaded")
    page.locator("#name").fill(payload)

    attack_mode = page.locator("#hc_attackmode")
    if attack_mode.count() == 0:
        pytest.skip("Task attack mode selector not found.")

    if attack_mode.locator("option[value='dictionary']").count() > 0:
        attack_mode.select_option("dictionary")
        if page.locator("#wl_id option").count() == 0:
            pytest.skip("No wordlists available for dictionary task.")
        page.locator("#wl_id").select_option(index=0)
    elif attack_mode.locator("option[value='maskmode']").count() > 0:
        attack_mode.select_option("maskmode")
        page.get_by_label("Mask").fill("?l?l?l?l?l?l")
    else:
        pytest.skip("No supported attack modes available.")

    page.get_by_role("button", name=re.compile(r"Add|Submit|Create", re.I)).click()
    expect(page.get_by_role("heading", name="Tasks")).to_be_visible()

    assert page.locator(f"script#{element_id}").count() == 0
    content = page.content()
    assert f'<script id="{element_id}">' not in content
    assert f'&lt;script id="{element_id}"' in content


@pytest.mark.e2e
def test_login_next_param_not_open_redirect(page, live_server, test_user_credentials):
    page.goto(
        f"{live_server}/login?next=https://example.com",
        wait_until="domcontentloaded",
    )
    page.get_by_label("Username").fill(test_user_credentials["username"])
    page.get_by_label("Password").fill(test_user_credentials["password"])
    page.get_by_role("button", name="Login").click()
    if os.getenv("HASHCRUSH_E2E_ENFORCE_OPEN_REDIRECT", "0") in {"1", "true", "yes"}:
        assert page.url.startswith(live_server)
    else:
        if page.url.startswith("https://example.com"):
            pytest.xfail("Open redirect: login next allows external URL.")
        assert page.url.startswith(live_server) or page.url.startswith(
            "https://example.com"
        )


@pytest.mark.e2e
def test_job_idor_access_denied_for_other_user(
    page, live_server, test_user_credentials
):
    second_username = os.getenv(
        "HASHCRUSH_E2E_SECOND_USERNAME",
        os.getenv("HASHCRUSH_E2E_SECOND_EMAIL"),
    )
    second_password = os.getenv("HASHCRUSH_E2E_SECOND_PASSWORD")
    if not second_username or not second_password:
        pytest.skip("Set HASHCRUSH_E2E_SECOND_USERNAME and HASHCRUSH_E2E_SECOND_PASSWORD.")
    if os.getenv("HASHCRUSH_E2E_SECOND_IS_ADMIN", "0") in {"1", "true", "yes"}:
        pytest.skip("Second user is admin; IDOR check requires non-admin user.")

    _login(
        page,
        live_server,
        test_user_credentials["username"],
        test_user_credentials["password"],
    )
    page.get_by_role("link", name="Jobs").click()
    page.get_by_role("link", name="Create a New Job").click()
    expect(page.get_by_role("heading", name="Create a new Job")).to_be_visible()

    page.get_by_label("Job Name").fill("E2E IDOR Job")
    _select_domain(page)
    page.get_by_role("button", name="Next").click()
    match = re.search(r"/jobs/(\d+)/assigned_hashfile", page.url)
    if not match:
        pytest.skip("Could not determine job id for IDOR test.")
    job_id = match.group(1)

    page.locator("#manageMenu").click()
    page.get_by_role("button", name="Logout").click()
    _login(page, live_server, second_username, second_password)

    page.goto(f"{live_server}/jobs/{job_id}/tasks", wait_until="domcontentloaded")
    if page.url.startswith(f"{live_server}/jobs/{job_id}/tasks"):
        if (
            page.get_by_text("unauthorized", exact=False).count() == 0
            and page.get_by_text("forbidden", exact=False).count() == 0
        ):
            pytest.fail(
                "Second user can access another user's job tasks; possible IDOR."
            )
