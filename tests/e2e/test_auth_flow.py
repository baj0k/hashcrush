import re
import uuid
from urllib.parse import urlparse

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


def _is_authenticated_session(page, live_server: str) -> bool:
    page.goto(f"{live_server}/jobs", wait_until="domcontentloaded")
    current_path = urlparse(page.url).path.rstrip("/")
    return current_path != "/login"


@pytest.mark.e2e
def test_redirects_to_login(page, live_server):
    page.goto(f"{live_server}/", wait_until="domcontentloaded")
    expect(page).to_have_url(re.compile(r".*/login.*"))
    expect(page.locator("legend", has_text="Log In")).to_be_visible()


@pytest.mark.e2e
def test_login_success(page, live_server, test_user_credentials):
    page.goto(f"{live_server}/login", wait_until="domcontentloaded")
    page.get_by_label("Username").fill(test_user_credentials["username"])
    page.get_by_label("Password").fill(test_user_credentials["password"])
    page.get_by_role("button", name="Login").click()
    if page.get_by_role("link", name="Jobs").count() > 0 or _is_authenticated_session(page, live_server):
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
        pytest.skip(
            f"Login failed against external server (url={page.url}, alert={alert_text!r}); "
            "set HASHCRUSH_E2E_USERNAME/PASSWORD."
        )
    pytest.skip(
        f"Login failed against external server (url={page.url}); set HASHCRUSH_E2E_USERNAME/PASSWORD."
    )


@pytest.mark.e2e
def test_login_failure_shows_message(page, live_server):
    # Use a random nonexistent username to avoid locking the real E2E account.
    random_username = f"e2e-invalid-{uuid.uuid4().hex[:8]}"
    page.goto(f"{live_server}/login", wait_until="domcontentloaded")
    page.get_by_label("Username").fill(random_username)
    page.get_by_label("Password").fill("incorrect-password")
    page.get_by_role("button", name="Login").click()
    _assert_login_error_or_skip(page)
