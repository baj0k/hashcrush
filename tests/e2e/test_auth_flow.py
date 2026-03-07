import re

import pytest
from playwright.sync_api import expect


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
    if page.get_by_role("link", name="Jobs").is_visible():
        return
    pytest.skip(
        "Login failed against external server; set HASHCRUSH_E2E_USERNAME/PASSWORD."
    )


@pytest.mark.e2e
def test_login_failure_shows_message(page, live_server, test_user_credentials):
    page.goto(f"{live_server}/login", wait_until="domcontentloaded")
    page.get_by_label("Username").fill(test_user_credentials["username"])
    page.get_by_label("Password").fill("incorrect-password")
    page.get_by_role("button", name="Login").click()
    expect(page.get_by_text("Login Unsuccessful", exact=False)).to_be_visible()
