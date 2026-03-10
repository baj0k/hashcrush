import re
import uuid

import pytest
from playwright.sync_api import expect

from tests.e2e.support import assert_login_error_feedback


@pytest.mark.e2e
def test_redirects_to_login(page, live_server):
    page.goto(f"{live_server}/", wait_until="domcontentloaded")
    expect(page).to_have_url(re.compile(r".*/login.*"))
    expect(page.locator("legend", has_text="Log In")).to_be_visible()


@pytest.mark.e2e
def test_login_success(page, login):
    login()
    expect(page.get_by_role("link", name="Jobs")).to_be_visible()


@pytest.mark.e2e
def test_login_failure_shows_message(page, live_server):
    random_username = f"e2e-invalid-{uuid.uuid4().hex[:8]}"
    page.goto(f"{live_server}/login", wait_until="domcontentloaded")
    page.get_by_label("Username").fill(random_username)
    page.get_by_label("Password").fill("incorrect-password")
    page.get_by_role("button", name="Login").click()
    assert_login_error_feedback(page)
