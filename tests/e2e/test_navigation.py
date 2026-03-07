import re

import pytest
from playwright.sync_api import expect


@pytest.mark.e2e
def test_jobs_page_accessible_after_login(page, live_server, login):
    login()
    if not page.get_by_role("link", name="Jobs").is_visible():
        pytest.skip(
            "Login failed against external server; set HASHCRUSH_E2E_USERNAME/PASSWORD."
        )
    page.get_by_role("link", name="Jobs").click()
    expect(page.get_by_role("heading", name="Jobs")).to_be_visible()


@pytest.mark.e2e
def test_logout_redirects_to_login(page, live_server, login):
    login()
    page.goto(f"{live_server}/logout", wait_until="domcontentloaded")
    expect(page).to_have_url(re.compile(r".*/login.*"))
