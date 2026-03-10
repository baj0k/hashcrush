import os
import re

import pytest
from playwright.sync_api import expect

pytestmark = [
    pytest.mark.e2e_external,
    pytest.mark.skipif(
        (os.getenv("HASHCRUSH_E2E_MODE") or "").strip().lower() not in {"external", "live"},
        reason="Set HASHCRUSH_E2E_MODE=external to run external smoke tests.",
    ),
]


def test_external_login_success(page, external_login):
    external_login()
    expect(page.get_by_role("link", name="Jobs")).to_be_visible()


def test_external_jobs_page_accessible_after_login(page, external_live_server, external_login):
    external_login()
    page.get_by_role("link", name="Jobs").click()
    expect(page.get_by_role("heading", name="Jobs")).to_be_visible()
    assert page.url.startswith(f"{external_live_server}/jobs")


def test_external_logout_redirects_to_login(page, external_login):
    external_login()
    page.locator("#manageMenu").click()
    page.get_by_role("button", name="Logout").click()
    expect(page).to_have_url(re.compile(r".*/login.*"))
