import re

import pytest
from playwright.sync_api import expect

from tests.e2e.support import unique_name


@pytest.mark.e2e
def test_shared_hashfile_add_flow(page, live_server, login, e2e_fixture_data):
    login()
    page.goto(f"{live_server}/hashfiles", wait_until="domcontentloaded")
    expect(page.get_by_role("heading", name="Hash Files")).to_be_visible()
    page.get_by_role("link", name="Add Hashfile").click()
    expect(page.get_by_role("heading", name="Create Shared Hashfile")).to_be_visible()

    hashfile_name = unique_name("E2E Shared Hashfile")
    page.locator("#domain_id").select_option(str(e2e_fixture_data["domain_id"]))
    page.locator("#file_type").select_option("hash_only")
    page.locator("#hash_type").select_option("0")
    page.locator("#name").fill(hashfile_name)
    page.locator("textarea[name='hashfilehashes']").fill("5f4dcc3b5aa765d61d8327deb882cf99")
    page.get_by_role("button", name="Create Hashfile").click()

    expect(page).to_have_url(re.compile(r".*/hashfiles$"))
    expect(page.get_by_role("cell", name=hashfile_name, exact=True)).to_be_visible()
