import re

import pytest
from playwright.sync_api import expect

from tests.e2e.support import unique_name


@pytest.mark.e2e
def test_job_creation_flow(page, live_server, login, e2e_fixture_data):
    login()
    domain_id = e2e_fixture_data["domain_id"]
    hashfile_id = e2e_fixture_data["hashfile_id"]
    task_name = e2e_fixture_data["task_name"]
    page.get_by_role("link", name="Jobs").click()
    page.get_by_role("link", name="Create a New Job").click()
    expect(page.get_by_role("heading", name="Create a new Job")).to_be_visible()

    page.get_by_label("Job Name").fill(unique_name("E2E Job"))
    if page.locator("#priority").count() > 0:
        page.locator("#priority").select_option("3")
    page.locator("#domain_id").select_option(str(domain_id))
    page.get_by_role("button", name="Next").click()

    expect(
        page.get_by_role("heading", name=re.compile(r"Assign Hashes for"))
    ).to_be_visible()
    option = page.locator(
        f"#nav-existing-hashfile #hashfile_id option[value='{hashfile_id}']"
    )
    assert option.count() > 0, "Seeded hashfile is missing from the existing hashfiles list."
    page.locator("#nav-existing-hashfile-tab").click()
    page.locator("#nav-existing-hashfile #hashfile_id").select_option(
        str(hashfile_id),
        force=True,
    )
    page.locator("#nav-existing-hashfile button[type='submit']").click()
    expect(page.get_by_role("heading", name="Tasks")).to_be_visible()
    match = re.search(r"/jobs/(\d+)/tasks", page.url)
    assert match, f"Unexpected tasks URL: {page.url}"
    page.get_by_role("button", name="Add Task", exact=True).click()
    task_entry = page.locator(".dropdown-menu .dropdown-item", has_text=task_name).first
    assert task_entry.count() > 0, "Seeded task is missing from the add-task dropdown."
    task_entry.click()
    expect(page.get_by_role("cell", name=task_name, exact=True)).to_be_visible()
