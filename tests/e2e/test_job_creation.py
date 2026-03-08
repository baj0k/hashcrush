import os
import re

import pytest
from playwright.sync_api import expect


@pytest.mark.e2e
def test_job_creation_flow(page, live_server, login):
    login()
    domain_id = os.getenv("HASHCRUSH_E2E_DOMAIN_ID")
    hashfile_id = os.getenv("HASHCRUSH_E2E_HASHFILE_ID")
    task_id = os.getenv("HASHCRUSH_E2E_TASK_ID")
    task_name = os.getenv("HASHCRUSH_E2E_TASK_NAME")
    if not all([domain_id, hashfile_id, task_id, task_name]):
        pytest.skip(
            "Set HASHCRUSH_E2E_DOMAIN_ID, HASHCRUSH_E2E_HASHFILE_ID, "
            "HASHCRUSH_E2E_TASK_ID, HASHCRUSH_E2E_TASK_NAME."
        )
    page.get_by_role("link", name="Jobs").click()
    page.get_by_role("link", name="Create a New Job").click()
    expect(page.get_by_role("heading", name="Create a new Job")).to_be_visible()

    page.get_by_label("Job Name").fill("E2E Job")
    if page.locator("#priority").count() > 0:
        page.locator("#priority").select_option("3")
    domain_option = page.locator(f"#domain_id option[value='{domain_id}']")
    if domain_option.count() == 0:
        page.locator("#domain_id").select_option("add_new")
        domain_name = os.getenv("HASHCRUSH_E2E_DOMAIN_NAME", "E2E Domain")
        page.locator("#new_domain_div input[name='domain_name']").fill(
            domain_name
        )
    else:
        page.locator("#domain_id").select_option(str(domain_id))
    page.get_by_role("button", name="Next").click()

    expect(
        page.get_by_role("heading", name=re.compile(r"Assign Hashes for"))
    ).to_be_visible()
    option = page.locator(
        f"#nav-existing-hashfile #hashfile_id option[value='{hashfile_id}']"
    )
    if option.count() == 0:
        pytest.skip("HASHCRUSH_E2E_HASHFILE_ID not present in existing hashfiles list.")
    page.locator("#nav-existing-hashfile-tab").click()
    page.locator("#nav-existing-hashfile #hashfile_id").select_option(
        str(hashfile_id),
        force=True,
    )
    page.locator("#nav-existing-hashfile button[type='submit']").click()
    expect(page.get_by_role("heading", name="Tasks")).to_be_visible()
    match = re.search(r"/jobs/(\d+)/tasks", page.url)
    assert match, f"Unexpected tasks URL: {page.url}"
    job_id = match.group(1)
    page.get_by_role("button", name="Add Task").click()
    task_entry = page.locator(".dropdown-menu .dropdown-item", has_text=task_name).first
    if task_entry.count() == 0:
        pytest.skip("HASHCRUSH_E2E_TASK_NAME not present in add-task dropdown.")
    task_entry.click()
    expect(page.get_by_role("cell", name=task_name, exact=True)).to_be_visible()
