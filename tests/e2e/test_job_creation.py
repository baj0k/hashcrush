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
    expect(page.get_by_role("heading", name="Create a New Job")).to_be_visible()

    page.get_by_label("Job Name").fill(unique_name("E2E Job"))
    if page.locator("#priority").count() > 0:
        page.locator("#priority").select_option("3")
    page.locator("#domain_id").select_option(str(domain_id))
    page.get_by_role("button", name="Create Draft").click()

    expect(page).to_have_url(re.compile(r".*/jobs/\d+/builder.*"))
    expect(page.get_by_role("heading", name="Hashes")).to_be_visible()
    option = page.locator(
        f"#nav-existing-hashfile #hashfile_id option[value='{hashfile_id}']"
    )
    assert option.count() > 0, "Seeded hashfile is missing from the existing hashfiles list."
    page.locator("#nav-existing-hashfile-tab").click()
    page.locator("#nav-existing-hashfile #hashfile_id").select_option(
        str(hashfile_id),
        force=True,
    )
    page.get_by_role("button", name="Use Selected Hashfile").click()
    expect(page.get_by_role("heading", name="Tasks")).to_be_visible()
    match = re.search(r"/jobs/(\d+)/builder", page.url)
    assert match, f"Unexpected builder URL: {page.url}"
    expect(page.get_by_text("Add New Task", exact=True)).to_be_visible()
    page.get_by_role("button", name="Add Task", exact=True).click()
    task_entry = page.locator(".dropdown-menu .dropdown-item", has_text=task_name).first
    assert task_entry.count() > 0, "Seeded task is missing from the add-task dropdown."
    task_entry.click()
    expect(
        page.locator("#tasks").get_by_role("cell", name=task_name, exact=True)
    ).to_be_visible()
    page.get_by_role("button", name="Review Job", exact=True).click()
    expect(page).to_have_url(re.compile(r".*/jobs/\d+/summary.*"))
    expect(page.get_by_role("heading", name="Review Job")).to_be_visible()
    page.get_by_role("button", name="Accept Job", exact=True).click()
    expect(page).to_have_url(re.compile(r".*/jobs(?:\?.*)?$"))


@pytest.mark.e2e
def test_tasks_add_can_create_wordlist_and_rule_inline(page, live_server, login, tmp_path):
    login()

    wordlist_name = unique_name("Inline Wordlist")
    rule_name = unique_name("Inline Rule")
    wordlist_path = tmp_path / "inline-wordlist.txt"
    wordlist_path.write_text("password\nletmein\n", encoding="utf-8")
    rule_path = tmp_path / "inline.rule"
    rule_path.write_text(":\n", encoding="utf-8")

    page.goto(f"{live_server}/tasks/add", wait_until="domcontentloaded")
    expect(page.get_by_role("heading", name="Create Task")).to_be_visible()
    page.get_by_label("Attack Mode").select_option("dictionary")

    expect(page.get_by_role("link", name="Add New Wordlist")).to_be_visible()
    page.get_by_role("link", name="Add New Wordlist").click()
    expect(page).to_have_url(re.compile(r".*/wordlists/add.*"))
    expect(page.get_by_role("heading", name="Upload Wordlist")).to_be_visible()
    page.get_by_label("Name").fill(wordlist_name)
    page.set_input_files("input[name='upload']", str(wordlist_path))
    page.get_by_role("button", name="Upload", exact=True).click()

    expect(page).to_have_url(re.compile(r".*/tasks/add.*selected_wordlist_id=.*"))
    expect(page.get_by_role("heading", name="Create Task")).to_be_visible()
    expect(page.locator("#wl_id option:checked")).to_have_text(wordlist_name)

    expect(page.get_by_role("link", name="Add New Rule")).to_be_visible()
    page.get_by_role("link", name="Add New Rule").click()
    expect(page).to_have_url(re.compile(r".*/rules/add.*"))
    expect(page.get_by_role("heading", name="Upload Rule")).to_be_visible()
    page.get_by_label("Name").fill(rule_name)
    page.set_input_files("input[name='upload']", str(rule_path))
    page.get_by_role("button", name="Upload", exact=True).click()

    expect(page).to_have_url(re.compile(r".*/tasks/add.*selected_rule_id=.*"))
    expect(page.get_by_role("heading", name="Create Task")).to_be_visible()
    expect(page.locator("#wl_id option:checked")).to_have_text(wordlist_name)
    expect(page.locator("#rule_id option:checked")).to_have_text(rule_name)
