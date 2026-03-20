import hashlib
import os
import re
import time

import pytest
from playwright.sync_api import expect

from tests.e2e.support import unique_name

pytestmark = [
    pytest.mark.e2e_external,
    pytest.mark.skipif(
        (os.getenv("HASHCRUSH_E2E_MODE") or "").strip().lower() not in {"external", "live"},
        reason="Set HASHCRUSH_E2E_MODE=external to run external smoke tests.",
    ),
]


def _assert_heading(page, heading, *, failure_message: str) -> None:
    locator = page.get_by_role("heading", name=heading)
    if locator.count() > 0:
        expect(locator).to_be_visible()
        return

    alert_text = ""
    if page.locator(".alert").count() > 0:
        alert_text = page.locator(".alert").first.inner_text().strip()
    pytest.fail(f"{failure_message} (url={page.url}, alert={alert_text!r})")


def _job_row(page, job_name: str):
    return page.locator("article.media.content-section table tbody tr", has_text=job_name).first

def _wait_for_job_completion(page, external_live_server: str, job_name: str, *, timeout_seconds: int = 90) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_row_text = ""

    while time.monotonic() < deadline:
        page.goto(f"{external_live_server}/jobs", wait_until="domcontentloaded")
        row = _job_row(page, job_name)
        if row.count() > 0:
            last_row_text = row.inner_text().strip()
            if "Completed" in last_row_text and "3/3" in last_row_text:
                return
        page.wait_for_timeout(1000)

    pytest.fail(
        f"Timed out waiting for smoke job {job_name!r} to complete with 3/3 recovered. "
        f"Last observed row text: {last_row_text!r}"
    )


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


def test_external_worker_cracks_dictionary_job_end_to_end(
    page, external_live_server, external_login, tmp_path
):
    external_login()

    wordlist_name = unique_name("External Smoke Wordlist")
    task_name = unique_name("External Smoke Task")
    job_name = unique_name("External Smoke Job")
    domain_name = unique_name("External Smoke Domain")
    token = unique_name("External Smoke Token").split()[-1].lower()

    plaintexts = [
        f"hc{token}1",
        f"hc{token}2",
        f"hc{token}3",
    ]
    hashes = [hashlib.md5(value.encode("utf-8")).hexdigest() for value in plaintexts]

    wordlist_path = tmp_path / "external-smoke-wordlist.txt"
    wordlist_path.write_text("\n".join(plaintexts) + "\n", encoding="utf-8")
    hashfile_path = tmp_path / "external-smoke-hashes.txt"
    hashfile_path.write_text("\n".join(hashes) + "\n", encoding="utf-8")

    page.goto(f"{external_live_server}/wordlists/add", wait_until="domcontentloaded")
    _assert_heading(
        page,
        "Upload Wordlist",
        failure_message=(
            "External worker smoke test requires an admin account so it can upload a shared wordlist"
        ),
    )
    page.get_by_label("Name").fill(wordlist_name)
    page.set_input_files("input[name='upload']", str(wordlist_path))
    page.get_by_role("button", name="Upload", exact=True).click()
    expect(page).to_have_url(re.compile(r".*/wordlists(?:\?.*)?$"), timeout=30000)
    expect(page.get_by_role("cell", name=wordlist_name, exact=True)).to_be_visible(timeout=30000)

    page.goto(f"{external_live_server}/tasks/add", wait_until="domcontentloaded")
    _assert_heading(
        page,
        "Add Tasks",
        failure_message=(
            "External worker smoke test requires an admin account so it can create a shared task"
        ),
    )
    page.get_by_label("Name").fill(task_name)
    page.get_by_label("Attack Mode").select_option("dictionary")
    page.locator("#wl_id").select_option(label=wordlist_name)
    page.get_by_role("button", name="Create", exact=True).click()
    expect(page).to_have_url(re.compile(r".*/tasks(?:\?.*)?$"))
    expect(page.get_by_role("cell", name=task_name, exact=True)).to_be_visible()

    page.goto(f"{external_live_server}/jobs/add", wait_until="domcontentloaded")
    _assert_heading(
        page,
        re.compile(r"Create a New Job", re.IGNORECASE),
        failure_message="Could not open the new job wizard for the external worker smoke test",
    )
    page.get_by_label("Job Name").fill(job_name)
    if page.locator("#priority").count() > 0:
        page.locator("#priority").select_option("3")
    option = page.locator("#domain_id option[value='add_new']")
    if option.count() == 0:
        pytest.fail(
            "External worker smoke test expected an admin-capable job form with an add_new domain option."
        )
    page.locator("#domain_id").select_option("add_new")
    page.get_by_label("New Domain").fill(domain_name)
    page.get_by_role("button", name="Create Draft", exact=True).click()

    expect(page).to_have_url(re.compile(r".*/jobs/\d+/builder.*"))
    expect(page.get_by_role("heading", name="Hashes")).to_be_visible()
    page.locator("select[name='file_type']").select_option("hash_only")
    page.locator("select[name='hash_type']").select_option("0")
    page.locator("#pills-profile-tab").click()
    page.set_input_files("input[name='hashfile']", str(hashfile_path))
    page.get_by_role("button", name="Save New Hashfile", exact=True).click()

    expect(page.get_by_role("heading", name="Tasks")).to_be_visible()
    page.get_by_role("button", name="Add Task", exact=True).click()
    task_entry = page.locator(".dropdown-menu .dropdown-item", has_text=task_name).first
    expect(task_entry).to_be_visible()
    task_entry.click()
    expect(
        page.locator("#tasks").get_by_role("cell", name=task_name, exact=True)
    ).to_be_visible()

    page.get_by_role("button", name="Create", exact=True).click()
    expect(page).to_have_url(re.compile(r".*/jobs/\d+/summary.*"))
    expect(page.get_by_role("heading", name="Job Summary")).to_be_visible()
    page.get_by_role("button", name="Accept Job", exact=True).click()
    expect(page).to_have_url(re.compile(r".*/jobs(?:\?.*)?$"))

    job_row = _job_row(page, job_name)
    expect(job_row).to_be_visible()
    expect(job_row).to_contain_text("Ready")
    expect(job_row).to_contain_text("0/3")

    job_row.get_by_role("button", name=f"Start job {job_name}").click()
    expect(page).to_have_url(re.compile(r".*/jobs(?:\?.*)?$"))
    expect(page.locator(".alert-success").first).to_contain_text("Job has been Started!")

    _wait_for_job_completion(page, external_live_server, job_name)
