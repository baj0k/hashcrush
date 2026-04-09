import re
import uuid

import pytest
from playwright.sync_api import expect

from tests.e2e.support import select_domain, unique_name


def _xss_payload(label: str):
    token = uuid.uuid4().hex[:8]
    element_id = f"xss-{label}-{token}"
    payload = f'<script id="{element_id}">window.__xss=1</script>'
    return element_id, payload


@pytest.mark.e2e
def test_fallback_domain_xss_is_escaped(page, live_server, login):
    login()
    payload_token = uuid.uuid4().hex[:6]
    payload = f"<svg id=x{payload_token}>"
    normalized_payload = payload.lower()

    page.goto(f"{live_server}/hashfiles/add", wait_until="domcontentloaded")
    expect(page.get_by_role("heading", name="Create Shared Hashfile")).to_be_visible()
    page.get_by_label("Fallback Domain (Optional)").fill(payload)
    page.locator("#file_type").select_option("hash_only")
    page.locator("#hash_type").select_option("0")
    page.get_by_label("Hashfile Name").fill(unique_name("Fallback Domain XSS"))
    page.get_by_text("Paste hashes manually instead", exact=True).click()
    page.locator("textarea[name='hashfilehashes']").fill("5f4dcc3b5aa765d61d8327deb882cf99")
    page.get_by_role("button", name="Create Hashfile").click()

    page.goto(f"{live_server}/domains", wait_until="domcontentloaded")
    expect(page.get_by_role("heading", name="Domains")).to_be_visible()
    expect(page.locator("body")).to_contain_text(normalized_payload)

    content = page.content()
    assert normalized_payload not in content
    assert f"&lt;svg id=x{payload_token}&gt;" in content


@pytest.mark.e2e
def test_task_name_xss_is_escaped(page, live_server, login):
    login()
    element_id, payload = _xss_payload("task")

    page.goto(f"{live_server}/tasks/add", wait_until="domcontentloaded")
    page.locator("#name").fill(payload)

    attack_mode = page.locator("#hc_attackmode")
    assert attack_mode.count() > 0, "Task attack mode selector not found."

    if attack_mode.locator("option[value='dictionary']").count() > 0:
        attack_mode.select_option("dictionary")
        assert page.locator("#wl_id option").count() > 0, (
            "Seeded wordlists are missing for dictionary task creation."
        )
        page.locator("#wl_id").select_option(index=0)
    elif attack_mode.locator("option[value='maskmode']").count() > 0:
        attack_mode.select_option("maskmode")
        page.get_by_label("Mask").fill("?l?l?l?l?l?l")
    else:
        pytest.fail("No supported attack modes available.")

    page.get_by_role("button", name=re.compile(r"Add|Submit|Create", re.I)).click()
    expect(page.get_by_role("heading", name="Tasks")).to_be_visible()

    assert page.locator(f"script#{element_id}").count() == 0
    content = page.content()
    assert f'<script id="{element_id}">' not in content
    assert f'&lt;script id="{element_id}"' in content


@pytest.mark.e2e
def test_login_next_param_not_open_redirect(page, live_server, test_user_credentials):
    page.goto(
        f"{live_server}/login?next=https://example.com",
        wait_until="domcontentloaded",
    )
    page.get_by_label("Username").fill(test_user_credentials["username"])
    page.get_by_label("Password").fill(test_user_credentials["password"])
    page.get_by_role("button", name="Login").click()
    assert page.url.startswith(live_server)


@pytest.mark.e2e
def test_job_idor_access_denied_for_other_user(
    page, live_server, test_user_credentials, e2e_fixture_data
):
    second_username = e2e_fixture_data["second_username"]
    second_password = e2e_fixture_data["second_password"]
    assert second_username and second_password, "Seeded second E2E user credentials are missing."

    page.goto(f"{live_server}/login", wait_until="domcontentloaded")
    page.get_by_label("Username").fill(test_user_credentials["username"])
    page.get_by_label("Password").fill(test_user_credentials["password"])
    page.get_by_role("button", name="Login").click()
    expect(page.get_by_role("link", name="Jobs")).to_be_visible()

    page.get_by_role("link", name="Jobs").click()
    page.get_by_role("link", name="Create a New Job").click()
    expect(page.get_by_role("heading", name="Create a New Job")).to_be_visible()

    page.get_by_label("Job Name").fill(unique_name("E2E IDOR Job"))
    select_domain(page, e2e_fixture_data["domain_id"])
    page.get_by_role("button", name="Continue to Hashes").click()
    match = re.search(r"/jobs/(\d+)/builder", page.url)
    assert match, f"Could not determine job id for IDOR test from URL: {page.url}"
    job_id = match.group(1)

    page.locator("#manageMenu").click()
    page.get_by_role("button", name="Logout").click()
    page.goto(f"{live_server}/login", wait_until="domcontentloaded")
    page.get_by_label("Username").fill(second_username)
    page.get_by_label("Password").fill(second_password)
    page.get_by_role("button", name="Login").click()
    expect(page.get_by_role("link", name="Jobs")).to_be_visible()

    page.goto(f"{live_server}/jobs/{job_id}/builder", wait_until="domcontentloaded")
    if page.url.startswith(f"{live_server}/jobs/{job_id}/builder"):
        unauthorized = page.get_by_text("unauthorized", exact=False)
        forbidden = page.get_by_text("forbidden", exact=False)
        if unauthorized.count() == 0 and forbidden.count() == 0:
            pytest.fail("Second user can access another user's draft job builder; possible IDOR.")
