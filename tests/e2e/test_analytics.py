import pytest
from playwright.sync_api import expect


@pytest.mark.e2e
def test_analytics_charts_render_and_download(page, live_server, login):
    login()
    page.goto(f"{live_server}/analytics", wait_until="domcontentloaded")

    expect(page.get_by_role("heading", name="Analytics", exact=True)).to_be_visible()
    page.locator("[data-chart-slot='recovered_accounts'] svg").wait_for()
    page.locator("[data-chart-slot='password_quality'] svg").wait_for()
    page.locator("[data-chart-slot='hash_reuse'] svg").wait_for()

    with page.expect_download() as download_info:
        page.get_by_role("button", name="Download Recovered Accounts chart").click()

    download = download_info.value
    assert download.suggested_filename == "recovered_accounts.svg"


@pytest.mark.e2e_external
def test_external_analytics_charts_render_and_download(
    page, external_live_server, external_login
):
    external_login()
    page.goto(f"{external_live_server}/analytics", wait_until="domcontentloaded")

    expect(page.get_by_role("heading", name="Analytics", exact=True)).to_be_visible()
    page.locator("[data-chart-slot='recovered_accounts'] svg").wait_for()
    page.locator("[data-chart-slot='password_quality'] svg").wait_for()
    page.locator("[data-chart-slot='hash_reuse'] svg").wait_for()

    with page.expect_download() as download_info:
        page.get_by_role("button", name="Download Recovered Accounts chart").click()

    download = download_info.value
    assert download.suggested_filename == "recovered_accounts.svg"


@pytest.mark.e2e
def test_analytics_domain_link_opens_domain_browse_search(
    page, live_server, login, e2e_fixture_data
):
    login()
    page.goto(f"{live_server}/analytics", wait_until="domcontentloaded")

    page.locator("[data-chart-slot='recovered_accounts'] svg").wait_for()
    page.locator(
        "table tbody tr td a", has_text=e2e_fixture_data["domain_name"]
    ).first.click()

    expect(page).to_have_url(
        f"{live_server}/search?domain_id={e2e_fixture_data['domain_id']}"
    )
    expect(page.get_by_role("heading", name="Search", exact=True)).to_be_visible()
    expect(
        page.get_by_text(
            f"Browsing all entries for domain {e2e_fixture_data['domain_name']}.",
            exact=False,
        )
    ).to_be_visible()
