import pytest
from playwright.sync_api import expect


@pytest.mark.e2e
def test_analytics_charts_render_and_download(page, live_server, login):
    login()
    page.goto(f"{live_server}/analytics", wait_until="domcontentloaded")

    expect(page.get_by_role("heading", name="Analytics", exact=True)).to_be_visible()
    page.locator("[data-chart-slot='recovered_accounts'] svg").wait_for()
    page.locator("[data-chart-slot='password_complexity'] svg").wait_for()
    page.locator("[data-chart-slot='top_10_passwords'] svg").wait_for()

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
    page.locator("[data-chart-slot='password_complexity'] svg").wait_for()
    page.locator("[data-chart-slot='top_10_passwords'] svg").wait_for()

    with page.expect_download() as download_info:
        page.get_by_role("button", name="Download Recovered Accounts chart").click()

    download = download_info.value
    assert download.suggested_filename == "recovered_accounts.svg"
