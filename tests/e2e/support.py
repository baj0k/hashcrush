import uuid
from urllib.parse import urlparse


def unique_name(prefix: str) -> str:
    return f"{prefix} {uuid.uuid4().hex[:8]}"


def is_authenticated_session(page, base_url: str) -> bool:
    page.goto(f"{base_url}/jobs", wait_until="domcontentloaded")
    current_path = urlparse(page.url).path.rstrip("/")
    return current_path != "/login"


def detect_login_failure(page) -> tuple[str, str] | None:
    if page.locator(".alert").count() > 0:
        alert_text = page.locator(".alert").first.inner_text().strip()
        if alert_text:
            return ("alert", alert_text)
    rendered = page.content().lower()
    if "too many failed login attempts" in rendered:
        return (
            "throttle",
            "Login account appears throttled by prior failed attempts. "
            "Wait lockout expiry or clear auth_throttle rows for this account/IP.",
        )
    if (
        "400 bad request" in rendered
        or ">bad request<" in rendered
        or "the csrf token" in rendered
        or "csrf session token is missing" in rendered
        or "csrf tokens do not match" in rendered
    ):
        return (
            "csrf",
            "Login POST appears blocked by CSRF/400. "
            "Use HTTPS and ensure session/cookie settings are compatible with your endpoint.",
        )
    return None


def assert_login_error_feedback(page) -> None:
    page.wait_for_load_state("domcontentloaded")
    alerts = page.locator(".alert")
    if alerts.count() > 0:
        alerts.first.wait_for(state="visible")
        alert_text = alerts.first.inner_text().strip()
        if (
            "Login Unsuccessful" in alert_text
            or "Too many failed login attempts" in alert_text
        ):
            return

    generic_error = page.get_by_text("Login Unsuccessful", exact=False)
    throttle_error = page.get_by_text("Too many failed login attempts", exact=False)
    if generic_error.count() > 0:
        generic_error.first.wait_for(state="visible")
        return
    if throttle_error.count() > 0:
        throttle_error.first.wait_for(state="visible")
        return
    raise AssertionError(
        "Login error feedback was not rendered; expected either invalid-login or throttle message."
    )


def select_domain(page, domain_id: str) -> None:
    option = page.locator(f"#domain_id option[value='{domain_id}']")
    assert option.count() > 0, "Seeded E2E domain is missing from the job form."
    page.locator("#domain_id").select_option(str(domain_id))
