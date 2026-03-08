import os
import ssl
from pathlib import Path
from urllib.parse import urlparse
from urllib.error import URLError
from urllib.request import urlopen

import pytest

TEST_USER_USERNAME = "admin"
TEST_USER_PASSWORD = "supersecretpassword"
_SETUP_COMPLETED = False


def _get_setup_value(key: str, fallback: str) -> str:
    value = os.getenv(key)
    if value is None or value == "":
        return fallback
    return value


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        if key and key not in os.environ:
            os.environ[key] = value


load_dotenv(Path(__file__).resolve().parents[1] / ".env.test")


def _e2e_verify_tls() -> bool:
    raw = os.getenv("HASHCRUSH_E2E_VERIFY_TLS", "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _is_authenticated_session(page, live_server: str) -> bool:
    """Best-effort auth check that does not depend on navbar visibility."""
    page.goto(f"{live_server}/jobs", wait_until="domcontentloaded")
    current_path = urlparse(page.url).path.rstrip("/")
    return current_path != "/login"


def build_test_config(db_path: Path):
    return {
        "SECRET_KEY": "test-secret-key",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_path}",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "SQLALCHEMY_ENGINE_OPTIONS": {
            "connect_args": {"check_same_thread": False},
        },
        "AUTO_SETUP_DEFAULTS": False,
        "ENABLE_SCHEDULER": False,
        "ENABLE_LOCAL_EXECUTOR": False,
        "SKIP_RUNTIME_BOOTSTRAP": True,
    }


@pytest.fixture(scope="session")
def app_config(tmp_path_factory):
    db_path_env = os.getenv("HASHCRUSH_E2E_DB_PATH")
    if db_path_env:
        db_path = Path(db_path_env).expanduser().resolve()
        db_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        db_path = tmp_path_factory.mktemp("data") / "hashcrush_test.db"
    return build_test_config(db_path)


@pytest.fixture(scope="session")
def live_server():
    base_url = os.getenv("HASHCRUSH_E2E_BASE_URL")
    if not base_url:
        pytest.skip("Set HASHCRUSH_E2E_BASE_URL to run e2e tests against a live host.")
    base_url = base_url.rstrip("/")
    parsed = urlparse(base_url)
    open_kwargs = {"timeout": 2}
    if parsed.scheme == "https" and (not _e2e_verify_tls()):
        # Local E2E commonly targets self-signed TLS endpoints.
        open_kwargs["context"] = ssl._create_unverified_context()

    try:
        with urlopen(f"{base_url}/login", **open_kwargs):
            pass
    except (URLError, OSError, TimeoutError) as exc:
        pytest.skip(
            f"External server not reachable ({type(exc).__name__}: {exc}); start it or check HASHCRUSH_E2E_BASE_URL."
        )
    yield base_url


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    base_url = (os.getenv("HASHCRUSH_E2E_BASE_URL") or "").strip().lower()
    if base_url.startswith("https://") and (not _e2e_verify_tls()):
        return {**browser_context_args, "ignore_https_errors": True}
    return browser_context_args


@pytest.fixture(autouse=True)
def ensure_setup(request):
    if not request.node.get_closest_marker("e2e"):
        return

    page = request.getfixturevalue("page")
    live_server = request.getfixturevalue("live_server")

    global _SETUP_COMPLETED
    if _SETUP_COMPLETED:
        return

    page.goto(f"{live_server}/login", wait_until="domcontentloaded")

    if "/setup/admin-pass" in page.url:
        username = _get_setup_value(
            "HASHCRUSH_E2E_SETUP_USERNAME",
            _get_setup_value("HASHCRUSH_E2E_SETUP_EMAIL", TEST_USER_USERNAME),
        )
        password = _get_setup_value(
            "HASHCRUSH_E2E_SETUP_PASSWORD",
            _get_setup_value("HASHCRUSH_E2E_PASSWORD", TEST_USER_PASSWORD),
        )

        page.get_by_label("Username").fill(username)
        page.locator("#password").fill(password)
        page.locator("#confirm_password").fill(password)
        page.get_by_role("button", name="Update").click()
        page.wait_for_load_state("domcontentloaded")

    if "/setup/settings" in page.url:
        page.get_by_role("button", name="Save").click()
        page.wait_for_load_state("domcontentloaded")

    page.goto(f"{live_server}/login", wait_until="domcontentloaded")
    if "/setup/" in page.url:
        pytest.skip(
            "Live host is in setup flow; complete setup before running e2e tests."
        )

    _SETUP_COMPLETED = True


@pytest.fixture(scope="session")
def test_user_credentials():
    username = os.getenv(
        "HASHCRUSH_E2E_USERNAME",
        os.getenv("HASHCRUSH_E2E_EMAIL", TEST_USER_USERNAME),
    )
    password = os.getenv("HASHCRUSH_E2E_PASSWORD", TEST_USER_PASSWORD)
    return {"username": username, "password": password}


@pytest.fixture()
def login(page, live_server, test_user_credentials):
    def _login():
        page.goto(f"{live_server}/login", wait_until="domcontentloaded")
        page.get_by_label("Username").fill(test_user_credentials["username"])
        page.get_by_label("Password").fill(test_user_credentials["password"])
        page.get_by_role("button", name="Login").click()
        if page.get_by_role("link", name="Jobs").count() > 0 or _is_authenticated_session(page, live_server):
            return page
        if "/setup/" in page.url:
            pytest.skip(
                "Live host is in setup flow; complete setup before running e2e tests."
            )
        rendered = page.content().lower()
        if "too many failed login attempts" in rendered:
            pytest.skip(
                "Login account appears throttled by prior failed attempts. "
                "Wait lockout expiry or clear auth_throttle rows for this account/IP."
            )
        alert_text = ""
        if page.locator(".alert").count() > 0:
            alert_text = page.locator(".alert").first.inner_text().strip()
        if alert_text:
            pytest.skip(
                f"Login failed against external server (url={page.url}, alert={alert_text!r}); "
                "set HASHCRUSH_E2E_USERNAME/PASSWORD."
            )
        pytest.skip(
            f"Login failed against external server (url={page.url}); "
            "set HASHCRUSH_E2E_USERNAME/PASSWORD."
        )

    return _login


@pytest.fixture(autouse=True)
def configure_page(request):
    if not request.node.get_closest_marker("e2e"):
        return

    page = request.getfixturevalue("page")
    page.set_default_timeout(5000)
    page.set_default_navigation_timeout(10000)
    return page
