import hashlib
import os
import ssl
import threading
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import urlopen

import pytest
from werkzeug.serving import make_server

from hashcrush.paths import iter_test_env_paths
from tests.db_runtime import (
    create_managed_postgres_database,
    sqlalchemy_engine_options,
)
from tests.e2e.support import detect_login_failure, is_authenticated_session

TEST_USER_USERNAME = "admin"
TEST_USER_PASSWORD = "supersecretpassword"
TEST_SECOND_USERNAME = "operator"
TEST_SECOND_PASSWORD = "supersecretpassword2"
TEST_DOMAIN_NAME = "E2E Domain"
TEST_HASHFILE_NAME = "e2e-existing-hashes.txt"
TEST_TASK_NAME = "All Characters [1 char]"
TEST_SECRET_KEY = "local-e2e-test-secret-key-for-hashcrush-0123456789"
TEST_DATA_ENCRYPTION_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
_SETUP_COMPLETED = False


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

for dotenv_path in iter_test_env_paths():
    load_dotenv(dotenv_path)


def _external_e2e_enabled() -> bool:
    normalized = (os.getenv("HASHCRUSH_E2E_MODE") or "").strip().lower()
    return normalized in {"external", "live"}


def _e2e_verify_tls() -> bool:
    raw = os.getenv("HASHCRUSH_E2E_VERIFY_TLS", "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_test_config(database_uri: str, runtime_path: Path, storage_path: Path):
    ssl_root = runtime_path.parent / "ssl"
    ssl_root.mkdir(parents=True, exist_ok=True)
    cert_path = ssl_root / "cert.pem"
    key_path = ssl_root / "key.pem"
    from hashcrush.container_bootstrap import ensure_tls_certificate

    ensure_tls_certificate(str(cert_path), str(key_path))
    return {
        "SECRET_KEY": TEST_SECRET_KEY,
        "DATA_ENCRYPTION_KEY": TEST_DATA_ENCRYPTION_KEY,
        "SQLALCHEMY_DATABASE_URI": database_uri,
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "SQLALCHEMY_ENGINE_OPTIONS": sqlalchemy_engine_options(),
        "ENABLE_LOCAL_EXECUTOR": False,
        "SKIP_RUNTIME_BOOTSTRAP": False,
        "RUNTIME_PATH": str(runtime_path),
        "STORAGE_PATH": str(storage_path),
        "SSL_CERT_PATH": str(cert_path),
        "SSL_KEY_PATH": str(key_path),
    }


def _seed_local_e2e_data(app, storage_path: Path) -> dict[str, str]:
    from hashcrush.models import (
        Domains,
        Hashes,
        HashfileHashes,
        Hashfiles,
        Tasks,
        Users,
        Wordlists,
        db,
    )
    from hashcrush.users.routes import bcrypt
    from hashcrush.utils.utils import (
        encode_ciphertext_for_storage,
        encode_username_for_storage,
        get_ciphertext_search_digest,
        get_username_search_digest,
    )

    with app.app_context():
        db.create_all()

        admin = Users(
            username=TEST_USER_USERNAME,
            password=bcrypt.generate_password_hash(TEST_USER_PASSWORD).decode("utf-8"),
            admin=True,
        )
        operator = Users(
            username=TEST_SECOND_USERNAME,
            password=bcrypt.generate_password_hash(TEST_SECOND_PASSWORD).decode("utf-8"),
            admin=False,
        )
        domain = Domains(name=TEST_DOMAIN_NAME)

        wordlists_dir = storage_path / "wordlists"
        wordlists_dir.mkdir(parents=True, exist_ok=True)
        wordlist_path = wordlists_dir / "e2e.txt"
        wordlist_path.write_text("password\nhashcrush\nletmein\n", encoding="utf-8")
        wordlist = Wordlists(
            name="e2e.txt",
            type="static",
            path=str(wordlist_path),
            size=wordlist_path.stat().st_size,
            checksum=_sha256_text(wordlist_path.read_text(encoding="utf-8")),
        )

        db.session.add_all([admin, operator, domain, wordlist])
        db.session.commit()

        task = Tasks(
            name=TEST_TASK_NAME,
            hc_attackmode="maskmode",
            wl_id=None,
            rule_id=None,
            hc_mask="?a",
        )
        db.session.add(task)
        db.session.commit()

        existing_hash = Hashes(
            sub_ciphertext=get_ciphertext_search_digest("5f4dcc3b5aa765d61d8327deb882cf99"),
            ciphertext=encode_ciphertext_for_storage("5f4dcc3b5aa765d61d8327deb882cf99"),
            hash_type=0,
            cracked=False,
            plaintext=None,
            plaintext_digest=None,
        )
        db.session.add(existing_hash)
        db.session.commit()

        hashfile = Hashfiles(name=TEST_HASHFILE_NAME, domain_id=domain.id)
        db.session.add(hashfile)
        db.session.commit()

        db.session.add(
            HashfileHashes(
                hash_id=existing_hash.id,
                hashfile_id=hashfile.id,
                username=encode_username_for_storage("alice"),
                username_digest=get_username_search_digest("alice") or "",
            )
        )
        db.session.commit()

        return {
            "base_url": "",
            "username": admin.username,
            "password": TEST_USER_PASSWORD,
            "second_username": operator.username,
            "second_password": TEST_SECOND_PASSWORD,
            "domain_id": str(domain.id),
            "domain_name": domain.name,
            "hashfile_id": str(hashfile.id),
            "hashfile_name": hashfile.name,
            "task_id": str(task.id),
            "task_name": task.name,
        }


@pytest.fixture(scope="session")
def local_e2e_environment(tmp_path_factory):
    root = tmp_path_factory.mktemp("e2e-local")
    runtime_path = root / "runtime"
    storage_path = root / "storage"
    runtime_path.mkdir(parents=True, exist_ok=True)
    storage_path.mkdir(parents=True, exist_ok=True)

    database_uri = create_managed_postgres_database()

    os.environ["HASHCRUSH_DATABASE_URI"] = database_uri
    os.environ["HASHCRUSH_SECRET_KEY"] = TEST_SECRET_KEY
    os.environ["HASHCRUSH_DATA_ENCRYPTION_KEY"] = TEST_DATA_ENCRYPTION_KEY

    from hashcrush import create_app

    app = create_app(
        testing=True,
        config_overrides=build_test_config(database_uri, runtime_path, storage_path),
    )
    fixture_data = _seed_local_e2e_data(app, storage_path)

    ssl_context = (
        app.config["SSL_CERT_PATH"],
        app.config["SSL_KEY_PATH"],
    )
    server = make_server("127.0.0.1", 0, app, threaded=True, ssl_context=ssl_context)
    server_port = server.socket.getsockname()[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    fixture_data["base_url"] = f"https://127.0.0.1:{server_port}"
    yield fixture_data

    server.shutdown()
    thread.join(timeout=5)
    server.server_close()


@pytest.fixture(scope="session")
def live_server(local_e2e_environment):
    yield local_e2e_environment["base_url"]


@pytest.fixture(scope="session")
def e2e_fixture_data(local_e2e_environment):
    return local_e2e_environment


@pytest.fixture(scope="session")
def test_user_credentials(e2e_fixture_data):
    return {
        "username": e2e_fixture_data["username"],
        "password": e2e_fixture_data["password"],
    }


@pytest.fixture()
def login(page, live_server, test_user_credentials):
    def _login():
        page.goto(f"{live_server}/login", wait_until="domcontentloaded")
        page.get_by_label("Username").fill(test_user_credentials["username"])
        page.get_by_label("Password").fill(test_user_credentials["password"])
        page.get_by_role("button", name="Login").click()
        if page.get_by_role("link", name="Jobs").count() > 0:
            return page
        failure = detect_login_failure(page)
        if failure is not None:
            _failure_type, message = failure
            pytest.fail(f"Local E2E login failed: {message}")
        if is_authenticated_session(page, live_server):
            return page
        pytest.fail(f"Local E2E login failed without feedback (url={page.url}).")

    return _login


@pytest.fixture(scope="session")
def external_e2e_fixture_data():
    if not _external_e2e_enabled():
        pytest.skip("Set HASHCRUSH_E2E_MODE=external to run external smoke tests.")

    return {
        "base_url": (os.getenv("HASHCRUSH_E2E_BASE_URL") or "").rstrip("/"),
        "username": os.getenv(
            "HASHCRUSH_E2E_USERNAME",
            os.getenv("HASHCRUSH_E2E_EMAIL", TEST_USER_USERNAME),
        ),
        "password": os.getenv("HASHCRUSH_E2E_PASSWORD", TEST_USER_PASSWORD),
    }


@pytest.fixture(scope="session")
def external_live_server(external_e2e_fixture_data):
    base_url = external_e2e_fixture_data["base_url"]
    if not base_url:
        pytest.skip("Set HASHCRUSH_E2E_BASE_URL to run external smoke tests.")

    parsed = urlparse(base_url)
    open_kwargs = {"timeout": 2}
    if parsed.scheme == "https" and (not _e2e_verify_tls()):
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
def external_test_user_credentials(external_e2e_fixture_data):
    return {
        "username": external_e2e_fixture_data["username"],
        "password": external_e2e_fixture_data["password"],
    }


@pytest.fixture()
def external_login(page, external_live_server, external_test_user_credentials):
    def _login():
        page.goto(f"{external_live_server}/login", wait_until="domcontentloaded")
        page.get_by_label("Username").fill(external_test_user_credentials["username"])
        page.get_by_label("Password").fill(external_test_user_credentials["password"])
        page.get_by_role("button", name="Login").click()
        if page.get_by_role("link", name="Jobs").count() > 0:
            return page
        failure = detect_login_failure(page)
        if failure is not None:
            failure_type, message = failure
            if failure_type in {"throttle", "csrf"}:
                pytest.skip(message)
            pytest.skip(
                f"Login failed against external server (url={page.url}, alert={message!r}); "
                "set HASHCRUSH_E2E_USERNAME/PASSWORD."
            )
        if is_authenticated_session(page, external_live_server):
            return page
        pytest.skip(
            f"Login failed against external server (url={page.url}); "
            "set HASHCRUSH_E2E_USERNAME/PASSWORD."
        )

    return _login


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    base_url = (os.getenv("HASHCRUSH_E2E_BASE_URL") or "").strip().lower()
    if (not _external_e2e_enabled()):
        return {**browser_context_args, "ignore_https_errors": True}
    if base_url.startswith("https://") and (not _e2e_verify_tls()):
        return {**browser_context_args, "ignore_https_errors": True}
    return browser_context_args


@pytest.fixture(autouse=True)
def ensure_external_setup(request):
    if not request.node.get_closest_marker("e2e_external"):
        return

    page = request.getfixturevalue("page")
    external_live_server = request.getfixturevalue("external_live_server")

    global _SETUP_COMPLETED
    if _SETUP_COMPLETED:
        return

    page.goto(f"{external_live_server}/login", wait_until="domcontentloaded")
    if "/setup/" in page.url:
        pytest.skip(
            "Live host is in a legacy removed setup flow state; rerun "
            "`python3 ./hashcrush.py setup` on the current code before external smoke tests."
        )

    _SETUP_COMPLETED = True


@pytest.fixture(autouse=True)
def configure_page(request):
    if not (
        request.node.get_closest_marker("e2e")
        or request.node.get_closest_marker("e2e_external")
    ):
        return

    page = request.getfixturevalue("page")
    page.set_default_timeout(5000)
    page.set_default_navigation_timeout(10000)
    return page
