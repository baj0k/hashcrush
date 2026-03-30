"""Container bootstrap helpers for one-command local deployments."""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path

from cryptography import x509
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import select, text
from sqlalchemy import create_engine

from hashcrush import create_app
from hashcrush.db_upgrade import upgrade_database
from hashcrush.models import Users, db
from hashcrush.setup import add_default_tasks, default_tasks_need_added
from hashcrush.users.routes import bcrypt
from hashcrush.utils.secret_storage import migrate_sensitive_storage_rows

DEFAULT_DB_WAIT_SECONDS = 60.0
DEFAULT_DB_POLL_SECONDS = 1.0
DEFAULT_TLS_CERT_DAYS = 825
DEFAULT_TLS_DNS_NAMES = ("localhost", "nginx", "nginx-test")
DEFAULT_TLS_IPS = ("127.0.0.1", "::1")


def _data_encryption_key_mismatch_message() -> str:
    """Explain how to recover from an existing volume using a different key."""
    return (
        "Existing encrypted application data could not be decrypted with the current "
        "HASHCRUSH_DATA_ENCRYPTION_KEY. This usually means the PostgreSQL volume "
        "contains data created with a different key. If you want a fresh environment, "
        "run `docker compose down -v --remove-orphans` and start again. If you need to "
        "keep the existing data, restore the original HASHCRUSH_DATA_ENCRYPTION_KEY "
        "and rerun bootstrap."
    )


def ensure_runtime_and_storage_dirs(
    runtime_path: str,
    storage_path: str,
    *,
    ssl_cert_path: str | None = None,
    ssl_key_path: str | None = None,
) -> None:
    """Create the runtime, storage, and optional TLS tree expected by the app."""
    runtime_root = Path(runtime_path).expanduser().resolve()
    storage_root = Path(storage_path).expanduser().resolve()

    for relative_path in (
        ("tmp",),
        ("hashes",),
        ("outfiles",),
    ):
        (runtime_root.joinpath(*relative_path)).mkdir(parents=True, exist_ok=True)

    for relative_path in (
        ("wordlists",),
        ("rules",),
    ):
        (storage_root.joinpath(*relative_path)).mkdir(parents=True, exist_ok=True)

    if ssl_cert_path:
        ssl_root = Path(ssl_cert_path).expanduser().resolve().parent
        ssl_root.mkdir(parents=True, exist_ok=True)
    if ssl_key_path:
        key_root = Path(ssl_key_path).expanduser().resolve().parent
        key_root.mkdir(parents=True, exist_ok=True)


def ensure_tls_certificate(cert_path: str, key_path: str) -> None:
    """Create a self-signed TLS certificate if one is not already present."""
    cert_file = Path(cert_path).expanduser().resolve()
    key_file = Path(key_path).expanduser().resolve()
    if cert_file.is_file() and key_file.is_file():
        return

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "HashCrush Local"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]
    )

    san_entries = [x509.DNSName(name) for name in DEFAULT_TLS_DNS_NAMES]
    san_entries.extend(x509.IPAddress(ip_address(value)) for value in DEFAULT_TLS_IPS)

    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=DEFAULT_TLS_CERT_DAYS))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )

    cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    os.chmod(cert_file, 0o644)
    os.chmod(key_file, 0o600)
    print(f"Generated self-signed TLS certificate at {cert_file}.")


def wait_for_database(
    database_uri: str,
    *,
    timeout_seconds: float = DEFAULT_DB_WAIT_SECONDS,
    poll_interval_seconds: float = DEFAULT_DB_POLL_SECONDS,
) -> None:
    """Wait until the configured database accepts connections."""
    deadline = time.monotonic() + max(1.0, float(timeout_seconds))
    poll_interval = max(0.1, float(poll_interval_seconds))
    last_error: Exception | None = None

    while time.monotonic() < deadline:
        engine = create_engine(database_uri, pool_pre_ping=True)
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            return
        except Exception as exc:  # pragma: no cover - exercised via timeout path
            last_error = exc
            time.sleep(poll_interval)
        finally:
            engine.dispose()

    raise RuntimeError(
        "Database did not become ready before timeout."
        + (f" Last error: {last_error}" if last_error else "")
    )


def ensure_seed_data(admin_username: str, admin_password: str) -> None:
    """Seed the minimum runtime rows needed for a usable instance."""
    if len(admin_password) < 14:
        raise RuntimeError(
            "HASHCRUSH_INITIAL_ADMIN_PASSWORD must be at least 14 characters long."
        )

    has_admin = db.session.execute(
        select(Users).where(Users.admin.is_(True)).limit(1)
    ).scalars().first()
    if not has_admin:
        db.session.add(
            Users(
                username=admin_username,
                password=bcrypt.generate_password_hash(admin_password).decode("utf-8"),
                admin=True,
            )
        )
        db.session.commit()

    if default_tasks_need_added(db):
        add_default_tasks(db)


def bootstrap_instance(app, admin_username: str, admin_password: str) -> tuple[int, int]:
    """Upgrade schema, migrate sensitive rows, and seed runtime state."""
    with app.app_context():
        result = upgrade_database(dry_run=False)
        try:
            migrated_rows = migrate_sensitive_storage_rows()
        except InvalidToken as exc:
            raise RuntimeError(_data_encryption_key_mismatch_message()) from exc
        ensure_seed_data(admin_username, admin_password)
    return result.target_version, migrated_rows


def build_bootstrap_app():
    return create_app(
        config_overrides={
            "ENABLE_LOCAL_EXECUTOR": False,
            "SKIP_RUNTIME_BOOTSTRAP": True,
        }
    )


def main() -> int:
    database_uri = str(os.getenv("HASHCRUSH_DATABASE_URI") or "").strip()
    if not database_uri:
        raise RuntimeError("HASHCRUSH_DATABASE_URI is required for container bootstrap.")

    runtime_path = str(
        os.getenv("HASHCRUSH_RUNTIME_PATH") or "/tmp/hashcrush-runtime"
    ).strip()
    storage_path = str(
        os.getenv("HASHCRUSH_STORAGE_PATH") or "/var/lib/hashcrush"
    ).strip()
    ssl_cert_path = str(
        os.getenv("HASHCRUSH_SSL_CERT_PATH") or "/etc/hashcrush/ssl/cert.pem"
    ).strip()
    ssl_key_path = str(
        os.getenv("HASHCRUSH_SSL_KEY_PATH") or "/etc/hashcrush/ssl/key.pem"
    ).strip()
    admin_username = (
        str(os.getenv("HASHCRUSH_INITIAL_ADMIN_USERNAME") or "admin").strip() or "admin"
    )
    admin_password = str(os.getenv("HASHCRUSH_INITIAL_ADMIN_PASSWORD") or "").strip()
    if not admin_password:
        raise RuntimeError("HASHCRUSH_INITIAL_ADMIN_PASSWORD is required.")

    timeout_seconds = float(
        os.getenv("HASHCRUSH_BOOTSTRAP_DB_WAIT_SECONDS") or DEFAULT_DB_WAIT_SECONDS
    )

    print("Ensuring runtime and storage directories exist.")
    ensure_runtime_and_storage_dirs(
        runtime_path,
        storage_path,
        ssl_cert_path=ssl_cert_path,
        ssl_key_path=ssl_key_path,
    )
    ensure_tls_certificate(ssl_cert_path, ssl_key_path)

    print("Waiting for PostgreSQL to accept connections.")
    wait_for_database(database_uri, timeout_seconds=timeout_seconds)

    print("Bootstrapping schema and seed data.")
    target_version, migrated_rows = bootstrap_instance(
        build_bootstrap_app(),
        admin_username,
        admin_password,
    )
    print(f"Schema version is now {target_version}.")
    if migrated_rows:
        print(f"Migrated {migrated_rows} sensitive storage row(s).")
    print("Container bootstrap completed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
