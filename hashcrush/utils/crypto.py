"""Application-level encryption helpers for persisted secret material."""

from __future__ import annotations

import base64
import hashlib
import hmac
from functools import lru_cache

from cryptography.fernet import Fernet
from flask import current_app

ENCRYPTED_PREFIX = "enc:"


def generate_data_encryption_key() -> str:
    """Generate a new Fernet-compatible data encryption key."""
    return Fernet.generate_key().decode("ascii")


def _configured_data_encryption_key() -> str:
    configured = str(current_app.config.get("DATA_ENCRYPTION_KEY") or "").strip()
    if not configured:
        raise RuntimeError(
            "Missing data encryption key. Set HASHCRUSH_DATA_ENCRYPTION_KEY or "
            "[app] data_encryption_key before starting HashCrush."
        )
    return configured


@lru_cache(maxsize=8)
def _fernet_for_key(configured_key: str) -> Fernet:
    return Fernet(configured_key.encode("ascii"))


@lru_cache(maxsize=8)
def _blind_index_key(configured_key: str) -> bytes:
    raw_key = base64.urlsafe_b64decode(configured_key.encode("ascii"))
    return hashlib.sha256(b"hashcrush-blind-index\x00" + raw_key).digest()


def is_encrypted_storage_value(value: str | None) -> bool:
    return bool(value) and str(value).startswith(ENCRYPTED_PREFIX)


def encrypt_secret_value(value: str | None) -> str | None:
    """Encrypt persisted secret text."""
    if value is None:
        return None
    token = _fernet_for_key(_configured_data_encryption_key()).encrypt(
        value.encode("utf-8")
    )
    return ENCRYPTED_PREFIX + token.decode("ascii")


def decrypt_secret_value(value: str | None) -> str | None:
    """Decrypt persisted secret text, with raw-value fallback for legacy rows."""
    if value is None:
        return None
    if not is_encrypted_storage_value(value):
        return value
    token = str(value)[len(ENCRYPTED_PREFIX) :].encode("ascii")
    return _fernet_for_key(_configured_data_encryption_key()).decrypt(token).decode(
        "utf-8"
    )


def blind_index(value: str | None, *, purpose: str, length: int = 64) -> str | None:
    """Return a keyed blind index for exact-match lookups."""
    if value is None:
        return None
    digest = hmac.new(
        _blind_index_key(_configured_data_encryption_key()),
        (purpose + "\x00" + value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return digest[:length]
