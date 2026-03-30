"""Sensitive storage encoding, decoding, and migration helpers."""

from __future__ import annotations

import re

from sqlalchemy import select

from hashcrush.crypto_utils import (
    blind_index,
    decrypt_secret_value,
    encrypt_secret_value,
    is_encrypted_storage_value,
)
from hashcrush.models import Hashes, HashfileHashes, db

_PLAINTEXT_HEX_PATTERN = re.compile(r"^[0-9a-f]+$")


def is_plaintext_hex_encoded(value: str | None) -> bool:
    """Return True when value matches canonical lowercase hex encoding."""
    if value is None:
        return False
    if value == "":
        return True
    if len(value) % 2 != 0:
        return False
    return bool(_PLAINTEXT_HEX_PATTERN.fullmatch(value))


def get_ciphertext_search_digest(value: str | None) -> str | None:
    return blind_index(value, purpose="ciphertext", length=32)


def get_plaintext_search_digest(value: str | None) -> str | None:
    return blind_index(value, purpose="plaintext", length=64)


def get_username_search_digest(value: str | None) -> str | None:
    return blind_index(value or "", purpose="username", length=64)


def encode_ciphertext_for_storage(value: str | None) -> str | None:
    return encrypt_secret_value(value)


def decode_ciphertext_from_storage(value: str | None) -> str | None:
    return decrypt_secret_value(value)


def encode_plaintext_for_storage(value: str | None) -> str | None:
    """Encrypt plaintext for DB storage."""
    return encrypt_secret_value(value)


def decode_plaintext_from_storage(value: str | None) -> str | None:
    """Decode encrypted plaintext storage format, with legacy fallback."""
    if value is None:
        return None
    if is_encrypted_storage_value(value):
        return decrypt_secret_value(value)
    if value == "":
        return ""
    if is_plaintext_hex_encoded(value):
        try:
            return bytes.fromhex(value).decode("latin-1")
        except (TypeError, ValueError):
            return value
    return value


def encode_username_for_storage(value: str | None) -> str:
    return encrypt_secret_value(value or "") or ""


def decode_username_from_storage(value: str | None) -> str | None:
    if value is None:
        return None
    if value == "":
        return ""
    if is_encrypted_storage_value(value):
        return decrypt_secret_value(value)
    if is_plaintext_hex_encoded(value):
        try:
            return bytes.fromhex(value).decode("latin-1")
        except (TypeError, ValueError):
            return value
    return value


def migrate_sensitive_storage_rows(batch_size: int = 1000) -> int:
    """Encrypt legacy persisted hash material and populate blind indexes."""
    migrated_rows = 0
    last_id = 0

    while True:
        rows = db.session.execute(
            select(Hashes)
            .where(Hashes.id > last_id)
            .order_by(Hashes.id.asc())
            .limit(batch_size)
        ).scalars().all()
        if not rows:
            break

        changed = False
        for row in rows:
            last_id = row.id
            expected_ciphertext_digest = get_ciphertext_search_digest(
                decode_ciphertext_from_storage(row.ciphertext)
            )
            if expected_ciphertext_digest and row.sub_ciphertext != expected_ciphertext_digest:
                row.sub_ciphertext = expected_ciphertext_digest
                changed = True
                migrated_rows += 1
            if row.ciphertext and not is_encrypted_storage_value(row.ciphertext):
                row.ciphertext = encode_ciphertext_for_storage(row.ciphertext)
                changed = True
                migrated_rows += 1

            decoded_plaintext = decode_plaintext_from_storage(row.plaintext)
            expected_plaintext_digest = get_plaintext_search_digest(decoded_plaintext)
            if row.plaintext_digest != expected_plaintext_digest:
                row.plaintext_digest = expected_plaintext_digest
                changed = True
                migrated_rows += 1
            if row.plaintext is not None and not is_encrypted_storage_value(row.plaintext):
                row.plaintext = encode_plaintext_for_storage(decoded_plaintext)
                changed = True
                migrated_rows += 1

        if changed:
            db.session.commit()

    association_last_id = 0
    while True:
        associations = db.session.execute(
            select(HashfileHashes)
            .where(HashfileHashes.id > association_last_id)
            .order_by(HashfileHashes.id.asc())
            .limit(batch_size)
        ).scalars().all()
        if not associations:
            break

        changed = False
        for row in associations:
            association_last_id = row.id
            decoded_username = decode_username_from_storage(row.username)
            expected_username_digest = get_username_search_digest(decoded_username)
            if row.username_digest != expected_username_digest:
                row.username_digest = expected_username_digest or ""
                changed = True
                migrated_rows += 1
            if row.username and not is_encrypted_storage_value(row.username):
                row.username = encode_username_for_storage(decoded_username)
                changed = True
                migrated_rows += 1

        if changed:
            db.session.commit()

    return migrated_rows


def migrate_plaintext_storage_rows(batch_size: int = 1000) -> int:
    """Backward-compatible wrapper for sensitive-storage migration."""
    return migrate_sensitive_storage_rows(batch_size=batch_size)
