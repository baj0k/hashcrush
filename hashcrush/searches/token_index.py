"""Blind-indexed trigram search token helpers."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from sqlalchemy import delete, select

from hashcrush.crypto_utils import blind_index
from hashcrush.models import HashSearchTokens, Hashes, HashfileHashSearchTokens, HashfileHashes, db
from hashcrush.utils.secret_storage import (
    decode_ciphertext_from_storage,
    decode_plaintext_from_storage,
    decode_username_from_storage,
)

SEARCH_SCOPE_HASH = "hash"
SEARCH_SCOPE_PASSWORD = "password"
SEARCH_SCOPE_USERNAME = "user"
SEARCH_TOKEN_NGRAM_SIZE = 3


def normalize_partial_search_text(value: str | None) -> str:
    """Normalize a value for case-insensitive substring indexing."""

    return str(value or "").casefold()


def partial_search_token_digests(
    value: str | None,
    *,
    scope: str,
) -> list[str]:
    """Return blind-indexed trigram digests for the normalized value."""

    normalized_value = normalize_partial_search_text(value)
    if len(normalized_value) < SEARCH_TOKEN_NGRAM_SIZE:
        return []

    seen: set[str] = set()
    digests: list[str] = []
    last_start = len(normalized_value) - SEARCH_TOKEN_NGRAM_SIZE + 1
    for start_index in range(last_start):
        token = normalized_value[start_index : start_index + SEARCH_TOKEN_NGRAM_SIZE]
        if token in seen:
            continue
        seen.add(token)
        digest = blind_index(
            token,
            purpose=f"search_token:{scope}",
            length=64,
        )
        if digest:
            digests.append(digest)
    return digests


def _normalize_id_sequence(ids: Iterable[int]) -> list[int]:
    seen: set[int] = set()
    ordered: list[int] = []
    for raw_id in ids:
        try:
            normalized_id = int(raw_id)
        except (TypeError, ValueError):
            continue
        if normalized_id <= 0 or normalized_id in seen:
            continue
        seen.add(normalized_id)
        ordered.append(normalized_id)
    return ordered


def _hash_token_rows_for_records(
    records: Sequence[tuple[int, str | None, str | None]],
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for hash_id, ciphertext, plaintext in records:
        ciphertext_value = decode_ciphertext_from_storage(ciphertext)
        for token_digest in partial_search_token_digests(
            ciphertext_value,
            scope=SEARCH_SCOPE_HASH,
        ):
            rows.append(
                {
                    "hash_id": int(hash_id),
                    "search_scope": SEARCH_SCOPE_HASH,
                    "token_digest": token_digest,
                }
            )

        plaintext_value = decode_plaintext_from_storage(plaintext)
        for token_digest in partial_search_token_digests(
            plaintext_value,
            scope=SEARCH_SCOPE_PASSWORD,
        ):
            rows.append(
                {
                    "hash_id": int(hash_id),
                    "search_scope": SEARCH_SCOPE_PASSWORD,
                    "token_digest": token_digest,
                }
            )
    return rows


def _hashfile_hash_token_rows_for_records(
    records: Sequence[tuple[int, str | None]],
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for hashfile_hash_id, username in records:
        username_value = decode_username_from_storage(username)
        for token_digest in partial_search_token_digests(
            username_value,
            scope=SEARCH_SCOPE_USERNAME,
        ):
            rows.append(
                {
                    "hashfile_hash_id": int(hashfile_hash_id),
                    "search_scope": SEARCH_SCOPE_USERNAME,
                    "token_digest": token_digest,
                }
            )
    return rows


def sync_hash_search_tokens(hash_ids: Iterable[int], *, commit: bool = True) -> int:
    """Rebuild blind-indexed search tokens for the selected hashes."""

    normalized_ids = _normalize_id_sequence(hash_ids)
    if not normalized_ids:
        return 0

    records = [
        (int(hash_id), ciphertext, plaintext)
        for hash_id, ciphertext, plaintext in db.session.execute(
            select(Hashes.id, Hashes.ciphertext, Hashes.plaintext).where(
                Hashes.id.in_(normalized_ids)
            )
        ).all()
    ]
    db.session.execute(
        delete(HashSearchTokens).where(HashSearchTokens.hash_id.in_(normalized_ids))
    )
    token_rows = _hash_token_rows_for_records(records)
    if token_rows:
        db.session.execute(HashSearchTokens.__table__.insert(), token_rows)
    if commit:
        db.session.commit()
    return len(token_rows)


def sync_hashfile_hash_search_tokens(
    hashfile_hash_ids: Iterable[int],
    *,
    commit: bool = True,
) -> int:
    """Rebuild blind-indexed search tokens for the selected hashfile links."""

    normalized_ids = _normalize_id_sequence(hashfile_hash_ids)
    if not normalized_ids:
        return 0

    records = [
        (int(hashfile_hash_id), username)
        for hashfile_hash_id, username in db.session.execute(
            select(HashfileHashes.id, HashfileHashes.username).where(
                HashfileHashes.id.in_(normalized_ids)
            )
        ).all()
    ]
    db.session.execute(
        delete(HashfileHashSearchTokens).where(
            HashfileHashSearchTokens.hashfile_hash_id.in_(normalized_ids)
        )
    )
    token_rows = _hashfile_hash_token_rows_for_records(records)
    if token_rows:
        db.session.execute(HashfileHashSearchTokens.__table__.insert(), token_rows)
    if commit:
        db.session.commit()
    return len(token_rows)


def migrate_search_token_rows(batch_size: int = 1000) -> int:
    """Backfill search-token indexes for existing hashes and hashfile links."""

    inserted_count = 0
    last_hash_id = 0
    while True:
        hash_records = [
            (int(hash_id), ciphertext, plaintext)
            for hash_id, ciphertext, plaintext in db.session.execute(
                select(Hashes.id, Hashes.ciphertext, Hashes.plaintext)
                .where(Hashes.id > last_hash_id)
                .order_by(Hashes.id.asc())
                .limit(batch_size)
            ).all()
        ]
        if not hash_records:
            break
        hash_ids = [hash_id for hash_id, _, _ in hash_records]
        db.session.execute(
            delete(HashSearchTokens).where(HashSearchTokens.hash_id.in_(hash_ids))
        )
        hash_token_rows = _hash_token_rows_for_records(hash_records)
        if hash_token_rows:
            db.session.execute(HashSearchTokens.__table__.insert(), hash_token_rows)
            inserted_count += len(hash_token_rows)
        db.session.commit()
        last_hash_id = hash_ids[-1]

    last_hashfile_hash_id = 0
    while True:
        link_records = [
            (int(hashfile_hash_id), username)
            for hashfile_hash_id, username in db.session.execute(
                select(HashfileHashes.id, HashfileHashes.username)
                .where(HashfileHashes.id > last_hashfile_hash_id)
                .order_by(HashfileHashes.id.asc())
                .limit(batch_size)
            ).all()
        ]
        if not link_records:
            break
        link_ids = [hashfile_hash_id for hashfile_hash_id, _ in link_records]
        db.session.execute(
            delete(HashfileHashSearchTokens).where(
                HashfileHashSearchTokens.hashfile_hash_id.in_(link_ids)
            )
        )
        link_token_rows = _hashfile_hash_token_rows_for_records(link_records)
        if link_token_rows:
            db.session.execute(
                HashfileHashSearchTokens.__table__.insert(),
                link_token_rows,
            )
            inserted_count += len(link_token_rows)
        db.session.commit()
        last_hashfile_hash_id = link_ids[-1]

    return inserted_count
