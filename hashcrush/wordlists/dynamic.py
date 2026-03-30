"""Dynamic wordlist rebuild helpers."""

from __future__ import annotations

import os
from datetime import UTC, datetime

from sqlalchemy import select

from hashcrush.models import Hashes, HashfileHashes, Hashfiles, Wordlists, db
from hashcrush.utils.file_ops import get_filehash, get_linecount
from hashcrush.utils.secret_storage import decode_plaintext_from_storage
from hashcrush.utils.storage_paths import resolve_stored_path


def update_dynamic_wordlist(wordlist_id, *, commit=True):
    """Update a managed dynamic wordlist from recovered plaintexts."""
    wordlist = db.session.get(Wordlists, wordlist_id)
    if not wordlist:
        return False

    plaintext_stmt = (
        select(Hashes.plaintext)
        .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
        .join(Hashfiles, HashfileHashes.hashfile_id == Hashfiles.id)
        .where(Hashes.cracked.is_(True))
        .where(Hashes.plaintext.isnot(None))
        .distinct()
    )
    plaintext_rows = db.session.execute(plaintext_stmt).scalars().all()

    resolved_path = resolve_stored_path(wordlist.path)
    os.makedirs(os.path.dirname(resolved_path), exist_ok=True)

    with open(resolved_path, "w") as handle:
        for plaintext in plaintext_rows:
            decoded_plaintext = decode_plaintext_from_storage(plaintext)
            if decoded_plaintext is not None:
                handle.write(decoded_plaintext + "\n")

    wordlist.size = get_linecount(resolved_path)
    wordlist.checksum = get_filehash(resolved_path)
    wordlist.last_updated = datetime.now(UTC).replace(tzinfo=None)
    if commit:
        db.session.commit()
    return True


def update_all_dynamic_wordlists() -> int:
    """Rebuild all managed dynamic wordlists from cracked plaintexts."""
    dynamic_wordlists = db.session.execute(
        select(Wordlists)
        .where(Wordlists.type == "dynamic")
        .order_by(Wordlists.id.asc())
    ).scalars().all()
    if not dynamic_wordlists:
        return 0

    updated = 0
    for wordlist in dynamic_wordlists:
        if update_dynamic_wordlist(wordlist.id, commit=False):
            updated += 1

    if updated:
        db.session.commit()
    return updated
