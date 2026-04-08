"""Shared hashfile creation helpers."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass

from flask import current_app
from sqlalchemy import func, select

from hashcrush.models import HashfileHashes, Hashfiles, db
from hashcrush.hashfiles.validation import (
    import_hashfilehashes,
    normalize_hashfile_file_type,
    validate_hash_only_hashfile,
    validate_kerberos_hashfile,
    validate_netntlm_hashfile,
    validate_pwdump_hashfile,
    validate_shadow_hashfile,
    validate_user_hash_hashfile,
)
from hashcrush.utils.file_ops import save_file
from hashcrush.utils.storage_paths import get_runtime_subdir


@dataclass(frozen=True)
class HashfileCreationResult:
    """Details for a newly created shared hashfile."""

    hashfile: Hashfiles
    hash_type: str
    imported_hash_links: int


def _selected_hash_type(
    *,
    file_type: str | None,
    hash_type: str | None = None,
    pwdump_hash_type: str | None = None,
    netntlm_hash_type: str | None = None,
    kerberos_hash_type: str | None = None,
    shadow_hash_type: str | None = None,
) -> str | None:
    file_type = normalize_hashfile_file_type(file_type)
    if file_type == "pwdump":
        return pwdump_hash_type
    if file_type == "NetNTLM":
        return netntlm_hash_type
    if file_type == "kerberos":
        return kerberos_hash_type
    if file_type == "shadow":
        return shadow_hash_type
    if file_type in {"user_hash", "hash_only"}:
        return hash_type
    return None


def _validation_result(
    *,
    file_type: str | None,
    hash_type: str | None,
    hashfile_path: str,
    progress_callback=None,
) -> tuple[str | None, str | None]:
    file_type = normalize_hashfile_file_type(file_type)
    if file_type == "pwdump":
        return (
            validate_pwdump_hashfile(
                hashfile_path,
                hash_type,
                progress_callback=progress_callback,
            ),
            hash_type,
        )
    if file_type == "NetNTLM":
        return (
            validate_netntlm_hashfile(
                hashfile_path,
                progress_callback=progress_callback,
            ),
            hash_type,
        )
    if file_type == "kerberos":
        return (
            validate_kerberos_hashfile(
                hashfile_path,
                hash_type,
                progress_callback=progress_callback,
            ),
            hash_type,
        )
    if file_type == "shadow":
        return (
            validate_shadow_hashfile(
                hashfile_path,
                hash_type,
                progress_callback=progress_callback,
            ),
            hash_type,
        )
    if file_type == "user_hash":
        return (
            validate_user_hash_hashfile(
                hashfile_path,
                progress_callback=progress_callback,
            ),
            hash_type,
        )
    if file_type == "hash_only":
        return (
            validate_hash_only_hashfile(
                hashfile_path,
                hash_type,
                progress_callback=progress_callback,
            ),
            hash_type,
        )
    return "Invalid File Format", None


def create_hashfile_from_path(
    *,
    hashfile_path: str,
    hashfile_name: str,
    domain_id: int,
    file_type: str,
    hash_type: str,
    progress_callback=None,
) -> tuple[HashfileCreationResult | None, str | None]:
    """Create and import a shared hashfile from an already-saved file path."""
    file_type = normalize_hashfile_file_type(file_type) or file_type

    validation_error, normalized_hash_type = _validation_result(
        file_type=file_type,
        hash_type=hash_type,
        hashfile_path=hashfile_path,
        progress_callback=(
            (lambda current, total: progress_callback("validate", current, total))
            if progress_callback is not None
            else None
        ),
    )
    if validation_error:
        return None, validation_error
    if not normalized_hash_type:
        return None, "Hash type is required for this hashfile format."

    hashfile = Hashfiles(name=hashfile_name, domain_id=domain_id)
    db.session.add(hashfile)
    db.session.flush()
    persisted_hashfile_id = int(hashfile.id)

    if not import_hashfilehashes(
        hashfile_id=persisted_hashfile_id,
        hashfile_path=hashfile_path,
        file_type=file_type,
        hash_type=normalized_hash_type,
        progress_callback=(
            (lambda current, total: progress_callback("import", current, total))
            if progress_callback is not None
            else None
        ),
    ):
        db.session.rollback()
        return (
            None,
            "Failed importing hashfile. Check file format/hash type and retry.",
        )

    persisted_hashfile = db.session.get(Hashfiles, persisted_hashfile_id)
    if persisted_hashfile is None:
        db.session.rollback()
        return None, "Failed importing hashfile. Refresh and retry."

    imported_hash_links = int(
        db.session.scalar(
            select(func.count())
            .select_from(HashfileHashes)
            .filter_by(hashfile_id=persisted_hashfile_id)
        )
        or 0
    )
    return (
        HashfileCreationResult(
            hashfile=persisted_hashfile,
            hash_type=str(normalized_hash_type),
            imported_hash_links=imported_hash_links,
        ),
        None,
    )


def create_hashfile_from_form(
    form,
    *,
    domain_id: int,
) -> tuple[HashfileCreationResult | None, str | None]:
    """Create and import a shared hashfile from a form submission."""

    runtime_tmp_dir = get_runtime_subdir("tmp")
    os.makedirs(runtime_tmp_dir, exist_ok=True)

    hashfile_path = ""
    try:
        if form.hashfile.data:
            hashfile_path = save_file(runtime_tmp_dir, form.hashfile.data)
        elif form.hashfilehashes.data:
            if len(form.name.data or "") == 0:
                return None, "You must assign a name to the hashfile."
            random_hex = secrets.token_hex(8)
            hashfile_path = os.path.join(runtime_tmp_dir, random_hex)
            with open(hashfile_path, "w", encoding="utf-8") as handle:
                handle.write(form.hashfilehashes.data)
        else:
            return None, "You must provide either a hashfile upload or pasted hashes."

        hashfile_name = form.name.data
        if not hashfile_name and form.hashfile.data:
            hashfile_name = form.hashfile.data.filename
        hashfile_name = hashfile_name or f"hashfile_{secrets.token_hex(4)}.txt"

        return create_hashfile_from_path(
            hashfile_path=hashfile_path,
            hashfile_name=hashfile_name,
            domain_id=domain_id,
            file_type=form.file_type.data,
            hash_type=(
                _selected_hash_type(
                    file_type=form.file_type.data,
                    hash_type=form.hash_type.data,
                    pwdump_hash_type=form.pwdump_hash_type.data,
                    netntlm_hash_type=form.netntlm_hash_type.data,
                    kerberos_hash_type=form.kerberos_hash_type.data,
                    shadow_hash_type=form.shadow_hash_type.data,
                )
                or ""
            ),
        )
    finally:
        if hashfile_path and os.path.isfile(hashfile_path):
            try:
                os.remove(hashfile_path)
            except OSError:
                current_app.logger.warning(
                    "Failed to remove temporary hash upload file: %s", hashfile_path
                )
