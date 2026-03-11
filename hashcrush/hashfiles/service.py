"""Shared hashfile creation helpers."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass

from flask import current_app
from sqlalchemy import func, select

from hashcrush.models import HashfileHashes, Hashfiles, db
from hashcrush.utils.utils import (
    get_runtime_subdir,
    import_hashfilehashes,
    save_file,
    validate_hash_only_hashfile,
    validate_kerberos_hashfile,
    validate_netntlm_hashfile,
    validate_pwdump_hashfile,
    validate_shadow_hashfile,
    validate_user_hash_hashfile,
)


@dataclass(frozen=True)
class HashfileCreationResult:
    """Details for a newly created shared hashfile."""

    hashfile: Hashfiles
    hash_type: str
    imported_hash_links: int


def _validation_result(form, hashfile_path: str) -> tuple[str | None, str | None]:
    if form.file_type.data == "pwdump":
        return (
            validate_pwdump_hashfile(hashfile_path, form.pwdump_hash_type.data),
            form.pwdump_hash_type.data,
        )
    if form.file_type.data == "NetNTLM":
        return (
            validate_netntlm_hashfile(hashfile_path),
            form.netntlm_hash_type.data,
        )
    if form.file_type.data == "kerberos":
        return (
            validate_kerberos_hashfile(hashfile_path, form.kerberos_hash_type.data),
            form.kerberos_hash_type.data,
        )
    if form.file_type.data == "shadow":
        return (
            validate_shadow_hashfile(hashfile_path, form.shadow_hash_type.data),
            form.shadow_hash_type.data,
        )
    if form.file_type.data == "user_hash":
        return validate_user_hash_hashfile(hashfile_path), form.hash_type.data
    if form.file_type.data == "hash_only":
        return (
            validate_hash_only_hashfile(hashfile_path, form.hash_type.data),
            form.hash_type.data,
        )
    return "Invalid File Format", None


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

        validation_error, hash_type = _validation_result(form, hashfile_path)
        if validation_error:
            return None, validation_error
        if not hash_type:
            return None, "Hash type is required for this hashfile format."

        hashfile_name = form.name.data
        if not hashfile_name and form.hashfile.data:
            hashfile_name = form.hashfile.data.filename
        hashfile_name = hashfile_name or f"hashfile_{secrets.token_hex(4)}.txt"

        hashfile = Hashfiles(name=hashfile_name, domain_id=domain_id)
        db.session.add(hashfile)
        db.session.flush()

        if not import_hashfilehashes(
            hashfile_id=hashfile.id,
            hashfile_path=hashfile_path,
            file_type=form.file_type.data,
            hash_type=hash_type,
        ):
            db.session.rollback()
            return (
                None,
                "Failed importing hashfile. Check file format/hash type and retry.",
            )

        imported_hash_links = int(
            db.session.scalar(
                select(func.count())
                .select_from(HashfileHashes)
                .filter_by(hashfile_id=hashfile.id)
            )
            or 0
        )
        return (
            HashfileCreationResult(
                hashfile=hashfile,
                hash_type=str(hash_type),
                imported_hash_links=imported_hash_links,
            ),
            None,
        )
    finally:
        if hashfile_path and os.path.isfile(hashfile_path):
            try:
                os.remove(hashfile_path)
            except OSError:
                current_app.logger.warning(
                    "Failed to remove temporary hash upload file: %s", hashfile_path
                )
