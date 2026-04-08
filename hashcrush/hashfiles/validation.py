"""Hashfile parsing, import, and validation helpers."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from flask import current_app, has_app_context
from sqlalchemy import select

from hashcrush.domains.service import (
    extract_domain_name_from_username,
    normalize_domain_name,
)
from hashcrush.models import Hashes, HashfileHashes, db
from hashcrush.utils.file_ops import get_md5_hash
from hashcrush.utils.secret_storage import (
    encode_ciphertext_for_storage,
    encode_username_for_storage,
    get_ciphertext_search_digest,
    get_username_search_digest,
)

DEFAULT_HASHFILE_MAX_LINE_LENGTH = 50_000
DEFAULT_HASHFILE_MAX_TOTAL_LINES = 1_000_000
DEFAULT_HASHFILE_MAX_TOTAL_BYTES = 1024 * 1024 * 1024
WINDOWS_PWDUMP_FILE_TYPES = frozenset({"pwdump", "secretsdump"})
IMPORT_BATCH_SIZE = 1000


@dataclass(frozen=True)
class _PreparedImportRow:
    hash_value: str
    normalized_hash_type: int
    preferred_digest: str
    alternate_digest: str | None
    encoded_username: str
    username_digest: str
    domain_name: str | None


def _get_hashfile_validation_limit(
    config_key: str,
    default: int,
    minimum: int = 1,
) -> int:
    if not has_app_context():
        return default
    value = current_app.config.get(config_key, default)
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    if parsed < minimum:
        return default
    return parsed


def _iter_hashfile_lines(hashfile_path: str, progress_callback=None):
    max_line_length = _get_hashfile_validation_limit(
        "HASHFILE_MAX_LINE_LENGTH",
        DEFAULT_HASHFILE_MAX_LINE_LENGTH,
    )
    max_total_bytes = _get_hashfile_validation_limit(
        "HASHFILE_MAX_TOTAL_BYTES",
        DEFAULT_HASHFILE_MAX_TOTAL_BYTES,
    )
    max_total_lines = _get_hashfile_validation_limit(
        "HASHFILE_MAX_TOTAL_LINES",
        DEFAULT_HASHFILE_MAX_TOTAL_LINES,
    )

    total_bytes = 0
    try:
        file_size = os.path.getsize(hashfile_path)
    except OSError:
        file_size = 0

    with open(hashfile_path, "rb") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            if line_number > max_total_lines:
                raise ValueError(
                    f"Error: Hashfile has too many lines ({line_number:,}). "
                    f"Max lines is {max_total_lines:,}."
                )
            total_bytes += len(raw_line)
            if total_bytes > max_total_bytes:
                raise ValueError(
                    f"Error: Hashfile is too large ({total_bytes:,} bytes). "
                    f"Max size is {max_total_bytes:,} bytes."
                )
            if len(raw_line) > max_line_length:
                raise ValueError(
                    "Error line "
                    + str(line_number)
                    + " is too long. Line length: "
                    + str(len(raw_line))
                    + ". Max length is "
                    + f"{max_line_length:,}"
                    + " chars."
                )

            if progress_callback is not None:
                progress_callback(total_bytes, file_size)

            yield line_number, raw_line.decode("utf-8", errors="replace")

    if progress_callback is not None:
        progress_callback(total_bytes, file_size)


def normalize_hash_type(hash_type):
    """Normalize form/request hash types to the integer DB representation."""
    try:
        return int(str(hash_type).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid hash type: {hash_type!r}") from exc


def normalize_hashfile_file_type(file_type: str | None) -> str | None:
    """Map equivalent Windows dump formats onto the canonical parser name."""
    if file_type in WINDOWS_PWDUMP_FILE_TYPES:
        return "pwdump"
    return file_type


def import_hash_only(line, hash_type):
    """Import a single normalized hash row."""
    normalized_hash_type = normalize_hash_type(hash_type)
    current_digest = get_ciphertext_search_digest(line)
    legacy_digest = get_md5_hash(line)

    hash_row = db.session.scalar(
        select(Hashes)
        .where(Hashes.hash_type == normalized_hash_type)
        .where(
            Hashes.sub_ciphertext.in_(
                [value for value in (current_digest, legacy_digest) if value]
            )
        )
    )

    if hash_row:
        return hash_row.id

    new_hash = Hashes(
        hash_type=normalized_hash_type,
        sub_ciphertext=current_digest or legacy_digest,
        ciphertext=encode_ciphertext_for_storage(line),
        cracked=0,
        plaintext_digest=None,
    )
    db.session.add(new_hash)
    db.session.flush()
    return new_hash.id


def _normalize_hashfile_import_row(
    *,
    line: str,
    file_type: str | None,
    hash_type: str,
) -> tuple[str, int, str | None, str | None] | None:
    file_type = normalize_hashfile_file_type(file_type)

    if file_type == "hash_only":
        hash_value = line
        if hash_type in ("300", "1731"):
            hash_value = hash_value.lower()
        elif hash_type == "2100":
            hash_value = hash_value.lower().replace("$dcc2$", "$DCC2$")
        username = None
        if hash_type == "2100":
            dcc_parts = hash_value.split("#")
            username = dcc_parts[1] if len(dcc_parts) >= 3 else None
        return (
            hash_value,
            normalize_hash_type(hash_type),
            username,
            extract_domain_name_from_username(username),
        )

    if file_type == "user_hash":
        if ":" not in line:
            raise ValueError("Invalid user_hash line")
        username, hash_value = line.split(":", 1)
        hash_value = hash_value.rstrip()
        if hash_type in ("300", "1731"):
            hash_value = hash_value.lower()
        elif hash_type == "2100":
            hash_value = hash_value.lower().replace("$dcc2$", "$DCC2$")
        return (
            hash_value,
            normalize_hash_type(hash_type),
            username,
            extract_domain_name_from_username(username),
        )

    if file_type == "shadow":
        line_parts = line.split(":")
        if len(line_parts) < 2:
            raise ValueError("Invalid shadow line")
        username = line_parts[0]
        return (
            line_parts[1],
            normalize_hash_type(hash_type),
            username,
            extract_domain_name_from_username(username),
        )

    if file_type == "pwdump":
        line_parts = line.split(":")
        if len(line_parts) < 4:
            raise ValueError("Invalid pwdump line")
        if re.search(r"\$$", line_parts[0]):
            return None
        username = line_parts[0]
        return (
            line_parts[3].lower(),
            1000,
            username,
            extract_domain_name_from_username(username),
        )

    if file_type == "kerberos":
        hash_value = line.lower()
        kerberos_parts = hash_value.split("$")
        if len(kerberos_parts) <= 3:
            raise ValueError("Invalid kerberos line")
        username = (
            kerberos_parts[3].split(":")[0]
            if hash_type == "18200"
            else kerberos_parts[3]
        )
        return (
            hash_value,
            normalize_hash_type(hash_type),
            username,
            extract_domain_name_from_username(username),
        )

    if file_type == "NetNTLM":
        line_list = line.split(":")
        if len(line_list) < 6:
            raise ValueError("Invalid NetNTLM line")
        if re.search(r"\$$", line_list[0]):
            return None
        line_list[0] = line_list[0].upper()
        line_list[3] = line_list[3].lower()
        line_list[4] = line_list[4].lower()
        line_list[5] = line_list[5].lower()
        normalized_line = ":".join(line_list)
        username = line_list[0]
        return (
            normalized_line,
            normalize_hash_type(hash_type),
            username,
            extract_domain_name_from_username(username),
        )

    raise ValueError("Invalid hashfile format")


def _prepare_import_row(
    *,
    line: str,
    file_type: str | None,
    hash_type: str,
    default_domain_name: str | None = None,
) -> _PreparedImportRow | None:
    normalized_row = _normalize_hashfile_import_row(
        line=line,
        file_type=file_type,
        hash_type=hash_type,
    )
    if normalized_row is None:
        return None

    hash_value, normalized_hash_type, username, inferred_domain_name = normalized_row
    current_digest = get_ciphertext_search_digest(hash_value)
    legacy_digest = get_md5_hash(hash_value)
    preferred_digest = current_digest or legacy_digest

    encoded_username = ""
    username_digest = ""
    if username is not None:
        normalized_username = username.encode("latin-1", errors="replace").decode(
            "latin-1"
        )
        encoded_username = encode_username_for_storage(normalized_username)
        username_digest = get_username_search_digest(normalized_username) or ""

    return _PreparedImportRow(
        hash_value=hash_value,
        normalized_hash_type=normalized_hash_type,
        preferred_digest=preferred_digest,
        alternate_digest=legacy_digest if legacy_digest != preferred_digest else None,
        encoded_username=encoded_username,
        username_digest=username_digest,
        domain_name=inferred_domain_name or normalize_domain_name(default_domain_name),
    )


def _flush_import_batch(
    *,
    hashfile_id: int,
    batch_rows: list[_PreparedImportRow],
) -> None:
    if not batch_rows:
        return

    rows_by_hash_type: dict[int, list[_PreparedImportRow]] = {}
    for row in batch_rows:
        rows_by_hash_type.setdefault(row.normalized_hash_type, []).append(row)

    row_hash_ids: dict[_PreparedImportRow, int] = {}
    for normalized_hash_type, typed_rows in rows_by_hash_type.items():
        digest_values = sorted(
            {
                digest
                for row in typed_rows
                for digest in (row.preferred_digest, row.alternate_digest)
                if digest
            }
        )
        existing_rows = (
            db.session.execute(
                select(Hashes).where(
                    Hashes.hash_type == normalized_hash_type,
                    Hashes.sub_ciphertext.in_(digest_values),
                )
            ).scalars().all()
            if digest_values
            else []
        )
        existing_by_digest = {
            hash_row.sub_ciphertext: hash_row.id for hash_row in existing_rows
        }

        new_hashes_by_digest: dict[str, Hashes] = {}
        for row in typed_rows:
            hash_id = existing_by_digest.get(row.preferred_digest)
            if hash_id is None and row.alternate_digest is not None:
                hash_id = existing_by_digest.get(row.alternate_digest)
            if hash_id is not None:
                row_hash_ids[row] = hash_id
                continue
            if row.preferred_digest not in new_hashes_by_digest:
                new_hash = Hashes(
                    hash_type=normalized_hash_type,
                    sub_ciphertext=row.preferred_digest,
                    ciphertext=encode_ciphertext_for_storage(row.hash_value),
                    cracked=0,
                    plaintext_digest=None,
                )
                db.session.add(new_hash)
                new_hashes_by_digest[row.preferred_digest] = new_hash

        if new_hashes_by_digest:
            db.session.flush()
            for digest, new_hash in new_hashes_by_digest.items():
                existing_by_digest[digest] = new_hash.id

        for row in typed_rows:
            if row in row_hash_ids:
                continue
            hash_id = existing_by_digest.get(row.preferred_digest)
            if hash_id is None and row.alternate_digest is not None:
                hash_id = existing_by_digest.get(row.alternate_digest)
            if hash_id is None:
                raise ValueError("Unable to resolve imported hash id")
            row_hash_ids[row] = hash_id

    hash_ids = sorted({row_hash_ids[row] for row in batch_rows})
    domain_names = sorted({row.domain_name for row in batch_rows if row.domain_name})
    domain_ids_by_name: dict[str, int] = {}
    if domain_names:
        from hashcrush.domains.service import get_or_create_domain_by_name

        for domain_name in domain_names:
            domain = get_or_create_domain_by_name(domain_name)
            if domain is not None:
                domain_ids_by_name[domain_name] = int(domain.id)

    username_digests = sorted({row.username_digest for row in batch_rows})
    existing_links = (
        db.session.execute(
            select(HashfileHashes.hash_id, HashfileHashes.username_digest).where(
                HashfileHashes.hashfile_id == hashfile_id,
                HashfileHashes.hash_id.in_(hash_ids),
                HashfileHashes.username_digest.in_(username_digests),
            )
        ).all()
        if hash_ids
        else []
    )
    existing_pairs = {
        (int(hash_id), str(username_digest))
        for hash_id, username_digest in existing_links
    }

    pending_pairs: set[tuple[int, str]] = set()
    new_links: list[HashfileHashes] = []
    for row in batch_rows:
        hash_id = row_hash_ids[row]
        pair = (hash_id, row.username_digest)
        if pair in existing_pairs or pair in pending_pairs:
            continue
        pending_pairs.add(pair)
        new_links.append(
            HashfileHashes(
                hash_id=hash_id,
                username=row.encoded_username,
                username_digest=row.username_digest,
                hashfile_id=hashfile_id,
                domain_id=domain_ids_by_name.get(row.domain_name)
                if row.domain_name
                else None,
            )
        )

    if new_links:
        db.session.add_all(new_links)

    db.session.flush()
    db.session.expunge_all()


def import_hashfilehashes(
    hashfile_id,
    hashfile_path,
    file_type,
    hash_type,
    default_domain_name=None,
    progress_callback=None,
):
    """Import all hashes from a staged hashfile into DB associations."""
    file_type = normalize_hashfile_file_type(file_type)
    normalized_default_domain_name = normalize_domain_name(default_domain_name)
    try:
        total_bytes = os.path.getsize(hashfile_path) if progress_callback is not None else 0
    except OSError:
        total_bytes = 0

    processed_bytes = 0
    batch_rows: list[_PreparedImportRow] = []
    try:
        with open(hashfile_path, "rb") as handle:
            for raw_line in handle:
                processed_bytes += len(raw_line)
                line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                if not line:
                    if progress_callback is not None:
                        progress_callback(processed_bytes, total_bytes)
                    continue

                prepared_row = _prepare_import_row(
                    line=line,
                    file_type=file_type,
                    hash_type=hash_type,
                    default_domain_name=normalized_default_domain_name,
                )
                if prepared_row is not None:
                    batch_rows.append(prepared_row)
                    if len(batch_rows) >= IMPORT_BATCH_SIZE:
                        _flush_import_batch(
                            hashfile_id=hashfile_id,
                            batch_rows=batch_rows,
                        )
                        batch_rows.clear()

                if progress_callback is not None:
                    progress_callback(processed_bytes, total_bytes)

        if batch_rows:
            _flush_import_batch(
                hashfile_id=hashfile_id,
                batch_rows=batch_rows,
            )

    except ValueError:
        db.session.rollback()
        return False

    db.session.commit()
    if progress_callback is not None:
        progress_callback(total_bytes, total_bytes)
    return True


def validate_pwdump_hashfile(hashfile_path, hash_type, progress_callback=None):
    """Validate a Windows pwdump style hashfile."""
    try:
        for line_number, line in _iter_hashfile_lines(
            hashfile_path,
            progress_callback=progress_callback,
        ):
            line = line.rstrip("\r\n")
            if len(line) == 0:
                continue
            if ":" not in line:
                return (
                    "Error line "
                    + str(line_number)
                    + " is missing a : character. Windows pwdump files should include usernames."
                )
            colon_cnt = line.count(":")
            if colon_cnt < 6:
                return (
                    "Error line "
                    + str(line_number)
                    + ". File does not appear to be in a Windows pwdump format."
                )
            if hash_type == "1000":
                line_parts = line.split(":")
                if len(line_parts) < 4 or len(line_parts[3]) != 32:
                    return (
                        "Error line "
                        + str(line_number)
                        + " has an invalid number of characters ("
                        + str(len(line.rstrip()))
                        + ") should be 32"
                    )
            else:
                return (
                    "Sorry. The only hash type we support for Windows pwdump files is NTLM."
                )
    except ValueError as error:
        return str(error)
    return False


def validate_netntlm_hashfile(hashfile_path, progress_callback=None):
    """Validate that a submitted hashfile matches NetNTLM format."""
    list_of_username_and_computers = set()
    try:
        for line_number, line in _iter_hashfile_lines(
            hashfile_path,
            progress_callback=progress_callback,
        ):
            line = line.rstrip("\r\n")
            if len(line) == 0:
                continue
            if ":" not in line:
                return (
                    "Error line "
                    + str(line_number)
                    + " is missing a : character. NetNTLM file should include usernames."
                )
            colon_cnt = line.count(":")
            if colon_cnt < 5:
                return (
                    "Error line "
                    + str(line_number)
                    + ". File does not appear to be be in a NetNTLM format."
                )

            line_parts = line.split(":")
            username_computer = (line_parts[0] + ":" + line_parts[2]).lower()
            if username_computer in list_of_username_and_computers:
                return (
                    "Error: Duplicate usernames / computer found in hashfiles ("
                    + str(username_computer)
                    + "). Please only submit unique usernames / computer."
                )
            list_of_username_and_computers.add(username_computer)
    except ValueError as error:
        return str(error)
    return False


def validate_kerberos_hashfile(hashfile_path, hash_type, progress_callback=None):
    """Validate that a submitted hashfile matches Kerberos format."""
    try:
        for line_number, line in _iter_hashfile_lines(
            hashfile_path,
            progress_callback=progress_callback,
        ):
            line = line.rstrip("\r\n")
            if len(line) == 0:
                continue
            if "$" not in line:
                return (
                    "Error line "
                    + str(line_number)
                    + " is missing a $ character. kerberos file should include these."
                )
            dollar_cnt = line.count("$")
            line_parts = line.split("$")

            if hash_type == "7500":
                if dollar_cnt != 6:
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: Kerberos 5, etype 23, AS-REQ Pre-Auth (1)"
                    )
                if line_parts[1] != "krb5pa":
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: Kerberos 5, etype 23, AS-REQ Pre-Auth (2)"
                    )
                if line_parts[2] != "23":
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: Kerberos 5, etype 23, AS-REQ Pre-Auth (3)"
                    )
            elif hash_type == "13100":
                if dollar_cnt != 7 and dollar_cnt != 8:
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: Kerberos 5, etype 23, TGS-REP (1)"
                    )
                if line_parts[1] != "krb5tgs":
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: Kerberos 5, etype 23, TGS-REP (2)"
                    )
                if line_parts[2] != "23":
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: Kerberos 5, etype 23, TGS-REP (3)"
                    )
            elif hash_type == "18200":
                if dollar_cnt != 4 and dollar_cnt != 5:
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: Kerberos 5, etype 23, AS-REP (1)"
                    )
                if line_parts[1] != "krb5asrep":
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: Kerberos 5, etype 23, AS-REP (2)"
                    )
                if line_parts[2] != "23":
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: Kerberos 5, etype 23, AS-REP (3)"
                    )
            elif hash_type == "19600":
                if dollar_cnt != 6 and dollar_cnt != 7:
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: Kerberos 5 TGS-REP etype 17 (AES128-CTS-HMAC-SHA1-96) (1)"
                    )
                if line_parts[1] != "krb5tgs":
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: Kerberos 5 TGS-REP etype 17 (AES128-CTS-HMAC-SHA1-96) (2)"
                    )
                if line_parts[2] != "17":
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: Kerberos 5 TGS-REP etype 17 (AES128-CTS-HMAC-SHA1-96) (3)"
                    )
            elif hash_type == "19700":
                if dollar_cnt != 6 and dollar_cnt != 7:
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: Kerberos 5 TGS-REP etype 18 (AES256-CTS-HMAC-SHA1-96) (1)"
                    )
                if line_parts[1] != "krb5tgs":
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: Kerberos 5 TGS-REP etype 18 (AES256-CTS-HMAC-SHA1-96) (2)"
                    )
                if line_parts[2] != "18":
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: Kerberos 5 TGS-REP etype 18 (AES256-CTS-HMAC-SHA1-96) (3)"
                    )
            elif hash_type == "19800":
                if dollar_cnt != 5 and dollar_cnt != 6:
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: Kerberos 5, etype 17, Pre-Auth (1)"
                    )
                if line_parts[1] != "krb5pa":
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: Kerberos 5, etype 17, Pre-Auth (2)"
                    )
                if line_parts[2] != "17":
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: Kerberos 5, etype 17, Pre-Auth (3)"
                    )
            elif hash_type == "19900":
                if dollar_cnt != 5 and dollar_cnt != 6:
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: Kerberos 5, etype 18, Pre-Auth (1)"
                    )
                if line_parts[1] != "krb5pa":
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: Kerberos 5, etype 18, Pre-Auth (2)"
                    )
                if line_parts[2] != "18":
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: Kerberos 5, etype 18, Pre-Auth (3)"
                    )
            else:
                return (
                    "Sorry. The only suppported Hash Types are: 7500, 13100, 18200, 19600, 19700, 19800 and 19900."
                )
    except ValueError as error:
        return str(error)
    return False


def validate_shadow_hashfile(hashfile_path, hash_type, progress_callback=None):
    """Validate that a submitted hashfile matches shadow format."""
    try:
        for line_number, line in _iter_hashfile_lines(
            hashfile_path,
            progress_callback=progress_callback,
        ):
            line = line.rstrip("\r\n")
            if len(line) == 0:
                continue
            if ":" not in line:
                return (
                    "Error line "
                    + str(line_number)
                    + " is missing a : character. shadow file should include usernames."
                )
            if hash_type == "1800":
                dollar_cnt = line.count("$")
                if dollar_cnt != 3:
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: Sha512 Crypt from a shadow file."
                    )
                if "$6$" not in line:
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: Sha512 Crypt from a shadow file."
                    )
    except ValueError as error:
        return str(error)
    return False


def validate_user_hash_hashfile(hashfile_path, progress_callback=None):
    """Validate that a submitted hashfile matches user:hash format."""
    try:
        for line_number, line in _iter_hashfile_lines(
            hashfile_path,
            progress_callback=progress_callback,
        ):
            line = line.rstrip("\r\n")
            if len(line) == 0:
                continue
            if ":" not in line:
                return (
                    "Error line "
                    + str(line_number)
                    + " is missing a : character. user:hash file should have just ONE of these"
                )
    except ValueError as error:
        return str(error)
    return False


def validate_hash_only_hashfile(hashfile_path, hash_type, progress_callback=None):
    """Validate that a submitted hashfile matches a hash-only format."""
    try:
        for line_number, line in _iter_hashfile_lines(
            hashfile_path,
            progress_callback=progress_callback,
        ):
            line = line.rstrip("\r\n")
            if len(line) == 0:
                continue

            if hash_type in ("0", "22", "1000") and len(line.rstrip()) != 32:
                return (
                    "Error line "
                    + str(line_number)
                    + " has an invalid number of characters ("
                    + str(len(line.rstrip()))
                    + ") should be 32"
                )
            if hash_type == "122" and len(line.rstrip()) != 50:
                return (
                    "Error line "
                    + str(line_number)
                    + " has an invalid number of characters ("
                    + str(len(line.rstrip()))
                    + ") should be 50"
                )
            if hash_type == "300" and len(line.rstrip()) != 40:
                return (
                    "Error line "
                    + str(line_number)
                    + " has an invalid number of characters ("
                    + str(len(line.rstrip()))
                    + ") should be 40"
                )
            if hash_type == "500" and "$1$" not in line:
                return (
                    "Error line "
                    + str(line_number)
                    + " is not a valid md5Crypt, MD5 (Unix) or Cisco-IOS $1$ (MD5) hash"
                )
            if hash_type == "1100" and ":" not in line:
                return (
                    "Error line "
                    + str(line_number)
                    + " is missing a : character. Domain Cached Credentials (DCC), MS Cache hashes should have one"
                )
            if hash_type == "1800":
                dollar_cnt = line.count("$")
                if dollar_cnt != 3:
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: Sha512 Crypt."
                    )
                if "$6$" not in line:
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: Sha512 Crypt."
                    )
            if hash_type == "2100":
                if "$" not in line:
                    return (
                        "Error line "
                        + str(line_number)
                        + " is missing a $ character. DCC2 Hashes should have these"
                    )
                dollar_cnt = line.count("$")
                hash_cnt = line.count("#")
                if dollar_cnt != 2:
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: DCC2 MS Cache"
                    )
                if hash_cnt != 2:
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: DCC2 MS Cache"
                    )
            if hash_type == "2400" and len(line.rstrip()) != 18:
                return (
                    "Error line "
                    + str(line_number)
                    + " has an invalid number of characters ("
                    + str(len(line.rstrip()))
                    + ") should be 18"
                )
            if hash_type == "2410" and ":" not in line:
                return (
                    "Error line "
                    + str(line_number)
                    + " is missing a : character. Cisco-ASA Hashes should have these."
                )
            if hash_type == "3200":
                if "$" not in line:
                    return (
                        "Error line "
                        + str(line_number)
                        + " is missing a $ character. bcrypt Hashes should have these."
                    )
                dollar_cnt = line.count("$")
                if dollar_cnt != 3:
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: bcrypt"
                    )
            if hash_type == "5700" and len(line.rstrip()) != 43:
                return (
                    "Error line "
                    + str(line_number)
                    + " has an invalid number of characters ("
                    + str(len(line.rstrip()))
                    + ") should be 43"
                )
            if hash_type == "7100":
                if "$" not in line:
                    return (
                        "Error line "
                        + str(line_number)
                        + " is missing a $ character. Mac OSX 10.8+ ($ml$) hashes should have these."
                    )
                dollar_cnt = line.count("$")
                if dollar_cnt != 2:
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Doesnt appear to be of the type: Mac OSX 10.8+ ($ml$)"
                    )
            if hash_type in ("9400", "9500", "9600"):
                if "$" not in line:
                    return (
                        "Error line "
                        + str(line_number)
                        + " is missing a $ character. Office hashes require 2."
                    )
                if "*" not in line:
                    return (
                        "Error line "
                        + str(line_number)
                        + " is missing a * character. Office hashes require 6."
                    )
                if line.count("*") != 7:
                    return (
                        "Error line "
                        + str(line_number)
                        + ". Does not appear to be of the type office."
                    )
    except ValueError as error:
        return str(error)

    return False
