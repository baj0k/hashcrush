"""Generic file and hashing helpers."""

from __future__ import annotations

import _md5
import hashlib
import os
import secrets

from flask import current_app
from werkzeug.utils import secure_filename


def save_file(path, form_file):
    """Persist an uploaded file under a randomized safe filename."""
    random_hex = secrets.token_hex(8)
    original_name = (
        secure_filename(os.path.basename(form_file.filename or "upload.txt"))
        or "upload.txt"
    )
    file_name = f"{random_hex}_{original_name}"
    target_dir = path if os.path.isabs(path) else os.path.join(current_app.root_path, path)
    os.makedirs(target_dir, exist_ok=True)
    file_path = os.path.join(target_dir, file_name)
    form_file.save(file_path)
    return file_path


def _count_generator(reader):
    block = reader(1024 * 1024)
    while block:
        yield block
        block = reader(1024 * 1024)


def get_linecount(filepath, progress_callback=None):
    """Return the number of logical lines in a file."""
    try:
        file_size = os.path.getsize(filepath)
    except OSError:
        file_size = 0

    with open(filepath, "rb") as handle:
        count = 0
        has_content = False
        trailing_newline = False
        total_bytes = 0
        for buffer in _count_generator(handle.raw.read):
            if not buffer:
                continue
            has_content = True
            total_bytes += len(buffer)
            count += buffer.count(b"\n")
            trailing_newline = buffer.endswith(b"\n")
            if progress_callback is not None:
                progress_callback(total_bytes, file_size)

        if not has_content:
            if progress_callback is not None:
                progress_callback(0, file_size)
            return 0
        if trailing_newline:
            if progress_callback is not None:
                progress_callback(total_bytes, file_size)
            return count
        if progress_callback is not None:
            progress_callback(total_bytes, file_size)
        return count + 1


def get_filehash(filepath, progress_callback=None):
    """Return the SHA-256 hash for a file."""
    sha256_hash = hashlib.sha256()
    try:
        file_size = os.path.getsize(filepath)
    except OSError:
        file_size = 0
    total_bytes = 0
    with open(filepath, "rb") as handle:
        for byte_block in iter(lambda: handle.read(4096), b""):
            sha256_hash.update(byte_block)
            total_bytes += len(byte_block)
            if progress_callback is not None:
                progress_callback(total_bytes, file_size)
    if progress_callback is not None:
        progress_callback(total_bytes, file_size)
    return sha256_hash.hexdigest()


def get_md5_hash(string):
    """Return the MD5 hash of a string."""
    return _md5.md5(string.encode("utf-8")).hexdigest()
