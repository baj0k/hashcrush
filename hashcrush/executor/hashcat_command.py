"""Hashcat argv construction and display helpers."""

from __future__ import annotations

import os
import re
import shlex

from flask import current_app
from sqlalchemy import select

from hashcrush.models import Hashes, HashfileHashes, Jobs, Rules, Tasks, Wordlists, db
from hashcrush.utils.storage_paths import get_runtime_subdir, resolve_stored_path

_HASHCAT_SPEED_PATTERN = re.compile(
    r"^\s*(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>[kmgtpe]?h/s)\s*$",
    re.IGNORECASE,
)
_HASHCAT_SPEED_UNITS = ["H/s", "kH/s", "MH/s", "GH/s", "TH/s", "PH/s", "EH/s"]
_HASHCAT_SPEED_UNIT_INDEX = {
    unit.lower(): index for index, unit in enumerate(_HASHCAT_SPEED_UNITS)
}


def format_hashcat_speed(value: str | None) -> str:
    """Normalize hashcat speeds to the most readable SI unit."""
    text = str(value or "").strip()
    if not text:
        return ""

    match = _HASHCAT_SPEED_PATTERN.fullmatch(text)
    if not match:
        return text

    try:
        numeric_value = float(match.group("value"))
    except (TypeError, ValueError):
        return text

    unit_index = _HASHCAT_SPEED_UNIT_INDEX.get(match.group("unit").lower())
    if unit_index is None:
        return text

    while numeric_value >= 1000 and unit_index < (len(_HASHCAT_SPEED_UNITS) - 1):
        numeric_value /= 1000
        unit_index += 1

    if numeric_value >= 10:
        rendered_value = f"{numeric_value:.1f}".rstrip("0").rstrip(".")
    else:
        rendered_value = f"{numeric_value:.2f}".rstrip("0").rstrip(".")

    return f"{rendered_value} {_HASHCAT_SPEED_UNITS[unit_index]}"


def build_hashcat_argv(job_id, task_id, hashcat_bin=None):
    """Build a safe argv list for launching hashcat without a shell."""
    task = db.session.get(Tasks, task_id)
    job = db.session.get(Jobs, job_id)
    if not task or not job:
        raise ValueError("Invalid job/task combination when building hashcat command.")

    hashfilehashes_single_entry = db.session.scalar(
        select(HashfileHashes).filter_by(hashfile_id=job.hashfile_id)
    )
    if not hashfilehashes_single_entry:
        raise ValueError("Job has no hashes assigned.")

    hashes_single_entry = db.session.get(Hashes, hashfilehashes_single_entry.hash_id)
    if not hashes_single_entry:
        raise ValueError("Hash type could not be determined from job hashfile.")

    hash_type = hashes_single_entry.hash_type
    attackmode = task.hc_attackmode
    mask = task.hc_mask
    rules_file = db.session.get(Rules, task.rule_id) if task.rule_id else None
    wordlist = db.session.get(Wordlists, task.wl_id) if task.wl_id else None

    hashes_dir = get_runtime_subdir("hashes")
    outfiles_dir = get_runtime_subdir("outfiles")
    os.makedirs(hashes_dir, exist_ok=True)
    os.makedirs(outfiles_dir, exist_ok=True)

    target_file = os.path.join(hashes_dir, f"hashfile_{job.id}_{task.id}.txt")
    crack_file = os.path.join(outfiles_dir, f"hc_cracked_{job.id}_{task.id}.txt")
    session = f"job{job.id}_task{task.id}"
    hashcat_bin_path = hashcat_bin or current_app.config.get("HASHCAT_BIN", "hashcat")
    try:
        status_timer = int(current_app.config.get("HASHCAT_STATUS_TIMER", 5))
    except (TypeError, ValueError):
        status_timer = 5
    status_timer = max(1, status_timer)

    common = [
        hashcat_bin_path,
        "-O",
        "-w",
        "3",
        "--session",
        session,
        "-m",
        str(hash_type),
        "--potfile-disable",
        "--status",
        "--status-timer",
        str(status_timer),
        "--outfile-format",
        "1,3",
        "--outfile-autohex-disable",
        "--outfile",
        crack_file,
    ]

    if attackmode == "combinator":
        raise ValueError(
            "Task attack mode 'combinator' is not supported yet. Edit the task and choose 'dictionary' or 'maskmode'."
        )
    if attackmode == "maskmode":
        if not mask:
            raise ValueError("Task attack mode 'maskmode' requires a hashcat mask.")
        return common + ["-a", "3", target_file, mask]
    if attackmode == "dictionary":
        if not wordlist:
            raise ValueError("Task attack mode 'dictionary' requires a wordlist.")
        wordlist_path = resolve_stored_path(wordlist.path)
        if not os.path.exists(wordlist_path):
            raise ValueError(
                f"Wordlist file is missing for task '{task.name}': {wordlist_path}"
            )
        cmd = list(common)
        if rules_file:
            rules_path = resolve_stored_path(rules_file.path)
            if not os.path.exists(rules_path):
                raise ValueError(
                    f"Rule file is missing for task '{task.name}': {rules_path}"
                )
            cmd.extend(["-r", rules_path])
        cmd.extend([target_file, wordlist_path])
        return cmd

    raise ValueError(f"Unsupported task attack mode: {attackmode}")


def build_hashcat_command(job_id, task_id):
    """Build a shell-quoted hashcat command string for display and persistence."""
    argv = build_hashcat_argv(job_id=job_id, task_id=task_id)
    return " ".join(shlex.quote(arg) for arg in argv)
