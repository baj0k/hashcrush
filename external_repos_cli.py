#!/usr/bin/python3
"""Clone and pin external repository dependencies outside the app repo."""

from __future__ import annotations

import argparse
import os
import subprocess
import tempfile
from configparser import ConfigParser

DEFAULT_SECLISTS_URL = "https://github.com/danielmiessler/SecLists.git"
DEFAULT_HASHCAT_URL = "https://github.com/hashcat/hashcat.git"
DEFAULT_CONFIG_PATH = os.path.join("hashcrush", "config.conf")


def _run_git(*args: str, capture_output: bool = False) -> str:
    result = subprocess.run(
        ["git", *args],
        check=True,
        text=True,
        capture_output=capture_output,
    )
    return result.stdout.strip() if capture_output else ""


def _repo_dir(base_dir: str, repo_name: str) -> str:
    return os.path.join(base_dir, repo_name)


def _ensure_clean_repo(repo_dir: str) -> None:
    status = _run_git("-C", repo_dir, "status", "--porcelain", capture_output=True)
    if status:
        raise RuntimeError(
            f"Repository has uncommitted changes and cannot be repinned safely: {repo_dir}"
        )


def _configure_sparse_checkout(repo_dir: str, subdir: str) -> None:
    _run_git("-C", repo_dir, "sparse-checkout", "init", "--cone")
    _run_git("-C", repo_dir, "sparse-checkout", "set", subdir)


def _clone_or_refresh_repo(url: str, repo_dir: str, subdir: str) -> None:
    if os.path.isdir(os.path.join(repo_dir, ".git")):
        _ensure_clean_repo(repo_dir)
        _configure_sparse_checkout(repo_dir, subdir)
        _run_git("-C", repo_dir, "fetch", "--tags", "origin")
        return

    if os.path.exists(repo_dir):
        raise RuntimeError(
            f"Target path exists but is not a git repository: {repo_dir}"
        )

    parent_dir = os.path.dirname(repo_dir) or "."
    os.makedirs(parent_dir, exist_ok=True)
    _run_git("clone", "--filter=blob:none", "--no-checkout", url, repo_dir)
    _configure_sparse_checkout(repo_dir, subdir)
    _run_git("-C", repo_dir, "fetch", "--tags", "origin")


def _checkout_pinned_ref(repo_dir: str, pinned_ref: str) -> str:
    _run_git("-C", repo_dir, "checkout", "--detach", pinned_ref)
    return _run_git("-C", repo_dir, "rev-parse", "HEAD", capture_output=True)


def _write_config_atomic(config_path: str, parser: ConfigParser) -> None:
    config_dir = os.path.dirname(config_path) or "."
    os.makedirs(config_dir, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".config.", dir=config_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as config_file:
            parser.write(config_file)
            config_file.flush()
            os.fsync(config_file.fileno())
        os.replace(tmp_path, config_path)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def _update_config_paths(config_path: str, wordlists_path: str, rules_path: str) -> None:
    parser = ConfigParser()
    if os.path.exists(config_path):
        parser.read(config_path, encoding="utf-8")
    if "app" not in parser:
        parser["app"] = {}
    parser["app"]["wordlists_path"] = wordlists_path
    parser["app"]["rules_path"] = rules_path
    _write_config_atomic(config_path, parser)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Clone and pin external SecLists/hashcat repositories.",
        allow_abbrev=False,
    )
    parser.add_argument("--base-dir", required=True, help="directory to store external repositories")
    parser.add_argument("--seclists-ref", required=True, help="pinned git ref for SecLists")
    parser.add_argument("--hashcat-ref", required=True, help="pinned git ref for hashcat")
    parser.add_argument("--seclists-url", default=DEFAULT_SECLISTS_URL)
    parser.add_argument("--hashcat-url", default=DEFAULT_HASHCAT_URL)
    parser.add_argument("--wordlists-subdir", default="Passwords")
    parser.add_argument("--rules-subdir", default="rules")
    parser.add_argument("--config-path", default=DEFAULT_CONFIG_PATH)
    parser.add_argument(
        "--no-write-config",
        action="store_true",
        help="clone and pin repositories without updating config.conf",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    base_dir = os.path.abspath(os.path.expanduser(args.base_dir))
    os.makedirs(base_dir, exist_ok=True)

    seclists_dir = _repo_dir(base_dir, "SecLists")
    hashcat_dir = _repo_dir(base_dir, "hashcat")

    _clone_or_refresh_repo(args.seclists_url, seclists_dir, args.wordlists_subdir)
    _clone_or_refresh_repo(args.hashcat_url, hashcat_dir, args.rules_subdir)

    seclists_commit = _checkout_pinned_ref(seclists_dir, args.seclists_ref)
    hashcat_commit = _checkout_pinned_ref(hashcat_dir, args.hashcat_ref)

    wordlists_path = os.path.join(seclists_dir, args.wordlists_subdir)
    rules_path = os.path.join(hashcat_dir, args.rules_subdir)

    if not args.no_write_config:
        _update_config_paths(args.config_path, wordlists_path, rules_path)
        print(f"Updated {args.config_path}")
    else:
        print("Config update skipped (--no-write-config).")

    print(f"SecLists pinned to {seclists_commit}")
    print(f"hashcat pinned to {hashcat_commit}")
    print(f"wordlists_path={wordlists_path}")
    print(f"rules_path={rules_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
