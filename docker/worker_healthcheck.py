#!/usr/bin/env python3
"""Container healthcheck for the local HashCrush worker."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path


def main() -> int:
    runtime_root = os.path.abspath(
        os.path.expanduser(os.getenv("HASHCRUSH_RUNTIME_PATH", "/tmp/hashcrush-runtime"))
    )
    heartbeat_path = Path(runtime_root) / "worker-heartbeat.json"
    max_age_seconds = float(
        os.getenv("HASHCRUSH_WORKER_HEARTBEAT_MAX_AGE_SECONDS", "30")
    )

    if not heartbeat_path.is_file():
        return 1

    try:
        payload = json.loads(heartbeat_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return 1

    if str(payload.get("status") or "").strip().lower() == "starting":
        return 1

    try:
        last_seen = float(payload["timestamp"])
    except (KeyError, TypeError, ValueError):
        return 1

    if (time.time() - last_seen) > max_age_seconds:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
