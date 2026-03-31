"""Gunicorn runtime profile for the HashCrush web UI."""

from __future__ import annotations

import os


def _env_int(name: str, default: int, minimum: int) -> int:
    try:
        value = int(str(os.getenv(name, default)).strip())
    except (TypeError, ValueError):
        return default
    return value if value >= minimum else default


bind = "0.0.0.0:8000"
worker_class = "gthread"
workers = _env_int("HASHCRUSH_WEB_WORKERS", 2, 1)
threads = _env_int("HASHCRUSH_WEB_THREADS", 4, 1)
timeout = _env_int("HASHCRUSH_WEB_TIMEOUT_SECONDS", 120, 15)
graceful_timeout = _env_int("HASHCRUSH_WEB_GRACEFUL_TIMEOUT_SECONDS", 30, 5)
keepalive = _env_int("HASHCRUSH_WEB_KEEPALIVE_SECONDS", 5, 1)
max_requests = _env_int("HASHCRUSH_WEB_MAX_REQUESTS", 1000, 1)
max_requests_jitter = _env_int("HASHCRUSH_WEB_MAX_REQUESTS_JITTER", 100, 0)
accesslog = "-"
errorlog = "-"
capture_output = True
loglevel = str(os.getenv("HASHCRUSH_WEB_LOG_LEVEL", "info")).strip() or "info"
