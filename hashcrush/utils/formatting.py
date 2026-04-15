"""Shared formatting and lightweight parsing helpers."""

from __future__ import annotations


def format_bytes(size_bytes: int) -> str:
    """Render a byte count into a compact human-readable string."""
    units = ["bytes", "KB", "MB", "GB", "TB"]
    value = float(max(size_bytes, 0))
    unit_index = 0
    while value >= 1024 and unit_index < len(units) - 1:
        value /= 1024
        unit_index += 1
    if unit_index == 0:
        return f"{int(value)} {units[unit_index]}"
    return f"{value:.2f} {units[unit_index]}"


def parse_positive_int(raw_value) -> int | None:
    """Parse a value as a positive int, returning None on failure."""
    if raw_value in (None, ""):
        return None
    try:
        parsed = int(str(raw_value).strip())
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None
