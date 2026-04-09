"""Shared task display ordering helpers."""

from __future__ import annotations

import re
from typing import Iterable, TypeVar

_NATURAL_TOKEN_RE = re.compile(r"(\d+)")
_TaskLike = TypeVar("_TaskLike")


def natural_text_sort_key(value: str | None) -> tuple[object, ...]:
    """Return a case-insensitive natural sort key for human-readable labels."""

    text = str(value or "")
    parts = _NATURAL_TOKEN_RE.split(text.casefold())
    key: list[object] = []
    for part in parts:
        if not part:
            continue
        if part.isdigit():
            key.append(int(part))
        else:
            key.append(part)
    return tuple(key)


def sort_tasks_naturally(task_rows: Iterable[_TaskLike]) -> list[_TaskLike]:
    """Return task rows sorted by natural task-name order."""

    return sorted(
        task_rows,
        key=lambda task: natural_text_sort_key(getattr(task, "name", "")),
    )
