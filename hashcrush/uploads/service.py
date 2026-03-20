"""Database-backed upload operation tracking for async UI progress."""

from __future__ import annotations

import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable

from flask import Flask
from sqlalchemy import delete

from hashcrush.models import UploadOperations, db, utc_now_naive


@dataclass
class UploadOperationRecord:
    """Mutable state for a single tracked upload operation."""

    id: str
    owner_user_id: int | None
    state: str
    title: str
    detail: str
    percent: float
    redirect_url: str | None = None
    error_message: str | None = None
    completion_flashes: list[tuple[str, str]] = field(default_factory=list)
    completion_flashes_consumed: bool = False
    created_at: datetime = field(default_factory=utc_now_naive)
    updated_at: datetime = field(default_factory=utc_now_naive)

    def to_response_dict(self) -> dict[str, object]:
        """Serialize operation state for JSON polling responses."""
        normalized_percent = max(0.0, min(100.0, float(self.percent or 0.0)))
        return {
            "operation_id": self.id,
            "state": self.state,
            "title": self.title,
            "detail": self.detail,
            "percent": round(normalized_percent, 1),
            "complete": self.state in {"succeeded", "failed"},
            "success": self.state == "succeeded",
            "failed": self.state == "failed",
            "redirect_url": self.redirect_url if self.state == "succeeded" else None,
            "error": self.error_message if self.state == "failed" else None,
        }


class UploadOperationReporter:
    """Worker-side helper for updating a tracked operation."""

    def __init__(self, service: "UploadOperationService", operation_id: str):
        self._service = service
        self._operation_id = operation_id

    def update(
        self,
        *,
        percent: float | None = None,
        title: str | None = None,
        detail: str | None = None,
    ) -> None:
        self._service.update_operation(
            self._operation_id,
            percent=percent,
            title=title,
            detail=detail,
        )

    def complete(
        self,
        *,
        title: str,
        detail: str,
        redirect_url: str | None = None,
        completion_flashes: list[tuple[str, str]] | None = None,
    ) -> None:
        self._service.complete_operation(
            self._operation_id,
            title=title,
            detail=detail,
            redirect_url=redirect_url,
            completion_flashes=completion_flashes,
        )

    def fail(self, *, title: str, detail: str) -> None:
        self._service.fail_operation(self._operation_id, title=title, detail=detail)


class UploadOperationService:
    """Track upload/import work for browser polling in persistent storage."""

    def __init__(
        self,
        app: Flask,
        *,
        retention_seconds: int = 3600,
        max_workers: int = 2,
    ):
        self.app = app
        self.retention_seconds = max(60, int(retention_seconds))
        self._cleanup_interval_seconds = max(
            30.0, min(300.0, float(self.retention_seconds) / 6.0)
        )
        self._last_cleanup_monotonic = 0.0
        self._executor = ThreadPoolExecutor(
            max_workers=max(1, int(max_workers)),
            thread_name_prefix="hashcrush-upload",
        )

    def _serialize_completion_flashes(
        self, flashes: list[tuple[str, str]] | None
    ) -> str:
        normalized = [
            [str(category), str(message)]
            for category, message in (flashes or [])
        ]
        return json.dumps(normalized, separators=(",", ":"))

    def _deserialize_completion_flashes(self, raw_value: str | None) -> list[tuple[str, str]]:
        if not raw_value:
            return []
        try:
            payload = json.loads(raw_value)
        except (TypeError, ValueError):
            return []
        flashes: list[tuple[str, str]] = []
        if not isinstance(payload, list):
            return flashes
        for item in payload:
            if not isinstance(item, list | tuple) or len(item) != 2:
                continue
            category, message = item
            flashes.append((str(category), str(message)))
        return flashes

    def _record_to_snapshot(
        self, record: UploadOperations | None
    ) -> UploadOperationRecord | None:
        if record is None:
            return None
        return UploadOperationRecord(
            id=record.id,
            owner_user_id=record.owner_user_id,
            state=record.state,
            title=record.title,
            detail=record.detail,
            percent=record.percent,
            redirect_url=record.redirect_url,
            error_message=record.error_message,
            completion_flashes=self._deserialize_completion_flashes(
                record.completion_flashes_json
            ),
            completion_flashes_consumed=record.completion_flashes_consumed,
            created_at=record.created_at,
            updated_at=record.updated_at,
        )

    def _cleanup_expired(self) -> None:
        now = time.monotonic()
        if (now - self._last_cleanup_monotonic) < self._cleanup_interval_seconds:
            return
        self._last_cleanup_monotonic = now
        cutoff = utc_now_naive() - timedelta(seconds=self.retention_seconds)
        db.session.execute(
            delete(UploadOperations).where(
                UploadOperations.updated_at < cutoff,
                UploadOperations.state.in_(("succeeded", "failed")),
            )
        )
        db.session.commit()

    def start_operation(
        self,
        *,
        owner_user_id: int | None,
        worker: Callable[[UploadOperationReporter], None],
        redirect_url: str | None = None,
    ) -> UploadOperationRecord:
        """Create a tracked operation and begin background processing."""

        self._cleanup_expired()
        operation_id = uuid.uuid4().hex
        record = UploadOperations(
            id=operation_id,
            owner_user_id=owner_user_id,
            state="queued",
            title="Queued for processing...",
            detail="The server is preparing the uploaded file.",
            percent=0.0,
            redirect_url=redirect_url,
            completion_flashes_json="[]",
            completion_flashes_consumed=False,
            created_at=utc_now_naive(),
            updated_at=utc_now_naive(),
        )
        db.session.add(record)
        db.session.commit()

        self._executor.submit(self._run_operation, operation_id, worker)
        return self.get_operation(operation_id) or UploadOperationRecord(
            id=record.id,
            owner_user_id=record.owner_user_id,
            state=record.state,
            title=record.title,
            detail=record.detail,
            percent=record.percent,
            redirect_url=record.redirect_url,
            error_message=record.error_message,
            created_at=record.created_at,
            updated_at=record.updated_at,
        )

    def _run_operation(
        self,
        operation_id: str,
        worker: Callable[[UploadOperationReporter], None],
    ) -> None:
        try:
            with self.app.app_context():
                reporter = UploadOperationReporter(self, operation_id)
                try:
                    reporter.update(
                        percent=1,
                        title="Processing file...",
                        detail="The server is preparing the upload for validation.",
                    )
                    worker(reporter)
                    snapshot = self.get_operation(operation_id)
                    if snapshot and snapshot.state not in {"succeeded", "failed"}:
                        reporter.complete(
                            title="Upload complete.",
                            detail="The uploaded file finished processing.",
                        )
                finally:
                    db.session.remove()
        except Exception:
            self.app.logger.exception(
                "Upload operation %s failed unexpectedly.", operation_id
            )
            self.fail_operation(
                operation_id,
                title="Processing failed.",
                detail="The server hit an unexpected error while processing the uploaded file.",
            )

    def get_operation(self, operation_id: str) -> UploadOperationRecord | None:
        """Return a detached snapshot of an operation."""

        self._cleanup_expired()
        return self._record_to_snapshot(
            db.session.get(UploadOperations, operation_id, populate_existing=True)
        )

    def update_operation(
        self,
        operation_id: str,
        *,
        percent: float | None = None,
        title: str | None = None,
        detail: str | None = None,
    ) -> None:
        """Update a running operation."""

        record = db.session.get(UploadOperations, operation_id)
        if record is None or record.state in {"succeeded", "failed"}:
            return
        record.state = "running"
        if percent is not None:
            record.percent = max(float(record.percent or 0.0), min(99.0, float(percent)))
        if title is not None:
            record.title = title
        if detail is not None:
            record.detail = detail
        record.updated_at = utc_now_naive()
        db.session.commit()

    def complete_operation(
        self,
        operation_id: str,
        *,
        title: str,
        detail: str,
        redirect_url: str | None = None,
        completion_flashes: list[tuple[str, str]] | None = None,
    ) -> None:
        """Mark an operation as successful."""

        record = db.session.get(UploadOperations, operation_id)
        if record is None:
            return
        record.state = "succeeded"
        record.percent = 100.0
        record.title = title
        record.detail = detail
        if redirect_url is not None:
            record.redirect_url = redirect_url
        if completion_flashes is not None:
            record.completion_flashes_json = self._serialize_completion_flashes(
                completion_flashes
            )
            record.completion_flashes_consumed = False
        record.error_message = None
        record.updated_at = utc_now_naive()
        db.session.commit()

    def fail_operation(self, operation_id: str, *, title: str, detail: str) -> None:
        """Mark an operation as failed."""

        record = db.session.get(UploadOperations, operation_id)
        if record is None:
            return
        record.state = "failed"
        record.percent = 100.0
        record.title = title
        record.detail = detail
        record.error_message = detail
        record.updated_at = utc_now_naive()
        db.session.commit()

    def consume_completion_flashes(self, operation_id: str) -> list[tuple[str, str]]:
        """Return completion flashes exactly once."""

        record = db.session.get(
            UploadOperations, operation_id, populate_existing=True
        )
        if (
            record is None
            or record.state != "succeeded"
            or record.completion_flashes_consumed
        ):
            return []
        flashes = self._deserialize_completion_flashes(record.completion_flashes_json)
        if not flashes:
            return []
        record.completion_flashes_consumed = True
        record.updated_at = utc_now_naive()
        db.session.commit()
        return flashes
