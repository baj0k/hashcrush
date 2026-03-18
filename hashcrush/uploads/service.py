"""In-process upload operation tracking for async UI progress."""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable

from flask import Flask

from hashcrush.models import db


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
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

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
    """Track in-process upload/import work for browser polling."""

    def __init__(self, app: Flask, *, retention_seconds: int = 3600):
        self.app = app
        self.retention_seconds = max(60, int(retention_seconds))
        self._lock = threading.Lock()
        self._operations: dict[str, UploadOperationRecord] = {}

    def _cleanup_expired_locked(self) -> None:
        cutoff = time.time() - self.retention_seconds
        expired_ids = [
            operation_id
            for operation_id, record in self._operations.items()
            if record.updated_at < cutoff
            and record.state in {"succeeded", "failed"}
        ]
        for operation_id in expired_ids:
            self._operations.pop(operation_id, None)

    def start_operation(
        self,
        *,
        owner_user_id: int | None,
        worker: Callable[[UploadOperationReporter], None],
        redirect_url: str | None = None,
    ) -> UploadOperationRecord:
        """Create a tracked operation and begin background processing."""

        operation_id = uuid.uuid4().hex
        record = UploadOperationRecord(
            id=operation_id,
            owner_user_id=owner_user_id,
            state="queued",
            title="Queued for processing...",
            detail="The server is preparing the uploaded file.",
            percent=0.0,
            redirect_url=redirect_url,
        )
        with self._lock:
            self._cleanup_expired_locked()
            self._operations[operation_id] = record

        thread = threading.Thread(
            target=self._run_operation,
            args=(operation_id, worker),
            name=f"hashcrush-upload-{operation_id[:8]}",
            daemon=True,
        )
        thread.start()
        return self.get_operation(operation_id) or record

    def _run_operation(
        self,
        operation_id: str,
        worker: Callable[[UploadOperationReporter], None],
    ) -> None:
        reporter = UploadOperationReporter(self, operation_id)
        reporter.update(
            percent=1,
            title="Processing file...",
            detail="The server is preparing the upload for validation.",
        )
        try:
            with self.app.app_context():
                try:
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

        with self._lock:
            self._cleanup_expired_locked()
            record = self._operations.get(operation_id)
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
                completion_flashes=list(record.completion_flashes),
                completion_flashes_consumed=record.completion_flashes_consumed,
                created_at=record.created_at,
                updated_at=record.updated_at,
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

        with self._lock:
            record = self._operations.get(operation_id)
            if record is None or record.state in {"succeeded", "failed"}:
                return
            record.state = "running"
            if percent is not None:
                record.percent = max(record.percent, min(99.0, float(percent)))
            if title is not None:
                record.title = title
            if detail is not None:
                record.detail = detail
            record.updated_at = time.time()

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

        with self._lock:
            record = self._operations.get(operation_id)
            if record is None:
                return
            record.state = "succeeded"
            record.percent = 100.0
            record.title = title
            record.detail = detail
            if redirect_url is not None:
                record.redirect_url = redirect_url
            if completion_flashes is not None:
                record.completion_flashes = list(completion_flashes)
                record.completion_flashes_consumed = False
            record.error_message = None
            record.updated_at = time.time()

    def fail_operation(self, operation_id: str, *, title: str, detail: str) -> None:
        """Mark an operation as failed."""

        with self._lock:
            record = self._operations.get(operation_id)
            if record is None:
                return
            record.state = "failed"
            record.percent = 100.0
            record.title = title
            record.detail = detail
            record.error_message = detail
            record.updated_at = time.time()

    def consume_completion_flashes(self, operation_id: str) -> list[tuple[str, str]]:
        """Return completion flashes exactly once."""

        with self._lock:
            record = self._operations.get(operation_id)
            if (
                record is None
                or record.state != "succeeded"
                or record.completion_flashes_consumed
            ):
                return []
            record.completion_flashes_consumed = True
            record.updated_at = time.time()
            return list(record.completion_flashes)
