"""Database-backed upload operation tracking and queued processing."""

from __future__ import annotations

import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from flask import Flask
from sqlalchemy import select

from hashcrush.models import UploadOperations, db, utc_now_naive

_STALE_UPLOAD_FAILURE_TITLE = "Processing interrupted."
_STALE_UPLOAD_FAILURE_DETAIL = (
    "Upload processing stopped before completion. Please retry the upload."
)


@dataclass
class UploadOperationRecord:
    """Mutable state snapshot for a single tracked upload operation."""

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
    """Worker-side helper for updating a tracked upload operation."""

    def __init__(self, service: "UploadOperationService", operation_id: str):
        self._service = service
        self._operation_id = operation_id

    @property
    def operation_id(self) -> str:
        return self._operation_id

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
    """Track upload/import work and hand it to an upload worker process."""

    def __init__(self, app: Flask):
        self.app = app
        self.retention_seconds = max(
            60, int(app.config.get("UPLOAD_OPERATION_RETENTION_SECONDS", 3600))
        )
        self.lease_seconds = max(
            30, int(app.config.get("UPLOAD_OPERATION_LEASE_SECONDS", 300))
        )
        self.inline_enabled = bool(app.config.get("ENABLE_INLINE_UPLOAD_WORKER", False))
        self._cleanup_interval_seconds = max(
            30.0, min(300.0, float(self.retention_seconds) / 6.0)
        )
        self._last_cleanup_monotonic = 0.0
        self._executor: ThreadPoolExecutor | None = None
        if self.inline_enabled:
            self._executor = ThreadPoolExecutor(
                max_workers=max(
                    1, int(app.config.get("UPLOAD_INLINE_MAX_WORKERS", 2))
                ),
                thread_name_prefix="hashcrush-upload-inline",
            )

    @staticmethod
    def _serialize_json_payload(payload: Any) -> str:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def _serialize_completion_flashes(
        self, flashes: list[tuple[str, str]] | None
    ) -> str:
        normalized = [
            [str(category), str(message)]
            for category, message in (flashes or [])
        ]
        return self._serialize_json_payload(normalized)

    @staticmethod
    def _deserialize_payload_json(raw_value: str | None, fallback):
        if not raw_value:
            return fallback
        try:
            payload = json.loads(raw_value)
        except (TypeError, ValueError):
            return fallback
        return payload

    def _deserialize_completion_flashes(
        self, raw_value: str | None
    ) -> list[tuple[str, str]]:
        payload = self._deserialize_payload_json(raw_value, [])
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
        expired_records = (
            db.session.execute(
                select(UploadOperations).where(
                    UploadOperations.updated_at < cutoff,
                    UploadOperations.state.in_(("succeeded", "failed")),
                )
            )
            .scalars()
            .all()
        )
        if not expired_records:
            return
        for record in expired_records:
            self._cleanup_operation_artifact(record)
            db.session.delete(record)
        db.session.commit()

    def _cleanup_operation_artifact(self, record: UploadOperations) -> None:
        operation_type = str(record.operation_type or "").strip().lower()
        if operation_type == "search_domain_export":
            from hashcrush.searches.export_service import remove_domain_export_artifact

            remove_domain_export_artifact(record.id)

    def _mark_stale_running_operations(self) -> int:
        now = utc_now_naive()
        stale_records = (
            db.session.execute(
                select(UploadOperations)
                .where(UploadOperations.state == "running")
                .where(UploadOperations.lease_expires_at.is_not(None))
                .where(UploadOperations.lease_expires_at < now)
            )
            .scalars()
            .all()
        )
        if not stale_records:
            return 0

        for record in stale_records:
            record.state = "failed"
            record.percent = 100.0
            record.title = _STALE_UPLOAD_FAILURE_TITLE
            record.detail = _STALE_UPLOAD_FAILURE_DETAIL
            record.error_message = _STALE_UPLOAD_FAILURE_DETAIL
            record.lease_expires_at = None
            record.updated_at = now
        db.session.commit()
        return len(stale_records)

    def _claim_stmt(self, stmt):
        if db.engine.dialect.name == "postgresql":
            return stmt.with_for_update(skip_locked=True)
        return stmt.with_for_update()

    def _mark_claimed(self, record: UploadOperations) -> None:
        now = utc_now_naive()
        record.state = "running"
        record.percent = max(float(record.percent or 0.0), 1.0)
        record.attempt_count = int(record.attempt_count or 0) + 1
        record.lease_expires_at = now + timedelta(seconds=self.lease_seconds)
        record.updated_at = now

    def _claim_next_operation(self) -> UploadOperations | None:
        stmt = (
            select(UploadOperations)
            .where(UploadOperations.state == "queued")
            .order_by(UploadOperations.created_at.asc())
            .limit(1)
        )
        record = db.session.execute(self._claim_stmt(stmt)).scalars().first()
        if record is None:
            return None
        self._mark_claimed(record)
        db.session.commit()
        return record

    def _claim_specific_operation(self, operation_id: str) -> UploadOperations | None:
        stmt = (
            select(UploadOperations)
            .where(UploadOperations.id == operation_id)
            .where(UploadOperations.state == "queued")
            .limit(1)
        )
        record = db.session.execute(self._claim_stmt(stmt)).scalars().first()
        if record is None:
            return None
        self._mark_claimed(record)
        db.session.commit()
        return record

    def start_operation(
        self,
        *,
        owner_user_id: int | None,
        operation_type: str,
        payload: dict[str, object],
        redirect_url: str | None = None,
    ) -> UploadOperationRecord:
        """Create a tracked operation and enqueue it for processing."""

        self._cleanup_expired()
        operation_id = uuid.uuid4().hex
        now = utc_now_naive()
        record = UploadOperations(
            id=operation_id,
            owner_user_id=owner_user_id,
            state="queued",
            operation_type=str(operation_type),
            title="Queued for processing...",
            detail="The server is preparing the uploaded file.",
            percent=0.0,
            redirect_url=redirect_url,
            error_message=None,
            payload_json=self._serialize_json_payload(payload),
            lease_expires_at=None,
            attempt_count=0,
            completion_flashes_json="[]",
            completion_flashes_consumed=False,
            created_at=now,
            updated_at=now,
        )
        db.session.add(record)
        db.session.commit()

        if self._executor is not None:
            self._executor.submit(self._process_operation_in_background, operation_id)

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

    def _process_operation_in_background(self, operation_id: str) -> None:
        try:
            with self.app.app_context():
                self.process_operation_by_id(operation_id)
        finally:
            with self.app.app_context():
                db.session.remove()

    def _process_claimed_operation(self, operation_id: str) -> bool:
        record = db.session.get(
            UploadOperations, operation_id, populate_existing=True
        )
        if record is None:
            return False

        reporter = UploadOperationReporter(self, operation_id)
        try:
            reporter.update(
                percent=1.0,
                title="Processing file...",
                detail="The server is preparing the upload for validation.",
            )
            payload = self._deserialize_payload_json(record.payload_json, {})
            from hashcrush.uploads.tasks import process_upload_operation

            process_upload_operation(record.operation_type, payload, reporter)
            snapshot = self.get_operation(operation_id)
            if snapshot and snapshot.state not in {"succeeded", "failed"}:
                reporter.complete(
                    title="Upload complete.",
                    detail="The uploaded file finished processing.",
                )
            return True
        except Exception:
            self.app.logger.exception(
                "Upload operation %s failed unexpectedly.", operation_id
            )
            self.fail_operation(
                operation_id,
                title="Processing failed.",
                detail=(
                    "The server hit an unexpected error while processing the "
                    "uploaded file."
                ),
            )
            return True

    def process_operation_by_id(self, operation_id: str) -> bool:
        """Claim and process a specific queued upload operation."""

        self._cleanup_expired()
        self._mark_stale_running_operations()
        record = self._claim_specific_operation(operation_id)
        if record is None:
            return False
        return self._process_claimed_operation(record.id)

    def process_next_operation(self) -> bool:
        """Claim and process the next queued upload operation, if any."""

        self._cleanup_expired()
        self._mark_stale_running_operations()
        record = self._claim_next_operation()
        if record is None:
            return False
        return self._process_claimed_operation(record.id)

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
        """Update a running operation and refresh its lease."""

        record = db.session.get(UploadOperations, operation_id)
        if record is None or record.state in {"succeeded", "failed"}:
            return
        now = utc_now_naive()
        record.state = "running"
        if percent is not None:
            record.percent = max(float(record.percent or 0.0), min(99.0, float(percent)))
        if title is not None:
            record.title = title
        if detail is not None:
            record.detail = detail
        record.lease_expires_at = now + timedelta(seconds=self.lease_seconds)
        record.updated_at = now
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
        record.lease_expires_at = None
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
        record.lease_expires_at = None
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
