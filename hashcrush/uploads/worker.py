"""Background queue worker for persisted upload/import operations."""

from __future__ import annotations

import json
import os
import threading
import time

from flask import current_app

from hashcrush.models import db

_UPLOAD_WORKER_HEARTBEAT_FILENAME = "upload-worker-heartbeat.json"


class UploadWorkerService:
    """Run queued upload/import work outside the web process."""

    def __init__(self, app, poll_interval: float = 2.0):
        self.app = app
        self.poll_interval = max(0.5, float(poll_interval))
        self._stop_event = threading.Event()

    def _heartbeat_path(self) -> str:
        runtime_root = os.path.abspath(
            os.path.expanduser(str(self.app.config.get("RUNTIME_PATH") or ""))
        )
        return os.path.join(runtime_root, _UPLOAD_WORKER_HEARTBEAT_FILENAME)

    def _write_heartbeat(self, *, status: str) -> None:
        heartbeat_path = self._heartbeat_path()
        os.makedirs(os.path.dirname(heartbeat_path), exist_ok=True)
        payload = {
            "pid": os.getpid(),
            "status": status,
            "timestamp": time.time(),
        }
        tmp_path = f"{heartbeat_path}.tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle)
            os.replace(tmp_path, heartbeat_path)
        except OSError:
            current_app.logger.warning(
                "Failed to update upload-worker heartbeat file: %s", heartbeat_path
            )

    def _remove_heartbeat(self) -> None:
        heartbeat_path = self._heartbeat_path()
        try:
            if os.path.exists(heartbeat_path):
                os.remove(heartbeat_path)
        except OSError:
            current_app.logger.warning(
                "Failed to remove upload-worker heartbeat file: %s", heartbeat_path
            )

    def stop(self) -> None:
        self._stop_event.set()

    def run_forever(self) -> None:
        service = self.app.extensions["upload_operations"]
        with self.app.app_context():
            self._remove_heartbeat()
        try:
            while not self._stop_event.is_set():
                processed = False
                try:
                    with self.app.app_context():
                        processed = bool(service.process_next_operation())
                        self._write_heartbeat(
                            status="active" if processed else "idle"
                        )
                except Exception:
                    self.app.logger.exception("Upload worker tick failed.")
                    with self.app.app_context():
                        self._write_heartbeat(status="error")
                finally:
                    with self.app.app_context():
                        db.session.remove()
                self._stop_event.wait(0.0 if processed else self.poll_interval)
        finally:
            with self.app.app_context():
                db.session.remove()
                self._remove_heartbeat()
