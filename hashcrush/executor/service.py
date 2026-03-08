"""Single-node task executor that runs hashcat locally."""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import TextIO

from flask import current_app

from hashcrush.models import Hashes, HashfileHashes, Jobs, JobTasks, Tasks, Wordlists, db
from hashcrush.utils.utils import (
    build_hashcat_argv,
    encode_plaintext_for_storage,
    get_md5_hash,
    get_runtime_subdir,
    update_dynamic_wordlist,
    update_job_task_status,
)


def _ensure_runtime_dirs() -> tuple[str, str]:
    hashes_dir = get_runtime_subdir("hashes")
    outfiles_dir = get_runtime_subdir("outfiles")
    os.makedirs(hashes_dir, exist_ok=True)
    os.makedirs(outfiles_dir, exist_ok=True)
    return hashes_dir, outfiles_dir


def _parse_hashcat_status(filepath: str) -> dict[str, str]:
    status: dict[str, str] = {}
    if not os.path.exists(filepath):
        return status

    with open(filepath, "r", encoding="utf-8", errors="ignore") as hashcat_output:
        for line in hashcat_output:
            if line.startswith("Time.Started."):
                status["Time_Started"] = line.split(": ", 1)[-1].rstrip()
            elif line.startswith("Time.Estimated."):
                status["Time_Estimated"] = line.split(".: ", 1)[-1].rstrip()
            elif line.startswith("Status"):
                status["Status"] = line.split(": ", 1)[-1].rstrip()
            elif line.startswith("Recovered."):
                status["Recovered"] = line.split(": ", 1)[-1].rstrip()
            elif line.startswith("Input.Mode."):
                status["Input_Mode"] = line.split(": ", 1)[-1].rstrip()
            elif line.startswith("Guess.Mask."):
                status["Guess_Mask"] = line.split(": ", 1)[-1].rstrip()
            elif line.startswith("Progress"):
                status["Progress"] = line.split(": ", 1)[-1].rstrip()
            elif line.startswith("Speed.#"):
                match = re.search(r"\b\d+.?\d?\s.*/s\b", line)
                if match:
                    status["Speed #"] = match.group()
    return status


def _is_successful_hashcat_exit(return_code: int | None, status: dict[str, str]) -> bool:
    """Return True when hashcat exit/result indicates normal task completion."""
    if return_code == 0:
        return True

    if return_code != 1:
        return False

    normalized_status = str(status.get("Status", "")).strip().lower()
    if normalized_status in {"exhausted", "cracked"}:
        return True

    progress = str(status.get("Progress", "")).strip()
    if "100.00%" in progress:
        return True

    return False


def _log_status_snapshot(job_task_id: int, status: dict[str, str], prefix: str) -> None:
    """Write a concise status snapshot to logs."""
    if not status:
        current_app.logger.info(
            "%s job_task id=%s unavailable (task likely finished before first status interval).",
            prefix,
            job_task_id,
        )
        return
    current_app.logger.info(
        "%s job_task id=%s status=%s recovered=%s speed=%s eta=%s progress=%s",
        prefix,
        job_task_id,
        status.get("Status", "n/a"),
        status.get("Recovered", "n/a"),
        status.get("Speed #", "n/a"),
        status.get("Time_Estimated", "n/a"),
        status.get("Progress", "n/a"),
    )


@dataclass
class ActiveTask:
    job_task_id: int
    process: subprocess.Popen
    output_file: TextIO
    output_path: str
    hash_path: str
    crack_path: str
    last_progress_log_at: float
    last_import_at: float


class LocalExecutorService:
    """Background worker that executes queued JobTasks on this host."""

    def __init__(self, app, poll_interval: float = 2.0):
        self.app = app
        self.poll_interval = max(0.5, float(poll_interval))
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._active: ActiveTask | None = None
        self._lock = threading.Lock()
        self._recovered_once = False

    def start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run_loop,
                name="hashcrush-local-executor",
                daemon=True,
            )
            self._thread.start()
        self.app.logger.info("Local executor started.")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                with self.app.app_context():
                    self._tick()
            except Exception:
                self.app.logger.exception("Local executor tick failed.")
            finally:
                with self.app.app_context():
                    db.session.remove()
            self._stop_event.wait(self.poll_interval)

    def _tick(self) -> None:
        if not self._recovered_once:
            self._recover_orphaned_tasks()
            self._cleanup_runtime_artifacts()
            self._recovered_once = True

        if self._active is not None:
            self._monitor_active_task()
            return
        self._claim_and_start_next()

    @staticmethod
    def _checkpoint_import_interval_seconds() -> float:
        try:
            interval = float(current_app.config.get("CRACK_IMPORT_INTERVAL_SECONDS", 15))
        except (TypeError, ValueError):
            interval = 15.0
        return max(1.0, interval)

    @staticmethod
    def _crack_file_path_for_job_task(job_task: JobTasks) -> str | None:
        job = Jobs.query.get(job_task.job_id)
        if not job:
            return None
        outfiles_dir = get_runtime_subdir("outfiles")
        os.makedirs(outfiles_dir, exist_ok=True)
        return os.path.join(outfiles_dir, f"hc_cracked_{job.id}_{job_task.task_id}.txt")

    def _recover_orphaned_tasks(self) -> None:
        """Requeue tasks that were running when the process exited."""
        orphaned = JobTasks.query.filter(JobTasks.status.in_(("Running", "Importing"))).all()
        if not orphaned:
            return

        touched_job_ids = set()
        imported_total = 0
        for job_task in orphaned:
            crack_path = self._crack_file_path_for_job_task(job_task)
            if crack_path:
                imported_total += self._safe_import_crack_file(job_task, crack_path)
            job_task.status = "Queued"
            job_task.worker_pid = None
            touched_job_ids.add(job_task.job_id)
        db.session.commit()

        for job_id in touched_job_ids:
            job = Jobs.query.get(job_id)
            if not job:
                continue
            has_running = JobTasks.query.filter(
                JobTasks.job_id == job.id,
                JobTasks.status.in_(("Running", "Importing")),
            ).count() > 0
            has_queued = JobTasks.query.filter(
                JobTasks.job_id == job.id,
                JobTasks.status == "Queued",
            ).count() > 0
            if not has_running and has_queued:
                job.status = "Queued"
        db.session.commit()

        current_app.logger.warning(
            "Recovered %s orphaned running task(s) to Queued state (imported_hashes=%s).",
            len(orphaned),
            imported_total,
        )

    def _claim_and_start_next(self) -> None:
        next_task = (
            JobTasks.query.filter(JobTasks.status == "Queued")
            .order_by(JobTasks.priority.desc(), JobTasks.id.asc())
            .first()
        )
        if not next_task:
            return

        now_dt = datetime.now().replace(microsecond=0)
        claimed = (
            JobTasks.query.filter(JobTasks.id == next_task.id, JobTasks.status == "Queued")
            .update(
                {
                    "status": "Running",
                    "started_at": now_dt,
                },
                synchronize_session=False,
            )
        )
        if claimed != 1:
            db.session.rollback()
            return
        db.session.commit()

        job_task = JobTasks.query.get(next_task.id)
        if not job_task:
            return
        update_job_task_status(job_task.id, "Running")
        job_task = JobTasks.query.get(next_task.id)
        if not job_task:
            return

        hash_path = ""
        crack_path = ""
        output_path = ""
        try:
            argv, hash_path, crack_path, output_path = self._prepare_execution(job_task)
            output_file = open(output_path, "w", encoding="utf-8", errors="ignore")
            process = subprocess.Popen(
                argv,
                stdout=output_file,
                stderr=subprocess.STDOUT,
                shell=False,
            )
        except Exception:
            current_app.logger.exception("Failed to start local job_task id=%s", job_task.id)
            self._remove_files(hash_path, crack_path, output_path)
            update_job_task_status(job_task.id, "Canceled")
            return

        job_task.worker_pid = process.pid
        db.session.commit()

        self._active = ActiveTask(
            job_task_id=job_task.id,
            process=process,
            output_file=output_file,
            output_path=output_path,
            hash_path=hash_path,
            crack_path=crack_path,
            last_progress_log_at=0.0,
            last_import_at=0.0,
        )
        current_app.logger.info("Started local job_task id=%s pid=%s", job_task.id, process.pid)

    def _prepare_execution(self, job_task: JobTasks) -> tuple[list[str], str, str, str]:
        job = Jobs.query.get(job_task.job_id)
        task = Tasks.query.get(job_task.task_id)
        if not job:
            raise RuntimeError(f"job_task={job_task.id} has missing job={job_task.job_id}")
        if not task:
            raise RuntimeError(f"job_task={job_task.id} has missing task={job_task.task_id}")
        if not job.hashfile_id:
            raise RuntimeError(f"job_task={job_task.id} has no hashfile context")

        if task.wl_id:
            wordlist = Wordlists.query.get(task.wl_id)
            if wordlist and str(wordlist.type).lower() == "dynamic":
                update_dynamic_wordlist(wordlist.id)

        hashes_dir, outfiles_dir = _ensure_runtime_dirs()
        hash_path = self._write_hashfile(job.id, task.id, job.hashfile_id, hashes_dir)

        argv = build_hashcat_argv(
            job_id=job.id,
            task_id=task.id,
            hashcat_bin=current_app.config.get("HASHCAT_BIN"),
        )
        crack_path = os.path.join(outfiles_dir, f"hc_cracked_{job.id}_{task.id}.txt")
        output_path = os.path.join(outfiles_dir, f"hcoutput_{job.id}_{job_task.id}.txt")
        return argv, hash_path, crack_path, output_path

    def _write_hashfile(self, job_id: int, task_id: int, hashfile_id: int, hashes_dir: str) -> str:
        target = os.path.join(hashes_dir, f"hashfile_{job_id}_{task_id}.txt")
        rows = (
            db.session.query(Hashes.ciphertext)
            .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
            .filter(Hashes.cracked.is_(False))
            .filter(HashfileHashes.hashfile_id == hashfile_id)
            .all()
        )
        with open(target, "w", encoding="utf-8", errors="ignore") as file_object:
            for row in rows:
                file_object.write(f"{row.ciphertext}\n")
        return target

    def _monitor_active_task(self) -> None:
        active = self._active
        if active is None:
            return

        job_task = JobTasks.query.get(active.job_task_id)
        if not job_task:
            self._terminate_process(active.process)
            self._finalize_active_task(final_status="Canceled")
            return

        if job_task.status in ("Paused", "Canceled"):
            self._terminate_process(active.process)
            if active.process.poll() is not None:
                imported_count = self._safe_import_crack_file(job_task, active.crack_path)
                if imported_count:
                    current_app.logger.info(
                        "Imported %s recovered hash(es) for job_task id=%s during %s flow",
                        imported_count,
                        job_task.id,
                        job_task.status.lower(),
                    )
                self._finalize_active_task(final_status=job_task.status)
            return

        if active.process.poll() is None:
            now = time.monotonic()
            status = _parse_hashcat_status(active.output_path)
            if status:
                job_task.progress = json.dumps(status)
                if status.get("Speed #"):
                    job_task.benchmark = status.get("Speed #")
                db.session.commit()
                if (now - active.last_progress_log_at) >= 30:
                    current_app.logger.info(
                        "Progress job_task id=%s recovered=%s speed=%s eta=%s progress=%s",
                        job_task.id,
                        status.get("Recovered", "n/a"),
                        status.get("Speed #", "n/a"),
                        status.get("Time_Estimated", "n/a"),
                        status.get("Progress", "n/a"),
                    )
                    active.last_progress_log_at = now
            if (now - active.last_import_at) >= self._checkpoint_import_interval_seconds():
                imported_count = self._safe_import_crack_file(job_task, active.crack_path)
                if imported_count:
                    current_app.logger.info(
                        "Checkpoint import job_task id=%s imported_hashes=%s",
                        job_task.id,
                        imported_count,
                    )
                active.last_import_at = now
            return

        return_code = active.process.returncode
        final_status_snapshot = _parse_hashcat_status(active.output_path)
        if final_status_snapshot:
            job_task.progress = json.dumps(final_status_snapshot)
            if final_status_snapshot.get("Speed #"):
                job_task.benchmark = final_status_snapshot.get("Speed #")
            db.session.commit()
        _log_status_snapshot(job_task.id, final_status_snapshot, prefix="Final status")

        if _is_successful_hashcat_exit(return_code, final_status_snapshot) and job_task.status not in ("Paused", "Canceled"):
            imported_count = self._safe_import_crack_file(job_task, active.crack_path)
            current_app.logger.info(
                "Completed local job_task id=%s return_code=%s imported_hashes=%s",
                job_task.id,
                return_code,
                imported_count,
            )
            self._finalize_active_task(final_status="Completed")
            return

        imported_count = self._safe_import_crack_file(job_task, active.crack_path)
        if imported_count:
            current_app.logger.info(
                "Imported %s recovered hash(es) for job_task id=%s before non-success finalize",
                imported_count,
                job_task.id,
            )
        current_app.logger.warning(
            "Local job_task id=%s ended with return_code=%s status=%s",
            job_task.id,
            return_code,
            job_task.status,
        )
        final_status = job_task.status if job_task.status in ("Paused", "Canceled") else "Canceled"
        self._finalize_active_task(final_status=final_status)

    def _terminate_process(self, process: subprocess.Popen) -> None:
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)

    def _finalize_active_task(self, final_status: str) -> None:
        active = self._active
        self._active = None
        if active is None:
            return

        try:
            active.output_file.close()
        except Exception:
            current_app.logger.exception("Failed closing output file for job_task id=%s", active.job_task_id)

        job_task = JobTasks.query.get(active.job_task_id)
        if not job_task:
            self._remove_files(active.output_path, active.crack_path, active.hash_path)
            return

        job_task.worker_pid = None
        db.session.commit()
        update_job_task_status(job_task.id, final_status)
        self._remove_files(active.output_path, active.crack_path, active.hash_path)

    def _safe_import_crack_file(self, job_task: JobTasks, crack_path: str) -> int:
        """Import recovered hashes from crack file, protecting caller flow on errors."""
        try:
            return self._import_crack_file_for_task(job_task, crack_path)
        except Exception:
            db.session.rollback()
            current_app.logger.exception(
                "Failed importing crack file for job_task id=%s path=%s",
                job_task.id,
                crack_path,
            )
            return 0

    def _import_crack_file_for_task(self, job_task: JobTasks, crack_path: str) -> int:
        if not os.path.exists(crack_path):
            return 0

        job = Jobs.query.get(job_task.job_id)
        if not job or not job.hashfile_id:
            return 0

        hashfile_hash = HashfileHashes.query.filter_by(hashfile_id=job.hashfile_id).first()
        if not hashfile_hash:
            return 0

        expected_hash = Hashes.query.get(hashfile_hash.hash_id)
        if not expected_hash:
            return 0

        parsed_entries: list[tuple[str, str]] = []
        with open(crack_path, "r", encoding="latin-1", errors="ignore") as file_contents:
            for entry in file_contents.read().split("\n"):
                if ":" not in entry:
                    continue
                encoded_plaintext = entry.split(":")[-1]
                plaintext = encode_plaintext_for_storage(encoded_plaintext.rstrip())
                elements = entry.split(":")
                elements.pop()
                ciphertext = ":".join(elements)
                parsed_entries.append((get_md5_hash(ciphertext), plaintext))

        if not parsed_entries:
            return 0

        sub_ciphertexts = {sub_ciphertext for sub_ciphertext, _ in parsed_entries}
        candidate_rows = (
            Hashes.query.filter(Hashes.hash_type == expected_hash.hash_type)
            .filter(Hashes.cracked.is_(False))
            .filter(Hashes.sub_ciphertext.in_(sub_ciphertexts))
            .all()
        )
        records_by_sub_ciphertext: dict[str, Hashes] = {}
        for row in candidate_rows:
            records_by_sub_ciphertext.setdefault(row.sub_ciphertext, row)

        imported_count = 0
        for sub_ciphertext, plaintext in parsed_entries:
            record = records_by_sub_ciphertext.get(sub_ciphertext)
            if record:
                record.plaintext = plaintext
                record.cracked = True
                imported_count += 1
        db.session.commit()
        return imported_count

    def _cleanup_runtime_artifacts(self) -> None:
        """Remove stale runtime artifacts from previous runs."""
        hashes_dir, outfiles_dir = _ensure_runtime_dirs()
        removed = 0

        for directory, prefixes in (
            (hashes_dir, ("hashfile_",)),
            (outfiles_dir, ("hcoutput_", "hc_cracked_")),
        ):
            for filename in os.listdir(directory):
                file_path = os.path.join(directory, filename)
                if (not os.path.isfile(file_path)) or (not filename.startswith(prefixes)):
                    continue
                try:
                    os.remove(file_path)
                    removed += 1
                except OSError:
                    current_app.logger.warning("Failed to remove stale runtime artifact: %s", file_path)

        if removed:
            current_app.logger.info("Removed %s stale runtime artifact(s).", removed)

    @staticmethod
    def _remove_files(*paths: str) -> None:
        for path in paths:
            if not path:
                continue
            try:
                if os.path.isfile(path):
                    os.remove(path)
            except OSError:
                current_app.logger.warning("Failed to remove runtime artifact: %s", path)
