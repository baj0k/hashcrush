"""Background upload/import task handlers for the dedicated upload worker."""

from __future__ import annotations

import errno
import os

from flask import current_app
import lmdb
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from hashcrush.audit import record_audit_event
from hashcrush.hashfiles.service import create_hashfile_from_path
from hashcrush.hibp.service import (
    HIBP_NTLM_KIND,
    load_hibp_ntlm_dataset_from_source,
    scan_all_ntlm_hashes_against_hibp_dataset,
    scan_hashfile_against_hibp_dataset,
)
from hashcrush.models import Jobs, Rules, Wordlists, db
from hashcrush.utils.file_ops import analyze_text_file
from hashcrush.utils.storage_paths import get_storage_subdir
from hashcrush.view_utils import append_query_params
from hashcrush.wordlists.service import (
    create_static_wordlist_from_path,
    remove_managed_wordlist_file,
)


def _format_progress_bytes(size_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(max(size_bytes, 0))
    unit_index = 0
    while value >= 1024 and unit_index < len(units) - 1:
        value /= 1024
        unit_index += 1
    if unit_index == 0:
        return f"{int(value)} {units[unit_index]}"
    if value >= 100:
        return f"{value:.0f} {units[unit_index]}"
    if value >= 10:
        return f"{value:.1f}".rstrip("0").rstrip(".") + f" {units[unit_index]}"
    return f"{value:.2f}".rstrip("0").rstrip(".") + f" {units[unit_index]}"


def _make_stage_progress_callback(
    reporter,
    *,
    title: str,
    detail: str,
    start_percent: float,
    end_percent: float,
):
    progress_span = max(0.0, float(end_percent) - float(start_percent))

    def callback(processed: int, total: int) -> None:
        if total > 0:
            fraction = max(0.0, min(1.0, float(processed) / float(total)))
        else:
            fraction = 1.0 if processed else 0.0
        reporter.update(
            percent=start_percent + (progress_span * fraction),
            title=title,
            detail=detail,
        )

    return callback


def _make_hashfile_progress_callback(reporter):
    stage_config = {
        "validate": (
            5.0,
            28.0,
            "Validating hashfile...",
            "Checking the uploaded hashfile format.",
        ),
        "import": (
            28.0,
            96.0,
            "Importing hashes...",
            "Loading hashes into the shared dataset.",
        ),
    }

    def callback(stage: str, current: int, total: int) -> None:
        start_percent, end_percent, title, detail = stage_config.get(
            stage,
            (
                5.0,
                95.0,
                "Processing hashfile...",
                "The server is processing the uploaded hashfile.",
            ),
        )
        if total > 0:
            fraction = max(0.0, min(1.0, float(current) / float(total)))
        else:
            fraction = 1.0 if current else 0.0
        reporter.update(
            percent=start_percent + ((end_percent - start_percent) * fraction),
            title=title,
            detail=detail,
        )

    return callback


def _make_hibp_dataset_progress_callback(reporter):
    stage_config = {
        "stream_insert": (
            4.0,
            97.0,
            "Building offline dataset...",
            "Streaming the selected HIBP NTLM dataset into the local LMDB index.",
        ),
        "partition": (
            4.0,
            88.0,
            "Building offline dataset...",
            "Reading the selected HIBP NTLM dataset and building the local LMDB index.",
        ),
        "insert": (
            88.0,
            97.0,
            "Finalizing offline dataset...",
            "Writing the deduplicated LMDB lookup store to managed storage.",
        ),
    }

    def callback(stage: str, current: int, total: int) -> None:
        start_percent, end_percent, title, detail = stage_config.get(
            stage,
            (
                4.0,
                97.0,
                "Processing offline dataset...",
                "The server is validating and loading the offline dataset.",
            ),
        )
        if total > 0:
            fraction = max(0.0, min(1.0, float(current) / float(total)))
        else:
            fraction = 1.0 if current else 0.0
        if stage == "stream_insert":
            current_amount = _format_progress_bytes(current)
            total_amount = _format_progress_bytes(total) if total > 0 else "unknown size"
            detail = (
                f"Loaded {current_amount} of {total_amount} into the LMDB lookup store."
            )
        elif stage == "partition":
            current_amount = _format_progress_bytes(current)
            total_amount = _format_progress_bytes(total) if total > 0 else "unknown size"
            detail = (
                f"Read {current_amount} of {total_amount} from the selected "
                "HIBP NTLM dataset."
            )
        elif stage == "insert":
            if total > 0:
                detail = (
                    f"Loaded shard {int(current):,} of {int(total):,} into the LMDB "
                    "lookup store."
                )
            else:
                detail = "Writing the deduplicated LMDB lookup store."
        reporter.update(
            percent=start_percent + ((end_percent - start_percent) * fraction),
            title=title,
            detail=detail,
        )

    return callback


def _make_hibp_backfill_progress_callback(reporter):
    def callback(current: int, total: int) -> None:
        if total > 0:
            fraction = max(0.0, min(1.0, float(current) / float(total)))
            detail = (
                f"Checked {int(current):,} of {int(total):,} stored NTLM hash(es) "
                "against the offline dataset."
            )
        else:
            fraction = 1.0 if current else 0.0
            detail = (
                f"Checked {int(current):,} stored NTLM hash(es) against the offline dataset."
            )
        reporter.update(
            percent=4.0 + (93.0 * fraction),
            title="Refreshing exposure matches...",
            detail=detail,
        )

    return callback


def _hibp_dataset_failure_detail(exc: Exception) -> str:
    if isinstance(exc, lmdb.MapFullError):
        return (
            "The offline dataset build ran out of LMDB map space while finalizing the "
            "lookup store. Increase HASHCRUSH_HIBP_DATASET_MIN_MAP_SIZE_GB and retry."
        )
    if isinstance(exc, OSError) and exc.errno == errno.ENOSPC:
        return (
            "The server ran out of disk space while building the offline dataset. "
            "The HIBP build needs free space for temporary shards and the final LMDB store."
        )
    if isinstance(exc, MemoryError):
        return (
            "The server ran out of memory while finalizing the offline dataset. "
            "Retry with the safer HIBP build settings or reduce concurrent memory pressure."
        )
    return str(exc)


def _maybe_scan_hashfile_public_exposure(
    hashfile_id: int,
    hash_type: str,
    *,
    reporter=None,
) -> list[tuple[str, str]]:
    if str(hash_type or "").strip() != "1000":
        return []

    progress_callback = None
    if reporter is not None:
        progress_callback = _make_stage_progress_callback(
            reporter,
            title="Checking public exposures...",
            detail="Comparing NTLM hashes against the offline HIBP dataset.",
            start_percent=96,
            end_percent=99,
        )

    try:
        scan_result = scan_hashfile_against_hibp_dataset(
            hashfile_id,
            progress_callback=progress_callback,
        )
    except Exception:
        current_app.logger.exception(
            "Offline public exposure scan failed for hashfile %s",
            hashfile_id,
        )
        return [
            (
                "warning",
                "Hashfile import succeeded, but the offline public exposure check could not be completed.",
            )
        ]

    if scan_result.matched_account_count > 0:
        return [
            (
                "info",
                "Offline public exposure check matched "
                f"{scan_result.matched_hash_count} unique NTLM hash(es) across "
                f"{scan_result.matched_account_count} account row(s).",
            )
        ]
    return []


def _managed_rules_dir() -> str:
    path = get_storage_subdir("rules")
    os.makedirs(path, exist_ok=True)
    return path


def _remove_managed_file(stored_path: str, managed_root: str) -> None:
    resolved_path = os.path.abspath(stored_path)
    normalized_root = os.path.abspath(managed_root)
    try:
        if os.path.commonpath([resolved_path, normalized_root]) != normalized_root:
            return
    except ValueError:
        return
    if os.path.isfile(resolved_path):
        try:
            os.remove(resolved_path)
        except OSError:
            pass


def _remove_staged_hashfile_file(staged_path: str) -> None:
    if staged_path and os.path.isfile(staged_path):
        try:
            os.remove(staged_path)
        except OSError:
            current_app.logger.warning(
                "Failed removing staged hash upload file: %s", staged_path
            )


def _wordlist_redirect_target(
    next_url: str | None,
    *,
    fallback_url: str,
    wordlist_id: int | None = None,
) -> str:
    if not next_url:
        return fallback_url
    return append_query_params(next_url, selected_wordlist_id=wordlist_id)


def _rule_redirect_target(
    next_url: str | None,
    *,
    fallback_url: str,
    rule_id: int | None = None,
) -> str:
    if not next_url:
        return fallback_url
    return append_query_params(next_url, selected_rule_id=rule_id)


def _process_wordlist_upload(payload: dict[str, object], reporter) -> None:
    wordlist_name = str(payload.get("wordlist_name") or "").strip()
    wordlist_path = os.path.abspath(str(payload.get("wordlist_path") or "").strip())
    redirect_url = str(payload.get("redirect_url") or "").strip() or None
    fallback_url = str(payload.get("fallback_url") or "/wordlists").strip()
    audit_actor = payload.get("audit_actor")

    try:
        reporter.update(
            percent=5,
            title="Processing wordlist...",
            detail="Analyzing the uploaded wordlist.",
        )
        wordlist = create_static_wordlist_from_path(
            wordlist_name,
            wordlist_path,
            progress_callback=_make_stage_progress_callback(
                reporter,
                title="Processing wordlist...",
                detail="Reading the uploaded wordlist and counting entries.",
                start_percent=5,
                end_percent=92,
            ),
        )
    except IntegrityError:
        db.session.rollback()
        remove_managed_wordlist_file(wordlist_path)
        reporter.fail(
            title="Wordlist upload failed.",
            detail=(
                "Wordlist could not be uploaded because that name or file already "
                "exists. Refresh and retry."
            ),
        )
        return
    except Exception:
        db.session.rollback()
        remove_managed_wordlist_file(wordlist_path)
        current_app.logger.exception(
            "Failed processing queued wordlist upload for %s", wordlist_name
        )
        reporter.fail(
            title="Wordlist upload failed.",
            detail=(
                "The server hit an unexpected error while processing the wordlist."
            ),
        )
        return

    record_audit_event(
        "wordlist.create",
        "wordlist",
        target_id=wordlist.id,
        summary=f'Uploaded shared wordlist "{wordlist.name}".',
        details={
            "wordlist_name": wordlist.name,
            "path": wordlist.path,
            "type": wordlist.type,
            "source": "managed",
            "size": wordlist.size,
        },
        actor=audit_actor if isinstance(audit_actor, dict) else None,
    )
    reporter.complete(
        title="Wordlist ready.",
        detail=f'Shared wordlist "{wordlist.name}" is available.',
        redirect_url=_wordlist_redirect_target(
            redirect_url,
            fallback_url=fallback_url,
            wordlist_id=wordlist.id,
        ),
        completion_flashes=[("success", "Wordlist uploaded!")],
    )


def _process_wordlist_external_register(payload: dict[str, object], reporter) -> None:
    wordlist_name = str(payload.get("wordlist_name") or "").strip()
    wordlist_path = os.path.abspath(str(payload.get("wordlist_path") or "").strip())
    redirect_url = str(payload.get("redirect_url") or "").strip() or None
    fallback_url = str(payload.get("fallback_url") or "/wordlists").strip()
    audit_actor = payload.get("audit_actor")

    try:
        reporter.update(
            percent=5,
            title="Scanning mounted wordlist...",
            detail="Reading the mounted wordlist and collecting metadata.",
        )
        wordlist = create_static_wordlist_from_path(
            wordlist_name,
            wordlist_path,
            progress_callback=_make_stage_progress_callback(
                reporter,
                title="Scanning mounted wordlist...",
                detail="Reading the mounted wordlist and collecting metadata.",
                start_percent=5,
                end_percent=92,
            ),
        )
        reporter.update(
            percent=95,
            title="Saving wordlist...",
            detail="Registering the mounted wordlist in the database.",
        )
    except IntegrityError:
        db.session.rollback()
        reporter.fail(
            title="Mounted wordlist registration failed.",
            detail=(
                "Wordlist could not be registered because that name or path "
                "already exists. Refresh and retry."
            ),
        )
        return
    except Exception:
        db.session.rollback()
        current_app.logger.exception(
            "Failed registering mounted wordlist %s", wordlist_name
        )
        reporter.fail(
            title="Mounted wordlist registration failed.",
            detail=(
                "The server hit an unexpected error while processing the mounted "
                "wordlist."
            ),
        )
        return

    record_audit_event(
        "wordlist.create",
        "wordlist",
        target_id=wordlist.id,
        summary=f'Registered external shared wordlist "{wordlist.name}".',
        details={
            "wordlist_name": wordlist.name,
            "path": wordlist.path,
            "type": wordlist.type,
            "source": "external",
            "size": wordlist.size,
        },
        actor=audit_actor if isinstance(audit_actor, dict) else None,
    )
    reporter.complete(
        title="Mounted wordlist ready.",
        detail=f'Shared wordlist "{wordlist.name}" is available.',
        redirect_url=_wordlist_redirect_target(
            redirect_url,
            fallback_url=fallback_url,
            wordlist_id=wordlist.id,
        ),
        completion_flashes=[("success", "External wordlist registered!")],
    )


def _process_rule_upload(payload: dict[str, object], reporter) -> None:
    rule_name = str(payload.get("rule_name") or "").strip()
    rules_path = os.path.abspath(str(payload.get("rules_path") or "").strip())
    redirect_url = str(payload.get("redirect_url") or "").strip() or None
    fallback_url = str(payload.get("fallback_url") or "/rules").strip()
    audit_actor = payload.get("audit_actor")
    managed_root = _managed_rules_dir()

    try:
        reporter.update(
            percent=5,
            title="Processing rule...",
            detail="Analyzing the uploaded rule file.",
        )
        file_analysis = analyze_text_file(
            rules_path,
            progress_callback=_make_stage_progress_callback(
                reporter,
                title="Processing rule...",
                detail="Reading the uploaded rule file and counting entries.",
                start_percent=5,
                end_percent=92,
            ),
        )
        reporter.update(
            percent=95,
            title="Saving rule...",
            detail="Registering the rule file in the database.",
        )
        rule = Rules(
            name=rule_name,
            path=rules_path,
            size=file_analysis.line_count,
            checksum=file_analysis.checksum,
        )
        db.session.add(rule)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        _remove_managed_file(rules_path, managed_root)
        reporter.fail(
            title="Rule upload failed.",
            detail=(
                "Rule file could not be uploaded because that name or file already "
                "exists. Refresh and retry."
            ),
        )
        return
    except Exception:
        db.session.rollback()
        _remove_managed_file(rules_path, managed_root)
        current_app.logger.exception(
            "Failed processing queued rule upload for %s", rule_name
        )
        reporter.fail(
            title="Rule upload failed.",
            detail=(
                "The server hit an unexpected error while processing the rule file."
            ),
        )
        return

    record_audit_event(
        "rule.create",
        "rule",
        target_id=rule.id,
        summary=f'Uploaded shared rule "{rule.name}".',
        details={
            "rule_name": rule.name,
            "path": rule.path,
            "size": rule.size,
        },
        actor=audit_actor if isinstance(audit_actor, dict) else None,
    )
    reporter.complete(
        title="Rule ready.",
        detail=f'Shared rule "{rule.name}" is available.',
        redirect_url=_rule_redirect_target(
            redirect_url,
            fallback_url=fallback_url,
            rule_id=rule.id,
        ),
        completion_flashes=[("success", "Rule file uploaded!")],
    )


def _process_hashfile_upload(payload: dict[str, object], reporter) -> None:
    staged_hashfile_path = os.path.abspath(
        str(payload.get("staged_hashfile_path") or "").strip()
    )
    hashfile_name = str(payload.get("hashfile_name") or "").strip()
    default_domain_name = (
        str(payload.get("default_domain_name") or "").strip() or None
    )
    file_type = str(payload.get("file_type") or "").strip()
    hash_type = str(payload.get("hash_type") or "").strip()
    audit_actor = payload.get("audit_actor")

    try:
        reporter.update(
            percent=4,
            title="Preparing hashfile...",
            detail="Checking the uploaded hashfile before import.",
        )

        creation_result, error_message = create_hashfile_from_path(
            hashfile_path=staged_hashfile_path,
            hashfile_name=hashfile_name,
            default_domain_name=default_domain_name,
            file_type=file_type,
            hash_type=hash_type,
            progress_callback=_make_hashfile_progress_callback(reporter),
        )
        if error_message or creation_result is None:
            db.session.rollback()
            reporter.fail(
                title="Hashfile upload failed.",
                detail=(
                    error_message
                    or "Failed importing hashfile. Check file format/hash type and retry."
                ),
            )
            return

        hashfile = creation_result.hashfile
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception(
            "Failed processing queued hashfile upload for %s", hashfile_name
        )
        reporter.fail(
            title="Hashfile upload failed.",
            detail=(
                "The server hit an unexpected error while processing the hashfile."
            ),
        )
        return
    finally:
        _remove_staged_hashfile_file(staged_hashfile_path)

    flashes: list[tuple[str, str]] = []
    actor = audit_actor if isinstance(audit_actor, dict) else None
    record_audit_event(
        "hashfile.create",
        "hashfile",
        target_id=hashfile.id,
        summary=f'Registered shared hashfile "{hashfile.name}".',
        details={
            "hashfile_name": hashfile.name,
            "domain_id": hashfile.domain_id,
            "domain_name": hashfile.domain.name if hashfile.domain else None,
            "hash_type": creation_result.hash_type,
            "imported_hash_links": creation_result.imported_hash_links,
        },
        actor=actor,
    )
    flashes.append(("success", "Hashfile created!"))
    flashes.extend(
        _maybe_scan_hashfile_public_exposure(
            hashfile.id,
            creation_result.hash_type,
            reporter=reporter,
        )
    )
    reporter.complete(
        title="Hashfile ready.",
        detail=f'Shared hashfile "{hashfile.name}" is available.',
        completion_flashes=flashes,
    )


def _process_job_hashfile_upload(payload: dict[str, object], reporter) -> None:
    staged_hashfile_path = os.path.abspath(
        str(payload.get("staged_hashfile_path") or "").strip()
    )
    hashfile_name = str(payload.get("hashfile_name") or "").strip()
    file_type = str(payload.get("file_type") or "").strip()
    hash_type = str(payload.get("hash_type") or "").strip()
    default_domain_name = (
        str(payload.get("default_domain_name") or "").strip() or None
    )
    audit_actor = payload.get("audit_actor")

    try:
        job_id = int(payload.get("job_id") or 0)
    except (TypeError, ValueError):
        reporter.fail(
            title="Hashfile upload failed.",
            detail="Draft job details are invalid or no longer available.",
        )
        _remove_staged_hashfile_file(staged_hashfile_path)
        return

    try:
        reporter.update(
            percent=4,
            title="Preparing hashfile...",
            detail="Checking the draft job before attaching the uploaded hashfile.",
        )
        job = db.session.get(Jobs, job_id)
        if job is None:
            db.session.rollback()
            reporter.fail(
                title="Hashfile upload failed.",
                detail="The draft job no longer exists.",
            )
            return
        if job.status in {"Running", "Queued", "Paused"}:
            db.session.rollback()
            reporter.fail(
                title="Hashfile upload failed.",
                detail="Stop the job before changing its hashfile.",
            )
            return
        job_reference_id = int(job.id)
        job_name = str(job.name)

        creation_result, error_message = create_hashfile_from_path(
            hashfile_path=staged_hashfile_path,
            hashfile_name=hashfile_name,
            default_domain_name=default_domain_name,
            file_type=file_type,
            hash_type=hash_type,
            progress_callback=_make_hashfile_progress_callback(reporter),
        )
        if error_message or creation_result is None:
            db.session.rollback()
            reporter.fail(
                title="Hashfile upload failed.",
                detail=(
                    error_message
                    or "Failed importing hashfile. Check file format/hash type and retry."
                ),
            )
            return

        hashfile = db.session.get(type(creation_result.hashfile), creation_result.hashfile.id)
        job = db.session.get(Jobs, job_reference_id)
        if hashfile is None or job is None:
            db.session.rollback()
            reporter.fail(
                title="Hashfile upload failed.",
                detail="The draft job or uploaded hashfile changed while processing.",
            )
            return
        job.hashfile_id = hashfile.id
        job.domain_id = hashfile.domain_id
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        reporter.fail(
            title="Hashfile upload failed.",
            detail=(
                "Hashfile could not be saved because that name already exists or the "
                "draft job changed while the file was processing."
            ),
        )
        return
    except Exception:
        db.session.rollback()
        current_app.logger.exception(
            "Failed processing queued builder hashfile upload for %s", hashfile_name
        )
        reporter.fail(
            title="Hashfile upload failed.",
            detail=(
                "The server hit an unexpected error while processing the hashfile."
            ),
        )
        return
    finally:
        _remove_staged_hashfile_file(staged_hashfile_path)

    record_audit_event(
        "hashfile.create",
        "hashfile",
        target_id=hashfile.id,
        summary=f'Registered shared hashfile "{hashfile.name}" via job assignment.',
        details={
            "hashfile_name": hashfile.name,
            "domain_id": hashfile.domain_id,
            "job_id": job_reference_id,
            "hash_type": creation_result.hash_type,
            "imported_hash_links": creation_result.imported_hash_links,
        },
        actor=audit_actor if isinstance(audit_actor, dict) else None,
    )
    flashes = [("success", "Hashfile created and assigned to the job.")]
    flashes.extend(
        _maybe_scan_hashfile_public_exposure(
            hashfile.id,
            creation_result.hash_type,
            reporter=reporter,
        )
    )
    reporter.complete(
        title="Hashfile ready.",
        detail=f'Shared hashfile "{hashfile.name}" was attached to job "{job_name}".',
        completion_flashes=flashes,
    )


def _process_hibp_ntlm_dataset_upload(payload: dict[str, object], reporter) -> None:
    staged_dataset_path = os.path.abspath(
        str(payload.get("staged_dataset_path") or "").strip()
    )
    version_label = str(payload.get("version_label") or "").strip() or None
    source_filename = str(payload.get("source_filename") or "").strip() or None
    audit_actor = payload.get("audit_actor")

    try:
        reporter.update(
            percent=4,
            title="Preparing offline dataset...",
            detail="Checking the uploaded HIBP NTLM dataset before indexing.",
        )
        load_result = load_hibp_ntlm_dataset_from_source(
            staged_dataset_path,
            version_label=version_label,
            source_filename=source_filename,
            progress_callback=_make_hibp_dataset_progress_callback(reporter),
            persist_source_copy=True,
        )
    except ValueError as exc:
        db.session.rollback()
        reporter.fail(
            title="Offline dataset load failed.",
            detail=str(exc),
        )
        return
    except (lmdb.MapFullError, OSError, MemoryError) as exc:
        db.session.rollback()
        current_app.logger.exception("Failed processing queued offline HIBP dataset upload")
        reporter.fail(
            title="Offline dataset load failed.",
            detail=_hibp_dataset_failure_detail(exc),
        )
        return
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Failed processing queued offline HIBP dataset upload")
        reporter.fail(
            title="Offline dataset load failed.",
            detail="The server hit an unexpected error while processing the offline dataset.",
        )
        return
    finally:
        _remove_staged_hashfile_file(staged_dataset_path)

    _complete_hibp_ntlm_dataset_load(
        load_result,
        reporter,
        audit_actor=audit_actor,
        load_method="upload",
    )


def _complete_hibp_ntlm_dataset_load(
    load_result,
    reporter,
    *,
    audit_actor,
    load_method: str,
    source_path: str | None = None,
) -> None:
    audit_details = {
        "kind": "hibp_ntlm",
        "version_label": load_result.version_label,
        "source_filename": load_result.source_filename,
        "checksum": load_result.checksum,
        "record_count": load_result.record_count,
        "dataset_path": load_result.dataset_path,
        "load_method": load_method,
    }
    if source_path:
        audit_details["source_path"] = source_path

    record_audit_event(
        "reference_dataset.load",
        "reference_dataset",
        target_id=load_result.checksum,
        summary='Loaded offline HIBP NTLM dataset.',
        details=audit_details,
        actor=audit_actor if isinstance(audit_actor, dict) else None,
    )
    completion_flashes = [
        ("success", "Offline HIBP NTLM dataset loaded."),
        (
            "info",
            "New NTLM hashfile imports will be checked automatically. "
            "Use Refresh Existing Hashes to backfill already stored data.",
        ),
    ]
    reporter.complete(
        title="Offline dataset ready.",
        detail=(
            f'Loaded offline HIBP NTLM dataset "{load_result.version_label}". '
            "Existing hashes can now be refreshed separately."
        ),
        completion_flashes=completion_flashes,
    )


def _process_hibp_ntlm_dataset_register(payload: dict[str, object], reporter) -> None:
    source_path = os.path.abspath(str(payload.get("source_path") or "").strip())
    version_label = str(payload.get("version_label") or "").strip() or None
    source_filename = str(payload.get("source_filename") or "").strip() or None
    audit_actor = payload.get("audit_actor")

    try:
        reporter.update(
            percent=4,
            title="Preparing offline dataset...",
            detail="Checking the mounted HIBP NTLM dataset before indexing.",
        )
        load_result = load_hibp_ntlm_dataset_from_source(
            source_path,
            version_label=version_label,
            source_filename=source_filename,
            progress_callback=_make_hibp_dataset_progress_callback(reporter),
        )
    except ValueError as exc:
        db.session.rollback()
        reporter.fail(
            title="Mounted dataset load failed.",
            detail=str(exc),
        )
        return
    except (lmdb.MapFullError, OSError, MemoryError) as exc:
        db.session.rollback()
        current_app.logger.exception("Failed processing queued mounted HIBP dataset load")
        reporter.fail(
            title="Mounted dataset load failed.",
            detail=_hibp_dataset_failure_detail(exc),
        )
        return
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Failed processing queued mounted HIBP dataset load")
        reporter.fail(
            title="Mounted dataset load failed.",
            detail="The server hit an unexpected error while processing the mounted dataset.",
        )
        return

    _complete_hibp_ntlm_dataset_load(
        load_result,
        reporter,
        audit_actor=audit_actor,
        load_method="mounted_path",
        source_path=source_path,
    )


def _process_hibp_ntlm_dataset_backfill(payload: dict[str, object], reporter) -> None:
    audit_actor = payload.get("audit_actor")

    try:
        reporter.update(
            percent=4,
            title="Refreshing exposure matches...",
            detail="Preparing the stored NTLM hash set for an offline exposure refresh.",
        )
        backfill_result = scan_all_ntlm_hashes_against_hibp_dataset(
            progress_callback=_make_hibp_backfill_progress_callback(reporter),
        )
    except Exception:
        db.session.rollback()
        current_app.logger.exception(
            "Failed processing queued offline HIBP dataset backfill"
        )
        reporter.fail(
            title="Exposure refresh failed.",
            detail="The server hit an unexpected error while refreshing existing hashes.",
        )
        return

    record_audit_event(
        "reference_dataset.backfill",
        "reference_dataset",
        target_id=HIBP_NTLM_KIND,
        summary="Refreshed offline public exposure matches for stored NTLM hashes.",
        details={
            "kind": HIBP_NTLM_KIND,
            "matched_hash_count": backfill_result.matched_hash_count,
            "matched_account_count": backfill_result.matched_account_count,
            "scanned_hash_count": backfill_result.scanned_hash_count,
        },
        actor=audit_actor if isinstance(audit_actor, dict) else None,
    )
    completion_flashes = [("success", "Existing NTLM hashes refreshed against the offline dataset.")]
    if backfill_result.matched_account_count > 0:
        completion_flashes.append(
            (
                "info",
                "The offline dataset matched "
                f"{backfill_result.matched_hash_count} unique NTLM hash(es) across "
                f"{backfill_result.matched_account_count} account row(s).",
            )
        )
    reporter.complete(
        title="Exposure refresh complete.",
        detail=(
            "Finished refreshing stored NTLM hashes against the active offline dataset."
        ),
        completion_flashes=completion_flashes,
    )


def process_upload_operation(
    operation_type: str, payload: dict[str, object], reporter
) -> None:
    """Dispatch a queued upload operation to its concrete handler."""

    if not isinstance(payload, dict):
        raise RuntimeError("Upload worker payload must be a JSON object.")

    normalized_type = str(operation_type or "").strip().lower()
    if normalized_type == "wordlist_upload":
        _process_wordlist_upload(payload, reporter)
        return
    if normalized_type == "wordlist_external_register":
        _process_wordlist_external_register(payload, reporter)
        return
    if normalized_type == "rule_upload":
        _process_rule_upload(payload, reporter)
        return
    if normalized_type == "hashfile_upload":
        _process_hashfile_upload(payload, reporter)
        return
    if normalized_type == "job_hashfile_upload":
        _process_job_hashfile_upload(payload, reporter)
        return
    if normalized_type == "hibp_ntlm_dataset_upload":
        _process_hibp_ntlm_dataset_upload(payload, reporter)
        return
    if normalized_type == "hibp_ntlm_dataset_register":
        _process_hibp_ntlm_dataset_register(payload, reporter)
        return
    if normalized_type == "hibp_ntlm_dataset_backfill":
        _process_hibp_ntlm_dataset_backfill(payload, reporter)
        return
    raise RuntimeError(f"Unsupported upload operation type: {operation_type!r}")
