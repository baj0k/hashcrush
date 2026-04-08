"""Background upload/import task handlers for the dedicated upload worker."""

from __future__ import annotations

import os

from flask import current_app
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from hashcrush.audit import record_audit_event
from hashcrush.domains.service import resolve_or_create_shared_domain
from hashcrush.hashfiles.service import create_hashfile_from_path
from hashcrush.models import Jobs, Rules, Wordlists, db
from hashcrush.utils.file_ops import analyze_text_file
from hashcrush.utils.storage_paths import get_storage_subdir
from hashcrush.view_utils import append_query_params


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


def _managed_wordlists_dir() -> str:
    path = get_storage_subdir("wordlists")
    os.makedirs(path, exist_ok=True)
    return path


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
    managed_root = _managed_wordlists_dir()

    try:
        reporter.update(
            percent=5,
            title="Processing wordlist...",
            detail="Analyzing the uploaded wordlist.",
        )
        file_analysis = analyze_text_file(
            wordlist_path,
            progress_callback=_make_stage_progress_callback(
                reporter,
                title="Processing wordlist...",
                detail="Reading the uploaded wordlist and counting entries.",
                start_percent=5,
                end_percent=92,
            ),
        )
        reporter.update(
            percent=95,
            title="Saving wordlist...",
            detail="Registering the wordlist in the database.",
        )
        wordlist = Wordlists(
            name=wordlist_name,
            type="static",
            path=wordlist_path,
            checksum=file_analysis.checksum,
            size=file_analysis.line_count,
        )
        db.session.add(wordlist)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        _remove_managed_file(wordlist_path, managed_root)
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
        _remove_managed_file(wordlist_path, managed_root)
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
    domain_selection = str(payload.get("domain_selection") or "").strip()
    new_domain_name = str(payload.get("new_domain_name") or "").strip() or None
    file_type = str(payload.get("file_type") or "").strip()
    hash_type = str(payload.get("hash_type") or "").strip()
    audit_actor = payload.get("audit_actor")

    domain_result = None
    domain_id: int | None = None
    domain_name: str | None = None
    domain_created = False
    try:
        reporter.update(
            percent=4,
            title="Preparing hashfile...",
            detail="Resolving the selected shared domain.",
        )
        domain_result, domain_error = resolve_or_create_shared_domain(
            domain_selection,
            new_domain_name=new_domain_name,
            allow_create=True,
        )
        if domain_error or domain_result is None:
            db.session.rollback()
            reporter.fail(
                title="Hashfile upload failed.",
                detail=(
                    domain_error
                    or "Selected domain is invalid or no longer available."
                ),
            )
            return
        domain_id = int(domain_result.domain.id)
        domain_name = str(domain_result.domain.name)
        domain_created = bool(domain_result.created)

        creation_result, error_message = create_hashfile_from_path(
            hashfile_path=staged_hashfile_path,
            hashfile_name=hashfile_name,
            domain_id=domain_id,
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
    if domain_created and domain_id is not None and domain_name:
        record_audit_event(
            "domain.create",
            "domain",
            target_id=domain_id,
            summary=f'Created shared domain "{domain_name}" from hashfile creation.',
            details={
                "domain_name": domain_name,
                "source": "hashfiles.add",
            },
            actor=actor,
        )
    elif domain_selection == "add_new" and domain_name:
        flashes.append(
            ("info", f'Using existing shared domain "{domain_name}".')
        )

    record_audit_event(
        "hashfile.create",
        "hashfile",
        target_id=hashfile.id,
        summary=f'Registered shared hashfile "{hashfile.name}".',
        details={
            "hashfile_name": hashfile.name,
            "domain_id": domain_id,
            "domain_name": domain_name,
            "hash_type": creation_result.hash_type,
            "imported_hash_links": creation_result.imported_hash_links,
        },
        actor=actor,
    )
    flashes.append(("success", "Hashfile created!"))
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
    audit_actor = payload.get("audit_actor")

    try:
        job_id = int(payload.get("job_id") or 0)
        domain_id = int(payload.get("domain_id") or 0)
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
        if job is None or int(job.domain_id or 0) != domain_id:
            db.session.rollback()
            reporter.fail(
                title="Hashfile upload failed.",
                detail="The draft job no longer exists or changed domains.",
            )
            return
        if job.status in {"Running", "Queued", "Paused"}:
            db.session.rollback()
            reporter.fail(
                title="Hashfile upload failed.",
                detail="Stop the job before changing its hashfile.",
            )
            return

        creation_result, error_message = create_hashfile_from_path(
            hashfile_path=staged_hashfile_path,
            hashfile_name=hashfile_name,
            domain_id=domain_id,
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
        job.hashfile_id = hashfile.id
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
            "domain_id": domain_id,
            "job_id": job.id,
            "hash_type": creation_result.hash_type,
            "imported_hash_links": creation_result.imported_hash_links,
        },
        actor=audit_actor if isinstance(audit_actor, dict) else None,
    )
    reporter.complete(
        title="Hashfile ready.",
        detail=f'Shared hashfile "{hashfile.name}" was attached to job "{job.name}".',
        completion_flashes=[("success", "Hashfile created and assigned to the job.")],
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
    if normalized_type == "rule_upload":
        _process_rule_upload(payload, reporter)
        return
    if normalized_type == "hashfile_upload":
        _process_hashfile_upload(payload, reporter)
        return
    if normalized_type == "job_hashfile_upload":
        _process_job_hashfile_upload(payload, reporter)
        return
    raise RuntimeError(f"Unsupported upload operation type: {operation_type!r}")
