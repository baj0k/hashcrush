"""Flask routes to handle Hashfiles"""
import os
from collections import defaultdict

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import case, delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql import exists

from hashcrush.audit import capture_audit_actor, record_audit_event
from hashcrush.authz import admin_required_redirect, visible_jobs_query
from hashcrush.domains.service import resolve_or_create_shared_domain
from hashcrush.hashfiles.forms import HashfilesAddForm
from hashcrush.hashfiles.service import create_hashfile_from_form, create_hashfile_from_path
from hashcrush.models import Domains, Hashes, HashfileHashes, Hashfiles, Jobs, db
from hashcrush.utils.utils import get_runtime_subdir, save_file
from hashcrush.view_utils import LIST_PAGE_SIZE, paginate_scalars, parse_page_arg

hashfiles = Blueprint('hashfiles', __name__)


def _is_async_upload_request() -> bool:
    return request.headers.get('X-Requested-With') == 'XMLHttpRequest'


def _async_operation_response(operation):
    payload = operation.to_response_dict()
    payload['status_url'] = url_for(
        'uploads.upload_operation_status',
        operation_id=operation.id,
    )
    return jsonify(payload), 202


def _remove_staged_hashfile_file(staged_path: str) -> None:
    if staged_path and os.path.isfile(staged_path):
        try:
            os.remove(staged_path)
        except OSError:
            current_app.logger.warning(
                'Failed removing staged hash upload file: %s', staged_path
            )


def _make_hashfile_progress_callback(reporter):
    stage_config = {
        'validate': (
            5.0,
            28.0,
            'Validating hashfile...',
            'Checking the uploaded hashfile format.',
        ),
        'import': (
            28.0,
            96.0,
            'Importing hashes...',
            'Loading hashes into the shared dataset.',
        ),
    }

    def callback(stage: str, current: int, total: int) -> None:
        start_percent, end_percent, title, detail = stage_config.get(
            stage,
            (
                5.0,
                95.0,
                'Processing hashfile...',
                'The server is processing the uploaded hashfile.',
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


def _count_orphan_uncracked_hashes_for_hashfiles(hashfile_ids: list[int]) -> int:
    if not hashfile_ids:
        return 0

    return int(
        db.session.scalar(
            select(func.count())
            .select_from(Hashes)
            .where(Hashes.cracked.is_(False))
            .where(
                exists()
                .where(HashfileHashes.hash_id == Hashes.id)
                .where(HashfileHashes.hashfile_id.in_(hashfile_ids))
            )
            .where(
                ~exists()
                .where(HashfileHashes.hash_id == Hashes.id)
                .where(~HashfileHashes.hashfile_id.in_(hashfile_ids))
            )
        )
        or 0
    )


def _hashfile_delete_impact(hashfile_id: int) -> dict[str, int]:
    return {
        'associated_jobs': int(
            db.session.scalar(
                select(func.count()).select_from(Jobs).filter_by(hashfile_id=hashfile_id)
            )
            or 0
        ),
        'hash_links': int(
            db.session.scalar(
                select(func.count()).select_from(HashfileHashes).filter_by(hashfile_id=hashfile_id)
            )
            or 0
        ),
        'orphan_uncracked_hashes': _count_orphan_uncracked_hashes_for_hashfiles([hashfile_id]),
    }


def _hashfile_delete_impact_previews(hashfile_ids: list[int]) -> dict[int, dict[str, int]]:
    if not hashfile_ids:
        return {}

    job_counts = {
        row.hashfile_id: int(row.associated_jobs or 0)
        for row in db.session.execute(
            select(
                Jobs.hashfile_id,
                func.count(Jobs.id).label('associated_jobs'),
            )
            .where(Jobs.hashfile_id.in_(hashfile_ids))
            .group_by(Jobs.hashfile_id)
        ).all()
    }

    hash_link_counts = {
        row.hashfile_id: int(row.hash_links or 0)
        for row in db.session.execute(
            select(
                HashfileHashes.hashfile_id,
                func.count(HashfileHashes.id).label('hash_links'),
            )
            .where(HashfileHashes.hashfile_id.in_(hashfile_ids))
            .group_by(HashfileHashes.hashfile_id)
        ).all()
    }

    orphan_hashes_subquery = (
        select(
            func.min(HashfileHashes.hashfile_id).label('hashfile_id'),
            Hashes.id.label('hash_id'),
        )
        .select_from(Hashes)
        .join(HashfileHashes, HashfileHashes.hash_id == Hashes.id)
        .where(Hashes.cracked.is_(False))
        .where(HashfileHashes.hashfile_id.in_(hashfile_ids))
        .group_by(Hashes.id)
        .having(func.count(func.distinct(HashfileHashes.hashfile_id)) == 1)
        .subquery()
    )
    orphan_hash_counts = {
        row.hashfile_id: int(row.orphan_hashes or 0)
        for row in db.session.execute(
            select(
                orphan_hashes_subquery.c.hashfile_id,
                func.count(orphan_hashes_subquery.c.hash_id).label('orphan_hashes'),
            )
            .group_by(orphan_hashes_subquery.c.hashfile_id)
        ).all()
    }

    return {
        hashfile_id: {
            'associated_jobs': job_counts.get(hashfile_id, 0),
            'hash_links': hash_link_counts.get(hashfile_id, 0),
            'orphan_uncracked_hashes': orphan_hash_counts.get(hashfile_id, 0),
        }
        for hashfile_id in hashfile_ids
    }


def _shared_domains() -> list[Domains]:
    return db.session.execute(
        select(Domains).order_by(Domains.name.asc())
    ).scalars().all()


def _render_hashfiles_add_form(form, domains):
    return render_template(
        'hashfiles_add.html',
        title='Hashfiles Add',
        hashfilesForm=form,
        domains=domains,
    )


def _process_hashfile_upload(
    *,
    staged_hashfile_path: str,
    hashfile_name: str,
    domain_selection: str,
    new_domain_name: str | None,
    file_type: str,
    hash_type: str,
    audit_actor: dict[str, object],
    reporter,
) -> None:
    domain_result = None
    try:
        reporter.update(
            percent=4,
            title='Preparing hashfile...',
            detail='Resolving the selected shared domain.',
        )
        domain_result, domain_error = resolve_or_create_shared_domain(
            domain_selection,
            new_domain_name=new_domain_name,
            allow_create=True,
        )
        if domain_error or domain_result is None:
            db.session.rollback()
            reporter.fail(
                title='Hashfile upload failed.',
                detail=domain_error or 'Selected domain is invalid or no longer available.',
            )
            return

        creation_result, error_message = create_hashfile_from_path(
            hashfile_path=staged_hashfile_path,
            hashfile_name=hashfile_name,
            domain_id=domain_result.domain.id,
            file_type=file_type,
            hash_type=hash_type,
            progress_callback=_make_hashfile_progress_callback(reporter),
        )
        if error_message or creation_result is None:
            db.session.rollback()
            reporter.fail(
                title='Hashfile upload failed.',
                detail=error_message or 'Failed importing hashfile. Check file format/hash type and retry.',
            )
            return

        hashfile = creation_result.hashfile
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception(
            'Failed processing async hashfile upload for %s', hashfile_name
        )
        reporter.fail(
            title='Hashfile upload failed.',
            detail='The server hit an unexpected error while processing the hashfile.',
        )
        return
    finally:
        _remove_staged_hashfile_file(staged_hashfile_path)

    flashes: list[tuple[str, str]] = []
    if domain_result.created:
        record_audit_event(
            'domain.create',
            'domain',
            target_id=domain_result.domain.id,
            summary=f'Created shared domain "{domain_result.domain.name}" from hashfile creation.',
            details={
                'domain_name': domain_result.domain.name,
                'source': 'hashfiles.add',
            },
            actor=audit_actor,
        )
    elif domain_selection == 'add_new':
        flashes.append(
            ('info', f'Using existing shared domain "{domain_result.domain.name}".')
        )

    record_audit_event(
        'hashfile.create',
        'hashfile',
        target_id=hashfile.id,
        summary=f'Registered shared hashfile "{hashfile.name}".',
        details={
            'hashfile_name': hashfile.name,
            'domain_id': domain_result.domain.id,
            'domain_name': domain_result.domain.name,
            'hash_type': creation_result.hash_type,
            'imported_hash_links': creation_result.imported_hash_links,
        },
        actor=audit_actor,
    )
    flashes.append(('success', 'Hashfile created!'))
    reporter.complete(
        title='Hashfile ready.',
        detail=f'Shared hashfile "{hashfile.name}" is available.',
        completion_flashes=flashes,
    )


@hashfiles.route("/hashfiles", methods=['GET', 'POST'])
@login_required

def hashfiles_list():
    """Function to return list of hashfiles"""
    page = parse_page_arg(request.args.get('page'))
    hashfiles, pagination = paginate_scalars(
        db.session,
        select(Hashfiles).order_by(Hashfiles.uploaded_at.desc()),
        page=page,
        per_page=LIST_PAGE_SIZE,
    )
    domain_ids = sorted({hashfile.domain_id for hashfile in hashfiles})
    domains = (
        db.session.execute(
            select(Domains)
            .where(Domains.id.in_(domain_ids))
            .order_by(Domains.name.asc())
        ).scalars().all()
        if domain_ids
        else []
    )
    hashfile_ids = [hashfile.id for hashfile in hashfiles]
    jobs = (
        db.session.execute(
            visible_jobs_query().where(Jobs.hashfile_id.in_(hashfile_ids))
        ).scalars().all()
        if hashfile_ids
        else []
    )
    jobs_by_hashfile: dict[int, list[Jobs]] = defaultdict(list)
    for job in jobs:
        if job.hashfile_id is not None:
            jobs_by_hashfile[job.hashfile_id].append(job)
    hashfiles_by_domain: dict[int, list[Hashfiles]] = defaultdict(list)
    for hashfile in hashfiles:
        hashfiles_by_domain[hashfile.domain_id].append(hashfile)

    cracked_rate = {}
    hash_type_dict = {}

    stats_by_hashfile_id = {}
    types_by_hashfile_id = {}
    if hashfile_ids:
        stats_rows = (
            db.session.execute(
                select(
                    HashfileHashes.hashfile_id,
                    func.count(Hashes.id).label('total_count'),
                    func.sum(case((Hashes.cracked.is_(True), 1), else_=0)).label('cracked_count'),
                )
                .select_from(HashfileHashes)
                .join(Hashes, Hashes.id == HashfileHashes.hash_id)
                .where(HashfileHashes.hashfile_id.in_(hashfile_ids))
                .group_by(HashfileHashes.hashfile_id)
            )
            .all()
        )
        stats_by_hashfile_id = {
            row.hashfile_id: (
                int(row.cracked_count or 0),
                int(row.total_count or 0),
            )
            for row in stats_rows
        }

        type_rows = (
            db.session.execute(
                select(
                    HashfileHashes.hashfile_id,
                    func.min(Hashes.hash_type).label('hash_type'),
                )
                .select_from(HashfileHashes)
                .join(Hashes, Hashes.id == HashfileHashes.hash_id)
                .where(HashfileHashes.hashfile_id.in_(hashfile_ids))
                .group_by(HashfileHashes.hashfile_id)
            )
            .all()
        )
        types_by_hashfile_id = {
            row.hashfile_id: row.hash_type
            for row in type_rows
        }

    for hashfile in hashfiles:
        cracked_cnt, hash_cnt = stats_by_hashfile_id.get(hashfile.id, (0, 0))
        cracked_rate[hashfile.id] = "(" + str(cracked_cnt) + "/" + str(hash_cnt) + ")"
        hash_type_dict[hashfile.id] = types_by_hashfile_id.get(hashfile.id, 'UNKNOWN')

    hashfile_delete_impacts = (
        _hashfile_delete_impact_previews(hashfile_ids)
        if current_user.admin
        else {}
    )
    return render_template(
        'hashfiles.html',
        title='Hashfiles',
        hashfiles=hashfiles,
        domains=domains,
        hashfiles_by_domain=hashfiles_by_domain,
        cracked_rate=cracked_rate,
        jobs_by_hashfile=jobs_by_hashfile,
        hash_type_dict=hash_type_dict,
        hashfile_delete_impacts=hashfile_delete_impacts,
        pagination=pagination,
    )


@hashfiles.route("/hashfiles/add", methods=['GET', 'POST'])
@login_required
@admin_required_redirect('hashfiles.hashfiles_list')
def hashfiles_add():
    """Create a new shared hashfile from the UI."""

    domains = _shared_domains()
    form = HashfilesAddForm()
    form.domain_id.choices = [('', '--SELECT DOMAIN--')] + [
        (str(domain.id), domain.name) for domain in domains
    ]
    form.domain_id.choices.append(('add_new', 'Add New Domain'))

    if request.method == 'POST' and form.validate_on_submit():
        if _is_async_upload_request() and form.hashfile.data:
            hash_type = (
                form.pwdump_hash_type.data
                if form.file_type.data == 'pwdump'
                else form.netntlm_hash_type.data
                if form.file_type.data == 'NetNTLM'
                else form.kerberos_hash_type.data
                if form.file_type.data == 'kerberos'
                else form.shadow_hash_type.data
                if form.file_type.data == 'shadow'
                else form.hash_type.data
            )
            runtime_tmp_dir = get_runtime_subdir('tmp')
            os.makedirs(runtime_tmp_dir, exist_ok=True)
            staged_hashfile_path = save_file(runtime_tmp_dir, form.hashfile.data)
            operation = current_app.extensions['upload_operations'].start_operation(
                owner_user_id=getattr(current_user, 'id', None),
                redirect_url=url_for('hashfiles.hashfiles_list'),
                worker=(
                    lambda reporter,
                    staged_hashfile_path=staged_hashfile_path,
                    hashfile_name=(
                        form.name.data
                        or form.hashfile.data.filename
                        or 'uploaded-hashfile.txt'
                    ),
                    domain_selection=form.domain_id.data,
                    new_domain_name=form.domain_name.data,
                    file_type=form.file_type.data,
                    hash_type=(hash_type or ''),
                    audit_actor=capture_audit_actor(): _process_hashfile_upload(
                        staged_hashfile_path=staged_hashfile_path,
                        hashfile_name=hashfile_name,
                        domain_selection=domain_selection,
                        new_domain_name=new_domain_name,
                        file_type=file_type,
                        hash_type=hash_type,
                        audit_actor=audit_actor,
                        reporter=reporter,
                    )
                ),
            )
            return _async_operation_response(operation)

        domain_result, domain_error = resolve_or_create_shared_domain(
            form.domain_id.data,
            new_domain_name=form.domain_name.data,
            allow_create=True,
        )
        if domain_error:
            flash(domain_error, 'danger')
            return _render_hashfiles_add_form(form, domains)
        domain = domain_result.domain

        creation_result, error_message = create_hashfile_from_form(
            form,
            domain_id=domain.id,
        )
        if error_message:
            flash(error_message, 'danger')
            return _render_hashfiles_add_form(form, domains)

        hashfile = creation_result.hashfile
        db.session.commit()
        if domain_result.created:
            record_audit_event(
                'domain.create',
                'domain',
                target_id=domain.id,
                summary=f'Created shared domain "{domain.name}" from hashfile creation.',
                details={'domain_name': domain.name, 'source': 'hashfiles.add'},
            )
        elif form.domain_id.data == 'add_new':
            flash(f'Using existing shared domain "{domain.name}".', 'info')
        record_audit_event(
            'hashfile.create',
            'hashfile',
            target_id=hashfile.id,
            summary=f'Registered shared hashfile "{hashfile.name}".',
            details={
                'hashfile_name': hashfile.name,
                'domain_id': domain.id,
                'domain_name': domain.name,
                'hash_type': creation_result.hash_type,
                'imported_hash_links': creation_result.imported_hash_links,
            },
        )
        flash('Hashfile created!', 'success')
        return redirect(url_for('hashfiles.hashfiles_list'))

    return _render_hashfiles_add_form(form, domains)

@hashfiles.route("/hashfiles/delete/<int:hashfile_id>", methods=['POST'])
@login_required
def hashfiles_delete(hashfile_id):
    """Function to delete hashfile by id"""
    hashfile = db.get_or_404(Hashfiles, hashfile_id)
    impact = _hashfile_delete_impact(hashfile_id)
    hashfile_name = hashfile.name

    if not current_user.admin:
        flash('Permission Denied', 'danger')
        return redirect(url_for('hashfiles.hashfiles_list'))

    if hashfile:
        if impact['associated_jobs'] > 0:
            flash(
                f"Error: Hashfile currently associated with {impact['associated_jobs']} job(s).",
                'danger',
            )
            return redirect(url_for('hashfiles.hashfiles_list'))
        if (request.form.get('confirm_name') or '').strip() != hashfile.name:
            flash('Type the hashfile name exactly to confirm deletion.', 'danger')
            return redirect(url_for('hashfiles.hashfiles_list'))
        try:
            db.session.execute(delete(HashfileHashes).filter_by(hashfile_id=hashfile_id))
            db.session.execute(delete(Hashfiles).filter_by(id=hashfile_id))
            db.session.execute(
                delete(Hashes)
                .where(~exists().where(Hashes.id == HashfileHashes.hash_id))
                .where(Hashes.cracked.is_(False))
            )
            db.session.commit()
            current_app.logger.info(
                'Deleted hashfile id=%s name=%s impact hash_links=%s orphan_uncracked=%s',
                hashfile.id,
                hashfile_name,
                impact['hash_links'],
                impact['orphan_uncracked_hashes'],
            )
            record_audit_event(
                'hashfile.delete',
                'hashfile',
                target_id=hashfile_id,
                summary=f'Deleted shared hashfile "{hashfile_name}".',
                details={
                    'hashfile_name': hashfile_name,
                    'hash_links_removed': impact['hash_links'],
                    'orphan_uncracked_hashes_removed': impact['orphan_uncracked_hashes'],
                },
            )
        except IntegrityError:
            db.session.rollback()
            flash('Error: Hashfile is associated with a job or changed concurrently.', 'danger')
            return redirect(url_for('hashfiles.hashfiles_list'))
        except Exception:
            db.session.rollback()
            current_app.logger.exception('Failed deleting hashfile id=%s', hashfile_id)
            flash('Error deleting hashfile.', 'danger')
            return redirect(url_for('hashfiles.hashfiles_list'))
        flash(
            'Hashfile has been deleted. '
            f"Removed {impact['hash_links']} hash association(s) and "
            f"{impact['orphan_uncracked_hashes']} orphaned uncracked hash(es).",
            'success',
        )
        return redirect(url_for('hashfiles.hashfiles_list'))

    flash('Error deleting hashfile', 'danger')
    return redirect(url_for('hashfiles.hashfiles_list'))
