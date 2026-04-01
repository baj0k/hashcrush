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
from hashcrush.hashfiles.validation import normalize_hashfile_file_type
from hashcrush.hashfiles.service import create_hashfile_from_form
from hashcrush.models import Domains, Hashes, HashfileHashes, Hashfiles, Jobs, db
from hashcrush.utils.file_ops import save_file
from hashcrush.utils.storage_paths import get_runtime_subdir
from hashcrush.view_utils import LIST_PAGE_SIZE, paginate_scalars, parse_page_arg, safe_relative_url

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


def _hashfile_stats_by_id(hashfile_ids: list[int]) -> dict[int, dict[str, int | str]]:
    if not hashfile_ids:
        return {}

    stats_rows = db.session.execute(
        select(
            HashfileHashes.hashfile_id,
            func.count(Hashes.id).label('total_count'),
            func.sum(case((Hashes.cracked.is_(True), 1), else_=0)).label('cracked_count'),
            func.min(Hashes.hash_type).label('hash_type'),
        )
        .select_from(HashfileHashes)
        .join(Hashes, Hashes.id == HashfileHashes.hash_id)
        .where(HashfileHashes.hashfile_id.in_(hashfile_ids))
        .group_by(HashfileHashes.hashfile_id)
    ).all()

    return {
        row.hashfile_id: {
            'cracked_count': int(row.cracked_count or 0),
            'total_count': int(row.total_count or 0),
            'hash_type': row.hash_type or 'UNKNOWN',
        }
        for row in stats_rows
    }


def _hashfile_detail_context(hashfile: Hashfiles) -> dict[str, object]:
    associated_jobs = db.session.execute(
        visible_jobs_query()
        .where(Jobs.hashfile_id == hashfile.id)
        .order_by(Jobs.created_at.desc())
    ).scalars().all()
    stats = _hashfile_stats_by_id([hashfile.id]).get(
        hashfile.id,
        {'cracked_count': 0, 'total_count': 0, 'hash_type': 'UNKNOWN'},
    )
    return {
        'associated_jobs': associated_jobs,
        'hashfile_stats': stats,
        'delete_impact': _hashfile_delete_impact(hashfile.id),
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
    hashfiles_by_domain: dict[int, list[Hashfiles]] = defaultdict(list)
    for hashfile in hashfiles:
        hashfiles_by_domain[hashfile.domain_id].append(hashfile)

    cracked_rate = {}
    hash_type_dict = {}
    stats_by_hashfile_id = _hashfile_stats_by_id(hashfile_ids)
    for hashfile in hashfiles:
        stats = stats_by_hashfile_id.get(
            hashfile.id,
            {'cracked_count': 0, 'total_count': 0, 'hash_type': 'UNKNOWN'},
        )
        cracked_rate[hashfile.id] = f"({stats['cracked_count']}/{stats['total_count']})"
        hash_type_dict[hashfile.id] = stats['hash_type']
    return render_template(
        'hashfiles.html',
        title='Hashfiles',
        hashfiles=hashfiles,
        domains=domains,
        hashfiles_by_domain=hashfiles_by_domain,
        cracked_rate=cracked_rate,
        hash_type_dict=hash_type_dict,
        pagination=pagination,
    )


@hashfiles.route("/hashfiles/<int:hashfile_id>", methods=['GET'])
@login_required
def hashfiles_detail(hashfile_id):
    """Show usage and deletion details for a shared hashfile."""

    hashfile = db.get_or_404(Hashfiles, hashfile_id)
    return render_template(
        'hashfiles_detail.html',
        title=f'Hashfile: {hashfile.name}',
        hashfile=hashfile,
        **_hashfile_detail_context(hashfile),
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
            normalized_file_type = normalize_hashfile_file_type(form.file_type.data)
            hash_type = (
                form.pwdump_hash_type.data
                if normalized_file_type == 'pwdump'
                else form.netntlm_hash_type.data
                if normalized_file_type == 'NetNTLM'
                else form.kerberos_hash_type.data
                if normalized_file_type == 'kerberos'
                else form.shadow_hash_type.data
                if normalized_file_type == 'shadow'
                else form.hash_type.data
            )
            runtime_tmp_dir = get_runtime_subdir('tmp')
            os.makedirs(runtime_tmp_dir, exist_ok=True)
            staged_hashfile_path = save_file(runtime_tmp_dir, form.hashfile.data)
            operation = current_app.extensions['upload_operations'].start_operation(
                owner_user_id=getattr(current_user, 'id', None),
                operation_type='hashfile_upload',
                redirect_url=url_for('hashfiles.hashfiles_list'),
                payload={
                    'staged_hashfile_path': staged_hashfile_path,
                    'hashfile_name': (
                        form.name.data
                        or form.hashfile.data.filename
                        or 'uploaded-hashfile.txt'
                    ),
                    'domain_selection': form.domain_id.data,
                    'new_domain_name': form.domain_name.data,
                    'file_type': normalized_file_type or form.file_type.data,
                    'hash_type': hash_type or '',
                    'audit_actor': capture_audit_actor(),
                },
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
    next_url = safe_relative_url(request.form.get('next'))

    if not current_user.admin:
        flash('Permission Denied', 'danger')
        return redirect(next_url or url_for('hashfiles.hashfiles_list'))

    if hashfile:
        if impact['associated_jobs'] > 0:
            flash(
                f"Error: Hashfile currently associated with {impact['associated_jobs']} job(s).",
                'danger',
            )
            return redirect(next_url or url_for('hashfiles.hashfiles_list'))
        if (request.form.get('confirm_name') or '').strip() != hashfile.name:
            flash('Type the hashfile name exactly to confirm deletion.', 'danger')
            return redirect(next_url or url_for('hashfiles.hashfiles_list'))
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
            return redirect(next_url or url_for('hashfiles.hashfiles_list'))
        except Exception:
            db.session.rollback()
            current_app.logger.exception('Failed deleting hashfile id=%s', hashfile_id)
            flash('Error deleting hashfile.', 'danger')
            return redirect(next_url or url_for('hashfiles.hashfiles_list'))
        flash(
            'Hashfile has been deleted. '
            f"Removed {impact['hash_links']} hash association(s) and "
            f"{impact['orphan_uncracked_hashes']} orphaned uncracked hash(es).",
            'success',
        )
        return redirect(next_url or url_for('hashfiles.hashfiles_list'))

    flash('Error deleting hashfile', 'danger')
    return redirect(next_url or url_for('hashfiles.hashfiles_list'))
