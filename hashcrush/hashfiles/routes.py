"""Flask routes to handle Hashfiles"""
from collections import defaultdict

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import case, delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql import exists

from hashcrush.audit import record_audit_event
from hashcrush.authz import admin_required_redirect, visible_jobs_query
from hashcrush.hashfiles.forms import HashfilesAddForm
from hashcrush.hashfiles.service import create_hashfile_from_form
from hashcrush.models import Domains, Hashes, HashfileHashes, Hashfiles, Jobs, db

hashfiles = Blueprint('hashfiles', __name__)


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


@hashfiles.route("/hashfiles", methods=['GET', 'POST'])
@login_required

def hashfiles_list():
    """Function to return list of hashfiles"""
    hashfiles = db.session.execute(
        select(Hashfiles).order_by(Hashfiles.uploaded_at.desc())
    ).scalars().all()
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
    )


@hashfiles.route("/hashfiles/add", methods=['GET', 'POST'])
@login_required
@admin_required_redirect('hashfiles.hashfiles_list')
def hashfiles_add():
    """Create a new shared hashfile from the UI."""

    domains = _shared_domains()
    form = HashfilesAddForm()
    form.domain_id.choices = [(0, '--SELECT DOMAIN--')] + [
        (domain.id, domain.name) for domain in domains
    ]

    if request.method == 'POST' and form.validate_on_submit():
        domain = db.session.get(Domains, form.domain_id.data)
        if not domain:
            flash('Selected domain is invalid or no longer available.', 'danger')
            return _render_hashfiles_add_form(form, domains)

        creation_result, error_message = create_hashfile_from_form(
            form,
            domain_id=domain.id,
        )
        if error_message:
            flash(error_message, 'danger')
            return _render_hashfiles_add_form(form, domains)

        hashfile = creation_result.hashfile
        db.session.commit()
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
