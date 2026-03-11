"""Flask routes to handle Domains"""
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
from sqlalchemy import case, delete, exists, func, select
from sqlalchemy.exc import IntegrityError

from hashcrush.audit import record_audit_event
from hashcrush.authz import visible_jobs_query
from hashcrush.domains.forms import DomainsForm
from hashcrush.models import (
    Domains,
    Hashes,
    HashfileHashes,
    Hashfiles,
    Jobs,
    JobTasks,
    db,
)
from hashcrush.view_utils import LIST_PAGE_SIZE, paginate_scalars, parse_page_arg

domains = Blueprint('domains', __name__)
ACTIVE_JOB_STATUSES = {'Running', 'Queued', 'Paused', 'Ready', 'Incomplete'}

#############################################
# Domains
#############################################


def _visible_domains_query():
    return select(Domains).order_by(Domains.name)


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


def _domain_delete_impact(domain_id: int) -> dict:
    all_job_ids = db.session.scalars(
        select(Jobs.id).filter_by(domain_id=domain_id)
    ).all()
    active_job_ids = db.session.scalars(
        select(Jobs.id)
        .filter_by(domain_id=domain_id)
        .where(Jobs.status.in_(ACTIVE_JOB_STATUSES))
    ).all()
    inactive_job_ids = [job_id for job_id in all_job_ids if job_id not in active_job_ids]
    hashfile_ids = db.session.scalars(
        select(Hashfiles.id).filter_by(domain_id=domain_id)
    ).all()
    hash_links = (
        int(
            db.session.scalar(
                select(func.count())
                .select_from(HashfileHashes)
                .where(HashfileHashes.hashfile_id.in_(hashfile_ids))
            )
            or 0
        )
        if hashfile_ids
        else 0
    )
    return {
        'active_jobs': len(active_job_ids),
        'inactive_jobs': len(inactive_job_ids),
        'inactive_job_ids': inactive_job_ids,
        'hashfiles': len(hashfile_ids),
        'hashfile_ids': hashfile_ids,
        'hash_links': hash_links,
        'orphan_uncracked_hashes': _count_orphan_uncracked_hashes_for_hashfiles(hashfile_ids),
    }


def _domain_delete_impact_previews(domain_ids: list[int]) -> dict[int, dict[str, int]]:
    if not domain_ids:
        return {}

    job_counts = {
        row.domain_id: {
            'total_jobs': int(row.total_jobs or 0),
            'active_jobs': int(row.active_jobs or 0),
        }
        for row in db.session.execute(
            select(
                Jobs.domain_id,
                func.count(Jobs.id).label('total_jobs'),
                func.sum(
                    case((Jobs.status.in_(ACTIVE_JOB_STATUSES), 1), else_=0)
                ).label('active_jobs'),
            )
            .where(Jobs.domain_id.in_(domain_ids))
            .group_by(Jobs.domain_id)
        ).all()
    }

    hashfile_counts = {
        row.domain_id: int(row.hashfile_count or 0)
        for row in db.session.execute(
            select(
                Hashfiles.domain_id,
                func.count(Hashfiles.id).label('hashfile_count'),
            )
            .where(Hashfiles.domain_id.in_(domain_ids))
            .group_by(Hashfiles.domain_id)
        ).all()
    }

    hash_link_counts = {
        row.domain_id: int(row.hash_links or 0)
        for row in db.session.execute(
            select(
                Hashfiles.domain_id,
                func.count(HashfileHashes.id).label('hash_links'),
            )
            .select_from(HashfileHashes)
            .join(Hashfiles, Hashfiles.id == HashfileHashes.hashfile_id)
            .where(Hashfiles.domain_id.in_(domain_ids))
            .group_by(Hashfiles.domain_id)
        ).all()
    }

    orphan_hashes_subquery = (
        select(
            func.min(Hashfiles.domain_id).label('domain_id'),
            Hashes.id.label('hash_id'),
        )
        .select_from(Hashes)
        .join(HashfileHashes, HashfileHashes.hash_id == Hashes.id)
        .join(Hashfiles, Hashfiles.id == HashfileHashes.hashfile_id)
        .where(Hashes.cracked.is_(False))
        .where(Hashfiles.domain_id.in_(domain_ids))
        .group_by(Hashes.id)
        .having(func.count(func.distinct(Hashfiles.domain_id)) == 1)
        .subquery()
    )
    orphan_hash_counts = {
        row.domain_id: int(row.orphan_hashes or 0)
        for row in db.session.execute(
            select(
                orphan_hashes_subquery.c.domain_id,
                func.count(orphan_hashes_subquery.c.hash_id).label('orphan_hashes'),
            )
            .group_by(orphan_hashes_subquery.c.domain_id)
        ).all()
    }

    return {
        domain_id: {
            'active_jobs': job_counts.get(domain_id, {}).get('active_jobs', 0),
            'inactive_jobs': (
                job_counts.get(domain_id, {}).get('total_jobs', 0)
                - job_counts.get(domain_id, {}).get('active_jobs', 0)
            ),
            'hashfiles': hashfile_counts.get(domain_id, 0),
            'hash_links': hash_link_counts.get(domain_id, 0),
            'orphan_uncracked_hashes': orphan_hash_counts.get(domain_id, 0),
        }
        for domain_id in domain_ids
    }

@domains.route("/domains", methods=['GET'])
@login_required
def domains_list():
    """Function to return list of domains"""
    page = parse_page_arg(request.args.get('page'))
    domains, pagination = paginate_scalars(
        db.session,
        _visible_domains_query(),
        page=page,
        per_page=LIST_PAGE_SIZE,
    )
    domain_ids = [domain.id for domain in domains]
    jobs = (
        db.session.execute(
            visible_jobs_query()
            .where(Jobs.domain_id.in_(domain_ids))
            .order_by(Jobs.created_at.desc())
        ).scalars().all()
        if domain_ids
        else []
    )
    hashfiles = (
        db.session.execute(
            select(Hashfiles)
            .where(Hashfiles.domain_id.in_(domain_ids))
            .order_by(Hashfiles.name.asc())
        ).scalars().all()
        if domain_ids
        else []
    )
    jobs_by_domain: dict[int, list[Jobs]] = defaultdict(list)
    for job in jobs:
        jobs_by_domain[job.domain_id].append(job)
    hashfiles_by_domain: dict[int, list[Hashfiles]] = defaultdict(list)
    for hashfile in hashfiles:
        hashfiles_by_domain[hashfile.domain_id].append(hashfile)
    domains_form = DomainsForm() if current_user.admin else None
    domain_delete_impacts = (
        _domain_delete_impact_previews(domain_ids)
        if current_user.admin
        else {}
    )
    return render_template(
        'domains.html',
        title='Domains',
        domains=domains,
        jobs_by_domain=jobs_by_domain,
        hashfiles_by_domain=hashfiles_by_domain,
        domainsForm=domains_form,
        domain_delete_impacts=domain_delete_impacts,
        pagination=pagination,
    )


@domains.route("/domains/add", methods=['POST'])
@login_required
def domains_add():
    """Create a new shared domain."""

    if not current_user.admin:
        flash('Permission Denied', 'danger')
        return redirect(url_for('domains.domains_list'))

    form = DomainsForm()
    if not form.validate_on_submit():
        for errors in form.errors.values():
            for error in errors:
                flash(error, 'danger')
        return redirect(url_for('domains.domains_list'))

    domain = Domains(name=form.name.data)
    db.session.add(domain)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash(
            'Domain could not be created because that name already exists or changed concurrently. Refresh and retry.',
            'danger',
        )
        return redirect(url_for('domains.domains_list'))

    record_audit_event(
        'domain.create',
        'domain',
        target_id=domain.id,
        summary=f'Created shared domain "{domain.name}".',
        details={'domain_name': domain.name},
    )
    flash('Domain created!', 'success')
    return redirect(url_for('domains.domains_list'))

@domains.route("/domains/delete/<int:domain_id>", methods=['POST'])
@login_required
def domains_delete(domain_id):
    """Function to delete a domain."""
    domain = db.get_or_404(Domains, domain_id)
    domain_name = domain.name

    if not current_user.admin:
        flash('Permission Denied', 'danger')
        return redirect(url_for('domains.domains_list'))

    impact = _domain_delete_impact(domain_id)
    if impact['active_jobs'] > 0:
        flash(
            f"Unable to delete. Domain has {impact['active_jobs']} active job(s).",
            'danger',
        )
        return redirect(url_for('domains.domains_list'))

    if (request.form.get('confirm_name') or '').strip() != domain.name:
        flash('Type the domain name exactly to confirm deletion.', 'danger')
        return redirect(url_for('domains.domains_list'))

    try:
        inactive_job_ids = impact['inactive_job_ids']
        if inactive_job_ids:
            db.session.execute(delete(JobTasks).where(JobTasks.job_id.in_(inactive_job_ids)))
            db.session.execute(delete(Jobs).where(Jobs.id.in_(inactive_job_ids)))

        hashfile_ids = impact['hashfile_ids']
        if hashfile_ids:
            db.session.execute(delete(HashfileHashes).where(HashfileHashes.hashfile_id.in_(hashfile_ids)))
            db.session.execute(delete(Hashfiles).where(Hashfiles.id.in_(hashfile_ids)))
            db.session.execute(
                delete(Hashes)
                .where(Hashes.cracked.is_(False))
                .where(~exists().where(Hashes.id == HashfileHashes.hash_id))
            )

        db.session.delete(domain)
        db.session.commit()
        current_app.logger.info(
            'Deleted domain id=%s name=%s impact inactive_jobs=%s hashfiles=%s hash_links=%s orphan_uncracked=%s',
            domain.id,
            domain_name,
            impact['inactive_jobs'],
            impact['hashfiles'],
            impact['hash_links'],
            impact['orphan_uncracked_hashes'],
        )
        record_audit_event(
            'domain.delete',
            'domain',
            target_id=domain_id,
            summary=f'Deleted shared domain "{domain_name}".',
            details={
                'domain_name': domain_name,
                'inactive_jobs_removed': impact['inactive_jobs'],
                'hashfiles_removed': impact['hashfiles'],
                'hash_links_removed': impact['hash_links'],
                'orphan_uncracked_hashes_removed': impact['orphan_uncracked_hashes'],
            },
        )
        flash(
            'Domain has been deleted. '
            f"Removed {impact['inactive_jobs']} inactive job(s), "
            f"{impact['hashfiles']} hashfile(s), and "
            f"{impact['orphan_uncracked_hashes']} orphaned uncracked hash(es).",
            'success',
        )
    except IntegrityError:
        db.session.rollback()
        flash('Unable to delete domain because related records changed concurrently. Refresh and retry.', 'danger')
    except Exception:
        db.session.rollback()
        current_app.logger.exception('Failed deleting domain id=%s', domain_id)
        flash('Unable to delete domain due to an internal error.', 'danger')

    return redirect(url_for('domains.domains_list'))
