"""Flask routes to handle Domains"""

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
from sqlalchemy import exists, func, or_, select
from sqlalchemy.exc import IntegrityError

from hashcrush.audit import record_audit_event
from hashcrush.authz import visible_jobs_query
from hashcrush.domains.service import visible_domains_with_hashes
from hashcrush.models import (
    Domains,
    Hashes,
    HashfileHashes,
    Hashfiles,
    Jobs,
    JobTasks,
    db,
)
from hashcrush.view_utils import (
    LIST_PAGE_SIZE,
    paginate_scalars,
    parse_page_arg,
    safe_relative_url,
)

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
        select(Jobs.id)
        .select_from(Jobs)
        .outerjoin(Hashfiles, Hashfiles.id == Jobs.hashfile_id)
        .outerjoin(HashfileHashes, HashfileHashes.hashfile_id == Hashfiles.id)
        .where(or_(Jobs.domain_id == domain_id, HashfileHashes.domain_id == domain_id))
        .distinct()
    ).all()
    active_job_ids = db.session.scalars(
        select(Jobs.id)
        .select_from(Jobs)
        .outerjoin(Hashfiles, Hashfiles.id == Jobs.hashfile_id)
        .outerjoin(HashfileHashes, HashfileHashes.hashfile_id == Hashfiles.id)
        .where(or_(Jobs.domain_id == domain_id, HashfileHashes.domain_id == domain_id))
        .where(Jobs.status.in_(ACTIVE_JOB_STATUSES))
        .distinct()
    ).all()
    inactive_job_ids = [job_id for job_id in all_job_ids if job_id not in active_job_ids]
    hashfile_ids = db.session.scalars(
        select(Hashfiles.id)
        .select_from(Hashfiles)
        .outerjoin(HashfileHashes, HashfileHashes.hashfile_id == Hashfiles.id)
        .where(or_(Hashfiles.domain_id == domain_id, HashfileHashes.domain_id == domain_id))
        .distinct()
    ).all()
    hash_links = int(
        db.session.scalar(
            select(func.count())
            .select_from(HashfileHashes)
            .where(HashfileHashes.domain_id == domain_id)
        )
        or 0
    )
    return {
        'active_jobs': len(active_job_ids),
        'inactive_jobs': len(inactive_job_ids),
        'inactive_job_ids': inactive_job_ids,
        'hashfiles': len(hashfile_ids),
        'hashfile_ids': hashfile_ids,
        'hash_links': hash_links,
        'orphan_uncracked_hashes': 0,
    }


def _domain_detail_context(domain: Domains) -> dict[str, object]:
    associated_jobs = db.session.execute(
        visible_jobs_query()
        .outerjoin(Hashfiles, Hashfiles.id == Jobs.hashfile_id)
        .outerjoin(HashfileHashes, HashfileHashes.hashfile_id == Hashfiles.id)
        .where(or_(Jobs.domain_id == domain.id, HashfileHashes.domain_id == domain.id))
        .distinct()
        .order_by(Jobs.created_at.desc())
    ).scalars().all()
    associated_hashfiles = db.session.execute(
        select(Hashfiles)
        .outerjoin(HashfileHashes, HashfileHashes.hashfile_id == Hashfiles.id)
        .where(or_(Hashfiles.domain_id == domain.id, HashfileHashes.domain_id == domain.id))
        .distinct()
        .order_by(Hashfiles.name.asc())
    ).scalars().all()
    return {
        'associated_jobs': associated_jobs,
        'associated_hashfiles': associated_hashfiles,
        'delete_impact': _domain_delete_impact(domain.id),
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
    return render_template(
        'domains.html',
        title='Domains',
        domains=domains,
        pagination=pagination,
    )


@domains.route("/domains/<int:domain_id>", methods=['GET'])
@login_required
def domains_detail(domain_id):
    """Show usage and deletion details for a shared domain."""

    domain = db.get_or_404(Domains, domain_id)
    return render_template(
        'domains_detail.html',
        title=f'Domain: {domain.name}',
        domain=domain,
        **_domain_detail_context(domain),
    )


@domains.route("/domains/add", methods=['POST'])
@login_required
def domains_add():
    """Domains are inferred from imported usernames and not created manually."""

    flash('Domains are created automatically from imported usernames or fallback values.', 'info')
    return redirect(url_for('domains.domains_list'))

@domains.route("/domains/delete/<int:domain_id>", methods=['POST'])
@login_required
def domains_delete(domain_id):
    """Function to delete a domain."""
    domain = db.get_or_404(Domains, domain_id)
    domain_name = domain.name
    next_url = safe_relative_url(request.form.get('next'))

    if not current_user.admin:
        flash('Permission Denied', 'danger')
        return redirect(next_url or url_for('domains.domains_list'))

    impact = _domain_delete_impact(domain_id)
    if (
        impact['active_jobs'] > 0
        or impact['inactive_jobs'] > 0
        or impact['hashfiles'] > 0
        or impact['hash_links'] > 0
    ):
        flash(
            'Unable to delete a domain that is still referenced by imported hashes, hashfiles, or jobs.',
            'danger',
        )
        return redirect(next_url or url_for('domains.domains_list'))

    if (request.form.get('confirm_name') or '').strip() != domain.name:
        flash('Type the domain name exactly to confirm deletion.', 'danger')
        return redirect(next_url or url_for('domains.domains_list'))

    try:
        db.session.delete(domain)
        db.session.commit()
        current_app.logger.info(
            'Deleted unused domain id=%s name=%s',
            domain.id,
            domain_name,
        )
        record_audit_event(
            'domain.delete',
            'domain',
            target_id=domain_id,
            summary=f'Deleted shared domain "{domain_name}".',
            details={
                'domain_name': domain_name,
                'hash_links_removed': 0,
            },
        )
        flash('Unused domain has been deleted.', 'success')
    except IntegrityError:
        db.session.rollback()
        flash('Unable to delete domain because related records changed concurrently. Refresh and retry.', 'danger')
    except Exception:
        db.session.rollback()
        current_app.logger.exception('Failed deleting domain id=%s', domain_id)
        flash('Unable to delete domain due to an internal error.', 'danger')

    return redirect(next_url or url_for('domains.domains_list'))
