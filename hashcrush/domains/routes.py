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
from sqlalchemy import delete, exists, func, select
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


def _domain_detail_context(domain: Domains) -> dict[str, object]:
    associated_jobs = db.session.execute(
        visible_jobs_query()
        .where(Jobs.domain_id == domain.id)
        .order_by(Jobs.created_at.desc())
    ).scalars().all()
    associated_hashfiles = db.session.execute(
        select(Hashfiles)
        .where(Hashfiles.domain_id == domain.id)
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
    domains_form = DomainsForm() if current_user.admin else None
    return render_template(
        'domains.html',
        title='Domains',
        domains=domains,
        domainsForm=domains_form,
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
    next_url = safe_relative_url(request.form.get('next'))

    if not current_user.admin:
        flash('Permission Denied', 'danger')
        return redirect(next_url or url_for('domains.domains_list'))

    impact = _domain_delete_impact(domain_id)
    if impact['active_jobs'] > 0:
        flash(
            f"Unable to delete. Domain has {impact['active_jobs']} active job(s).",
            'danger',
        )
        return redirect(next_url or url_for('domains.domains_list'))

    if (request.form.get('confirm_name') or '').strip() != domain.name:
        flash('Type the domain name exactly to confirm deletion.', 'danger')
        return redirect(next_url or url_for('domains.domains_list'))

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

    return redirect(next_url or url_for('domains.domains_list'))
