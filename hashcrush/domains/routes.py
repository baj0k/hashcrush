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
from sqlalchemy import exists
from sqlalchemy.exc import IntegrityError

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

domains = Blueprint('domains', __name__)
ACTIVE_JOB_STATUSES = {'Running', 'Queued', 'Paused', 'Ready', 'Incomplete'}

#############################################
# Domains
#############################################


def _visible_domains_query():
    return Domains.query.order_by(Domains.name)


def _count_orphan_uncracked_hashes_for_hashfiles(hashfile_ids: list[int]) -> int:
    if not hashfile_ids:
        return 0

    return (
        db.session.query(Hashes.id)
        .filter(Hashes.cracked.is_(False))
        .filter(
            exists()
            .where(HashfileHashes.hash_id == Hashes.id)
            .where(HashfileHashes.hashfile_id.in_(hashfile_ids))
        )
        .filter(
            ~exists()
            .where(HashfileHashes.hash_id == Hashes.id)
            .where(~HashfileHashes.hashfile_id.in_(hashfile_ids))
        )
        .count()
    )


def _domain_delete_impact(domain_id: int) -> dict:
    all_job_ids = [
        row.id
        for row in Jobs.query.with_entities(Jobs.id).filter_by(domain_id=domain_id).all()
    ]
    active_job_ids = [
        row.id
        for row in Jobs.query.with_entities(Jobs.id)
        .filter_by(domain_id=domain_id)
        .filter(Jobs.status.in_(ACTIVE_JOB_STATUSES))
        .all()
    ]
    inactive_job_ids = [job_id for job_id in all_job_ids if job_id not in active_job_ids]
    hashfile_ids = [
        row.id
        for row in Hashfiles.query.with_entities(Hashfiles.id)
        .filter_by(domain_id=domain_id)
        .all()
    ]
    hash_links = (
        HashfileHashes.query.filter(HashfileHashes.hashfile_id.in_(hashfile_ids)).count()
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

@domains.route("/domains", methods=['GET'])
@login_required
def domains_list():
    """Function to return list of domains"""
    domains = _visible_domains_query().all()
    jobs = visible_jobs_query().all()
    hashfiles = Hashfiles.query.all()
    domains_form = DomainsForm() if current_user.admin else None
    domain_delete_impacts = (
        {domain.id: _domain_delete_impact(domain.id) for domain in domains}
        if current_user.admin
        else {}
    )
    return render_template(
        'domains.html',
        title='Domains',
        domains=domains,
        jobs=jobs,
        hashfiles=hashfiles,
        domainsForm=domains_form,
        domain_delete_impacts=domain_delete_impacts,
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

    flash('Domain created!', 'success')
    return redirect(url_for('domains.domains_list'))

@domains.route("/domains/delete/<int:domain_id>", methods=['POST'])
@login_required
def domains_delete(domain_id):
    """Function to delete a domain."""
    domain = Domains.query.get_or_404(domain_id)

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
            JobTasks.query.filter(JobTasks.job_id.in_(inactive_job_ids)).delete(synchronize_session=False)
            Jobs.query.filter(Jobs.id.in_(inactive_job_ids)).delete(synchronize_session=False)

        hashfile_ids = impact['hashfile_ids']
        if hashfile_ids:
            HashfileHashes.query.filter(HashfileHashes.hashfile_id.in_(hashfile_ids)).delete(synchronize_session=False)
            Hashfiles.query.filter(Hashfiles.id.in_(hashfile_ids)).delete(synchronize_session=False)
            Hashes.query.filter(Hashes.cracked.is_(False)).filter(
                ~exists().where(Hashes.id == HashfileHashes.hash_id)
            ).delete(synchronize_session=False)

        db.session.delete(domain)
        db.session.commit()
        current_app.logger.info(
            'Deleted domain id=%s name=%s impact inactive_jobs=%s hashfiles=%s hash_links=%s orphan_uncracked=%s',
            domain.id,
            domain.name,
            impact['inactive_jobs'],
            impact['hashfiles'],
            impact['hash_links'],
            impact['orphan_uncracked_hashes'],
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
