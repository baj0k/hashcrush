"""Flask routes to handle Domains"""
from flask import Blueprint, current_app, flash, redirect, render_template, url_for
from flask_login import current_user, login_required
from sqlalchemy import exists
from sqlalchemy.exc import IntegrityError

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

@domains.route("/domains", methods=['GET'])
@login_required
def domains_list():
    """Function to return list of domains"""
    domains = _visible_domains_query().all()
    jobs = Jobs.query.all()
    hashfiles = Hashfiles.query.all()
    return render_template('domains.html', title='Domains', domains=domains, jobs=jobs, hashfiles=hashfiles)

@domains.route("/domains/delete/<int:domain_id>", methods=['POST'])
@login_required
def domains_delete(domain_id):
    """Function to delete a domain."""
    domain = Domains.query.get_or_404(domain_id)

    if not current_user.admin:
        flash('Permission Denied', 'danger')
        return redirect(url_for('domains.domains_list'))

    active_jobs = (
        Jobs.query.filter_by(domain_id=domain_id)
        .filter(Jobs.status.in_(ACTIVE_JOB_STATUSES))
        .count()
    )
    if active_jobs > 0:
        flash('Unable to delete. Domain has active jobs.', 'danger')
        return redirect(url_for('domains.domains_list'))

    try:
        inactive_job_ids = [
            row.id
            for row in Jobs.query.with_entities(Jobs.id).filter_by(domain_id=domain_id).all()
        ]
        if inactive_job_ids:
            JobTasks.query.filter(JobTasks.job_id.in_(inactive_job_ids)).delete(synchronize_session=False)
            Jobs.query.filter(Jobs.id.in_(inactive_job_ids)).delete(synchronize_session=False)

        hashfile_ids = [
            row.id
            for row in Hashfiles.query.with_entities(Hashfiles.id).filter_by(domain_id=domain_id).all()
        ]
        if hashfile_ids:
            HashfileHashes.query.filter(HashfileHashes.hashfile_id.in_(hashfile_ids)).delete(synchronize_session=False)
            Hashfiles.query.filter(Hashfiles.id.in_(hashfile_ids)).delete(synchronize_session=False)
            Hashes.query.filter(Hashes.cracked.is_(False)).filter(
                ~exists().where(Hashes.id == HashfileHashes.hash_id)
            ).delete(synchronize_session=False)

        db.session.delete(domain)
        db.session.commit()
        flash('Domain has been deleted!', 'success')
    except IntegrityError:
        db.session.rollback()
        flash('Unable to delete domain because related records changed concurrently. Refresh and retry.', 'danger')
    except Exception:
        db.session.rollback()
        current_app.logger.exception('Failed deleting domain id=%s', domain_id)
        flash('Unable to delete domain due to an internal error.', 'danger')

    return redirect(url_for('domains.domains_list'))
