"""Flask routes to handle Domains"""
from flask import Blueprint, render_template, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from sqlalchemy import exists
from hashcrush.models import Domains, Jobs, Hashfiles, HashfileHashes, Hashes, JobTasks
from hashcrush.models import db

domains = Blueprint('domains', __name__)
ACTIVE_JOB_STATUSES = {'Running', 'Queued', 'Paused', 'Ready', 'Incomplete'}

#############################################
# Domains
#############################################

@domains.route("/domains", methods=['GET'])
@login_required
def domains_list():
    """Function to return list of domains"""
    domains = Domains.query.order_by(Domains.name).all()
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
    except Exception:
        db.session.rollback()
        current_app.logger.exception('Failed deleting domain id=%s', domain_id)
        flash('Unable to delete domain due to an internal error.', 'danger')

    return redirect(url_for('domains.domains_list'))
