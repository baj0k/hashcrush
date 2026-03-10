"""Flask routes to handle Hashfiles"""
from flask import Blueprint, current_app, flash, redirect, render_template, url_for
from flask_login import current_user, login_required
from sqlalchemy import case, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql import exists

from hashcrush.models import Domains, Hashes, HashfileHashes, Hashfiles, Jobs, db

hashfiles = Blueprint('hashfiles', __name__)


@hashfiles.route("/hashfiles", methods=['GET', 'POST'])
@login_required

def hashfiles_list():
    """Function to return list of hashfiles"""
    hashfiles = Hashfiles.query.order_by(Hashfiles.uploaded_at.desc()).all()
    domain_ids = sorted({hashfile.domain_id for hashfile in hashfiles})
    domains = (
        Domains.query.filter(Domains.id.in_(domain_ids)).all()
        if domain_ids
        else []
    )
    jobs = Jobs.query.all()

    cracked_rate = {}
    hash_type_dict = {}

    hashfile_ids = [hashfile.id for hashfile in hashfiles]
    stats_by_hashfile_id = {}
    types_by_hashfile_id = {}
    if hashfile_ids:
        stats_rows = (
            db.session.query(
                HashfileHashes.hashfile_id,
                func.count(Hashes.id).label('total_count'),
                func.sum(case((Hashes.cracked.is_(True), 1), else_=0)).label('cracked_count'),
            )
            .join(Hashes, Hashes.id == HashfileHashes.hash_id)
            .filter(HashfileHashes.hashfile_id.in_(hashfile_ids))
            .group_by(HashfileHashes.hashfile_id)
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
            db.session.query(
                HashfileHashes.hashfile_id,
                func.min(Hashes.hash_type).label('hash_type'),
            )
            .join(Hashes, Hashes.id == HashfileHashes.hash_id)
            .filter(HashfileHashes.hashfile_id.in_(hashfile_ids))
            .group_by(HashfileHashes.hashfile_id)
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

    return render_template('hashfiles.html', title='Hashfiles', hashfiles=hashfiles, domains=domains, cracked_rate=cracked_rate, jobs=jobs, hash_type_dict=hash_type_dict)

@hashfiles.route("/hashfiles/delete/<int:hashfile_id>", methods=['POST'])
@login_required
def hashfiles_delete(hashfile_id):
    """Function to delete hashfile by id"""
    hashfile = Hashfiles.query.get_or_404(hashfile_id)
    jobs = Jobs.query.filter_by(hashfile_id = hashfile_id).first()

    if not current_user.admin:
        flash('Permission Denied', 'danger')
        return redirect(url_for('hashfiles.hashfiles_list'))

    if hashfile:
        if jobs:
            flash('Error: Hashfile currently associated with a job.', 'danger')
            return redirect(url_for('hashfiles.hashfiles_list'))
        try:
            HashfileHashes.query.filter_by(hashfile_id = hashfile_id).delete()
            Hashfiles.query.filter_by(id = hashfile_id).delete()
            Hashes.query.filter().where(~exists().where(Hashes.id == HashfileHashes.hash_id)).where(Hashes.cracked.is_(False)).delete(synchronize_session='fetch')
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash('Error: Hashfile is associated with a job or changed concurrently.', 'danger')
            return redirect(url_for('hashfiles.hashfiles_list'))
        except Exception:
            db.session.rollback()
            current_app.logger.exception('Failed deleting hashfile id=%s', hashfile_id)
            flash('Error deleting hashfile.', 'danger')
            return redirect(url_for('hashfiles.hashfiles_list'))
        flash('Hashfile has been deleted!', 'success')
        return redirect(url_for('hashfiles.hashfiles_list'))

    flash('Error deleting hashfile', 'danger')
    return redirect(url_for('hashfiles.hashfiles_list'))
