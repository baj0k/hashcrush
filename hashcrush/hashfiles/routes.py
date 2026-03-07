"""Flask routes to handle Hashfiles"""
from flask import Blueprint, render_template, url_for, redirect, flash
from flask_login import login_required, current_user
from sqlalchemy.sql import exists
from sqlalchemy import func, case
from hashcrush.models import Hashfiles, Customers, Jobs, HashfileHashes, Hashes
from hashcrush.models import db

hashfiles = Blueprint('hashfiles', __name__)

@hashfiles.route("/hashfiles", methods=['GET', 'POST'])
@login_required

def hashfiles_list():
    """Function to return list of hashfiles"""
    hashfiles = Hashfiles.query.order_by(Hashfiles.uploaded_at.desc()).all()
    # customers = Customers.query.order_by(Customers.name).all()
    customers = Customers.query.filter(exists().where(Customers.id == Hashfiles.customer_id)).all()
    # Hashes.query.filter(~ exists().where(Hashes.id==HashfileHashes.hash_id)).filter_by(cracked = '0')
    # select * from customers where id in (select customer_id from hashfiles);
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

    return render_template('hashfiles.html', title='Hashfiles', hashfiles=hashfiles, customers=customers, cracked_rate=cracked_rate, jobs=jobs, hash_type_dict=hash_type_dict)

@hashfiles.route("/hashfiles/delete/<int:hashfile_id>", methods=['GET', 'POST'])
@login_required
def hashfiles_delete(hashfile_id):
    """Function to delete hashfile by id"""
    hashfile = Hashfiles.query.get_or_404(hashfile_id)
    jobs = Jobs.query.filter_by(hashfile_id = hashfile_id).first()

    if hashfile:
        if current_user.admin or hashfile.owner_id == current_user.id:
            if jobs:
                flash('Error: Hashfile currently associated with a job.', 'danger')
                return redirect(url_for('hashfiles.hashfiles_list'))
            else:
                HashfileHashes.query.filter_by(hashfile_id = hashfile_id).delete()
                Hashfiles.query.filter_by(id = hashfile_id).delete()
                Hashes.query.filter().where(~exists().where(Hashes.id == HashfileHashes.hash_id)).where(Hashes.cracked == 0).delete(synchronize_session='fetch')
                db.session.commit()
                flash('Hashfile has been deleted!', 'success')
                return redirect(url_for('hashfiles.hashfiles_list'))
        else:
            flash('You do not have rights to delete this hashfile!', 'danger')
            return redirect(url_for('hashfiles.hashfiles_list'))
    else:
        flash('Error in deleteing hashfile', 'danger')
        return redirect(url_for('hashfiles.hashfiles_list'))
