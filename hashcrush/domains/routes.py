"""Flask routes to handle Domains"""
from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from hashcrush.models import Domains, Jobs, Hashfiles, HashfileHashes, Hashes
from hashcrush.models import db

domains = Blueprint('domains', __name__)

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
    if current_user.admin:
        # Check if jobs are present
        jobs = Jobs.query.filter_by(domain_id=domain_id).all()
        if jobs:
            flash('Unable to delete. Domain has active job', 'danger')
            return redirect(url_for('domains.domains_list'))
        else:
            # remove associated hash files and unreferenced uncracked hashes
            hashfiles = Hashfiles.query.filter_by(domain_id=domain_id)
            for hashfile in hashfiles:
                hashfile_hashes = HashfileHashes.query.filter_by(hashfile_id=hashfile.id).all()
                for hashfile_hash in hashfile_hashes:
                    hashes = Hashes.query.filter_by(id=hashfile_hash.hash_id, cracked=False).all()
                    for hash in hashes:
                        # Delete only if this hash exists in a single domain.
                        domain_cnt = (
                            db.session.query(Hashfiles.domain_id)
                            .join(HashfileHashes, Hashfiles.id == HashfileHashes.hashfile_id)
                            .filter(HashfileHashes.hash_id == hash.id)
                            .distinct()
                            .count()
                        )
                        if domain_cnt < 2:
                            db.session.delete(hash)
                    db.session.delete(hashfile_hash)
                db.session.delete(hashfile)
        db.session.delete(domain)
        db.session.commit()
        flash('Domain has been deleted!', 'success')
    else:
        flash('Permission Denied', 'danger')
    return redirect(url_for('domains.domains_list'))
