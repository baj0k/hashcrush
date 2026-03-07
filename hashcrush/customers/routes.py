"""Flask routes to handle Customers"""
from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from hashcrush.models import Customers, Jobs, Hashfiles, HashfileHashes, Hashes
from hashcrush.customers.forms import CustomersForm
from hashcrush.models import db

customers = Blueprint('customers', __name__)

#############################################
# Customers
#############################################

@customers.route("/customers", methods=['GET'])
@login_required
def customers_list():
    """Function to return list of customers"""
    customers = Customers.query.order_by(Customers.name).all()
    jobs = Jobs.query.all()
    hashfiles = Hashfiles.query.all()
    return render_template('customers.html', title='Cusomters', customers=customers, jobs=jobs, hashfiles=hashfiles)

@customers.route("/customers/add", methods=['GET', 'POST'])
@login_required
def customers_add():
    """Function to add a new customer"""
    form = CustomersForm()
    if form.validate_on_submit():
        customer = Customers(name=form.name.data)
        db.session.add(customer)
        db.session.commit()
        flash('Customer created!', 'success')
        return redirect(url_for('customers.customers_list'))  # will need to do a conditional return if this was reated during a job creation
    return render_template('cusomers_add.html', title='Customer Add', form=form)

@customers.route("/customers/delete/<int:customer_id>", methods=['POST'])
@login_required
def customers_delete(customer_id):
    """Function to delete a customer"""
    customer = Customers.query.get_or_404(customer_id)
    if current_user.admin:
        # Check if jobs are present
        jobs = Jobs.query.filter_by(customer_id=customer_id).all()
        if jobs:
            flash('Unable to delete. Customer has active job', 'danger')
        else:
            # remove associated hash files and unreferenced uncracked hashes
            hashfiles = Hashfiles.query.filter_by(customer_id=customer_id)
            for hashfile in hashfiles:
                hashfile_hashes = HashfileHashes.query.filter_by(hashfile_id = hashfile.id).all()
                for hashfile_hash in hashfile_hashes:
                    hashes = Hashes.query.filter_by(id=hashfile_hash.hash_id, cracked=False).all()
                    for hash in hashes:
                        # Check to see if our hashfile is the ONLY hashfile for this customer that has this hash
                        customer_cnt = (
                            db.session.query(Hashfiles.customer_id)
                            .join(HashfileHashes, Hashfiles.id == HashfileHashes.hashfile_id)
                            .filter(HashfileHashes.hash_id == hash.id)
                            .distinct()
                            .count()
                        )
                        if customer_cnt < 2:
                            db.session.delete(hash)
                    db.session.delete(hashfile_hash)
                db.session.delete(hashfile)
        db.session.delete(customer)
        db.session.commit()
        flash('Customer has been deleted!', 'success')
    else:
        flash('Permission Denied', 'danger')
    return redirect(url_for('customers.customers_list'))
