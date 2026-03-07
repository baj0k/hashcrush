"""Flask routes to handle Rules"""
import csv
import io
from flask import Blueprint, render_template, redirect, url_for, request, flash, send_file
from flask_login import login_required
from hashcrush.searches.forms import SearchForm
from hashcrush.models import Customers, Hashfiles, HashfileHashes, Hashes
from hashcrush.models import db
from hashcrush import jinja_hex_decode

searches = Blueprint('searches', __name__)

@searches.route("/search", methods=['GET', 'POST'])
@login_required
def searches_list():
    """Function to return list of search results"""

    customers = Customers.query.all()
    hashfiles = Hashfiles.query.all()
    search_form = SearchForm()
    # Customer and hashfile labels are resolved at render/export time.
    if search_form.validate_on_submit():
        if search_form.search_type.data == 'hash':
            results = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.ciphertext==search_form.query.data).all()
        elif search_form.search_type.data == 'user':
            results = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(HashfileHashes.username.like('%' + search_form.query.data.encode('latin-1').hex() + '%')).all()
        elif search_form.search_type.data == 'password':
            results = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id==HashfileHashes.hash_id).filter(Hashes.plaintext == search_form.query.data.encode('latin-1').hex()).all()
        else:
            flash('No results found', 'warning')
            return redirect(url_for('searches.searches_list'))
    elif request.args.get("hash_id"):
        results = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id == HashfileHashes.hash_id).filter(Hashes.id == request.args.get("hash_id"))
        first_result = results.first()
        if first_result: #Without a value in the search input the export button will not pass the form validation
            search_form.query.data = first_result[0].ciphertext #All hashs should be the same, so set the search input as the first rows hash value
            search_form.search_type.data = 'hash' #Set the search type to hash
    else:
        customers = None
        results = None
    if not results and request.method == 'POST':
        flash('No results found', 'warning')

    if results and "export" in request.form: #Export Results
        return export_results(customers, results, hashfiles, search_form.export_type.data)

    return render_template('search.html', title='Search', searchForm=search_form, customers=customers, results=results, hashfiles=hashfiles )

#Creating this in memory instead of on disk to avoid any extra cleanup. This can be changed later if files get too large
def export_results(customers, results, hashfiles, separator):
    """Function to export search results"""
    str_io = io.StringIO()
    separator = (',' if separator == "Comma" else ":")
    get_rows(str_io, customers, results, hashfiles, separator)
    byte_io = io.BytesIO()
    byte_io.write(str_io.getvalue().encode())
    byte_io.seek(0)
    str_io.close()
    return send_file(byte_io, download_name="search.txt", as_attachment=True)

# If this logic changes in the HTML (search.html), update this helper too.
def get_rows(str_io, customers, results, hashfiles, separator):
    """Function to get rows for export search results"""

    writer = csv.writer(str_io,delimiter=separator)

    customer_names_by_id = {customer.id: customer.name for customer in customers}
    customer_names_by_hashfile_id = {
        hashfile.id: customer_names_by_id.get(hashfile.customer_id, "None")
        for hashfile in hashfiles
    }

    for entry in results:
        col = [customer_names_by_hashfile_id.get(entry[1].hashfile_id, "None")] # Customer

        if entry[1].username: # Username
            col.append(jinja_hex_decode(entry[1].username))
        else:
            col.append("None")

        col.append(entry[0].ciphertext) # Hash

        if entry[0].cracked: #Plaintext
            col.append(jinja_hex_decode(entry[0].plaintext))
        else:
            col.append("unrecovered")

        writer.writerow([col[0],col[1],col[2],col[3]])
    return str_io
