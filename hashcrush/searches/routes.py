"""Flask routes to handle Rules"""
import csv
import io
from flask import Blueprint, render_template, redirect, url_for, request, flash, send_file
from flask_login import login_required, current_user
from sqlalchemy import or_
from hashcrush.searches.forms import SearchForm
from hashcrush.models import Domains, Hashfiles, HashfileHashes, Hashes
from hashcrush.models import db
from hashcrush import jinja_hex_decode
from hashcrush.utils.utils import encode_plaintext_for_storage

searches = Blueprint('searches', __name__)


def _visible_hashfiles_query():
    query = Hashfiles.query
    if not current_user.admin:
        query = query.filter(Hashfiles.owner_id == current_user.id)
    return query


def _visible_domains_for_hashfiles(hashfile_rows: list[Hashfiles]) -> list[Domains]:
    domain_ids = sorted({hashfile.domain_id for hashfile in hashfile_rows})
    if not domain_ids:
        return []
    return Domains.query.filter(Domains.id.in_(domain_ids)).all()


def _scoped_search_query():
    query = db.session.query(Hashes, HashfileHashes).join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
    if not current_user.admin:
        query = query.join(Hashfiles, HashfileHashes.hashfile_id == Hashfiles.id).filter(Hashfiles.owner_id == current_user.id)
    return query

@searches.route("/search", methods=['GET', 'POST'])
@login_required
def searches_list():
    """Function to return list of search results"""

    hashfiles = _visible_hashfiles_query().all()
    domains = _visible_domains_for_hashfiles(hashfiles)
    search_form = SearchForm()
    # Domain and hashfile labels are resolved at render/export time.
    if search_form.validate_on_submit():
        if search_form.search_type.data == 'hash':
            results = _scoped_search_query().filter(Hashes.ciphertext == search_form.query.data).all()
        elif search_form.search_type.data == 'user':
            results = _scoped_search_query().filter(
                HashfileHashes.username.like('%' + search_form.query.data.encode('latin-1').hex() + '%')
            ).all()
        elif search_form.search_type.data == 'password':
            query_text = search_form.query.data or ''
            try:
                encoded_query = encode_plaintext_for_storage(query_text)
            except UnicodeEncodeError:
                encoded_query = None
            legacy_query = query_text.upper()

            password_filters = []
            if encoded_query is not None:
                password_filters.append(Hashes.plaintext == encoded_query)
            password_filters.append(Hashes.plaintext == legacy_query)

            results = (
                _scoped_search_query()
                .filter(or_(*password_filters))
                .all()
            )
        else:
            flash('No results found', 'warning')
            return redirect(url_for('searches.searches_list'))
    elif request.args.get("hash_id"):
        results = _scoped_search_query().filter(Hashes.id == request.args.get("hash_id"))
        first_result = results.first()
        if first_result: #Without a value in the search input the export button will not pass the form validation
            search_form.query.data = first_result[0].ciphertext #All hashs should be the same, so set the search input as the first rows hash value
            search_form.search_type.data = 'hash' #Set the search type to hash
    else:
        domains = None
        results = None
    if not results and request.method == 'POST':
        flash('No results found', 'warning')

    if results and "export" in request.form: #Export Results
        return export_results(domains, results, hashfiles, search_form.export_type.data)

    return render_template('search.html', title='Search', searchForm=search_form, domains=domains, results=results, hashfiles=hashfiles )

#Creating this in memory instead of on disk to avoid any extra cleanup. This can be changed later if files get too large
def export_results(domains, results, hashfiles, separator):
    """Function to export search results"""
    str_io = io.StringIO()
    separator = (',' if separator == "Comma" else ":")
    get_rows(str_io, domains, results, hashfiles, separator)
    byte_io = io.BytesIO()
    byte_io.write(str_io.getvalue().encode())
    byte_io.seek(0)
    str_io.close()
    return send_file(byte_io, download_name="search.txt", as_attachment=True)

# If this logic changes in the HTML (search.html), update this helper too.
def get_rows(str_io, domains, results, hashfiles, separator):
    """Function to get rows for export search results"""

    writer = csv.writer(str_io,delimiter=separator)

    domain_names_by_id = {domain.id: domain.name for domain in domains}
    domain_names_by_hashfile_id = {
        hashfile.id: domain_names_by_id.get(hashfile.domain_id, "None")
        for hashfile in hashfiles
    }

    for entry in results:
        col = [domain_names_by_hashfile_id.get(entry[1].hashfile_id, "None")] # Domain

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
