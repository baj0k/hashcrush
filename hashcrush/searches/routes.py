"""Flask routes to handle Searches."""
import csv
import io

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import func, or_, select

from hashcrush import jinja_hex_decode
from hashcrush.audit import record_audit_event
from hashcrush.models import Domains, Hashes, HashfileHashes, Hashfiles, db
from hashcrush.searches.forms import SearchForm
from hashcrush.utils.utils import encode_plaintext_for_storage, get_md5_hash

searches = Blueprint('searches', __name__)


def _visible_domains_for_hashfiles(hashfile_rows: list[Hashfiles]) -> list[Domains]:
    domain_ids = sorted({hashfile.domain_id for hashfile in hashfile_rows})
    if not domain_ids:
        return []
    return db.session.execute(
        select(Domains).where(Domains.id.in_(domain_ids))
    ).scalars().all()


def _scoped_search_stmt():
    return select(Hashes, HashfileHashes).join(
        HashfileHashes, Hashes.id == HashfileHashes.hash_id
    )


def _normalized_query_text(raw_value: str | None) -> str:
    return (raw_value or '').strip()


def _parse_positive_int(raw_value) -> int | None:
    if raw_value in (None, ''):
        return None
    try:
        parsed = int(str(raw_value).strip())
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _hash_search_filters(query_text: str):
    query_lower = query_text.lower()
    return or_(
        Hashes.ciphertext == query_text,
        func.lower(Hashes.ciphertext) == query_lower,
        Hashes.sub_ciphertext == get_md5_hash(query_text),
    )


def _password_search_filters(query_text: str):
    candidates = {query_text}

    try:
        encoded_query = encode_plaintext_for_storage(query_text)
    except UnicodeEncodeError:
        encoded_query = None

    if encoded_query is not None:
        # Canonical format is lowercase hex, but include uppercase for legacy rows.
        candidates.add(encoded_query)
        candidates.add(encoded_query.upper())

    # Some legacy databases may still contain raw plaintext rows.
    candidates.add(query_text.lower())
    candidates.add(query_text.upper())

    return or_(*[Hashes.plaintext == candidate for candidate in sorted(candidates)])

@searches.route("/search", methods=['GET', 'POST'])
@login_required
def searches_list():
    """Function to return list of search results"""

    hashfiles = db.session.execute(select(Hashfiles)).scalars().all()
    domains = _visible_domains_for_hashfiles(hashfiles)
    search_form = SearchForm()
    # Domain and hashfile labels are resolved at render/export time.
    if search_form.validate_on_submit():
        query_text = _normalized_query_text(search_form.query.data)
        search_form.query.data = query_text
        if not query_text:
            flash('No results found', 'warning')
            return redirect(url_for('searches.searches_list'))

        if search_form.search_type.data == 'hash':
            results = db.session.execute(
                _scoped_search_stmt().where(_hash_search_filters(query_text))
            ).tuples().all()
        elif search_form.search_type.data == 'user':
            user_filters = [HashfileHashes.username == query_text]
            try:
                encoded_username = query_text.encode('latin-1').hex()
            except UnicodeEncodeError:
                encoded_username = None
            if encoded_username:
                user_filters.append(HashfileHashes.username.like('%' + encoded_username + '%'))
            results = db.session.execute(
                _scoped_search_stmt().where(or_(*user_filters))
            ).tuples().all()
        elif search_form.search_type.data == 'password':
            results = db.session.execute(
                _scoped_search_stmt().where(_password_search_filters(query_text))
            ).tuples().all()
        else:
            flash('No results found', 'warning')
            return redirect(url_for('searches.searches_list'))
    else:
        raw_hash_id = request.args.get("hash_id")
        hash_id = _parse_positive_int(raw_hash_id)
        if raw_hash_id and hash_id is None:
            return redirect(url_for('searches.searches_list'))
        if hash_id is not None:
            results = db.session.execute(
                _scoped_search_stmt().where(Hashes.id == hash_id)
            ).tuples().all()
            first_result = results[0] if results else None
            if first_result: #Without a value in the search input the export button will not pass the form validation
                search_form.query.data = first_result[0].ciphertext #All hashs should be the same, so set the search input as the first rows hash value
                search_form.search_type.data = 'hash' #Set the search type to hash
        else:
            domains = None
            results = None
    if not results and request.method == 'POST':
        flash('No results found', 'warning')

    if results and "export" in request.form: #Export Results
        if not current_user.admin:
            flash('Permission Denied', 'danger')
        else:
            record_audit_event(
                'search.export',
                'search_export',
                target_id=search_form.search_type.data,
                summary='Exported search results.',
                details={
                    'search_type': search_form.search_type.data,
                    'export_type': search_form.export_type.data,
                    'result_count': len(results),
                },
            )
            return export_results(domains, results, hashfiles, search_form.export_type.data)

    return render_template('search.html', title='Search', searchForm=search_form, domains=domains, results=results, hashfiles=hashfiles )

# Creating this in memory instead of on disk to avoid extra cleanup.
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
