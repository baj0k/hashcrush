"""Flask routes to handle Searches."""
import csv
import io

from flask import (
    abort,
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import select

from hashcrush import jinja_ciphertext_decode, jinja_hex_decode
from hashcrush.audit import record_audit_event
from hashcrush.domains.service import visible_domains_with_hashes
from hashcrush.models import Hashes, HashfileHashes, Hashfiles, db
from hashcrush.searches.forms import SearchForm
from hashcrush.utils.file_ops import get_md5_hash
from hashcrush.utils.secret_storage import (
    decode_ciphertext_from_storage,
    decode_plaintext_from_storage,
    decode_username_from_storage,
    get_ciphertext_search_digest,
    get_plaintext_search_digest,
    get_username_search_digest,
)

searches = Blueprint('searches', __name__)
SEARCH_MAX_RESULTS = 250
SEARCH_MAX_SCAN_ROWS = 20000


def _scoped_search_stmt():
    return select(Hashes, HashfileHashes).join(
        HashfileHashes, Hashes.id == HashfileHashes.hash_id
    )


def _normalized_query_text(raw_value: str | None) -> str:
    return (raw_value or '').strip()


def _normalized_query_key(raw_value: str | None) -> str:
    return _normalized_query_text(raw_value).casefold()


def _parse_positive_int(raw_value) -> int | None:
    if raw_value in (None, ''):
        return None
    try:
        parsed = int(str(raw_value).strip())
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _search_candidate_stmt(search_type: str):
    stmt = _scoped_search_stmt()
    if search_type == 'user':
        return stmt.where(HashfileHashes.username != '')
    if search_type == 'password':
        return stmt.where(Hashes.cracked.is_(True), Hashes.plaintext.is_not(None))
    return stmt


def _search_row_matches(search_type: str, query_key: str, hash_row: Hashes, link_row: HashfileHashes) -> bool:
    if search_type == 'hash':
        candidate_value = decode_ciphertext_from_storage(hash_row.ciphertext) or ''
    elif search_type == 'user':
        candidate_value = decode_username_from_storage(link_row.username) or ''
    elif search_type == 'password':
        candidate_value = decode_plaintext_from_storage(hash_row.plaintext) or ''
    else:
        return False
    return query_key in candidate_value.casefold()


def _non_empty_unique(values: list[str | None]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def _exact_search_stmt(search_type: str, query_text: str):
    if search_type == 'hash':
        variants = _non_empty_unique([query_text, query_text.upper(), query_text.lower()])
        digest_values = _non_empty_unique(
            [get_ciphertext_search_digest(value) for value in variants]
            + [get_md5_hash(value) for value in variants]
        )
        if not digest_values:
            return None
        return _scoped_search_stmt().where(Hashes.sub_ciphertext.in_(digest_values))
    if search_type == 'user':
        username_digest = get_username_search_digest(query_text)
        if not username_digest:
            return None
        return _scoped_search_stmt().where(
            HashfileHashes.username_digest == username_digest
        )
    if search_type == 'password':
        plaintext_digest = get_plaintext_search_digest(query_text)
        if not plaintext_digest:
            return None
        return _scoped_search_stmt().where(
            Hashes.cracked.is_(True),
            Hashes.plaintext_digest == plaintext_digest,
        )
    return None


def _execute_exact_search(search_type: str, query_text: str):
    stmt = _exact_search_stmt(search_type, query_text)
    if stmt is None:
        return []
    return db.session.execute(stmt).tuples().all()


def _execute_partial_search(search_type: str, query_text: str):
    query_key = _normalized_query_key(query_text)
    if not query_key:
        return [], False

    stmt = _search_candidate_stmt(search_type).execution_options(yield_per=1000)
    matches = []
    scanned_rows = 0
    for hash_row, link_row in db.session.execute(stmt).tuples():
        scanned_rows += 1
        if _search_row_matches(search_type, query_key, hash_row, link_row):
            matches.append((hash_row, link_row))
            if len(matches) >= SEARCH_MAX_RESULTS:
                return matches, True
        if scanned_rows >= SEARCH_MAX_SCAN_ROWS:
            return matches, True
    return matches, False


def _execute_search(search_type: str, query_text: str):
    exact_results = _execute_exact_search(search_type, query_text)
    if exact_results:
        return exact_results, False
    return _execute_partial_search(search_type, query_text)


@searches.route("/search", methods=['GET', 'POST'])
@login_required
def searches_list():
    """Function to return list of search results"""
    if not current_user.admin:
        abort(403)

    hashfiles = db.session.execute(select(Hashfiles)).scalars().all()
    domains = visible_domains_with_hashes()
    domain_names_by_id = {domain.id: domain.name for domain in domains}
    hashfile_domain_ids = {hashfile.id: hashfile.domain_id for hashfile in hashfiles}
    search_form = SearchForm()
    # Domain and hashfile labels are resolved at render/export time.
    truncated_results = False
    if search_form.validate_on_submit():
        query_text = _normalized_query_text(search_form.query.data)
        search_form.query.data = query_text
        if not query_text:
            flash('No results found', 'warning')
            return redirect(url_for('searches.searches_list'))

        if search_form.search_type.data in {'hash', 'user', 'password'}:
            results, truncated_results = _execute_search(
                search_form.search_type.data,
                query_text,
            )
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
                search_form.query.data = decode_ciphertext_from_storage(first_result[0].ciphertext) #All hashes should be the same, so set the search input as the first rows hash value
                search_form.search_type.data = 'hash' #Set the search type to hash
        else:
            domains = None
            results = None
    if not results and request.method == 'POST':
        flash('No results found', 'warning')
    elif truncated_results:
        flash(
            (
                'Search results were capped to keep the application responsive. '
                'Refine the query for a complete result set.'
            ),
            'warning',
        )

    if results and "export" in request.form: #Export Results
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

    return render_template(
        'search.html',
        title='Search',
        searchForm=search_form,
        domains=domains,
        domain_names_by_id=domain_names_by_id,
        hashfile_domain_ids=hashfile_domain_ids,
        results=results,
        hashfiles=hashfiles,
    )

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
    hashfile_domain_ids = {hashfile.id: hashfile.domain_id for hashfile in hashfiles}
    for entry in results:
        row_domain_id = entry[1].domain_id or hashfile_domain_ids.get(entry[1].hashfile_id)
        col = [domain_names_by_id.get(row_domain_id, "None")] # Domain

        if entry[1].username: # Username
            col.append(jinja_hex_decode(entry[1].username))
        else:
            col.append("None")

        col.append(jinja_ciphertext_decode(entry[0].ciphertext)) # Hash

        if entry[0].cracked: #Plaintext
            col.append(jinja_hex_decode(entry[0].plaintext))
        else:
            col.append("unrecovered")

        writer.writerow([col[0],col[1],col[2],col[3]])
    return str_io
