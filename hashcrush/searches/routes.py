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
from sqlalchemy import and_, func, or_, select

from hashcrush import jinja_ciphertext_decode, jinja_hex_decode
from hashcrush.audit import record_audit_event
from hashcrush.domains.service import visible_domains_with_hashes
from hashcrush.models import (
    HashSearchTokens,
    Hashes,
    HashfileHashSearchTokens,
    HashfileHashes,
    Hashfiles,
    db,
)
from hashcrush.searches.forms import SearchForm
from hashcrush.searches.token_index import (
    SEARCH_SCOPE_HASH,
    SEARCH_SCOPE_PASSWORD,
    SEARCH_SCOPE_USERNAME,
    SEARCH_TOKEN_NGRAM_SIZE,
    partial_search_token_digests,
)
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
SEARCH_MAX_CANDIDATES = 2000
SEARCH_DOMAIN_BROWSE_PAGE_SIZE = 250


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


def _domain_browse_stmt(domain_id: int):
    return (
        _scoped_search_stmt()
        .join(Hashfiles, Hashfiles.id == HashfileHashes.hashfile_id)
        .where(
            or_(
                HashfileHashes.domain_id == domain_id,
                and_(
                    HashfileHashes.domain_id.is_(None),
                    Hashfiles.domain_id == domain_id,
                ),
            )
        )
        .order_by(HashfileHashes.id.asc())
    )


def _execute_domain_browse(domain_id: int, page: int):
    offset = max(page - 1, 0) * SEARCH_DOMAIN_BROWSE_PAGE_SIZE
    rows = db.session.execute(
        _domain_browse_stmt(domain_id)
        .limit(SEARCH_DOMAIN_BROWSE_PAGE_SIZE + 1)
        .offset(offset)
    ).tuples().all()
    has_next = len(rows) > SEARCH_DOMAIN_BROWSE_PAGE_SIZE
    page_rows = rows[:SEARCH_DOMAIN_BROWSE_PAGE_SIZE]
    return page_rows, {
        "page": page,
        "page_size": SEARCH_DOMAIN_BROWSE_PAGE_SIZE,
        "has_previous": page > 1,
        "has_next": has_next,
        "page_first": (offset + 1) if page_rows else 0,
        "page_last": offset + len(page_rows),
    }


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


def _partial_search_scope(search_type: str) -> str | None:
    if search_type == 'hash':
        return SEARCH_SCOPE_HASH
    if search_type == 'user':
        return SEARCH_SCOPE_USERNAME
    if search_type == 'password':
        return SEARCH_SCOPE_PASSWORD
    return None


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
        return [], False, False

    if len(query_key) < SEARCH_TOKEN_NGRAM_SIZE:
        return [], False, True

    search_scope = _partial_search_scope(search_type)
    token_digests = partial_search_token_digests(query_key, scope=search_scope or "")
    if not search_scope or not token_digests:
        return [], False, True

    if search_type in {'hash', 'password'}:
        owner_ids = [
            int(hash_id)
            for (hash_id,) in db.session.execute(
                select(HashSearchTokens.hash_id)
                .where(HashSearchTokens.search_scope == search_scope)
                .where(HashSearchTokens.token_digest.in_(token_digests))
                .group_by(HashSearchTokens.hash_id)
                .having(
                    func.count(func.distinct(HashSearchTokens.token_digest))
                    == len(token_digests)
                )
                .order_by(HashSearchTokens.hash_id.asc())
                .limit(SEARCH_MAX_CANDIDATES + 1)
            ).all()
        ]
    else:
        owner_ids = [
            int(hashfile_hash_id)
            for (hashfile_hash_id,) in db.session.execute(
                select(HashfileHashSearchTokens.hashfile_hash_id)
                .where(HashfileHashSearchTokens.search_scope == search_scope)
                .where(HashfileHashSearchTokens.token_digest.in_(token_digests))
                .group_by(HashfileHashSearchTokens.hashfile_hash_id)
                .having(
                    func.count(func.distinct(HashfileHashSearchTokens.token_digest))
                    == len(token_digests)
                )
                .order_by(HashfileHashSearchTokens.hashfile_hash_id.asc())
                .limit(SEARCH_MAX_CANDIDATES + 1)
            ).all()
        ]

    truncated_results = len(owner_ids) > SEARCH_MAX_CANDIDATES
    owner_ids = owner_ids[:SEARCH_MAX_CANDIDATES]
    if not owner_ids:
        return [], truncated_results, False

    stmt = _search_candidate_stmt(search_type)
    if search_type in {'hash', 'password'}:
        stmt = stmt.where(Hashes.id.in_(owner_ids)).order_by(
            Hashes.id.asc(),
            HashfileHashes.id.asc(),
        )
    else:
        stmt = stmt.where(HashfileHashes.id.in_(owner_ids)).order_by(
            HashfileHashes.id.asc()
        )
    stmt = stmt.execution_options(yield_per=1000)
    matches = []
    for hash_row, link_row in db.session.execute(stmt).tuples():
        if _search_row_matches(search_type, query_key, hash_row, link_row):
            matches.append((hash_row, link_row))
            if len(matches) >= SEARCH_MAX_RESULTS:
                return matches, True, False
    return matches, truncated_results, False


def _execute_search(search_type: str, query_text: str):
    exact_results = _execute_exact_search(search_type, query_text)
    if exact_results:
        return exact_results, False, False
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
    partial_search_too_short = False
    show_export_actions = False
    browsed_domain = None
    browsed_domain_page = 1
    browsed_domain_has_previous = False
    browsed_domain_has_next = False
    browsed_domain_first_result = 0
    browsed_domain_last_result = 0
    if search_form.validate_on_submit():
        query_text = _normalized_query_text(search_form.query.data)
        search_form.query.data = query_text
        if not query_text:
            flash('No results found', 'warning')
            return redirect(url_for('searches.searches_list'))

        if search_form.search_type.data in {'hash', 'user', 'password'}:
            results, truncated_results, partial_search_too_short = _execute_search(
                search_form.search_type.data,
                query_text,
            )
            show_export_actions = bool(results)
        else:
            flash('No results found', 'warning')
            return redirect(url_for('searches.searches_list'))
    else:
        raw_hash_id = request.args.get("hash_id")
        hash_id = _parse_positive_int(raw_hash_id)
        raw_domain_id = request.args.get("domain_id")
        domain_id = _parse_positive_int(raw_domain_id)
        raw_page = request.args.get("page")
        page = _parse_positive_int(raw_page)
        if raw_hash_id and hash_id is None:
            return redirect(url_for('searches.searches_list'))
        if raw_domain_id and domain_id is None:
            return redirect(url_for('searches.searches_list'))
        if raw_page and page is None:
            if domain_id is not None:
                return redirect(url_for('searches.searches_list', domain_id=domain_id))
            return redirect(url_for('searches.searches_list'))
        if hash_id is not None:
            results = db.session.execute(
                _scoped_search_stmt().where(Hashes.id == hash_id)
            ).tuples().all()
            first_result = results[0] if results else None
            if first_result: #Without a value in the search input the export button will not pass the form validation
                search_form.query.data = decode_ciphertext_from_storage(first_result[0].ciphertext) #All hashes should be the same, so set the search input as the first rows hash value
                search_form.search_type.data = 'hash' #Set the search type to hash
                show_export_actions = True
        elif domain_id is not None:
            browsed_domain = next((domain for domain in domains if domain.id == domain_id), None)
            if browsed_domain is None:
                return redirect(url_for('searches.searches_list'))
            results, pagination = _execute_domain_browse(domain_id, page or 1)
            if not results and (page or 1) > 1:
                flash(
                    'That domain page is no longer available. Showing the first page instead.',
                    'warning',
                )
                return redirect(url_for('searches.searches_list', domain_id=domain_id))
            browsed_domain_page = pagination["page"]
            browsed_domain_has_previous = pagination["has_previous"]
            browsed_domain_has_next = pagination["has_next"]
            browsed_domain_first_result = pagination["page_first"]
            browsed_domain_last_result = pagination["page_last"]
        else:
            results = None
    if request.method == 'POST' and not results:
        if partial_search_too_short:
            flash(
                (
                    'Partial search requires at least 3 characters when an exact match is not found. '
                    'Refine the query and try again.'
                ),
                'warning',
            )
        elif truncated_results:
            flash(
                (
                    'No results were found before the indexed partial search hit its safety limit. '
                    'Refine the query for a complete result set.'
                ),
                'warning',
            )
        else:
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
        show_export_actions=show_export_actions,
        browsed_domain=browsed_domain,
        browsed_domain_page=browsed_domain_page,
        browsed_domain_has_previous=browsed_domain_has_previous,
        browsed_domain_has_next=browsed_domain_has_next,
        browsed_domain_first_result=browsed_domain_first_result,
        browsed_domain_last_result=browsed_domain_last_result,
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
