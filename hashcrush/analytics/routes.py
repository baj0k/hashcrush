"""Flask routes to handle Analytics."""
import io
from collections import Counter

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
from sqlalchemy import func, select

from hashcrush.audit import record_audit_event
from hashcrush.models import Domains, Hashes, HashfileHashes, Hashfiles, db
from hashcrush.utils.utils import (
    decode_ciphertext_from_storage,
    decode_plaintext_from_storage,
    decode_username_from_storage,
)

analytics = Blueprint('analytics', __name__)

CHARSET_CATEGORY_NAMES = {
    (False, False, True, False): "Numeric Only",
    (False, True, False, False): "LowerAlpha Only",
    (True, False, False, False): "UpperAlpha Only",
    (False, False, False, True): "Special Only",
    (True, True, False, False): "MixedAlpha",
    (True, True, True, False): "MixedAlphaNumeric",
    (False, True, True, False): "LowerAlphaNumeric",
    (True, False, True, False): "UpperAlphaNumeric",
    (False, True, False, True): "LowerAlphaSpecial",
    (True, False, False, True): "UpperAlphaSpecial",
    (False, False, True, True): "SpecialNumeric",
    (True, True, False, True): "MixedAlphaSpecial",
    (True, False, True, True): "UpperAlphaSpecialNumeric",
    (False, True, True, True): "LowerAlphaSpecialNumeric",
    (True, True, True, True): "MixedAlphaSpecialNumeric",
}


def _decoded_plaintext(value: str | None) -> str:
    decoded = decode_plaintext_from_storage(value)
    return decoded if decoded is not None else ''


def _decode_username(value: str | None) -> str | None:
    decoded_username = decode_username_from_storage(value)
    if decoded_username is None:
        return None
    if '\\' in decoded_username:
        return decoded_username.split('\\', 1)[1]
    if '*' in decoded_username:
        return decoded_username.split('*', 1)[1]
    return decoded_username


def _mask_for_plaintext(decoded_plaintext: str) -> str:
    mask_parts: list[str] = []
    for char in decoded_plaintext:
        if char.isupper():
            mask_parts.append('?u')
        elif char.islower():
            mask_parts.append('?l')
        elif char.isdigit():
            mask_parts.append('?d')
        else:
            mask_parts.append('?s')
    return ''.join(mask_parts)


def _build_cracked_password_metrics(cracked_rows: list[tuple[str | None, str | None]]) -> dict[str, object]:
    complexity_fails = 0
    complexity_meets = 0
    composition_counts: Counter[str] = Counter()
    length_counts: Counter[int] = Counter()
    password_counts: Counter[str] = Counter()
    mask_counts: Counter[str] = Counter()
    username_matches: list[str] = []
    blank_label = 'Blank (unset)'

    for plaintext_value, username_value in cracked_rows:
        decoded_plaintext = _decoded_plaintext(plaintext_value)
        length = len(decoded_plaintext)
        has_lower = any(char.islower() for char in decoded_plaintext)
        has_upper = any(char.isupper() for char in decoded_plaintext)
        has_digit = any(char.isdigit() for char in decoded_plaintext)
        has_special = any(not char.isalnum() for char in decoded_plaintext)
        complexity_flags = int(has_lower) + int(has_upper) + int(has_digit) + int(has_special)

        if length >= 8 and complexity_flags >= 3:
            complexity_meets += 1
        else:
            complexity_fails += 1

        if length == 0:
            composition_counts[blank_label] += 1
        else:
            composition_counts[
                CHARSET_CATEGORY_NAMES.get(
                    (has_upper, has_lower, has_digit, has_special),
                    'Other',
                )
            ] += 1

        length_counts[length] += 1
        password_counts[decoded_plaintext or blank_label] += 1
        mask_counts[_mask_for_plaintext(decoded_plaintext)] += 1

        decoded_username = _decode_username(username_value)
        if plaintext_value and decoded_username is not None and decoded_plaintext == decoded_username:
            username_matches.append(decoded_plaintext)

    return {
        'complexity_fails': complexity_fails,
        'complexity_meets': complexity_meets,
        'composition_counts': composition_counts,
        'length_counts': length_counts,
        'password_counts': password_counts,
        'mask_counts': mask_counts,
        'username_matches': username_matches,
        'blank_label': blank_label,
    }


def _parse_positive_int(value):
    if value in (None, ''):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _format_runtime_display(total_runtime: int) -> str:
    if total_runtime > 604800:
        return f"{round(total_runtime / 604800):.0f} week(s)"
    if total_runtime > 86400:
        return f"{round(total_runtime / 86400):.0f} day(s)"
    if total_runtime > 3600:
        return f"{round(total_runtime / 3600):.0f} hour(s)"
    if total_runtime > 60:
        return f"{round(total_runtime / 60):.0f} minute(s)"
    return "< 1 minute"


def _resolve_scope(domain_id: int | None, hashfile_id: int | None):
    visible_hashfiles = db.session.execute(
        select(Hashfiles).order_by(Hashfiles.name.asc())
    ).scalars().all()
    visible_hashfiles_by_id = {hashfile.id: hashfile for hashfile in visible_hashfiles}
    visible_domain_ids = sorted({hashfile.domain_id for hashfile in visible_hashfiles})

    if domain_id is not None and domain_id not in visible_domain_ids:
        return None

    selected_hashfile = None
    if hashfile_id is not None:
        selected_hashfile = visible_hashfiles_by_id.get(hashfile_id)
        if not selected_hashfile:
            return None
        if domain_id is not None and selected_hashfile.domain_id != domain_id:
            return None
        domain_id = selected_hashfile.domain_id

    if domain_id is not None:
        scoped_hashfiles = [hashfile for hashfile in visible_hashfiles if hashfile.domain_id == domain_id]
    else:
        scoped_hashfiles = visible_hashfiles

    if selected_hashfile:
        scoped_hashfiles = [selected_hashfile]

    scoped_hashfile_ids = [hashfile.id for hashfile in scoped_hashfiles]
    return {
        'domain_id': domain_id,
        'hashfile_id': hashfile_id,
        'visible_hashfiles': visible_hashfiles,
        'scoped_hashfiles': scoped_hashfiles,
        'scoped_hashfile_ids': scoped_hashfile_ids,
        'visible_domain_ids': visible_domain_ids,
    }


def _scoped_hash_rows_stmt(scoped_hashfile_ids: list[int]):
    return (
        select(Hashes, HashfileHashes)
        .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
        .where(HashfileHashes.hashfile_id.in_(scoped_hashfile_ids))
    )


@analytics.route('/analytics', methods=['GET'])
@login_required
def get_analytics():
    """Function to list Analytics Page."""
    domain_id_arg = request.args.get('domain_id')
    hashfile_id_arg = request.args.get('hashfile_id')
    domain_id = _parse_positive_int(domain_id_arg)
    hashfile_id = _parse_positive_int(hashfile_id_arg)
    if domain_id_arg and domain_id is None:
        return redirect('/analytics')
    if hashfile_id_arg and hashfile_id is None:
        return redirect('/analytics')

    scope = _resolve_scope(domain_id, hashfile_id)
    if scope is None:
        return redirect('/analytics')

    domain_rows = (
        db.session.execute(
            select(Domains)
            .where(Domains.id.in_(scope['visible_domain_ids']))
            .order_by(Domains.name.asc())
        ).scalars().all()
        if scope['visible_domain_ids']
        else []
    )
    hashfile_rows = scope['visible_hashfiles']
    scoped_hashfile_ids = scope['scoped_hashfile_ids']
    domain_id = scope['domain_id']
    hashfile_id = scope['hashfile_id']
    selected_domain_name = next((domain.name for domain in domain_rows if domain.id == domain_id), None)
    selected_hashfile_name = next((hashfile.name for hashfile in hashfile_rows if hashfile.id == hashfile_id), None)
    filter_hashfiles = [hashfile for hashfile in hashfile_rows if domain_id is None or hashfile.domain_id == domain_id]

    if not scoped_hashfile_ids:
        return render_template(
            'analytics.html',
            title='analytics',
            analytics_chart_data={
                'recovered_accounts': {'labels': [], 'values': [], 'center_text': ''},
                'password_complexity': {'labels': [], 'values': []},
                'recovered_hashes': {'labels': [], 'values': [], 'center_text': ''},
                'composition_makeup': {'labels': [], 'values': []},
                'passwords_count_len': {'labels': [], 'values': []},
                'top_10_passwords': {'labels': [], 'values': []},
            },
            fig7_values={},
            fig7_total=0,
            fig8_table=[],
            domains=domain_rows,
            hashfiles=hashfile_rows,
            filter_hashfiles=filter_hashfiles,
            hashfile_id=hashfile_id,
            domain_id=domain_id,
            selected_domain_name=selected_domain_name,
            selected_hashfile_name=selected_hashfile_name,
            total_runtime=0,
            runtime_display=_format_runtime_display(0),
            total_accounts=format_display(0),
            total_unique_hashes=format_display(0),
        )

    status_counts = dict(
        db.session.execute(
            select(Hashes.cracked, func.count(Hashes.id))
            .select_from(Hashes)
            .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
            .where(HashfileHashes.hashfile_id.in_(scoped_hashfile_ids))
            .group_by(Hashes.cracked)
        ).all()
    )

    # Figure 1 (Recovered vs unrecovered account rows)
    fig1_cracked_cnt = int(status_counts.get(True, 0))
    fig1_uncracked_cnt = int(status_counts.get(False, 0))
    fig1_data = [
        ("Recovered: " + str(format_display(fig1_cracked_cnt)), fig1_cracked_cnt),
        ("Unrecovered: " + str(format_display(fig1_uncracked_cnt)), fig1_uncracked_cnt),
    ]
    fig1_labels = [row[0] for row in fig1_data]
    fig1_values = [row[1] for row in fig1_data]
    fig1_total = fig1_cracked_cnt + fig1_uncracked_cnt
    fig1_percent = 0 if fig1_total == 0 else [str(round((fig1_cracked_cnt / fig1_total) * 100, 1)) + '%']

    cracked_rows = db.session.execute(
        select(Hashes.plaintext, HashfileHashes.username)
        .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
        .where(HashfileHashes.hashfile_id.in_(scoped_hashfile_ids))
        .where(Hashes.cracked.is_(True))
    ).all()
    cracked_metrics = _build_cracked_password_metrics(cracked_rows)
    fig2_uncracked_cnt = fig1_uncracked_cnt
    fig2_fails_complexity_cnt = int(cracked_metrics['complexity_fails'])
    fig2_meets_complexity_cnt = int(cracked_metrics['complexity_meets'])

    fig2_data = [
        ("Fails Complexity: " + str(format_display(fig2_fails_complexity_cnt)), fig2_fails_complexity_cnt),
        ("Meets Complexity: " + str(format_display(fig2_meets_complexity_cnt)), fig2_meets_complexity_cnt),
        ("Unrecovered: " + str(format_display(fig2_uncracked_cnt)), fig2_uncracked_cnt),
    ]
    fig2_labels = [row[0] for row in fig2_data]
    fig2_values = [row[1] for row in fig2_data]

    # Figure 3 (Recovered Hashes)
    fig3_cracked_cnt = int(
        db.session.scalar(
            select(func.count(func.distinct(func.coalesce(Hashes.plaintext_digest, Hashes.plaintext))))
            .select_from(Hashes)
            .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
            .where(HashfileHashes.hashfile_id.in_(scoped_hashfile_ids))
            .where(Hashes.cracked.is_(True))
        )
        or 0
    )
    fig3_uncracked_cnt = int(
        db.session.scalar(
            select(func.count(func.distinct(Hashes.sub_ciphertext)))
            .select_from(Hashes)
            .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
            .where(HashfileHashes.hashfile_id.in_(scoped_hashfile_ids))
            .where(Hashes.cracked.is_(False))
        )
        or 0
    )
    fig3_data = [
        ("Recovered: " + str(format_display(fig3_cracked_cnt)), fig3_cracked_cnt),
        ("Unrecovered: " + str(format_display(fig3_uncracked_cnt)), fig3_uncracked_cnt),
    ]
    fig3_labels = [row[0] for row in fig3_data]
    fig3_values = [row[1] for row in fig3_data]
    fig3_total = fig3_cracked_cnt + fig3_uncracked_cnt
    fig3_percent = 0 if fig3_total == 0 else [str(round((fig3_cracked_cnt / fig3_total) * 100, 1)) + '%']

    # General Stats Table
    total_runtime = sum(hashfile.runtime or 0 for hashfile in scope['scoped_hashfiles'])
    total_accounts = fig1_total
    total_unique_hashes = int(
        db.session.scalar(
            select(func.count(func.distinct(Hashes.sub_ciphertext)))
            .select_from(Hashes)
            .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
            .where(HashfileHashes.hashfile_id.in_(scoped_hashfile_ids))
        )
        or 0
    )
    total_accounts = format_display(total_accounts)
    total_unique_hashes = format_display(total_unique_hashes)

    # Figure 4 (Charset Breakdown)
    fig4_labels = []
    fig4_values = []
    fig4_rows = sorted(
        cracked_metrics['composition_counts'].items(),
        key=lambda item: (-item[1], item[0]),
    )
    limit = 0
    fig4_other = 0
    for label, count in fig4_rows:
        if limit <= 3:
            fig4_labels.append(f"{label}: {format_display(count)}")
            fig4_values.append(count)
            limit += 1
        else:
            fig4_other += count
    if fig4_other > 0:
        fig4_labels.append('Other: ' + str(fig4_other))
        fig4_values.append(fig4_other)

    # Figure 5 (Passwords by Length)
    fig5_labels = []
    fig5_values = []
    for entry in sorted(cracked_metrics['length_counts']):
        if len(fig5_labels) < 20:
            fig5_labels.append(entry)
            fig5_values.append(cracked_metrics['length_counts'][entry])
        else:
            break

    # Figure 6 (Top 10 Passwords)
    fig6_labels = []
    fig6_values = []
    top_password_rows = sorted(
        cracked_metrics['password_counts'].items(),
        key=lambda item: (-item[1], item[0]),
    )
    for entry, count in top_password_rows[:10]:
        if len(fig6_labels) < 10:
            fig6_labels.append(entry)
            fig6_values.append(count)
        else:
            break

    # Figure 7 (Top 10 Masks)
    fig7_values = {}
    fig7_total = int(sum(cracked_metrics['mask_counts'].values()))
    for entry, count in cracked_metrics['mask_counts'].most_common(10):
        if len(fig7_values) < 10:
            fig7_values[entry] = count
        else:
            break

    # Figure 8 (Users where password == username)
    fig8_table = cracked_metrics['username_matches']

    return render_template(
        'analytics.html',
        title='analytics',
        analytics_chart_data={
            'recovered_accounts': {
                'labels': fig1_labels,
                'values': fig1_values,
                'center_text': fig1_percent[0] if fig1_percent else '',
            },
            'password_complexity': {
                'labels': fig2_labels,
                'values': fig2_values,
            },
            'recovered_hashes': {
                'labels': fig3_labels,
                'values': fig3_values,
                'center_text': fig3_percent[0] if fig3_percent else '',
            },
            'composition_makeup': {
                'labels': fig4_labels,
                'values': fig4_values,
            },
            'passwords_count_len': {
                'labels': fig5_labels,
                'values': fig5_values,
            },
            'top_10_passwords': {
                'labels': fig6_labels,
                'values': fig6_values,
            },
        },
        fig7_values=fig7_values,
        fig7_total=fig7_total,
        fig8_table=fig8_table,
        domains=domain_rows,
        hashfiles=hashfile_rows,
        filter_hashfiles=filter_hashfiles,
        hashfile_id=hashfile_id,
        domain_id=domain_id,
        selected_domain_name=selected_domain_name,
        selected_hashfile_name=selected_hashfile_name,
        total_runtime=total_runtime,
        runtime_display=_format_runtime_display(total_runtime),
        total_accounts=total_accounts,
        total_unique_hashes=total_unique_hashes,
    )


@analytics.route('/analytics/download', methods=['GET'])
@login_required
def analytics_download_hashes():
    """Function to download hashes."""
    if not current_user.admin:
        flash('Permission Denied', 'danger')
        return redirect(url_for('analytics.get_analytics'))

    export_type = (request.args.get('type') or '').strip().lower()
    if export_type == 'found':
        filename = 'found'
    elif export_type == 'left':
        filename = 'left'
    else:
        return redirect('/analytics')

    domain_id_arg = request.args.get('domain_id')
    hashfile_id_arg = request.args.get('hashfile_id')
    domain_id = _parse_positive_int(domain_id_arg)
    hashfile_id = _parse_positive_int(hashfile_id_arg)
    if domain_id_arg and domain_id is None:
        return redirect('/analytics')
    if hashfile_id_arg and hashfile_id is None:
        return redirect('/analytics')

    scope = _resolve_scope(domain_id, hashfile_id)
    if scope is None:
        return redirect('/analytics')
    scoped_hashfile_ids = scope['scoped_hashfile_ids']

    if domain_id is not None:
        filename += '_' + str(domain_id)
    if hashfile_id is not None:
        filename += '_' + str(hashfile_id)
    else:
        filename += '_all'
    filename += '.txt'

    if not scoped_hashfile_ids:
        cracked_hashes = []
        uncracked_hashes = []
    else:
        cracked_hashes = db.session.execute(
            _scoped_hash_rows_stmt(scoped_hashfile_ids).where(Hashes.cracked.is_(True))
        ).tuples().all()
        uncracked_hashes = db.session.execute(
            _scoped_hash_rows_stmt(scoped_hashfile_ids).where(Hashes.cracked.is_(False))
        ).tuples().all()

    output = io.StringIO()
    if export_type == 'found':
        for entry in cracked_hashes:
            if entry[1].username:
                username = decode_username_from_storage(entry[1].username)
                if username:
                    output.write(
                        str(username)
                        + ":"
                        + str(decode_ciphertext_from_storage(entry[0].ciphertext))
                        + ':'
                        + str(_decoded_plaintext(entry[0].plaintext))
                        + "\n"
                    )
                    continue
            output.write(
                str(decode_ciphertext_from_storage(entry[0].ciphertext))
                + ':'
                + str(_decoded_plaintext(entry[0].plaintext))
                + "\n"
            )

    if export_type == 'left':
        for entry in uncracked_hashes:
            if entry[1].username:
                username = decode_username_from_storage(entry[1].username)
                if username:
                    output.write(
                        str(username)
                        + ":"
                        + str(decode_ciphertext_from_storage(entry[0].ciphertext))
                        + "\n"
                    )
                    continue
            output.write(str(decode_ciphertext_from_storage(entry[0].ciphertext)) + "\n")

    record_audit_event(
        'analytics.download',
        'analytics_export',
        target_id=filename,
        summary=f'Downloaded analytics export "{filename}".',
        details={
            'export_type': export_type,
            'domain_id': domain_id,
            'hashfile_id': hashfile_id,
            'row_count': len(cracked_hashes) if export_type == 'found' else len(uncracked_hashes),
        },
    )
    buffer = io.BytesIO(output.getvalue().encode('utf-8'))
    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype='text/plain; charset=utf-8',
    )


def format_display(number):
    """Function to add commas to numbers."""
    return f"{number:,}"
