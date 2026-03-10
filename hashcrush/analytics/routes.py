"""Flask routes to handle Analytics."""
import io
import operator
import re

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
from sqlalchemy import func

from hashcrush.models import Domains, Hashes, HashfileHashes, Hashfiles, db
from hashcrush.utils.utils import decode_plaintext_from_storage

analytics = Blueprint('analytics', __name__)


def _decoded_plaintext(value: str | None) -> str:
    decoded = decode_plaintext_from_storage(value)
    return decoded if decoded is not None else ''


def _parse_positive_int(value):
    if value in (None, ''):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _resolve_scope(domain_id: int | None, hashfile_id: int | None):
    visible_hashfiles = Hashfiles.query.order_by(Hashfiles.name.asc()).all()
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


def _scoped_hash_rows_query(scoped_hashfile_ids: list[int]):
    return (
        db.session.query(Hashes, HashfileHashes)
        .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
        .filter(HashfileHashes.hashfile_id.in_(scoped_hashfile_ids))
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
        Domains.query.filter(Domains.id.in_(scope['visible_domain_ids'])).order_by(Domains.name.asc()).all()
        if scope['visible_domain_ids']
        else []
    )
    hashfile_rows = scope['visible_hashfiles']
    scoped_hashfile_ids = scope['scoped_hashfile_ids']
    domain_id = scope['domain_id']
    hashfile_id = scope['hashfile_id']

    if not scoped_hashfile_ids:
        return render_template(
            'analytics.html',
            title='analytics',
            fig1_labels=[],
            fig1_values=[],
            fig1_percent=0,
            fig2_labels=[],
            fig2_values=[],
            fig3_labels=[],
            fig3_values=[],
            fig3_percent=0,
            fig4_labels=[],
            fig4_values=[],
            fig5_labels=[],
            fig5_values=[],
            fig6_labels=[],
            fig6_values=[],
            fig7_values={},
            fig7_total=0,
            fig8_table=[],
            domains=domain_rows,
            hashfiles=hashfile_rows,
            hashfile_id=hashfile_id,
            domain_id=domain_id,
            total_runtime=0,
            total_accounts=format_display(0),
            total_unique_hashes=format_display(0),
        )

    scoped_hash_rows = _scoped_hash_rows_query(scoped_hashfile_ids)
    status_counts = dict(
        db.session.query(Hashes.cracked, func.count(Hashes.id))
        .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
        .filter(HashfileHashes.hashfile_id.in_(scoped_hashfile_ids))
        .group_by(Hashes.cracked)
        .all()
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

    # Figure 2 (Password complexity)
    fig2_cracked_hashes = (
        scoped_hash_rows.filter(Hashes.cracked.is_(True)).with_entities(Hashes.plaintext).all()
    )
    fig2_uncracked_cnt = fig1_uncracked_cnt
    fig2_fails_complexity_cnt = 0
    fig2_meets_complexity_cnt = 0
    for entry in fig2_cracked_hashes:
        flags = 0
        decoded_plaintext = _decoded_plaintext(entry[0])
        if len(decoded_plaintext) < 8:
            flags = -3
        if re.search(r"[a-z]", decoded_plaintext):
            flags = flags + 1
        if re.search(r"[A-Z]", decoded_plaintext):
            flags = flags + 1
        if re.search(r"[0-9]", decoded_plaintext):
            flags = flags + 1
        if re.search(r"[^0-9A-Za-z]", decoded_plaintext):
            flags = flags + 1

        if flags < 3:
            fig2_fails_complexity_cnt = fig2_fails_complexity_cnt + 1
        else:
            fig2_meets_complexity_cnt = fig2_meets_complexity_cnt + 1

    fig2_data = [
        ("Fails Complexity: " + str(format_display(fig2_fails_complexity_cnt)), fig2_fails_complexity_cnt),
        ("Meets Complexity: " + str(format_display(fig2_meets_complexity_cnt)), fig2_meets_complexity_cnt),
        ("Unrecovered: " + str(format_display(fig2_uncracked_cnt)), fig2_uncracked_cnt),
    ]
    fig2_labels = [row[0] for row in fig2_data]
    fig2_values = [row[1] for row in fig2_data]

    # Figure 3 (Recovered Hashes)
    fig3_cracked_cnt = (
        scoped_hash_rows
        .filter(Hashes.cracked.is_(True))
        .with_entities(Hashes.plaintext)
        .distinct()
        .count()
    )
    fig3_uncracked_cnt = (
        scoped_hash_rows
        .filter(Hashes.cracked.is_(False))
        .with_entities(Hashes.ciphertext)
        .distinct()
        .count()
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
    total_unique_hashes = (
        scoped_hash_rows.with_entities(Hashes.ciphertext).distinct().count()
    )
    total_accounts = format_display(total_accounts)
    total_unique_hashes = format_display(total_unique_hashes)

    # Figure 4 (Charset Breakdown)
    blank = 0
    numeric = 0
    loweralpha = 0
    upperalpha = 0
    special = 0
    mixedalpha = 0
    mixedalphanum = 0
    loweralphanum = 0
    upperalphanum = 0
    loweralphaspecial = 0
    upperalphaspecial = 0
    specialnum = 0
    mixedalphaspecial = 0
    upperalphaspecialnum = 0
    loweralphaspecialnum = 0
    mixedalphaspecialnum = 0
    other = 0

    for entry in fig2_cracked_hashes:
        tmp_plaintext = _decoded_plaintext(entry[0])
        tmp_plaintext = re.sub(r"[A-Z]", 'U', tmp_plaintext)
        tmp_plaintext = re.sub(r"[a-z]", 'L', tmp_plaintext)
        tmp_plaintext = re.sub(r"[0-9]", 'D', tmp_plaintext)
        tmp_plaintext = re.sub(r"[^0-9A-Za-z]", 'S', tmp_plaintext)

        if len(tmp_plaintext) == 0:
            blank += 1
        elif not re.search("U", tmp_plaintext) and not re.search("L", tmp_plaintext) and re.search("D", tmp_plaintext) and not re.search("S", tmp_plaintext):
            numeric += 1
        elif not re.search("U", tmp_plaintext) and re.search("L", tmp_plaintext) and not re.search("D", tmp_plaintext) and not re.search("S", tmp_plaintext):
            loweralpha += 1
        elif re.search("U", tmp_plaintext) and not re.search("L", tmp_plaintext) and not re.search("D", tmp_plaintext) and not re.search("S", tmp_plaintext):
            upperalpha += 1
        elif not re.search("U", tmp_plaintext) and not re.search("L", tmp_plaintext) and not re.search("D", tmp_plaintext) and re.search("S", tmp_plaintext):
            special += 1
        elif re.search("U", tmp_plaintext) and re.search("L", tmp_plaintext) and not re.search("D", tmp_plaintext) and not re.search("S", tmp_plaintext):
            mixedalpha += 1
        elif re.search("U", tmp_plaintext) and re.search("L", tmp_plaintext) and re.search("D", tmp_plaintext) and not re.search("S", tmp_plaintext):
            mixedalphanum += 1
        elif not re.search("U", tmp_plaintext) and re.search("L", tmp_plaintext) and re.search("D", tmp_plaintext) and not re.search("S", tmp_plaintext):
            loweralphanum += 1
        elif re.search("U", tmp_plaintext) and not re.search("L", tmp_plaintext) and re.search("D", tmp_plaintext) and not re.search("S", tmp_plaintext):
            upperalphanum += 1
        elif not re.search("U", tmp_plaintext) and re.search("L", tmp_plaintext) and not re.search("D", tmp_plaintext) and re.search("S", tmp_plaintext):
            loweralphaspecial += 1
        elif re.search("U", tmp_plaintext) and not re.search("L", tmp_plaintext) and not re.search("D", tmp_plaintext) and re.search("S", tmp_plaintext):
            upperalphaspecial += 1
        elif not re.search("U", tmp_plaintext) and not re.search("L", tmp_plaintext) and re.search("D", tmp_plaintext) and re.search("S", tmp_plaintext):
            specialnum += 1
        elif re.search("U", tmp_plaintext) and re.search("L", tmp_plaintext) and not re.search("D", tmp_plaintext) and re.search("S", tmp_plaintext):
            mixedalphaspecial += 1
        elif re.search("U", tmp_plaintext) and not re.search("L", tmp_plaintext) and re.search("D", tmp_plaintext) and re.search("S", tmp_plaintext):
            upperalphaspecialnum += 1
        elif not re.search("U", tmp_plaintext) and re.search("L", tmp_plaintext) and re.search("D", tmp_plaintext) and re.search("S", tmp_plaintext):
            loweralphaspecialnum += 1
        elif re.search("U", tmp_plaintext) and re.search("L", tmp_plaintext) and re.search("D", tmp_plaintext) and re.search("S", tmp_plaintext):
            mixedalphaspecialnum += 1
        else:
            other += 1

    fig4_labels = []
    fig4_values = []
    fig4_dict = {
        "Blank (unset): " + str(format_display(blank)): blank,
        "Numeric Only: " + str(format_display(numeric)): numeric,
        "LowerAlpha Only: " + str(format_display(loweralpha)): loweralpha,
        "UpperAlpha Only: " + str(format_display(upperalpha)): upperalpha,
        "Special Only: " + str(format_display(special)): special,
        "MixedAlpha: " + str(format_display(mixedalpha)): mixedalpha,
        "MixedAlphaNumeric: " + str(format_display(mixedalphanum)): mixedalphanum,
        "LowerAlphaNumeric: " + str(format_display(loweralphanum)): loweralphanum,
        "LowerAlphaSpecial: " + str(format_display(loweralphaspecial)): loweralphaspecial,
        "UpperAlphaSpecial: " + str(format_display(upperalphaspecial)): upperalphaspecial,
        "SpecialNumeric: " + str(format_display(specialnum)): specialnum,
        "MixedAlphaSpecial: " + str(format_display(mixedalphaspecial)): mixedalphaspecial,
        "UpperAlphaSpecialNumeric: " + str(format_display(upperalphaspecialnum)): upperalphaspecialnum,
        "LowerAlphaSpecialNumeric: " + str(format_display(loweralphaspecialnum)): loweralphaspecialnum,
        "MixedAlphaSpecialNumeric: " + str(format_display(mixedalphaspecialnum)): mixedalphaspecialnum,
        "Other: " + str(format_display(other)): other,
    }
    fig4_array_sorted = dict(sorted(fig4_dict.items(), key=operator.itemgetter(1), reverse=True))
    limit = 0
    fig4_other = 0
    for key in fig4_array_sorted:
        if limit <= 3:
            fig4_labels.append(key)
            fig4_values.append(fig4_array_sorted[key])
            limit += 1
        else:
            fig4_other += fig4_array_sorted[key]
    fig4_labels.append('Other: ' + str(fig4_other))
    fig4_values.append(fig4_other)

    # Figure 5 (Passwords by Length)
    fig5_cracked_hashes = fig2_cracked_hashes
    fig5_data = {}
    for entry in fig5_cracked_hashes:
        password_length = len(_decoded_plaintext(entry[0]))
        if password_length in fig5_data:
            fig5_data[password_length] += 1
        else:
            fig5_data[password_length] = 1
    fig5_labels = []
    fig5_values = []
    for entry in sorted(fig5_data):
        if len(fig5_labels) < 20:
            fig5_labels.append(entry)
            fig5_values.append(fig5_data[entry])
        else:
            break

    # Figure 6 (Top 10 Passwords)
    fig6_cracked_hashes = fig2_cracked_hashes
    fig6_data = {}
    blank_label = 'Blank (unset)'
    for entry in fig6_cracked_hashes:
        decoded_plaintext = _decoded_plaintext(entry[0])
        if len(decoded_plaintext) > 0:
            if decoded_plaintext in fig6_data:
                fig6_data[decoded_plaintext] += 1
            else:
                fig6_data[decoded_plaintext] = 1
        else:
            if blank_label in fig6_data:
                fig6_data[blank_label] += 1
            else:
                fig6_data[blank_label] = 1
    fig6_labels = []
    fig6_values = []
    for entry in sorted(fig6_data, key=fig6_data.__getitem__, reverse=True):
        if len(fig6_labels) < 10:
            fig6_labels.append(entry)
            fig6_values.append(fig6_data[entry])
        else:
            break

    # Figure 7 (Top 10 Masks)
    fig7_values = {}
    fig7_data = {}
    fig7_total = 0
    for entry in fig6_cracked_hashes:
        tmp_plaintext = _decoded_plaintext(entry[0])
        tmp_plaintext = re.sub(r"[A-Z]", 'U', tmp_plaintext)
        tmp_plaintext = re.sub(r"[a-z]", 'L', tmp_plaintext)
        tmp_plaintext = re.sub(r"[0-9]", 'D', tmp_plaintext)
        tmp_plaintext = re.sub(r"[^0-9A-Za-z]", 'S', tmp_plaintext)
        tmp_plaintext = re.sub(r"U", '?u', tmp_plaintext)
        tmp_plaintext = re.sub(r"L", '?l', tmp_plaintext)
        tmp_plaintext = re.sub(r"D", '?d', tmp_plaintext)
        tmp_plaintext = re.sub(r"S", '?s', tmp_plaintext)
        if tmp_plaintext not in fig7_data:
            fig7_data[tmp_plaintext] = 1
        else:
            fig7_data[tmp_plaintext] += 1
        fig7_total += 1
    for entry in sorted(fig7_data, key=fig7_data.__getitem__, reverse=True):
        if len(fig7_values) < 10:
            fig7_values[entry] = fig7_data[entry]
        else:
            break

    # Figure 8 (Users where password == username)
    fig8_cracked_hashes = (
        scoped_hash_rows
        .filter(Hashes.cracked.is_(True))
        .with_entities(Hashes.plaintext, HashfileHashes.username)
        .all()
    )
    fig8_table = []
    for entry in fig8_cracked_hashes:
        if entry[1] and entry[0]:
            try:
                decoded_username = bytes.fromhex(entry[1]).decode('latin-1')
            except (TypeError, ValueError):
                continue
            if '\\' in decoded_username:
                username = decoded_username.split('\\')[1]
            elif '*' in decoded_username:
                username = decoded_username.split('*')[1]
            else:
                username = decoded_username
            if _decoded_plaintext(entry[0]) == username:
                fig8_table.append(_decoded_plaintext(entry[0]))

    return render_template(
        'analytics.html',
        title='analytics',
        fig1_labels=fig1_labels,
        fig1_values=fig1_values,
        fig1_percent=fig1_percent,
        fig2_labels=fig2_labels,
        fig2_values=fig2_values,
        fig3_labels=fig3_labels,
        fig3_values=fig3_values,
        fig3_percent=fig3_percent,
        fig4_labels=fig4_labels,
        fig4_values=fig4_values,
        fig5_labels=fig5_labels,
        fig5_values=fig5_values,
        fig6_labels=fig6_labels,
        fig6_values=fig6_values,
        fig7_values=fig7_values,
        fig7_total=fig7_total,
        fig8_table=fig8_table,
        domains=domain_rows,
        hashfiles=hashfile_rows,
        hashfile_id=hashfile_id,
        domain_id=domain_id,
        total_runtime=total_runtime,
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
        scoped_query = _scoped_hash_rows_query(scoped_hashfile_ids)
        cracked_hashes = scoped_query.filter(Hashes.cracked.is_(True)).all()
        uncracked_hashes = scoped_query.filter(Hashes.cracked.is_(False)).all()

    output = io.StringIO()
    if export_type == 'found':
        for entry in cracked_hashes:
            if entry[1].username:
                try:
                    username = bytes.fromhex(entry[1].username).decode('latin-1')
                except (TypeError, ValueError):
                    username = None
                if username:
                    output.write(
                        str(username)
                        + ":"
                        + str(entry[0].ciphertext)
                        + ':'
                        + str(_decoded_plaintext(entry[0].plaintext))
                        + "\n"
                    )
                    continue
            output.write(str(entry[0].ciphertext) + ':' + str(_decoded_plaintext(entry[0].plaintext)) + "\n")

    if export_type == 'left':
        for entry in uncracked_hashes:
            if entry[1].username:
                try:
                    username = bytes.fromhex(entry[1].username).decode('latin-1')
                except (TypeError, ValueError):
                    username = None
                if username:
                    output.write(str(username) + ":" + str(entry[0].ciphertext) + "\n")
                    continue
            output.write(str(entry[0].ciphertext) + "\n")

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
