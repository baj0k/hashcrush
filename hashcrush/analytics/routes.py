"""Flask routes to handle Analytics."""
import io
from collections import Counter, defaultdict
from datetime import UTC, datetime

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
from hashcrush.domains.service import hashfile_ids_for_domain, visible_domains_with_hashes
from hashcrush.hibp.service import HIBP_NTLM_KIND, public_exposure_summary_for_hashfile_ids
from hashcrush.models import (
    Domains,
    HashPublicExposure,
    Hashes,
    HashfileHashes,
    Hashfiles,
    db,
)
from hashcrush.utils.secret_storage import (
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


def _empty_cracked_password_metrics() -> dict[str, object]:
    blank_label = 'Blank (unset)'
    return {
        'recovered_accounts': 0,
        'complexity_fails': 0,
        'complexity_meets': 0,
        'composition_counts': Counter(),
        'length_counts': Counter(),
        'password_counts': Counter(),
        'mask_counts': Counter(),
        'username_match_counts': Counter(),
        'blank_label': blank_label,
    }


def _accumulate_cracked_password_metric(
    metrics: dict[str, object],
    plaintext_value: str | None,
    username_value: str | None,
) -> None:
    blank_label = str(metrics['blank_label'])
    composition_counts: Counter[str] = metrics['composition_counts']
    length_counts: Counter[int] = metrics['length_counts']
    password_counts: Counter[str] = metrics['password_counts']
    mask_counts: Counter[str] = metrics['mask_counts']
    username_match_counts: Counter[str] = metrics['username_match_counts']

    decoded_plaintext = _decoded_plaintext(plaintext_value)
    length = len(decoded_plaintext)
    has_lower = any(char.islower() for char in decoded_plaintext)
    has_upper = any(char.isupper() for char in decoded_plaintext)
    has_digit = any(char.isdigit() for char in decoded_plaintext)
    has_special = any(not char.isalnum() for char in decoded_plaintext)
    complexity_flags = int(has_lower) + int(has_upper) + int(has_digit) + int(has_special)

    metrics['recovered_accounts'] = int(metrics['recovered_accounts']) + 1

    if length >= 8 and complexity_flags >= 3:
        metrics['complexity_meets'] = int(metrics['complexity_meets']) + 1
    else:
        metrics['complexity_fails'] = int(metrics['complexity_fails']) + 1

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
        username_match_counts[decoded_plaintext] += 1


def _build_cracked_password_metrics(cracked_rows) -> dict[str, object]:
    metrics = _empty_cracked_password_metrics()
    for plaintext_value, username_value in cracked_rows:
        _accumulate_cracked_password_metric(metrics, plaintext_value, username_value)
    return metrics


def _build_hash_reuse_summary(scoped_hashfile_ids: list[int]) -> dict[str, int | float]:
    if not scoped_hashfile_ids:
        return {
            'total_unique_hashes': 0,
            'reused_hash_value_count': 0,
            'reused_hash_account_count': 0,
            'unique_hash_account_count': 0,
            'reused_hash_value_percent': 0.0,
            'reused_hash_account_percent': 0.0,
        }

    grouped_rows = db.session.execute(
        select(Hashes.sub_ciphertext, func.count(HashfileHashes.id))
        .select_from(Hashes)
        .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
        .where(HashfileHashes.hashfile_id.in_(scoped_hashfile_ids))
        .group_by(Hashes.sub_ciphertext)
    ).all()

    total_unique_hashes = len(grouped_rows)
    reused_hash_value_count = int(sum(1 for _, count in grouped_rows if int(count) > 1))
    reused_hash_account_count = int(
        sum(int(count) for _, count in grouped_rows if int(count) > 1)
    )
    total_accounts = int(sum(int(count) for _, count in grouped_rows))
    unique_hash_account_count = max(total_accounts - reused_hash_account_count, 0)

    return {
        'total_unique_hashes': total_unique_hashes,
        'reused_hash_value_count': reused_hash_value_count,
        'reused_hash_account_count': reused_hash_account_count,
        'unique_hash_account_count': unique_hash_account_count,
        'reused_hash_value_percent': _ratio(reused_hash_value_count, total_unique_hashes),
        'reused_hash_account_percent': _ratio(reused_hash_account_count, total_accounts),
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
    visible_domain_ids = [domain.id for domain in visible_domains_with_hashes()]

    if domain_id is not None and domain_id not in visible_domain_ids:
        return None

    selected_hashfile = None
    if hashfile_id is not None:
        selected_hashfile = visible_hashfiles_by_id.get(hashfile_id)
        if not selected_hashfile:
            return None
        if domain_id is not None and hashfile_id not in set(hashfile_ids_for_domain(domain_id)):
            return None

    if domain_id is not None:
        scoped_hashfile_ids = set(hashfile_ids_for_domain(domain_id))
        scoped_hashfiles = [
            hashfile for hashfile in visible_hashfiles if hashfile.id in scoped_hashfile_ids
        ]
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


def _iter_scoped_hash_rows(scoped_hashfile_ids: list[int], *, cracked: bool | None = None):
    stmt = _scoped_hash_rows_stmt(scoped_hashfile_ids)
    if cracked is True:
        stmt = stmt.where(Hashes.cracked.is_(True))
    elif cracked is False:
        stmt = stmt.where(Hashes.cracked.is_(False))
    return db.session.execute(stmt.execution_options(yield_per=1000)).tuples()


def _download_date_label() -> str:
    return datetime.now(UTC).date().isoformat()


def _export_scope_suffix(domain_id: int | None, hashfile_id: int | None) -> str:
    if hashfile_id is not None and domain_id is not None:
        return f"domain_{domain_id}_hashfile_{hashfile_id}"
    if domain_id is not None:
        return f"domain_{domain_id}"
    return "all_domains"


def _export_filename(base_name: str, domain_id: int | None, hashfile_id: int | None) -> str:
    return f"{base_name}_{_export_scope_suffix(domain_id, hashfile_id)}_{_download_date_label()}.txt"


def _write_account_export_line(
    output: io.StringIO,
    hash_row: Hashes,
    account_row: HashfileHashes,
    *,
    include_plaintext: bool,
    trailing_fields: list[str] | None = None,
) -> None:
    parts: list[str] = []
    if account_row.username:
        username = decode_username_from_storage(account_row.username)
        if username:
            parts.append(str(username))
    parts.append(str(decode_ciphertext_from_storage(hash_row.ciphertext)))
    if include_plaintext:
        parts.append(str(_decoded_plaintext(hash_row.plaintext)))
    parts.extend(str(field) for field in (trailing_fields or []))
    output.write(":".join(parts) + "\n")


def _ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round((numerator / denominator) * 100, 1)


def _format_percent(value: float | None) -> str:
    if value is None:
        return "N/A"
    formatted = f"{value:.1f}%"
    return formatted.replace(".0%", "%")


def _median_from_counts(length_counts: Counter[int]) -> float | None:
    total = sum(length_counts.values())
    if total <= 0:
        return None

    lower_target = (total - 1) // 2
    upper_target = total // 2
    lower_value = None
    seen = 0

    for length in sorted(length_counts):
        next_seen = seen + length_counts[length]
        if lower_value is None and lower_target < next_seen:
            lower_value = length
        if upper_target < next_seen:
            upper_value = length
            if lower_value is None:
                lower_value = upper_value
            if lower_value == upper_value:
                return float(upper_value)
            return round((lower_value + upper_value) / 2, 1)
        seen = next_seen

    return None


def _posture_risk_band(
    weak_recovered_percent: float,
    reused_recovered_percent: float,
    username_match_count: int,
    recovered_accounts: int,
) -> tuple[str, int]:
    if recovered_accounts <= 0:
        return ("Unknown", -1)

    score = 0
    if weak_recovered_percent >= 60:
        score += 3
    elif weak_recovered_percent >= 35:
        score += 2
    elif weak_recovered_percent >= 15:
        score += 1

    if reused_recovered_percent >= 40:
        score += 3
    elif reused_recovered_percent >= 20:
        score += 2
    elif reused_recovered_percent >= 10:
        score += 1

    if username_match_count >= 10:
        score += 3
    elif username_match_count >= 1:
        score += 2

    if score >= 6:
        return ("High", score)
    if score >= 3:
        return ("Medium", score)
    return ("Low", score)


def _build_posture_summary(total_accounts: int, cracked_metrics: dict[str, object]) -> dict[str, object]:
    recovered_accounts = int(cracked_metrics['recovered_accounts'])
    weak_recovered_count = int(cracked_metrics['complexity_fails'])
    reused_recovered_count = int(
        sum(
            count
            for count in cracked_metrics['password_counts'].values()
            if count > 1
        )
    )
    reused_password_count = int(
        sum(
            1
            for count in cracked_metrics['password_counts'].values()
            if count > 1
        )
    )
    username_match_count = int(sum(cracked_metrics['username_match_counts'].values()))
    weak_recovered_percent = _ratio(weak_recovered_count, recovered_accounts)
    reused_recovered_percent = _ratio(reused_recovered_count, recovered_accounts)
    recovered_percent = _ratio(recovered_accounts, total_accounts)
    median_length = _median_from_counts(cracked_metrics['length_counts'])
    average_length = None
    if recovered_accounts > 0:
        average_length = round(
            sum(length * count for length, count in cracked_metrics['length_counts'].items())
            / recovered_accounts,
            1,
        )
    top_password_count = max(cracked_metrics['password_counts'].values(), default=0)
    risk_band, risk_score = _posture_risk_band(
        weak_recovered_percent,
        reused_recovered_percent,
        username_match_count,
        recovered_accounts,
    )
    return {
        'total_accounts': total_accounts,
        'recovered_accounts': recovered_accounts,
        'unrecovered_accounts': max(total_accounts - recovered_accounts, 0),
        'recovered_percent': recovered_percent,
        'weak_recovered_count': weak_recovered_count,
        'weak_recovered_percent': weak_recovered_percent,
        'reused_recovered_count': reused_recovered_count,
        'reused_recovered_percent': reused_recovered_percent,
        'reused_password_count': reused_password_count,
        'username_match_count': username_match_count,
        'username_match_percent': _ratio(username_match_count, recovered_accounts),
        'median_length': median_length,
        'average_length': average_length,
        'top_password_count': top_password_count,
        'risk_band': risk_band,
        'risk_score': risk_score,
    }


def _format_length_value(value: float | None) -> str:
    if value is None:
        return "N/A"
    if float(value).is_integer():
        return str(int(value))
    return str(value)


def _build_scope_findings(
    posture_summary: dict[str, object],
    hash_reuse_summary: dict[str, int | float],
    public_exposure_summary,
) -> list[str]:
    total_accounts = int(posture_summary['total_accounts'])
    recovered_accounts = int(posture_summary['recovered_accounts'])
    weak_recovered_count = int(posture_summary['weak_recovered_count'])
    reused_recovered_count = int(posture_summary['reused_recovered_count'])
    username_match_count = int(posture_summary['username_match_count'])
    findings: list[str] = []

    if total_accounts <= 0:
        return ["No accounts are available in the selected scope yet."]

    if recovered_accounts <= 0:
        return [
            "No passwords have been recovered in this scope yet, so quality and reuse analysis is not available.",
            f"{format_display(total_accounts)} account row(s) remain unrecovered in this scope.",
        ]

    findings.append(
        f"{_format_percent(posture_summary['recovered_percent'])} of account rows in this scope are recovered."
    )
    if weak_recovered_count > 0:
        findings.append(
            f"{_format_percent(posture_summary['weak_recovered_percent'])} of recovered accounts fail the current quality baseline."
        )
    else:
        findings.append("All recovered passwords in this scope currently meet the quality baseline.")

    if reused_recovered_count > 0:
        findings.append(
            f"{_format_percent(posture_summary['reused_recovered_percent'])} of recovered accounts reuse a password in this scope."
        )
    else:
        findings.append("No recovered passwords are currently reused in this scope.")

    reused_hash_account_count = int(hash_reuse_summary['reused_hash_account_count'])
    if reused_hash_account_count > 0:
        findings.append(
            f"{_format_percent(float(hash_reuse_summary['reused_hash_account_percent']))} of account rows share a non-unique hash value in this scope."
        )
    else:
        findings.append("No account rows currently share a non-unique hash value in this scope.")

    if not public_exposure_summary.dataset_loaded:
        findings.append(
            "Offline public exposure checks are unavailable until a HIBP NTLM dataset is loaded in Settings."
        )
    elif public_exposure_summary.eligible_account_count <= 0:
        findings.append(
            "No NTLM account rows are present in this scope, so offline public exposure checks do not apply here."
        )
    elif public_exposure_summary.exposed_account_count > 0:
        findings.append(
            f"{format_display(public_exposure_summary.exposed_account_count)} account row(s) in this scope use NTLM hashes found in the offline public breach dataset."
        )
    else:
        findings.append(
            "No NTLM account rows in this scope currently match the offline public breach dataset."
        )

    if username_match_count > 0:
        findings.append(
            f"{format_display(username_match_count)} recovered account(s) use a password that matches the username."
        )
    else:
        findings.append("No recovered accounts in this scope currently have password equal to username.")

    return findings[:5]


def _build_domain_posture_rows(domain_rows: list[Domains], selected_domain_id: int | None) -> list[dict[str, object]]:
    domain_ids = [domain.id for domain in domain_rows]
    if not domain_ids:
        return []

    effective_domain_id = func.coalesce(HashfileHashes.domain_id, Hashfiles.domain_id)
    status_rows = db.session.execute(
        select(effective_domain_id.label('domain_id'), Hashes.cracked, func.count(Hashes.id))
        .select_from(Hashes)
        .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
        .join(Hashfiles, Hashfiles.id == HashfileHashes.hashfile_id)
        .where(effective_domain_id.in_(domain_ids))
        .group_by(effective_domain_id, Hashes.cracked)
    ).all()
    status_counts: dict[int, dict[bool, int]] = defaultdict(lambda: {True: 0, False: 0})
    for domain_id, cracked, count in status_rows:
        status_counts[int(domain_id)][bool(cracked)] = int(count)

    cracked_metrics_by_domain: dict[int, dict[str, object]] = defaultdict(
        _empty_cracked_password_metrics
    )
    cracked_rows = db.session.execute(
        select(effective_domain_id.label('domain_id'), Hashes.plaintext, HashfileHashes.username)
        .select_from(Hashes)
        .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
        .join(Hashfiles, Hashfiles.id == HashfileHashes.hashfile_id)
        .where(effective_domain_id.in_(domain_ids))
        .where(Hashes.cracked.is_(True))
        .execution_options(yield_per=1000)
    )
    for domain_id, plaintext, username in cracked_rows:
        _accumulate_cracked_password_metric(
            cracked_metrics_by_domain[int(domain_id)],
            plaintext,
            username,
        )

    comparison_rows: list[dict[str, object]] = []
    for domain in domain_rows:
        counts = status_counts.get(domain.id, {True: 0, False: 0})
        total_accounts = int(counts.get(True, 0)) + int(counts.get(False, 0))
        cracked_metrics = cracked_metrics_by_domain.get(
            domain.id, _empty_cracked_password_metrics()
        )
        posture_summary = _build_posture_summary(total_accounts, cracked_metrics)
        comparison_rows.append(
            {
                'id': domain.id,
                'name': domain.name,
                'selected': domain.id == selected_domain_id,
                'total_accounts': total_accounts,
                'recovered_accounts': posture_summary['recovered_accounts'],
                'recovered_percent': posture_summary['recovered_percent'],
                'recovered_percent_display': _format_percent(posture_summary['recovered_percent']),
                'weak_recovered_percent': posture_summary['weak_recovered_percent'],
                'weak_recovered_percent_display': _format_percent(posture_summary['weak_recovered_percent']),
                'reused_recovered_percent': posture_summary['reused_recovered_percent'],
                'reused_recovered_percent_display': _format_percent(posture_summary['reused_recovered_percent']),
                'username_match_count': posture_summary['username_match_count'],
                'median_length': _format_length_value(posture_summary['median_length']),
                'risk_band': posture_summary['risk_band'],
                'risk_score': posture_summary['risk_score'],
            }
        )

    risk_order = {'High': 3, 'Medium': 2, 'Low': 1, 'Unknown': 0}
    comparison_rows.sort(
        key=lambda row: (
            -risk_order.get(str(row['risk_band']), 0),
            -float(row['weak_recovered_percent']),
            -float(row['reused_recovered_percent']),
            str(row['name']).lower(),
        )
    )
    return comparison_rows


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
        [domain for domain in visible_domains_with_hashes() if domain.id in scope['visible_domain_ids']]
        if scope['visible_domain_ids']
        else []
    )
    hashfile_rows = scope['visible_hashfiles']
    scoped_hashfile_ids = scope['scoped_hashfile_ids']
    domain_id = scope['domain_id']
    hashfile_id = scope['hashfile_id']
    selected_domain_name = next((domain.name for domain in domain_rows if domain.id == domain_id), None)
    selected_hashfile_name = next((hashfile.name for hashfile in hashfile_rows if hashfile.id == hashfile_id), None)
    filter_hashfile_id_set = (
        set(hashfile_ids_for_domain(domain_id)) if domain_id is not None else None
    )
    filter_hashfiles = [
        hashfile
        for hashfile in hashfile_rows
        if filter_hashfile_id_set is None or hashfile.id in filter_hashfile_id_set
    ]
    domain_posture_rows = (
        _build_domain_posture_rows(domain_rows, domain_id)
        if hashfile_id is None
        else []
    )

    if not scoped_hashfile_ids:
        empty_public_exposure_summary = public_exposure_summary_for_hashfile_ids([])
        return render_template(
            'analytics.html',
            title='analytics',
            analytics_chart_data={
                'recovered_accounts': {'labels': [], 'values': [], 'center_text': ''},
                'password_quality': {'labels': [], 'values': []},
                'hash_reuse': {'labels': [], 'values': []},
                'composition_makeup': {'labels': [], 'values': []},
                'passwords_count_len': {'labels': [], 'values': []},
            },
            fig7_values={},
            fig7_total=0,
            findings=_build_scope_findings(
                _build_posture_summary(0, _build_cracked_password_metrics([])),
                _build_hash_reuse_summary([]),
                empty_public_exposure_summary,
            ),
            scope_posture={
                'recovered_accounts': format_display(0),
                'recovered_percent': _format_percent(0.0),
                'reused_hash_value_count': format_display(0),
                'reused_hash_value_percent': _format_percent(0.0),
                'reused_hash_account_count': format_display(0),
                'reused_hash_account_percent': _format_percent(0.0),
                'weak_recovered_count': format_display(0),
                'weak_recovered_percent': _format_percent(0.0),
                'reused_recovered_count': format_display(0),
                'reused_recovered_percent': _format_percent(0.0),
                'username_match_count': format_display(0),
                'median_length': "N/A",
                'risk_band': "Unknown",
                'public_exposed_hash_count': format_display(0),
                'public_exposed_hash_percent': _format_percent(0.0),
                'public_exposed_account_count': format_display(0),
                'public_exposed_account_percent': _format_percent(0.0),
                'public_exposure_dataset_label': empty_public_exposure_summary.dataset_version_label or 'Not loaded',
                'public_exposure_last_checked': empty_public_exposure_summary.last_checked_at or 'N/A',
            },
            public_exposure_summary=empty_public_exposure_summary,
            domain_posture_rows=domain_posture_rows,
            show_domain_comparison=hashfile_id is None and bool(domain_posture_rows),
            reused_password_rows=[],
            username_match_rows=[],
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
    fig1_percent = _format_percent(_ratio(fig1_cracked_cnt, fig1_total))

    cracked_rows = db.session.execute(
        select(Hashes.plaintext, HashfileHashes.username)
        .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
        .where(HashfileHashes.hashfile_id.in_(scoped_hashfile_ids))
        .where(Hashes.cracked.is_(True))
        .execution_options(yield_per=1000)
    )
    cracked_metrics = _build_cracked_password_metrics(cracked_rows)
    fig2_fails_complexity_cnt = int(cracked_metrics['complexity_fails'])
    fig2_meets_complexity_cnt = int(cracked_metrics['complexity_meets'])

    fig2_data = [
        ("Fails Quality: " + str(format_display(fig2_fails_complexity_cnt)), fig2_fails_complexity_cnt),
        ("Meets Quality: " + str(format_display(fig2_meets_complexity_cnt)), fig2_meets_complexity_cnt),
    ]
    fig2_labels = [row[0] for row in fig2_data]
    fig2_values = [row[1] for row in fig2_data]

    # Figure 3 (Hash Reuse)
    hash_reuse_summary = _build_hash_reuse_summary(scoped_hashfile_ids)
    fig3_reused_hash_accounts = int(hash_reuse_summary['reused_hash_account_count'])
    fig3_unique_hash_accounts = int(hash_reuse_summary['unique_hash_account_count'])
    fig3_data = [
        (
            "Shared Hash Rows: " + str(format_display(fig3_reused_hash_accounts)),
            fig3_reused_hash_accounts,
        ),
        (
            "Unique Hash Rows: " + str(format_display(fig3_unique_hash_accounts)),
            fig3_unique_hash_accounts,
        ),
    ]
    fig3_labels = [row[0] for row in fig3_data]
    fig3_values = [row[1] for row in fig3_data]

    # General Stats Table
    total_runtime = sum(hashfile.runtime or 0 for hashfile in scope['scoped_hashfiles'])
    total_accounts = fig1_total
    total_unique_hashes = int(hash_reuse_summary['total_unique_hashes'])
    posture_summary = _build_posture_summary(fig1_total, cracked_metrics)
    public_exposure_summary = public_exposure_summary_for_hashfile_ids(scoped_hashfile_ids)
    total_accounts_display = format_display(total_accounts)
    total_unique_hashes_display = format_display(total_unique_hashes)

    # Figure 5 (Charset Breakdown)
    fig5_labels = []
    fig5_values = []
    fig5_rows = sorted(
        cracked_metrics['composition_counts'].items(),
        key=lambda item: (-item[1], item[0]),
    )
    limit = 0
    fig5_other = 0
    for label, count in fig5_rows:
        if limit <= 3:
            fig5_labels.append(f"{label}: {format_display(count)}")
            fig5_values.append(count)
            limit += 1
        else:
            fig5_other += count
    if fig5_other > 0:
        fig5_labels.append('Other: ' + str(fig5_other))
        fig5_values.append(fig5_other)

    # Figure 6 (Passwords by Length)
    fig6_labels = []
    fig6_values = []
    for entry in sorted(cracked_metrics['length_counts']):
        if len(fig6_labels) < 20:
            fig6_labels.append(entry)
            fig6_values.append(cracked_metrics['length_counts'][entry])
        else:
            break

    reused_password_rows = [
        (entry, count)
        for entry, count in sorted(
            cracked_metrics['password_counts'].items(),
            key=lambda item: (-item[1], item[0]),
        )
        if count > 1
    ][:10]
    username_match_rows = sorted(
        cracked_metrics['username_match_counts'].items(),
        key=lambda item: (-item[1], item[0]),
    )[:10]

    # Figure 7 (Top 10 Masks)
    fig7_values = {}
    fig7_total = int(sum(cracked_metrics['mask_counts'].values()))
    for entry, count in cracked_metrics['mask_counts'].most_common(10):
        if len(fig7_values) < 10:
            fig7_values[entry] = count
        else:
            break

    scope_posture = {
        'recovered_accounts': format_display(posture_summary['recovered_accounts']),
        'recovered_percent': _format_percent(posture_summary['recovered_percent']),
        'reused_hash_value_count': format_display(hash_reuse_summary['reused_hash_value_count']),
        'reused_hash_value_percent': _format_percent(float(hash_reuse_summary['reused_hash_value_percent'])),
        'reused_hash_account_count': format_display(hash_reuse_summary['reused_hash_account_count']),
        'reused_hash_account_percent': _format_percent(float(hash_reuse_summary['reused_hash_account_percent'])),
        'weak_recovered_count': format_display(posture_summary['weak_recovered_count']),
        'weak_recovered_percent': _format_percent(posture_summary['weak_recovered_percent']),
        'reused_recovered_count': format_display(posture_summary['reused_recovered_count']),
        'reused_recovered_percent': _format_percent(posture_summary['reused_recovered_percent']),
        'username_match_count': format_display(posture_summary['username_match_count']),
        'median_length': _format_length_value(posture_summary['median_length']),
        'risk_band': posture_summary['risk_band'],
        'public_exposed_hash_count': format_display(public_exposure_summary.exposed_hash_count),
        'public_exposed_hash_percent': _format_percent(
            _ratio(
                public_exposure_summary.exposed_hash_count,
                public_exposure_summary.eligible_hash_count,
            )
        ),
        'public_exposed_account_count': format_display(public_exposure_summary.exposed_account_count),
        'public_exposed_account_percent': _format_percent(
            _ratio(
                public_exposure_summary.exposed_account_count,
                public_exposure_summary.eligible_account_count,
            )
        ),
        'public_exposure_dataset_label': public_exposure_summary.dataset_version_label or 'Not loaded',
        'public_exposure_last_checked': public_exposure_summary.last_checked_at or 'N/A',
    }

    return render_template(
        'analytics.html',
        title='analytics',
        analytics_chart_data={
            'recovered_accounts': {
                'labels': fig1_labels,
                'values': fig1_values,
                'center_text': fig1_percent,
            },
            'password_quality': {
                'labels': fig2_labels,
                'values': fig2_values,
            },
            'hash_reuse': {
                'labels': fig3_labels,
                'values': fig3_values,
            },
            'composition_makeup': {
                'labels': fig5_labels,
                'values': fig5_values,
            },
            'passwords_count_len': {
                'labels': fig6_labels,
                'values': fig6_values,
            },
        },
        fig7_values=fig7_values,
        fig7_total=fig7_total,
        findings=_build_scope_findings(
            posture_summary,
            hash_reuse_summary,
            public_exposure_summary,
        ),
        scope_posture=scope_posture,
        public_exposure_summary=public_exposure_summary,
        domain_posture_rows=domain_posture_rows,
        show_domain_comparison=hashfile_id is None and bool(domain_posture_rows),
        reused_password_rows=reused_password_rows,
        username_match_rows=username_match_rows,
        domains=domain_rows,
        hashfiles=hashfile_rows,
        filter_hashfiles=filter_hashfiles,
        hashfile_id=hashfile_id,
        domain_id=domain_id,
        selected_domain_name=selected_domain_name,
        selected_hashfile_name=selected_hashfile_name,
        total_runtime=total_runtime,
        runtime_display=_format_runtime_display(total_runtime),
        total_accounts=total_accounts_display,
        total_unique_hashes=total_unique_hashes_display,
    )


@analytics.route('/analytics/download', methods=['GET'])
@login_required
def analytics_download_hashes():
    """Function to download hashes."""
    if not current_user.admin:
        flash('Permission Denied', 'danger')
        return redirect(url_for('analytics.get_analytics'))

    export_type = (request.args.get('type') or '').strip().lower()
    export_names = {
        'found': 'recovered_accounts',
        'left': 'unrecovered_accounts',
        'reused_hashes': 'reused_hash_accounts',
        'reused_passwords': 'reused_password_accounts',
        'public_exposures': 'public_exposure_accounts',
    }
    base_filename = export_names.get(export_type)
    if base_filename is None:
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

    filename = _export_filename(base_filename, domain_id, hashfile_id)

    output = io.StringIO()
    row_count = 0
    if scoped_hashfile_ids:
        if export_type == 'found':
            for hash_row, link_row in _iter_scoped_hash_rows(scoped_hashfile_ids, cracked=True):
                _write_account_export_line(output, hash_row, link_row, include_plaintext=True)
                row_count += 1
        elif export_type == 'left':
            for hash_row, link_row in _iter_scoped_hash_rows(scoped_hashfile_ids, cracked=False):
                _write_account_export_line(output, hash_row, link_row, include_plaintext=False)
                row_count += 1
        elif export_type == 'reused_hashes':
            reused_hash_subquery = (
                select(Hashes.sub_ciphertext)
                .select_from(Hashes)
                .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
                .where(HashfileHashes.hashfile_id.in_(scoped_hashfile_ids))
                .group_by(Hashes.sub_ciphertext)
                .having(func.count(HashfileHashes.id) > 1)
            )
            reused_hash_accounts = db.session.execute(
                _scoped_hash_rows_stmt(scoped_hashfile_ids)
                .where(Hashes.sub_ciphertext.in_(reused_hash_subquery))
                .order_by(Hashes.sub_ciphertext.asc(), HashfileHashes.id.asc())
                .execution_options(yield_per=1000)
            ).tuples()
            for hash_row, link_row in reused_hash_accounts:
                _write_account_export_line(
                    output,
                    hash_row,
                    link_row,
                    include_plaintext=bool(hash_row.cracked),
                )
                row_count += 1
        elif export_type == 'reused_passwords':
            plaintext_key = func.coalesce(Hashes.plaintext_digest, Hashes.plaintext)
            reused_password_subquery = (
                select(plaintext_key)
                .select_from(Hashes)
                .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
                .where(HashfileHashes.hashfile_id.in_(scoped_hashfile_ids))
                .where(Hashes.cracked.is_(True))
                .group_by(plaintext_key)
                .having(func.count(HashfileHashes.id) > 1)
            )
            reused_password_accounts = db.session.execute(
                _scoped_hash_rows_stmt(scoped_hashfile_ids)
                .where(Hashes.cracked.is_(True))
                .where(plaintext_key.in_(reused_password_subquery))
                .order_by(plaintext_key.asc(), HashfileHashes.id.asc())
                .execution_options(yield_per=1000)
            ).tuples()
            for hash_row, link_row in reused_password_accounts:
                _write_account_export_line(output, hash_row, link_row, include_plaintext=True)
                row_count += 1
        elif export_type == 'public_exposures':
            public_exposure_accounts = db.session.execute(
                select(Hashes, HashfileHashes, HashPublicExposure.prevalence_count)
                .join(HashfileHashes, Hashes.id == HashfileHashes.hash_id)
                .join(HashPublicExposure, HashPublicExposure.hash_id == Hashes.id)
                .where(HashfileHashes.hashfile_id.in_(scoped_hashfile_ids))
                .where(Hashes.hash_type == 1000)
                .where(HashPublicExposure.source_kind == HIBP_NTLM_KIND)
                .where(HashPublicExposure.matched.is_(True))
                .order_by(HashfileHashes.id.asc())
                .execution_options(yield_per=1000)
            )
            for hash_row, link_row, prevalence_count in public_exposure_accounts:
                trailing_fields = [str(int(prevalence_count))] if int(prevalence_count or 0) > 0 else []
                _write_account_export_line(
                    output,
                    hash_row,
                    link_row,
                    include_plaintext=bool(hash_row.cracked),
                    trailing_fields=trailing_fields,
                )
                row_count += 1

    record_audit_event(
        'analytics.download',
        'analytics_export',
        target_id=filename,
        summary=f'Downloaded analytics export "{filename}".',
        details={
            'export_type': export_type,
            'domain_id': domain_id,
            'hashfile_id': hashfile_id,
            'row_count': row_count,
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
