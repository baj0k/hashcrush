"""Shared domain creation helpers."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import exists, func, or_, select

from hashcrush.utils.forms import normalize_text_input
from hashcrush.models import Domains, HashfileHashes, Hashfiles, Jobs, db


@dataclass(frozen=True)
class DomainSelectionResult:
    """Outcome of resolving or creating a shared domain."""

    domain: Domains
    created: bool


@dataclass(frozen=True)
class DomainSummary:
    """Human-friendly summary for a hashfile or job domain scope."""

    domain_id: int | None
    name: str | None
    label: str


def normalize_domain_name(value: str | None) -> str | None:
    """Normalize imported or user-provided domain names for stable matching."""

    normalized = normalize_text_input(value)
    if not normalized:
        return None
    if normalized.casefold() == "none":
        return None
    return normalized.lower()


def username_has_redundant_domain_prefix(username: str | None) -> bool:
    """Return True when a username repeats the same value as both domain and user."""

    normalized_username = normalize_text_input(username)
    if not normalized_username:
        return False
    for separator in ("\\", "*"):
        if separator not in normalized_username:
            continue
        candidate, remainder = normalized_username.split(separator, 1)
        normalized_candidate = normalize_domain_name(candidate)
        normalized_remainder = normalize_text_input(remainder)
        if (
            normalized_candidate
            and normalized_remainder
            and normalized_candidate == normalized_remainder.casefold()
        ):
            return True
    return False


def extract_domain_name_from_username(username: str | None) -> str | None:
    """Extract a domain prefix from DOMAIN\\user style usernames."""

    normalized_username = normalize_text_input(username)
    if not normalized_username:
        return None
    if username_has_redundant_domain_prefix(normalized_username):
        return None
    for separator in ("\\", "*"):
        if separator in normalized_username:
            candidate, remainder = normalized_username.split(separator, 1)
            if candidate and remainder:
                return normalize_domain_name(candidate)
    return None


def get_or_create_domain_by_name(name: str | None) -> Domains | None:
    """Fetch or create a shared domain row for the given normalized name."""

    normalized_name = normalize_domain_name(name)
    if not normalized_name:
        return None

    existing_domain = db.session.scalar(
        select(Domains).where(func.lower(Domains.name) == normalized_name)
    )
    if existing_domain is not None:
        return existing_domain

    domain = Domains(name=normalized_name)
    db.session.add(domain)
    db.session.flush()
    return domain


def visible_domains_with_hashes() -> list[Domains]:
    """Return domains referenced by imported rows or legacy single-domain hashfiles."""

    return db.session.execute(
        select(Domains)
        .where(
            or_(
                exists(
                    select(HashfileHashes.id).where(HashfileHashes.domain_id == Domains.id)
                ),
                exists(
                    select(Hashfiles.id).where(Hashfiles.domain_id == Domains.id)
                ),
            )
        )
        .order_by(Domains.name.asc())
    ).scalars().all()


def hashfile_ids_for_domain(domain_id: int) -> list[int]:
    """Return hashfiles containing the given domain via rows or legacy hashfile scope."""

    return [
        int(hashfile_id)
        for hashfile_id in db.session.scalars(
            select(Hashfiles.id)
            .outerjoin(HashfileHashes, HashfileHashes.hashfile_id == Hashfiles.id)
            .where(
                or_(
                    HashfileHashes.domain_id == domain_id,
                    Hashfiles.domain_id == domain_id,
                )
            )
            .distinct()
            .order_by(Hashfiles.id.asc())
        ).all()
    ]


def hashfile_domain_summaries(hashfile_ids: list[int]) -> dict[int, DomainSummary]:
    """Summarize imported domains for each hashfile as single, mixed, or none."""

    if not hashfile_ids:
        return {}

    explicit_rows = db.session.execute(
        select(Hashfiles.id, Hashfiles.domain_id, Domains.name)
        .select_from(Hashfiles)
        .outerjoin(Domains, Domains.id == Hashfiles.domain_id)
        .where(Hashfiles.id.in_(hashfile_ids))
    ).all()
    explicit_by_hashfile = {
        int(hashfile_id): (
            int(domain_id) if domain_id is not None else None,
            str(name) if name is not None else None,
        )
        for hashfile_id, domain_id, name in explicit_rows
    }

    distinct_rows = db.session.execute(
        select(HashfileHashes.hashfile_id, HashfileHashes.domain_id, Domains.name)
        .select_from(HashfileHashes)
        .join(Domains, Domains.id == HashfileHashes.domain_id)
        .where(
            HashfileHashes.hashfile_id.in_(hashfile_ids),
            HashfileHashes.domain_id.is_not(None),
        )
        .distinct()
    ).all()
    domains_by_hashfile: dict[int, list[tuple[int, str]]] = {}
    for hashfile_id, domain_id, name in distinct_rows:
        domains_by_hashfile.setdefault(int(hashfile_id), []).append(
            (int(domain_id), str(name))
        )

    summaries: dict[int, DomainSummary] = {}
    for hashfile_id in hashfile_ids:
        domain_rows = domains_by_hashfile.get(hashfile_id, [])
        if len(domain_rows) == 1:
            domain_id, name = domain_rows[0]
            summaries[hashfile_id] = DomainSummary(
                domain_id=domain_id,
                name=name,
                label=name,
            )
            continue
        if len(domain_rows) > 1:
            summaries[hashfile_id] = DomainSummary(
                domain_id=None,
                name=None,
                label="Mixed",
            )
            continue
        explicit_domain_id, explicit_name = explicit_by_hashfile.get(hashfile_id, (None, None))
        if explicit_domain_id is not None and explicit_name is not None:
            summaries[hashfile_id] = DomainSummary(
                domain_id=explicit_domain_id,
                name=explicit_name,
                label=explicit_name,
            )
        else:
            summaries[hashfile_id] = DomainSummary(
                domain_id=None,
                name=None,
                label="None",
            )
    return summaries


def job_domain_summaries(job_ids: list[int]) -> dict[int, DomainSummary]:
    """Summarize effective domains for jobs via their selected hashfile."""

    if not job_ids:
        return {}
    rows = db.session.execute(
        select(Jobs.id, Jobs.hashfile_id, Jobs.domain_id, Domains.name)
        .select_from(Jobs)
        .outerjoin(Domains, Domains.id == Jobs.domain_id)
        .where(Jobs.id.in_(job_ids))
    ).all()
    hashfile_ids = [int(hashfile_id) for _, hashfile_id, _, _ in rows if hashfile_id]
    hashfile_summaries = hashfile_domain_summaries(hashfile_ids)
    summaries: dict[int, DomainSummary] = {}
    for job_id, hashfile_id, explicit_domain_id, explicit_domain_name in rows:
        if hashfile_id is not None:
            summaries[int(job_id)] = hashfile_summaries.get(
                int(hashfile_id),
                DomainSummary(
                    domain_id=(
                        int(explicit_domain_id) if explicit_domain_id is not None else None
                    ),
                    name=str(explicit_domain_name) if explicit_domain_name else None,
                    label=str(explicit_domain_name) if explicit_domain_name else "None",
                ),
            )
            continue
        if explicit_domain_id is not None and explicit_domain_name is not None:
            summaries[int(job_id)] = DomainSummary(
                domain_id=int(explicit_domain_id),
                name=str(explicit_domain_name),
                label=str(explicit_domain_name),
            )
        else:
            summaries[int(job_id)] = DomainSummary(
                domain_id=None,
                name=None,
                label="None",
            )
    return summaries


def resolve_or_create_shared_domain(
    selected_value: str | None,
    *,
    new_domain_name: str | None = None,
    allow_create: bool = False,
) -> tuple[DomainSelectionResult | None, str | None]:
    """Resolve an existing shared domain or create one for admin flows."""

    normalized_selection = (selected_value or "").strip()
    if normalized_selection == "add_new":
        if not allow_create:
            return None, "Only admins can create new domains from this form."

        normalized_name = normalize_domain_name(new_domain_name)
        if not normalized_name:
            return None, "You must provide a domain name."

        existing_domain = db.session.scalar(
            select(Domains).where(func.lower(Domains.name) == normalized_name)
        )
        if existing_domain:
            return DomainSelectionResult(domain=existing_domain, created=False), None

        domain = Domains(name=normalized_name)
        db.session.add(domain)
        db.session.flush()
        return DomainSelectionResult(domain=domain, created=True), None

    try:
        domain_id = int(normalized_selection)
    except (TypeError, ValueError):
        return None, "Selected domain is invalid or no longer available."

    domain = db.session.get(Domains, domain_id)
    if not domain:
        return None, "Selected domain is invalid or no longer available."
    return DomainSelectionResult(domain=domain, created=False), None
