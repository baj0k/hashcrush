"""Shared domain creation helpers."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select

from hashcrush.forms_utils import normalize_text_input
from hashcrush.models import Domains, db


@dataclass(frozen=True)
class DomainSelectionResult:
    """Outcome of resolving or creating a shared domain."""

    domain: Domains
    created: bool


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

        normalized_name = normalize_text_input(new_domain_name)
        if not normalized_name:
            return None, "You must provide a domain name."

        existing_domain = db.session.scalar(
            select(Domains).where(Domains.name == normalized_name)
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
