"""Helpers shared across WTForms definitions."""


def normalize_text_input(value):
    """Trim string inputs so whitespace-only submissions fail validation."""
    if isinstance(value, str):
        return value.strip()
    return value
