"""Shared CVSS severity constants and helpers.

Used by both the kernel reconciliation module and SuggestImpact.
Kept in a standalone file to avoid circular imports.
"""

SEVERITY_ORDER = {"CRITICAL": 0, "IMPORTANT": 1, "MODERATE": 2, "LOW": 3, "": 4}


def score_to_band(score: float) -> str | None:
    """Map a CVSS v3.1 base score to the Red Hat impact band."""
    if score > 9.0:
        return "CRITICAL"
    if score > 7.0:
        return "IMPORTANT"
    if score >= 4.0:
        return "MODERATE"
    if score > 0.0:
        return "LOW"
    if score == 0.0:
        return ""
    return None
