"""Shared CVSS severity constants and helpers.

Used by both the kernel reconciliation module and SuggestImpact.
Kept in a standalone file to avoid circular imports.
"""

SEVERITY_ORDER = {"CRITICAL": 0, "IMPORTANT": 1, "MODERATE": 2, "LOW": 3, "": 4}

# fmt: off
NUM_BY_IMPACT = {
    "NONE": 0.0,        # 0
    "LOW": 2.0,         # 0..4
    "MODERATE": 5.5,    # 4..7
    "IMPORTANT": 8.0,   # 7..9
    "CRITICAL": 9.5,    # 9..10
}
# fmt: on

_CVSS_SCALES: dict[str, list[str]] = {
    "AV": ["P", "L", "A", "N"],
    "AC": ["H", "L"],
    "PR": ["H", "L", "N"],
    "UI": ["R", "N"],
    "S": ["U", "C"],
    "C": ["N", "L", "H"],
    "I": ["N", "L", "H"],
    "A": ["N", "L", "H"],
}


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


def score_impact_diff(impact: str, impact_exp: str) -> float:
    """Compare two impact severity strings and return a similarity score.
    0.0 means completely different, 1.0 means exact match.
    Raises KeyError if either value is not a recognised severity level."""
    imp = NUM_BY_IMPACT[impact.strip().upper()]
    imp_exp = NUM_BY_IMPACT[impact_exp.strip().upper()]
    return 1.0 - abs(imp - imp_exp) / 10.0


def _parse_cvss_vector(vector: str) -> dict[str, str]:
    parts = vector.split("/")
    if parts and parts[0].startswith("CVSS:"):
        parts = parts[1:]
    out: dict[str, str] = {}
    for p in parts:
        if ":" in p:
            k, val = p.split(":", 1)
            out[k] = val
    return out


def score_cvss3_diff(cvss3: str, cvss3_exp: str) -> tuple[float, str | None]:
    """Compare two CVSS 3.1 vectors and return (score, reason).
    0.0 means completely different, 1.0 means exact match.
    When the score is not 1.0, reason enumerates mismatched metrics."""
    if cvss3 == cvss3_exp:
        return (1.0, None)

    a = _parse_cvss_vector(cvss3)
    b = _parse_cvss_vector(cvss3_exp)

    def _norm_dist(metric: str) -> float:
        order = _CVSS_SCALES[metric]
        try:
            ia = order.index(a.get(metric, ""))
            ib = order.index(b.get(metric, ""))
        except ValueError:
            return 1.0
        max_d = len(order) - 1
        if max_d == 0:
            return 0.0
        return abs(ia - ib) / max_d

    metrics = tuple(_CVSS_SCALES.keys())
    diffs = [_norm_dist(m) for m in metrics]
    avg_diff = sum(diffs) / len(diffs)
    score = (1.0 - avg_diff) ** 2

    mismatch_list: list[str] = []
    for m in metrics:
        va = a.get(m)
        vb = b.get(m)
        if va is not None and vb is not None and va != vb:
            mismatch_list.append(f"{m}: got {va}, expected {vb}")

    reason = ", ".join(mismatch_list) if mismatch_list else None
    return (round(score, 4), reason)
