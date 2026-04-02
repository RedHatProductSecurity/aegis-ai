"""Post-prediction severity adjustment cascade ported from al-kernel daemon.

Authoritative implementation of the severity cascade rules.  Both the
runtime classifier (``aegis_ai.kernel_classifier``) and the ML training
pipeline (``aegis_ai_ml``) import from here so that rules stay in sync.

Design rationale — asymmetric error costs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Underestimation (predicting lower severity than truth) is far more costly
than overestimation.  A missed IMPORTANT means a high-impact vulnerability
ships without the urgency it deserves — delayed patches, inadequate customer
advisories, and potential exploitation in the field.  Overestimation merely
triggers extra analyst review with no security harm.  The cascade therefore
favours escalation rules that reduce underestimation, accepting a modest
increase in overestimation as an acceptable trade-off.

Escalation rules (MODERATE/LOW → IMPORTANT):
  R9   MODERATE → IMPORTANT  if CVSS ≥ 8.5
  R10  MODERATE → IMPORTANT  if CVSS ≥ 7.5 with C:H/I:H/A:H, !BPF

Adjustment rules (LOW ↔ MODERATE):
  R6  LOW  → MODERATE  if CVSS ≥ 6.7 (or ≥ 5.5 with C:H/I:H/A:H), !BPF
  R7  MODERATE → LOW   if CVSS ≤ 3.9, !KPANIC
  R8  MODERATE → LOW   if CVSS < 5.5, AV:L, low CIA impact, !C:H/I:H/A:H

All features gracefully degrade to no-ops when CVSS data is unavailable.
"""

SEVERITY_MAP: dict[str, int] = {"IMPORTANT": 0, "MODERATE": 1, "LOW": 2}
SEVERITY_LABELS: dict[int, str] = {0: "IMPORTANT", 1: "MODERATE", 2: "LOW"}


def parse_cvss_vector(vector_str: str) -> dict[str, str]:
    """Parse a CVSS v3.x vector string into metric → value pairs."""
    parts: dict[str, str] = {}
    for seg in vector_str.split("/"):
        if ":" in seg and seg != "CVSS:3.1":
            k, v = seg.split(":", 1)
            parts[k] = v
    return parts


def apply_cascade(
    severity: int,
    cvss_score: float,
    cvss_vector: str,
    patch_flags: set[str],
) -> int:
    """Apply daemon-derived severity adjustment rules (R6–R10).

    Args:
        severity: XGBoost prediction (0=IMPORTANT, 1=MODERATE, 2=LOW)
        cvss_score: NIST CVSS v3.1 base score (0.0 if unavailable)
        cvss_vector: full CVSS vector string (empty if unavailable)
        patch_flags: set of active binary feature flag names from the patch

    Returns:
        Adjusted severity int (same encoding).
    """
    if not cvss_vector or cvss_score <= 0:
        return severity

    vec = parse_cvss_vector(cvss_vector)
    cia_hhh = vec.get("C") == "H" and vec.get("I") == "H" and vec.get("A") == "H"
    has_bpf = "bpf" in patch_flags
    has_kpanic = "kernel_panic" in patch_flags

    # R9: MODERATE → IMPORTANT when CVSS is very high
    if severity == 1 and cvss_score >= 8.5:
        severity = 0

    # R10: MODERATE → IMPORTANT when CVSS ≥ 7.5 with full CIA:H/I:H/A:H,
    # unless BPF patch
    if severity == 1 and cvss_score >= 7.5 and cia_hhh and not has_bpf:
        severity = 0

    # R6: LOW → MODERATE when CVSS indicates meaningful severity
    if severity == 2:
        if ((cvss_score >= 6.7) or (cvss_score >= 5.5 and cia_hhh)) and not has_bpf:
            severity = 1

    # R7: MODERATE → LOW when CVSS is very low and no kernel panic concern
    if severity == 1 and cvss_score <= 3.9 and not has_kpanic:
        severity = 2

    # R8: MODERATE → LOW when CVSS is low-moderate with local/low-impact vector
    if severity == 1 and cvss_score < 5.5 and vec.get("AV") == "L" and not cia_hhh:
        c = vec.get("C", "")
        i = vec.get("I", "")
        a = vec.get("A", "")
        if c in ("L", "N") and i in ("L", "N") and a in ("H", "L"):
            severity = 2

    return severity
