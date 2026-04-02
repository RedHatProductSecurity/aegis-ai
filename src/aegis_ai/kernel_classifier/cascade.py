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

Rule ordering
~~~~~~~~~~~~~
R6 runs *before* R9/R10 so that a LOW prediction promoted to MODERATE by
CVSS data can then be further escalated to IMPORTANT by the CVSS-threshold
rules.  Without this ordering, LOW → MODERATE → IMPORTANT is impossible in
a single pass (the al-kernel daemon applies rules in this same order).

Promotion rules (LOW → MODERATE):
  R6  LOW  → MODERATE  if CVSS ≥ 6.7 (or ≥ 5.5 with C:H/I:H/A:H), !BPF

Escalation rules (MODERATE → IMPORTANT):
  R9   MODERATE → IMPORTANT  if CVSS ≥ 8.5
  R10  MODERATE → IMPORTANT  if CVSS ≥ 7.5 with C:H/I:H/A:H, !BPF
  R11  MODERATE → IMPORTANT  if kernel_panic_plus_uaf flag (memory corruption crash)
  R12  MODERATE → IMPORTANT  if kernel_panic + network-facing path

De-escalation rules (MODERATE → LOW):
  R7  MODERATE → LOW   if CVSS ≤ 3.9, !KPANIC
  R8  MODERATE → LOW   if CVSS < 5.5, AV:L, low CIA impact, !C:H/I:H/A:H

All rules gracefully degrade to no-ops when CVSS data is unavailable.
R11/R12 are feature-only rules that fire regardless of CVSS availability.
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
    """Apply daemon-derived severity adjustment rules (R6–R12).

    Args:
        severity: XGBoost prediction (0=IMPORTANT, 1=MODERATE, 2=LOW)
        cvss_score: NIST CVSS v3.1 base score (0.0 if unavailable)
        cvss_vector: full CVSS vector string (empty if unavailable)
        patch_flags: set of active binary feature flag names from the patch

    Returns:
        Adjusted severity int (same encoding).
    """
    has_bpf = "bpf" in patch_flags
    has_kpanic = "kernel_panic" in patch_flags

    has_cvss = bool(cvss_vector) and cvss_score > 0
    if has_cvss:
        vec = parse_cvss_vector(cvss_vector)
        cia_hhh = vec.get("C") == "H" and vec.get("I") == "H" and vec.get("A") == "H"
    else:
        vec = {}
        cia_hhh = False

    # --- Promotion: LOW → MODERATE (run first so escalation rules see it) ---

    # R6: LOW → MODERATE when CVSS indicates meaningful severity
    if has_cvss and severity == 2:
        if ((cvss_score >= 6.7) or (cvss_score >= 5.5 and cia_hhh)) and not has_bpf:
            severity = 1

    # --- Escalation: MODERATE → IMPORTANT ---

    # R9: MODERATE → IMPORTANT when CVSS is very high
    if has_cvss and severity == 1 and cvss_score >= 8.5:
        severity = 0

    # R10: MODERATE → IMPORTANT when CVSS ≥ 7.5 with full C:H/I:H/A:H
    if has_cvss and severity == 1 and cvss_score >= 7.5 and cia_hhh and not has_bpf:
        severity = 0

    # R11: MODERATE → IMPORTANT when patch shows kernel panic + UAF corruption
    if severity == 1 and "kernel_panic_plus_uaf" in patch_flags:
        severity = 0

    # R12: MODERATE → IMPORTANT when kernel crash is reachable via network path
    if severity == 1 and has_kpanic:
        if "servertoclientfail" in patch_flags or (
            "remote" in patch_flags and "danger" in patch_flags
        ):
            severity = 0

    # --- De-escalation: MODERATE → LOW ---

    # R7: MODERATE → LOW when CVSS is very low and no kernel panic concern
    if has_cvss and severity == 1 and cvss_score <= 3.9 and not has_kpanic:
        severity = 2

    # R8: MODERATE → LOW when CVSS is low-moderate with local/low-impact vector
    if has_cvss and severity == 1 and cvss_score < 5.5:
        if vec.get("AV") == "L" and not cia_hhh:
            c = vec.get("C", "")
            i = vec.get("I", "")
            a = vec.get("A", "")
            if c in ("L", "N") and i in ("L", "N") and a in ("H", "L"):
                severity = 2

    return severity
