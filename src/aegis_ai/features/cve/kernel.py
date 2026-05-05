"""Kernel-specific reconciliation, guardrails, and CVSS overrides.

Extracted from ``SuggestImpact`` to keep kernel logic separate from the
shared suggest-impact orchestration.
"""

from __future__ import annotations

import logging
import math

import cvss

from aegis_ai import get_settings
from aegis_ai.features.cve.impact_mappings import SEVERITY_ORDER, score_to_band

logger = logging.getLogger(__name__)

CONTAINED_SUBSYSTEM_FLAGS = {"bpf", "nvme", "debugfs", "notincludedcomponent"}
MEMORY_CORRUPTION_FLAGS = {
    "uaf",
    "kernel_panic_plus_uaf",
    "danger",
    "write",
    "outofbounds",
    "memory",
}
NETWORK_EXPOSURE_FLAGS = {"remote", "networking", "servertoclientfail"}

RULES_KERNEL = """
                - Output format (must follow exactly):
                    - cvss3_vector: "CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X"
                      where AV in [N,A,L,P], AC in [L,H], PR in [N,L,H], UI in [N,R], S in [U,C], C/I/A in [N,L,H].
                    - cvss3_score: numeric string matching the vector (we will verify and adjust if needed).
                    - impact: Critical/Important/Moderate/Low — set this to match the standard CVSS band from your computed score. Post-processing handles any severity adjustments.
                    - deescalation_rationale: If you believe the impact should be LOWER than the standard CVSS band based on contextual factors (contained subsystem, restricted attack surface, high privilege requirements), note the justification here as advisory input. Leave null when impact matches the standard band.
                    - classifier_disagreement_rationale: If the kernel_impact_tool returned patch signals and your CVSS-based assessment implies a different severity, explain factually why your independent technical assessment differs (attack surface, preconditions, scope). Do not adjust your CVSS metrics to match the classifier. Leave null when you agree or no classifier result was available.
                - Metric selection guide:
                    - AV: N if reachable over network from off-host; A if same subnet/Bluetooth/802.11 link-limited; L if requires local account/session/CLI/local IPC; P if requires physical access.
                    - AC: H if requires uncommon configuration, precise timing/race, multiple conditions, or lengthy preparation; else L.
                    - PR: N if no prior auth; L if basic/local user privileges are enough; H if admin/root/high-privileges are required to trigger.
                    - Linux capabilities: Treat required CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_NET_RAW, CAP_SYS_MODULE, and similar admin-class capabilities as strong evidence for PR:H when the vulnerable operation cannot be triggered without them.
                    - Kernel attack surface: Mounting filesystems (mount(2)), loading filesystem or network driver modules, configuring interfaces or traffic classes, or privileged ioctls usually implies PR:H unless the advisory clearly shows exploitation by an unprivileged user without those capabilities (e.g. unprivileged user namespaces with a specific exposed entry point).
                    - UI: R if victim must click/open/provide content; else N.
                    - S: C only when exploitation changes scope between security authorities (e.g. container/guest escape to host, crossing VM or user-namespace boundary per CVSS definition). Do not choose S:C merely because the kernel is involved or because other processes exist on the system; many local kernel bugs remain S:U.
                    - CIA: Set each based on realistic consequences: use A for availability-only DoS; use C/I when plausible user-visible confidentiality or integrity impact exists. For internal kernel object lifetime/corruption with no direct user data read/write, prefer C:N/I:N or low scores unless a credible path to disclosure or controlled modification of user data is described.
                    - Linux networking internals (tc, qdisc, net_sched, classifiers, queue discipline): flaws confined to internal queue/scheduling/state or buffer accounting for traffic shaping usually do not read or forge application payload data. Prefer C:N and I:N unless the advisory describes a concrete cross-boundary or user-data effect (e.g. leaking packet contents or socket buffers to userspace, forging another user's traffic, container-to-host data leak). Do not set C:H or I:H from generic "memory corruption" or "undefined behavior" alone; if you output C:H or I:H, the explanation must spell out that user-data impact path in one sentence.
                - Consider Red Hat hardening defaults (SELinux enforcing, least privilege) only to inform AC and S, not AV.
                - Retrieve and summarize additional context from vulnerability references:
                    - Use github mcp and web search tools to resolve reference URLs.
                    - Always use kernel_cve tool if the component is the Linux kernel.
                    - If the component is the Linux kernel and kernel_impact_tool is available, you MUST call it; it is inadequate and unacceptable to produce an impact assessment without this tool. You must use the output of kernel_impact_tool to obtain patch-level analysis (active feature flags and severity class probabilities). Treat the returned signals as informative context for your explanation. Produce your own independent CVSS vector and score — do not adjust your metrics to match the classifier's implied severity. Report any disagreement factually in classifier_disagreement_rationale.
                    - If cisa_kev_tool is available, check for known exploits.
                - CVSS accuracy is paramount: keep your CVSS vector metrics technically accurate. Do not inflate C or I beyond what the bug technically enables. If you output C:H or I:H, the explanation must spell out the concrete user-data impact path in one sentence.
                - Confidence:
                    - Calibrate confidence to the fraction of base metrics you are ≥80% sure about (e.g., 0.75 if 6/8 are certain).
                - Explanation must match the vector (mandatory):
                    - Do not write that exploitation requires admin capabilities, mount privileges, or privileged syscalls and output PR:L; use PR:H when those are required to trigger the flaw.
                    - If you revise the narrative and it implies stricter privileges than your draft vector, update PR in the vector before finalizing.
                - Output
                    - Provide the vector and score first, then impact, then a concise explanation with metric-by-metric rationale.
                    - Keep explanations concise.
            """


# ---------------------------------------------------------------------------
# Kernel threshold rules (al-kernel H1-H11)
# ---------------------------------------------------------------------------


def apply_threshold_rules(
    severity: int,
    llm_cvss: float,
    llm_vector: dict,
    active_features: set[str],
    has_contained: bool,
) -> tuple[int, list[str], bool]:
    """Apply al-kernel threshold rules H1-H11.

    Returns (severity, rules_applied, h1_fired).

    Rule reference: see al-kernel-spec.md Phase 4 for daemon
    originals.  Rules H12-H14 are deferred (require CWE extraction
    and manual-check signal not yet in SuggestImpactModel).
    """
    IMP, MOD, LOW = (
        SEVERITY_ORDER["IMPORTANT"],
        SEVERITY_ORDER["MODERATE"],
        SEVERITY_ORDER["LOW"],
    )

    if math.isnan(llm_cvss):
        return severity, ["no_llm_cvss"], False

    cia_hhh = (
        llm_vector.get("C") == "H"
        and llm_vector.get("I") == "H"
        and llm_vector.get("A") == "H"
    )
    av_local = llm_vector.get("AV") == "L"
    pr_h_only = llm_vector.get("PR") == "H"

    rules_applied: list[str] = []
    kpanic_marked = False
    decreased = False  # noqa: F841 — gates H14 (deferred, not yet ported)
    h1_fired = False

    # H1: IMPORTANT -> MODERATE when LLM CVSS < 6.5
    if severity == IMP and llm_cvss < 6.5:
        severity = MOD
        h1_fired = True
        rules_applied.append("H1:IMP->MOD(cvss<6.5)")

    # H2: MODERATE -> IMPORTANT when LLM CVSS very high
    if severity == MOD and (
        llm_cvss >= 8.5 or (llm_cvss >= 7.5 and cia_hhh and not has_contained)
    ):
        severity = IMP
        rules_applied.append("H2:MOD->IMP(cvss>=8.5|7.5+HHH)")

    # H3: annotation — mark kpanic for moderate-range CVSS (blocks H7)
    if severity == MOD and (
        llm_cvss >= 7.5
        or (llm_cvss >= 6.5 and cia_hhh and not kpanic_marked and not has_contained)
    ):
        kpanic_marked = True
        rules_applied.append("H3:kpanic_set")

    # H4: annotation — block H7 for moderate-range CVSS without
    # local NULL-ptr pattern (approximates daemon CWE-476 gating)
    is_local_nullptr = "nullptr" in active_features and llm_vector.get("AV") not in (
        "N",
        "A",
    )
    if (
        severity == MOD
        and llm_cvss >= 6.0
        and not kpanic_marked
        and not is_local_nullptr
    ):
        kpanic_marked = True
        rules_applied.append("H4:kpanic_set")

    # H5: LOW or MODERATE -> IMPORTANT when LLM CVSS > 8.5
    if severity in (MOD, LOW) and llm_cvss > 8.5:
        severity = IMP
        rules_applied.append("H5:LOW/MOD->IMP(cvss>8.5)")

    # H6: LOW -> MODERATE when LLM CVSS indicates meaningful severity
    if severity == LOW and (
        (llm_cvss >= 6.7 or (llm_cvss >= 5.5 and cia_hhh)) and not has_contained
    ):
        severity = MOD
        rules_applied.append("H6:LOW->MOD(cvss>=6.7|5.5+HHH)")

    # H7: MODERATE -> LOW when LLM CVSS very low, no kernel_panic,
    # and kpanic not marked by H3/H4
    if (
        severity == MOD
        and llm_cvss <= 3.9
        and "kernel_panic" not in active_features
        and not kpanic_marked
    ):
        severity = LOW
        rules_applied.append("H7:MOD->LOW(cvss<=3.9)")

    # H8: MODERATE -> LOW for local/low-impact vectors (blocked by KPANIC)
    if (
        severity == MOD
        and llm_cvss < 5.5
        and av_local
        and not cia_hhh
        and "kernel_panic" not in active_features
        and not kpanic_marked
    ):
        c_val = llm_vector.get("C", "")
        i_val = llm_vector.get("I", "")
        a_val = llm_vector.get("A", "")
        if c_val in ("L", "N") and i_val in ("L", "N") and a_val in ("H", "L"):
            severity = LOW
            rules_applied.append("H8:MOD->LOW(cvss<5.5+local+low)")

    # H9: annotation — unblock H7 path, block H14 (future) for low CVSS
    if severity == MOD and llm_cvss <= 4.5:
        kpanic_marked = False  # noqa: F841
        decreased = True  # noqa: F841
        rules_applied.append("H9:decreased_set")

    # H10: annotation — same for local/low-impact vectors
    c_val = llm_vector.get("C", "")
    i_val = llm_vector.get("I", "")
    a_val = llm_vector.get("A", "")
    if (
        severity == MOD
        and llm_cvss <= 5.5
        and av_local
        and c_val in ("L", "N")
        and i_val in ("L", "N")
        and a_val in ("H", "L")
        and not cia_hhh
    ):
        kpanic_marked = False  # noqa: F841
        decreased = True  # noqa: F841
        rules_applied.append("H10:decreased_set")

    # H11: IMPORTANT -> MODERATE when PR:H with moderate CVSS
    if severity == IMP and llm_cvss < 8.0 and pr_h_only:
        severity = MOD
        rules_applied.append("H11:IMP->MOD(cvss<8.0+PR:H)")

    return severity, rules_applied, h1_fired


# ---------------------------------------------------------------------------
# Post-threshold guardrails (G1-G4)
# ---------------------------------------------------------------------------


def apply_guardrails(
    severity: int,
    llm_cvss: float,
    clf_cvss_score: float,
    clf_cvss_issuer: str,
    h1_fired: bool,
    has_corruption: bool,
    has_network: bool,
    has_contained: bool,
) -> tuple[int, list[str], str | None]:
    """Apply post-threshold guardrails G1-G4.

    Returns (severity, guardrails_applied, ext_band).
    """
    LABELS = {v: k for k, v in SEVERITY_ORDER.items()}
    IMP, MOD = SEVERITY_ORDER["IMPORTANT"], SEVERITY_ORDER["MODERATE"]

    guardrails_applied: list[str] = []

    # G1: LLM band floor for LOW severity.
    if severity == SEVERITY_ORDER["LOW"]:
        llm_band = score_to_band(llm_cvss)
        if llm_band and llm_band in SEVERITY_ORDER:
            band_rank = SEVERITY_ORDER[llm_band]
            if has_contained:
                band_rank = max(band_rank, MOD)
            if severity > band_rank:
                severity = band_rank
                guardrails_applied.append(f"G1: llm_band_floor({LABELS[band_rank]})")

    # G2: memory corruption floor
    if has_corruption and severity > MOD:
        severity = MOD
        guardrails_applied.append("G2: memory_corruption_floor(MODERATE)")

    # G3: network + corruption floor
    if has_corruption and has_network and severity > IMP:
        severity = IMP
        guardrails_applied.append("G3: network_corruption_floor(IMPORTANT)")

    # G4: external CVSS confirmation for H1 de-escalation.
    ext_band = score_to_band(clf_cvss_score) if clf_cvss_score else None
    if (
        not math.isnan(llm_cvss)
        and h1_fired
        and severity == MOD
        and clf_cvss_issuer != "RH"
        and ext_band
        and ext_band in SEVERITY_ORDER
        and SEVERITY_ORDER[ext_band] < MOD
    ):
        severity = IMP
        guardrails_applied.append(f"ext_cvss_confirms_imp({clf_cvss_score:.1f})")

    return severity, guardrails_applied, ext_band


# ---------------------------------------------------------------------------
# Trace assembly
# ---------------------------------------------------------------------------


def build_trace(
    start_label: str,
    clf_confidence: float,
    llm_cvss: float,
    clf_cvss_score: float,
    clf_cvss_issuer: str,
    ext_band: str | None,
    rules_applied: list[str],
    guardrails_applied: list[str],
    final: str,
) -> str:
    """Assemble the reconciliation trace string."""
    parts = [
        "path=kernel_threshold",
        f"start={start_label}(clf_conf={clf_confidence:.2f})",
        f"llm_cvss={llm_cvss:.1f}",
    ]
    if ext_band:
        issuer_tag = f",{clf_cvss_issuer}" if clf_cvss_issuer else ""
        parts.append(f"ext_cvss={clf_cvss_score:.1f}({ext_band}{issuer_tag})")
    if rules_applied:
        parts.append(f"rules=[{', '.join(rules_applied)}]")
    if guardrails_applied:
        parts.append(f"guardrails=[{', '.join(guardrails_applied)}]")
    parts.append(f"result={final}")
    return "; ".join(parts)


# ---------------------------------------------------------------------------
# Kernel reconciliation orchestrator
# ---------------------------------------------------------------------------


def reconcile_kernel(output, call_str: str, classifier_result: dict) -> str:
    """Threshold-based reconciliation for kernel CVEs (al-kernel port).

    The classifier's cascade-adjusted prediction is the starting
    severity.  The LLM's own CVSS score drives bidirectional
    adjustments through deterministic threshold rules (H1-H11).
    Classifier confidence is logged but does not affect the outcome.
    """
    from aegis_ai.kernel_classifier.cascade import parse_cvss_vector

    LABELS = {v: k for k, v in SEVERITY_ORDER.items()}
    MOD = SEVERITY_ORDER["MODERATE"]

    try:
        llm_cvss = float(output.cvss3_score)
    except (ValueError, TypeError):
        llm_cvss = float("nan")

    llm_vector = parse_cvss_vector(output.cvss3_vector or "")

    clf_impact = classifier_result.get("impact")
    clf_confidence = classifier_result.get("confidence", 0.0) or 0.0
    clf_cvss_score = classifier_result.get("cvss_score", 0.0) or 0.0
    clf_cvss_issuer = classifier_result.get("cvss_issuer", "") or ""
    active_features: set[str] = set(classifier_result.get("active_features", []))

    severity = (
        SEVERITY_ORDER[clf_impact]
        if clf_impact and clf_impact in SEVERITY_ORDER
        else MOD
    )
    start_label = LABELS.get(severity, clf_impact)

    has_contained = bool(active_features & CONTAINED_SUBSYSTEM_FLAGS)
    has_corruption = bool(active_features & MEMORY_CORRUPTION_FLAGS)
    has_network = bool(active_features & NETWORK_EXPOSURE_FLAGS)

    severity, rules_applied, h1_fired = apply_threshold_rules(
        severity, llm_cvss, llm_vector, active_features, has_contained
    )

    severity, guardrails_applied, ext_band = apply_guardrails(
        severity,
        llm_cvss,
        clf_cvss_score,
        clf_cvss_issuer,
        h1_fired,
        has_corruption,
        has_network,
        has_contained,
    )

    final = LABELS.get(severity, clf_impact)

    trace = build_trace(
        start_label,
        clf_confidence,
        llm_cvss,
        clf_cvss_score,
        clf_cvss_issuer,
        ext_band,
        rules_applied,
        guardrails_applied,
        final,
    )

    if final != output.impact:
        logger.info(
            "%s: reconciled %s -> %s (%s)",
            call_str,
            output.impact,
            final,
            trace,
        )
    else:
        logger.info(
            "%s: reconciliation confirmed %s (%s)",
            call_str,
            final,
            trace,
        )

    output.impact = final
    return trace


# ---------------------------------------------------------------------------
# CVSS override for kernel panic / IMPORTANT impact
# ---------------------------------------------------------------------------

_CVSS_BASE_KEYS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def apply_kpanic_cvss_override(
    output, call_str: str, classifier_result: dict | None
) -> str | None:
    """Override CVSS components when kernel_panic is detected or impact
    is IMPORTANT.

    Forces ``AC:H``, ``S:U``, ``A:H`` to reflect kernel-panic
    reachability without assuming user-data exposure.  All other
    metrics (``C``, ``I``, ``PR``, ``AV``, ``UI``) are preserved
    from the LLM's assessment — the prompt already requires a
    concrete user-data impact path for ``C:H``/``I:H`` and uses
    ``PR:H`` when admin-class capabilities are needed.

    Returns a trace fragment when the override fires, or ``None``.
    """
    if not classifier_result or not isinstance(classifier_result, dict):
        return None

    active_features: set[str] = set(classifier_result.get("active_features", []))
    has_kpanic = "kernel_panic" in active_features
    is_important = output.impact == "IMPORTANT"

    if output.impact == "CRITICAL":
        return None

    if not (has_kpanic or is_important):
        return None

    original_vector = output.cvss3_vector or ""
    original_score = output.cvss3_score

    parsed = cvss.CVSS3(original_vector)
    parsed.metrics.update({"AC": "H", "S": "U", "A": "H"})
    output.cvss3_vector = "CVSS:3.1/" + "/".join(
        f"{k}:{parsed.metrics[k]}" for k in _CVSS_BASE_KEYS
    )
    output.cvss3_score = str(cvss.CVSS3(output.cvss3_vector).scores()[0])

    reason = "kernel_panic" if has_kpanic else "important_impact"
    trace = (
        f"kpanic_cvss_override({reason},"
        f" llm_vector={original_vector},"
        f" llm_score={original_score})"
    )
    logger.info(
        "%s: CVSS overridden to %s (%s) — %s",
        call_str,
        output.cvss3_score,
        output.cvss3_vector,
        trace,
    )
    return trace


# ---------------------------------------------------------------------------
# Output check (retry enforcement)
# ---------------------------------------------------------------------------


def check_kernel_output(output, deps) -> str | None:
    """Return a retry message if kernel_impact_tool was not called for a
    kernel CVE, or ``None`` to accept the output."""
    use_clf = get_settings().use_kernel_classifier
    is_kernel = getattr(deps, "is_kernel_cve", False)
    tool_called = getattr(deps, "kernel_tool_called", False)
    clf_result = getattr(deps, "classifier_result", None)

    if use_clf and is_kernel and hasattr(output, "cvss3_vector"):
        if not tool_called:
            logger.warning(
                "kernel_impact_tool was not called for a kernel CVE; requesting retry"
            )
            return (
                "This is a Linux kernel CVE. You MUST call kernel_impact_tool "
                "to obtain patch-level analysis before producing your final answer."
            )
        if tool_called and clf_result is None:
            logger.warning(
                "kernel_impact_tool was called but returned no classifier data for this CVE"
            )
    return None
