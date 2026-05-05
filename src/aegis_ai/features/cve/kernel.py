"""Kernel-specific reconciliation, guardrails, and CVSS overrides.

This module implements the al-kernel severity reconciliation pipeline for
kernel CVEs.  The pipeline runs in two phases:

1. **Threshold rules** (H1-H11) — bidirectional adjustments that move
   severity up or down based on the LLM's CVSS score and vector metrics.
2. **Guardrails** (G1-G4) — safety-net floors and confirmations applied
   after the threshold rules.

Both phases use a declarative rule architecture:

- Each rule is a **pure function** that reads a :class:`RuleContext` and
  returns an immutable :class:`RuleEffect` payload (or ``None``).
- A single :func:`apply_effect` mutator applies the payload to the context.
- :func:`run_rules` iterates an ordered rule list, feeding effects through
  the mutator and collecting trace labels.

Rules H12-H14 from the upstream al-kernel spec are deferred; they require
CWE extraction and a manual-check signal not yet present in
``SuggestImpactModel``.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Callable
from dataclasses import dataclass, field

import cvss

from aegis_ai import get_settings
from aegis_ai.features.cve.impact_mappings import SEVERITY_ORDER, score_to_band

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Feature-flag sets used to detect kernel patch characteristics.
# These are derived from the XGBoost classifier's active_features output.
# ---------------------------------------------------------------------------

# Subsystems considered "contained" — bugs confined here are less likely to
# affect the broader kernel attack surface, so escalation is suppressed.
CONTAINED_SUBSYSTEM_FLAGS = {"bpf", "nvme", "debugfs", "notincludedcomponent"}

# Flags indicating memory-corruption potential (UAF, OOB write, etc.).
# Presence gates guardrail G2 (MODERATE floor) and G3 (IMPORTANT floor
# when combined with network exposure).
MEMORY_CORRUPTION_FLAGS = {
    "uaf",
    "kernel_panic_plus_uaf",
    "danger",
    "write",
    "outofbounds",
    "memory",
}

# Flags indicating network-reachable attack surface.  Combined with
# memory-corruption flags to trigger guardrail G3.
NETWORK_EXPOSURE_FLAGS = {"remote", "networking", "servertoclientfail"}

# ---------------------------------------------------------------------------
# LLM prompt rules injected when the CVE is a kernel component.
# ---------------------------------------------------------------------------

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
# Severity rank shortcuts (lower numeric rank = more severe).
# ---------------------------------------------------------------------------

IMP = SEVERITY_ORDER["IMPORTANT"]  # 1
MOD = SEVERITY_ORDER["MODERATE"]  # 2
LOW = SEVERITY_ORDER["LOW"]  # 3


# ===========================================================================
# Rule engine data model
# ===========================================================================


@dataclass
class RuleContext:
    """Immutable-ish bag of signals read by every rule function.

    Built once per reconciliation pass in :func:`reconcile_kernel` from
    the classifier result and the LLM's CVSS output.  Rule functions read
    fields but never mutate them directly — mutations are described in a
    :class:`RuleEffect` and applied by :func:`apply_effect`.

    Attributes that *are* mutated (``severity``, ``kpanic_marked``,
    ``h1_fired``, ``decreased``, ``ext_band``) are written exclusively
    by :func:`apply_effect`.
    """

    # --- Classifier / LLM signals (set once, read-only thereafter) ---

    #: Current severity rank (mutated only by ``apply_effect``).
    severity: int
    #: CVSS base score parsed from the LLM's ``cvss3_score`` output.
    llm_cvss: float
    #: Parsed CVSS vector dict (keys like ``"AV"``, ``"C"``, etc.).
    llm_vector: dict
    #: Set of active feature flags from the XGBoost classifier.
    active_features: set[str]
    #: True when any flag in ``CONTAINED_SUBSYSTEM_FLAGS`` is active.
    has_contained: bool
    #: True when any flag in ``MEMORY_CORRUPTION_FLAGS`` is active.
    has_corruption: bool
    #: True when any flag in ``NETWORK_EXPOSURE_FLAGS`` is active.
    has_network: bool

    # --- Pre-computed vector properties ---

    #: True when the LLM's vector has C:H, I:H, and A:H simultaneously.
    cia_hhh: bool
    #: True when ``AV == "L"`` (local attack vector).
    av_local: bool
    #: True when ``PR == "H"`` (high privileges required).
    pr_h_only: bool

    # --- External CVSS (for guardrail G4) ---

    #: Numeric CVSS score from an external source (NVD, NIST, etc.).
    clf_cvss_score: float = 0.0
    #: Issuer tag for the external score (``"NIST"``, ``"RH"``, etc.).
    clf_cvss_issuer: str = ""
    #: Classifier confidence (logged, does not affect outcome).
    clf_confidence: float = 0.0

    # --- Mutable flags (written only by ``apply_effect``) ---

    #: Set by H3/H4 to block de-escalation in H7/H8; reset by H9/H10.
    kpanic_marked: bool = False
    #: Set by H9/H10; gates future rule H14 (deferred).
    decreased: bool = False
    #: Set by H1; read by guardrail G4 to reverse the de-escalation.
    h1_fired: bool = False
    #: External CVSS band computed by G4; consumed by ``build_trace``.
    ext_band: str | None = None


@dataclass(frozen=True)
class RuleEffect:
    """Immutable payload returned by a pure rule function.

    Describes the mutations that should be applied to a
    :class:`RuleContext` when the rule fires.  The rule function itself
    never touches the context — :func:`apply_effect` reads the effect
    and performs all writes.

    A rule that does not fire returns ``None`` instead of a
    ``RuleEffect``.
    """

    #: New severity rank, or ``None`` to leave severity unchanged
    #: (used by annotation-only rules like H3/H4/H9/H10).
    severity: int | None = None
    #: Human-readable label appended to the reconciliation trace log.
    trace: str = ""
    #: Flag mutations to apply (e.g. ``{"h1_fired": True}``).
    #: Keys must match ``RuleContext`` attribute names.
    flags: dict[str, bool | str | None] = field(default_factory=dict)


# ===========================================================================
# Engine: mutator + runner
# ===========================================================================


def apply_effect(ctx: RuleContext, effect: RuleEffect) -> None:
    """Apply a :class:`RuleEffect` payload to a :class:`RuleContext`.

    This is the **only** function that mutates ``ctx``.  Centralising
    all writes here keeps rule functions pure and makes the mutation
    surface auditable in one place.
    """
    if effect.severity is not None:
        ctx.severity = effect.severity
    for flag, value in effect.flags.items():
        setattr(ctx, flag, value)


def run_rules(
    ctx: RuleContext,
    rules: list[Callable[[RuleContext], RuleEffect | None]],
) -> list[str]:
    """Execute an ordered list of rule functions against *ctx*.

    For each rule that returns a non-``None`` :class:`RuleEffect`, the
    effect is applied to *ctx* via :func:`apply_effect` and the trace
    label is collected.

    Returns the list of trace labels from rules that fired.
    """
    traces: list[str] = []
    for rule in rules:
        effect = rule(ctx)
        if effect is not None:
            apply_effect(ctx, effect)
            traces.append(effect.trace)
    return traces


# ===========================================================================
# Threshold rules H1-H11 (al-kernel Phase 4 port)
#
# Each function is a pure predicate: it reads ``ctx`` and returns a
# ``RuleEffect`` describing the state change, or ``None`` to skip.
# ===========================================================================


def h1(ctx: RuleContext) -> RuleEffect | None:
    """H1: IMPORTANT -> MODERATE when the LLM's CVSS score is below 6.5.

    When the classifier rates IMPORTANT but the LLM's own score is in
    the moderate range, de-escalate.  Sets ``h1_fired`` so guardrail G4
    can reverse this if an independent external CVSS confirms IMPORTANT.
    """
    if ctx.severity != IMP or ctx.llm_cvss >= 6.5:
        return None
    return RuleEffect(
        severity=MOD,
        trace="H1:IMP->MOD(cvss<6.5)",
        flags={"h1_fired": True},
    )


def h2(ctx: RuleContext) -> RuleEffect | None:
    """H2: MODERATE -> IMPORTANT when the LLM CVSS is very high.

    Fires when CVSS >= 8.5 unconditionally, or >= 7.5 with C:H/I:H/A:H
    and no contained-subsystem suppression.
    """
    if ctx.severity != MOD:
        return None
    if ctx.llm_cvss >= 8.5 or (
        ctx.llm_cvss >= 7.5 and ctx.cia_hhh and not ctx.has_contained
    ):
        return RuleEffect(severity=IMP, trace="H2:MOD->IMP(cvss>=8.5|7.5+HHH)")
    return None


def h3(ctx: RuleContext) -> RuleEffect | None:
    """H3: Annotation — set ``kpanic_marked`` for moderate-range high CVSS.

    Does not change severity.  Blocks later de-escalation rules H7/H8
    from dropping to LOW when the CVSS is in a borderline range that
    suggests meaningful impact.
    """
    if ctx.severity != MOD:
        return None
    if ctx.llm_cvss >= 7.5 or (
        ctx.llm_cvss >= 6.5
        and ctx.cia_hhh
        and not ctx.kpanic_marked
        and not ctx.has_contained
    ):
        return RuleEffect(trace="H3:kpanic_set", flags={"kpanic_marked": True})
    return None


def h4(ctx: RuleContext) -> RuleEffect | None:
    """H4: Annotation — block H7 for moderate-range CVSS without local NULL-ptr.

    Approximates the upstream daemon's CWE-476 gating: if the CVSS is
    >= 6.0, ``kpanic_marked`` is not yet set, and this is not a local
    null-pointer dereference, mark kpanic to prevent unwarranted
    de-escalation.
    """
    if ctx.severity != MOD or ctx.kpanic_marked:
        return None
    # Local NULL-ptr pattern: nullptr flag + non-remote vector
    is_local_nullptr = "nullptr" in ctx.active_features and ctx.llm_vector.get(
        "AV"
    ) not in ("N", "A")
    if ctx.llm_cvss >= 6.0 and not is_local_nullptr:
        return RuleEffect(trace="H4:kpanic_set", flags={"kpanic_marked": True})
    return None


def h5(ctx: RuleContext) -> RuleEffect | None:
    """H5: LOW or MODERATE -> IMPORTANT when LLM CVSS exceeds 8.5.

    Hard escalation for very high CVSS regardless of classifier output.
    """
    if ctx.severity in (MOD, LOW) and ctx.llm_cvss > 8.5:
        return RuleEffect(severity=IMP, trace="H5:LOW/MOD->IMP(cvss>8.5)")
    return None


def h6(ctx: RuleContext) -> RuleEffect | None:
    """H6: LOW -> MODERATE when LLM CVSS indicates meaningful severity.

    Promotes LOW when CVSS >= 6.7, or >= 5.5 with C:H/I:H/A:H, unless
    the subsystem is contained.
    """
    if ctx.severity != LOW:
        return None
    if (
        ctx.llm_cvss >= 6.7 or (ctx.llm_cvss >= 5.5 and ctx.cia_hhh)
    ) and not ctx.has_contained:
        return RuleEffect(severity=MOD, trace="H6:LOW->MOD(cvss>=6.7|5.5+HHH)")
    return None


def h7(ctx: RuleContext) -> RuleEffect | None:
    """H7: MODERATE -> LOW when LLM CVSS is very low and no panic signal.

    Only fires when ``kpanic_marked`` is False (i.e. H3/H4 did not
    block) and the ``kernel_panic`` feature flag is absent.
    """
    if (
        ctx.severity == MOD
        and ctx.llm_cvss <= 3.9
        and "kernel_panic" not in ctx.active_features
        and not ctx.kpanic_marked
    ):
        return RuleEffect(severity=LOW, trace="H7:MOD->LOW(cvss<=3.9)")
    return None


def h8(ctx: RuleContext) -> RuleEffect | None:
    """H8: MODERATE -> LOW for local, low-impact vectors.

    Fires when CVSS < 5.5, attack is local (AV:L), CIA is not all-High,
    and the individual C/I/A values are Low or None.  Blocked by
    ``kernel_panic`` feature or ``kpanic_marked`` annotation.
    """
    if (
        ctx.severity != MOD
        or ctx.llm_cvss >= 5.5
        or not ctx.av_local
        or ctx.cia_hhh
        or "kernel_panic" in ctx.active_features
        or ctx.kpanic_marked
    ):
        return None
    c = ctx.llm_vector.get("C", "")
    i = ctx.llm_vector.get("I", "")
    a = ctx.llm_vector.get("A", "")
    if c in ("L", "N") and i in ("L", "N") and a in ("H", "L"):
        return RuleEffect(severity=LOW, trace="H8:MOD->LOW(cvss<5.5+local+low)")
    return None


def h9(ctx: RuleContext) -> RuleEffect | None:
    """H9: Annotation — unblock the H7 path for low CVSS.

    Resets ``kpanic_marked`` and sets ``decreased`` (gates future
    rule H14, currently deferred).  Does not change severity.
    """
    if ctx.severity == MOD and ctx.llm_cvss <= 4.5:
        return RuleEffect(
            trace="H9:decreased_set",
            flags={"kpanic_marked": False, "decreased": True},
        )
    return None


def h10(ctx: RuleContext) -> RuleEffect | None:
    """H10: Annotation — same as H9 for local, low-impact vectors.

    Resets ``kpanic_marked`` and sets ``decreased`` when the vector is
    local with low individual CIA values and CVSS <= 5.5.
    """
    if ctx.severity != MOD or ctx.llm_cvss > 5.5 or not ctx.av_local or ctx.cia_hhh:
        return None
    c = ctx.llm_vector.get("C", "")
    i = ctx.llm_vector.get("I", "")
    a = ctx.llm_vector.get("A", "")
    if c in ("L", "N") and i in ("L", "N") and a in ("H", "L"):
        return RuleEffect(
            trace="H10:decreased_set",
            flags={"kpanic_marked": False, "decreased": True},
        )
    return None


def h11(ctx: RuleContext) -> RuleEffect | None:
    """H11: IMPORTANT -> MODERATE when PR:H with moderate CVSS.

    When admin-class privileges are required (PR:H) and the CVSS is
    below 8.0, the effective risk is lower than IMPORTANT.
    """
    if ctx.severity == IMP and ctx.llm_cvss < 8.0 and ctx.pr_h_only:
        return RuleEffect(severity=MOD, trace="H11:IMP->MOD(cvss<8.0+PR:H)")
    return None


# ===========================================================================
# Guardrail rules G1-G4
#
# Post-threshold safety nets that enforce severity floors and cross-check
# against external signals.
# ===========================================================================

# Reverse lookup: severity rank -> label (e.g. 2 -> "MODERATE").
IMPACT_LABELS = {v: k for k, v in SEVERITY_ORDER.items()}


def g1(ctx: RuleContext) -> RuleEffect | None:
    """G1: LLM band floor — prevent LOW from dropping below the LLM's own band.

    Al-kernel's thresholds assume the classifier starting point is close
    to the final answer, so small CVSS-based adjustments work.  Aegis's
    XGBoost cascade can diverge from the LLM by 2+ levels, causing
    H1+H8 chains that push severity to LOW even when the LLM's own CVSS
    says MODERATE.  This guardrail prevents that.

    For contained subsystems the promotion caps at MODERATE (containment
    still suppresses escalation above that).
    """
    if ctx.severity != LOW:
        return None
    llm_band = score_to_band(ctx.llm_cvss)
    if not llm_band or llm_band not in SEVERITY_ORDER:
        return None
    band_rank = SEVERITY_ORDER[llm_band]
    if ctx.has_contained:
        band_rank = max(band_rank, MOD)
    if ctx.severity > band_rank:
        return RuleEffect(
            severity=band_rank,
            trace=f"G1: llm_band_floor({IMPACT_LABELS[band_rank]})",
        )
    return None


def g2(ctx: RuleContext) -> RuleEffect | None:
    """G2: Memory-corruption floor — severity cannot drop below MODERATE.

    When memory-corruption flags are active, the bug has at least
    moderate exploitability regardless of the CVSS score.
    """
    if ctx.has_corruption and ctx.severity > MOD:
        return RuleEffect(severity=MOD, trace="G2: memory_corruption_floor(MODERATE)")
    return None


def g3(ctx: RuleContext) -> RuleEffect | None:
    """G3: Network + corruption floor — severity cannot drop below IMPORTANT.

    Memory corruption reachable over the network is high-risk; enforce
    an IMPORTANT floor.
    """
    if ctx.has_corruption and ctx.has_network and ctx.severity > IMP:
        return RuleEffect(severity=IMP, trace="G3: network_corruption_floor(IMPORTANT)")
    return None


def g4(ctx: RuleContext) -> RuleEffect | None:
    """G4: External CVSS confirmation — reverse H1 when NVD agrees on IMPORTANT.

    When H1 fired (de-escalated IMP -> MOD) and an independent external
    CVSS score confirms IMPORTANT, two stable signals (classifier + NVD)
    outweigh the LLM's lower score.  RH-issued scores are excluded to
    avoid circular confirmation (they may originate from a prior Aegis run).

    Note: ``ctx.ext_band`` is pre-computed by :func:`apply_guardrails`
    before the rule pipeline runs.
    """
    if (
        not math.isnan(ctx.llm_cvss)
        and ctx.h1_fired
        and ctx.severity == MOD
        and ctx.clf_cvss_issuer != "RH"
        and ctx.ext_band
        and ctx.ext_band in SEVERITY_ORDER
        and SEVERITY_ORDER[ctx.ext_band] < MOD
    ):
        return RuleEffect(
            severity=IMP,
            trace=f"ext_cvss_confirms_imp({ctx.clf_cvss_score:.1f})",
        )
    return None


# ===========================================================================
# Rule pipeline manifests
#
# Execution order matters: rules are evaluated top-to-bottom.  Annotation
# rules (H3, H4, H9, H10) set flags that gate later transition rules.
# ===========================================================================

#: Threshold rules applied in order during Phase 1 of reconciliation.
THRESHOLD_RULES: list[Callable[[RuleContext], RuleEffect | None]] = [
    h1,
    h2,
    h3,
    h4,
    h5,
    h6,
    h7,
    h8,
    h9,
    h10,
    h11,
]

#: Guardrail rules applied in order during Phase 2 of reconciliation.
GUARDRAIL_RULES: list[Callable[[RuleContext], RuleEffect | None]] = [
    g1,
    g2,
    g3,
    g4,
]


# ===========================================================================
# Pipeline entry points
# ===========================================================================


def apply_threshold_rules(ctx: RuleContext) -> list[str]:
    """Run all threshold rules (H1-H11) against *ctx*.

    Short-circuits with a ``["no_llm_cvss"]`` trace when the LLM score
    is NaN (unparseable), preserving the classifier's original severity.
    """
    if math.isnan(ctx.llm_cvss):
        return ["no_llm_cvss"]
    return run_rules(ctx, THRESHOLD_RULES)


def apply_guardrails(ctx: RuleContext) -> list[str]:
    """Run all guardrail rules (G1-G4) against *ctx*.

    Pre-computes ``ctx.ext_band`` from the external CVSS score so that
    G4 and ``build_trace`` can read it without side-effects in the rule
    functions themselves.

    Returns the list of trace labels from guardrails that fired.
    """
    ctx.ext_band = score_to_band(ctx.clf_cvss_score) if ctx.clf_cvss_score else None
    return run_rules(ctx, GUARDRAIL_RULES)


# ===========================================================================
# Trace assembly
# ===========================================================================


def build_trace(
    ctx: RuleContext,
    start_label: str,
    rules_applied: list[str],
    guardrails_applied: list[str],
    final: str,
) -> str:
    """Assemble the reconciliation trace string from *ctx* and rule results.

    The trace is a semicolon-separated sequence of key=value pairs logged
    alongside the reconciliation outcome for diagnostics and debugging.
    """
    parts = [
        "path=kernel_threshold",
        f"start={start_label}(clf_conf={ctx.clf_confidence:.2f})",
        f"llm_cvss={ctx.llm_cvss:.1f}",
    ]
    if ctx.ext_band:
        issuer_tag = f",{ctx.clf_cvss_issuer}" if ctx.clf_cvss_issuer else ""
        parts.append(f"ext_cvss={ctx.clf_cvss_score:.1f}({ctx.ext_band}{issuer_tag})")
    if rules_applied:
        parts.append(f"rules=[{', '.join(rules_applied)}]")
    if guardrails_applied:
        parts.append(f"guardrails=[{', '.join(guardrails_applied)}]")
    parts.append(f"result={final}")
    return "; ".join(parts)


# ===========================================================================
# Kernel reconciliation orchestrator
# ===========================================================================


def reconcile_kernel(output, call_str: str, classifier_result: dict) -> str:
    """Threshold-based severity reconciliation for kernel CVEs.

    Ported from al-kernel Phase 4.  The classifier's cascade-adjusted
    prediction is the starting severity.  The LLM's own CVSS score
    drives bidirectional adjustments through deterministic threshold
    rules (H1-H11), followed by guardrail safety nets (G1-G4).

    Classifier confidence is logged in the trace but does not affect
    the outcome.

    Args:
        output: Mutable ``SuggestImpactModel`` namespace; ``impact``
            is updated in place.
        call_str: CVE identifier string used in log messages.
        classifier_result: Dict from the XGBoost cascade containing
            ``impact``, ``confidence``, ``cvss_score``, ``cvss_issuer``,
            and ``active_features``.

    Returns:
        A trace string describing the full reconciliation path.
    """
    from aegis_ai.kernel_classifier.cascade import parse_cvss_vector

    try:
        llm_cvss = float(output.cvss3_score)
    except (ValueError, TypeError):
        llm_cvss = float("nan")

    llm_vector = parse_cvss_vector(output.cvss3_vector or "")

    clf_impact = classifier_result.get("impact")
    active_features: set[str] = set(classifier_result.get("active_features", []))

    severity = (
        SEVERITY_ORDER[clf_impact]
        if clf_impact and clf_impact in SEVERITY_ORDER
        else MOD
    )
    start_label = IMPACT_LABELS.get(severity, clf_impact)

    ctx = RuleContext(
        severity=severity,
        llm_cvss=llm_cvss,
        llm_vector=llm_vector,
        active_features=active_features,
        has_contained=bool(active_features & CONTAINED_SUBSYSTEM_FLAGS),
        has_corruption=bool(active_features & MEMORY_CORRUPTION_FLAGS),
        has_network=bool(active_features & NETWORK_EXPOSURE_FLAGS),
        cia_hhh=(
            llm_vector.get("C") == "H"
            and llm_vector.get("I") == "H"
            and llm_vector.get("A") == "H"
        ),
        av_local=llm_vector.get("AV") == "L",
        pr_h_only=llm_vector.get("PR") == "H",
        clf_cvss_score=classifier_result.get("cvss_score", 0.0) or 0.0,
        clf_cvss_issuer=classifier_result.get("cvss_issuer", "") or "",
        clf_confidence=classifier_result.get("confidence", 0.0) or 0.0,
    )

    rules_applied = apply_threshold_rules(ctx)
    guardrails_applied = apply_guardrails(ctx)

    final = IMPACT_LABELS.get(ctx.severity, clf_impact)

    trace = build_trace(ctx, start_label, rules_applied, guardrails_applied, final)

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


# ===========================================================================
# CVSS override for kernel panic / IMPORTANT impact
# ===========================================================================

#: Canonical ordering of CVSS v3.1 base metric keys used when
#: reconstructing a vector string from individual metric values.
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


# ===========================================================================
# Output check (retry enforcement)
# ===========================================================================


def check_kernel_output(output, deps) -> str | None:
    """Return a retry message if kernel_impact_tool was not called for a
    kernel CVE, or ``None`` to accept the output.

    The kernel_impact_tool provides patch-level analysis (active feature
    flags and severity class probabilities) that the LLM must incorporate
    into its assessment.  If the tool was available but not invoked, the
    output is rejected and the LLM is asked to retry.
    """
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
