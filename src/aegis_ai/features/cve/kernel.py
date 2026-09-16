"""Kernel-specific reconciliation, guardrails, and CVSS overrides.

This module implements the al-kernel severity reconciliation pipeline for
kernel CVEs.

A.Larkin NN+LLM parity POC (Sep 2026): the post-LLM path below is shaped
as closely as practical after the supplied current Perl daemon block:

1. **Perl CVSS/hint rules** (H1-H15) — deterministic rules before the Perl
   "And now another block of corrections based on ActionableScore" comment.
2. **Perl ActionableScore rules** (AS1-AS7) — numeric conservative-score
   corrections in the same order as the Perl if() statements.

Historical Aegis G1-G4 helpers remain for reference but are disabled in this
NN-compatible path because the supplied Perl block has no equivalent general
LLM-band/memory/network floors. request_llm_kpanic() is represented by a
structured asynchronous review after H1-H15/AS1-AS7, followed by the
request_llm_afterpushedtohigh() structured false-positive review when the old
Perl pushed_to_high/current-IMPORTANT gate is satisfied.

Both phases use a declarative rule architecture:

- Each rule is a **pure function** that reads a :class:`RuleContext` and
  returns an immutable :class:`RuleEffect` payload (or ``None``).
- A single :func:`apply_effect` mutator applies the payload to the context.
- :func:`run_rules` iterates an ordered rule list, feeding effects through
  the mutator and collecting trace labels.

Structured primary-LLM fields now carry the legacy $rs predicates for
manual-review, NULL/CWE-476/CWE-833/CWE-401, and btrfs checks so those
conditions can be ported without scraping explanation prose.
"""

from __future__ import annotations

import logging
import math
import re
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
                      CRITICAL (CVSS > 9.0) is exceptionally rare for kernel CVEs. It requires unauthenticated remote code execution (AV:N/AC:L/PR:N/UI:N) with broad C:H + I:H impact on user data. Most kernel vulnerabilities require local access (AV:L) or elevated privileges (PR:H), which precludes CRITICAL. When uncertain between CRITICAL and IMPORTANT, choose IMPORTANT.
                    - deescalation_rationale: If you believe the impact should be LOWER than the standard CVSS band based on contextual factors (contained subsystem, restricted attack surface, high privilege requirements), note the justification here as advisory input. Leave null when impact matches the standard band.
                    - classifier_disagreement_rationale: If the kernel_impact_tool returned patch signals and your CVSS-based assessment implies a different severity, explain factually why your independent technical assessment differs (attack surface, preconditions, scope). Do not adjust your CVSS metrics to match the classifier. Leave null when you agree or no classifier result was available.

                    # A.Larkin NN+LLM parity POC: structured equivalents of
                    # Perl $rs predicates used by the deterministic cascade.
                    # PERL:
                    #   /YES REQUIRES MANUAL CHECK/
                    #   /NO MANUAL CHECK/
                    #   /CWE-476|CWE-833|CWE-401|NULL pointer dereference/i
                    #   /btrfs/i
                    # -----------------------------------------------------------------
                    # A.Larkin NN+LLM parity corrective patch.
                    #
                    # BEFORE:
                    #   These fields existed in the schema, but Gemini could omit them
                    - kernel_manual_review: For Linux kernel CVEs only, output exactly YES, NO, or UNKNOWN.
                      Treat this as the structured equivalent of the legacy
                      'YES REQUIRES MANUAL CHECK' / 'NO MANUAL CHECK' decision.
                    
                      Output YES when ANY of these is true:
                      * a real kernel UAF, double-free, OOB write, memory corruption, ownership/COW
                        violation, or authorization/security-boundary primitive is established and
                        the Moderate-vs-Important decision depends on unresolved exploitation leverage;
                      * a technically supported non-crash confidentiality, integrity, privilege,
                        protected-resource, or cross-boundary consequence remains plausible but is
                        not conclusive enough for automatic severity selection;
                      * conservative and paranoid interpretations materially differ in a way that
                        can change operational impact or whether automatic closure/downgrade is safe;
                      * contradictory evidence or an incomplete trigger/privilege/reachability chain
                        materially affects the impact decision and requires analyst resolution.
                    
                      Output NO only when the supported consequence is sufficiently bounded and the
                      impact decision does not depend on unresolved stronger exploitation.
                      Typical NO cases include clear crash/correctness-only NULL dereferences,
                      bounded invalid-state bugs, or similarly constrained issues with no meaningful
                      unresolved non-crash primitive.
                    
                      Output UNKNOWN only when required tools/context genuinely cannot resolve
                      whether review is needed. UNKNOWN is not a neutral/default value.
                    
                      Do not derive this field merely from classifier severity, CVSS score, or the
                      presence of a kernel_panic flag.
                      # A.Larkin primary manual-review calibration v5.
                    #   kernel_nullptr_related was also too broad: incidental phrases
                    #   such as "vmalloc_to_page() returns NULL" could make a UAF/race
                    #   look like the legacy NULL-dereference branch.
                    #
                    # PERL SOURCE represented structurally:
                    #   $rs =~ /YES REQUIRES MANUAL CHECK/
                    #   $rs =~ /NO MANUAL CHECK/
                    #   $rs =~ /CWE-476|CWE-833|CWE-401|NULL pointer dereference/i
                    #   $rs =~ /btrfs/i
                    #
                    # AFTER:
                    #   Emit an explicit primary-analysis decision for each field.
                    # -----------------------------------------------------------------
                    - kernel_manual_review: For Linux kernel CVEs only, output exactly YES, NO, or UNKNOWN.
                      * YES = your PRIMARY technical assessment says a human analyst should review this CVE before relying on the automated impact decision. Use YES when the Important-vs-Moderate/Low boundary materially depends on unresolved exploitation leverage, a plausible but unproven non-crash primitive, contradictory technical evidence, or another security-significant uncertainty that needs analyst judgment.
                      * NO = the primary technical evidence is sufficiently clear that no additional manual impact review is needed.
                      * UNKNOWN = use only when the evidence is genuinely insufficient to decide YES versus NO even after using the required kernel tools. Do NOT use UNKNOWN as a neutral/default value.
                      This is the structured Aegis equivalent of the legacy hints text "YES REQUIRES MANUAL CHECK" / "NO MANUAL CHECK". Do not derive it merely from the XGBoost severity class.
                    - kernel_nullptr_related: For Linux kernel CVEs only, output true ONLY when the ROOT VULNERABILITY MECHANISM itself is CWE-476, CWE-833, CWE-401, or an actual NULL-pointer dereference.
                      Output false when NULL is only a downstream symptom/consequence of UAF, race, OOB, double-free, failed lookup, or another root bug. A UAF/race where vmalloc_to_page() later returns NULL or vm_insert_page(NULL) is called MUST remain false unless the root flaw is independently a NULL-dereference-class bug.
                    - kernel_btrfs_context: For Linux kernel CVEs only, true when the vulnerable subsystem/fix being analyzed is btrfs; otherwise false.
                - Metric selection guide:
                    - AV: N if reachable over network from off-host; A if same subnet/Bluetooth/802.11 link-limited; L if requires local account/session/CLI/local IPC; P if requires physical access.
                    - AC: H if requires uncommon configuration, precise timing/race, multiple conditions, or lengthy preparation; else L.
                    - PR: N if no prior auth; L if basic/local user privileges are enough; H if admin/root/high-privileges are required to trigger.
                    - Linux capabilities: Treat required CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_NET_RAW, CAP_SYS_MODULE, and similar admin-class capabilities as strong evidence for PR:H when the vulnerable operation cannot be triggered without them.
                    - Kernel attack surface: Mounting filesystems (mount(2)), loading filesystem or network driver modules, configuring interfaces or traffic classes, or privileged ioctls usually implies PR:H unless the advisory clearly shows exploitation by an unprivileged user without those capabilities (e.g. unprivileged user namespaces with a specific exposed entry point).
                    - Network filesystem worker races (e.g., oplock/lease break handlers, deferred close): when the trigger is normal file I/O on an already-mounted share, use PR:L — the attacker needs only ordinary file access, not mount privileges, granted by an already-mounted share.
                    - UI: R if victim must click/open/provide content; else N.
                    - S: C only when exploitation changes scope between security authorities (e.g. container/guest escape to host, crossing VM or user-namespace boundary per CVSS definition). Do not choose S:C merely because the kernel is involved or because other processes exist on the system; many local kernel bugs remain S:U.
                    - CIA: Set each based on realistic consequences: use A for availability-only DoS; use C/I when plausible user-visible confidentiality or integrity impact exists. For internal kernel object lifetime/corruption with no direct user data read/write, prefer C:N/I:N or low scores unless a credible path to disclosure or controlled modification of user data is described.
                    - OOB write with attacker-controlled data (e.g., malicious USB device, crafted packet): corrupting kernel structures that mediate user-visible state (fs metadata, security descriptors, memory mappings) compromise system integrity and can expose user-data — use I:H and name the control mechanism and target structures in the explanation.
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
    #: CVSS score used by the Perl-compatible cascade.
    #: Prefer second-opinion CVSSSelectedScore; primary LLM is fallback only.
    llm_cvss: float
    #: Parsed CVSS vector used by the Perl-compatible cascade.
    llm_vector: dict
    #: Diagnostic source for llm_cvss/llm_vector.
    llm_cvss_source: str
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

    # --- ActionableScore / second-opinion signals ---
    # Computed before reconciliation, consumed only in Phase 3 after H/G.
    actionable_score: int | None = None
    actionable_score_lower: int | None = None
    actionable_primitive: str = ""
    actionable_important_candidate: bool = False
    actionable_manual_review: str = ""
    actionable_auto_downgrade_allowed: bool = False
    actionable_recommended_impact: str = ""

    # --- Primary LLM structured equivalents of Perl $rs predicates ---
    #
    # BEFORE:
    #   The simplified H rules approximated/omitted Perl text checks.
    # AFTER:
    #   Read explicit values from SuggestImpactModel.
    # PERL examples:
    #   $rs =~ /YES REQUIRES MANUAL CHECK/
    #   $rs =~ /NO MANUAL CHECK/
    #   $rs =~ /CWE-476|CWE-833|CWE-401|NULL pointer dereference/i
    #   $rs !~ /btrfs/i
    primary_manual_review: str = "UNKNOWN"
    primary_nullptr_related: bool = False
    primary_btrfs_context: bool = False

    # Literal classifier crash evidence at entry. This is evidence; the
    # mutable kpanic_marked below is the Perl operational state.
    has_real_kpanic: bool = False

    # --- Mutable state mirroring Perl variables/flags ---
    # Perl: $flags{$cve} =~ /KPANIC/. Operational MODERATE7 marker.
    kpanic_marked: bool = False
    # Perl: my $lowered = 0;
    lowered: bool = False
    # Perl: my $dec_cnt = 0;
    decrease_count: int = 0
    # Perl: my $pushed_to_high = 0; if($severity == 0) { ... = 1; }
    pushed_to_high: bool = False
    # Perl: $flags{$cve} !~ /DECREASED/. Separate from $lowered.
    decreased_marker: bool = False

    # Historical fields kept only because disabled G1-G4 helpers remain.
    decreased: bool = False
    h1_fired: bool = False
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
    flags: dict[str, bool | int | str | None] = field(default_factory=dict)


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


def _sync_output_operational_kpanic_flag(output) -> None:
    """Keep exported Patch Flags aligned with final Perl-compatible KPANIC."""
    final_kpanic = getattr(output, "_kernel_kpanic_marked", None)
    if final_kpanic is None:
        return
    flags = getattr(output, "_flags", None)
    if not isinstance(flags, list):
        return
    flags[:] = [f for f in flags if f != "kernel_panic"]
    if final_kpanic:
        flags.append("kernel_panic")


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
# Perl-compatible deterministic CVSS/hint rules H1-H15
#
# BEFORE: simplified Aegis H1-H11 + active G1-G4 + semantic AS1/AS2.
# AFTER: predicates/order below mirror the supplied Perl block.
# WHY: Perl mutates severity/KPANIC/lowered/pushed_to_high in place and every
#      later if() observes prior mutations; run_rules preserves that ordering.
# ===========================================================================


def _cia_any_high(ctx: RuleContext) -> bool:
    # Perl: ($rs =~ /C:H/ || $rs =~ /I:H/ || $rs =~ /A:H/)
    return any(ctx.llm_vector.get(k) == "H" for k in ("C", "I", "A"))


def _cia_hhh_or_llh(ctx: RuleContext) -> bool:
    # Perl: C:H/I:H/A:H OR C:L/I:L/A:H
    return (
        ctx.llm_vector.get("C"),
        ctx.llm_vector.get("I"),
        ctx.llm_vector.get("A"),
    ) in {("H", "H", "H"), ("L", "L", "H")}


def _cia_local_low_shape(ctx: RuleContext) -> bool:
    # Perl: AV:L ... C:[LN]/I:[LN]/A:H OR .../A:L
    return (
        ctx.llm_vector.get("AV") == "L"
        and ctx.llm_vector.get("C") in ("L", "N")
        and ctx.llm_vector.get("I") in ("L", "N")
        and ctx.llm_vector.get("A") in ("H", "L")
    )


def _cia_all_non_none(ctx: RuleContext) -> bool:
    # Perl: $rs =~ /C:[LH]\/I:[LH]\/A:[LH]/
    return all(ctx.llm_vector.get(k) in ("L", "H") for k in ("C", "I", "A"))


def _blocked_bpf_btrfs(ctx: RuleContext) -> bool:
    return "bpf" in ctx.active_features or ctx.primary_btrfs_context


def _blocked_bpf_btrfs_nvme(ctx: RuleContext) -> bool:
    return (
        "bpf" in ctx.active_features
        or "nvme" in ctx.active_features
        or ctx.primary_btrfs_context
    )


def h1(ctx: RuleContext) -> RuleEffect | None:
    # PERL:
    # if($severity == 0 && $sc < 6.5 && (!$lowered)) {
    #   $severity = 1;
    #   $flags{$cve} .= " KPANIC LOWERED_FROM_HIGH_BASED_ON_GUESSCVSS ";
    #   $lowered = 1;
    # }
    # REPLACES old H1 by also reproducing KPANIC + $lowered state.
    if ctx.severity != IMP or ctx.llm_cvss >= 6.5 or ctx.lowered:
        return None
    return RuleEffect(
        severity=MOD,
        trace="H1:IMP->MOD7(cvss<6.5)",
        flags={"kpanic_marked": True, "lowered": True, "h1_fired": True},
    )


def h2(ctx: RuleContext) -> RuleEffect | None:
    # PERL:
    # if($severity == 1 && ($sc >= 8.5 ||
    #   (($sc > 7.8 || ($sc >= 5.5 && $alimpactscore >= 6)) &&
    #    (C:H || I:H || A:H) && !BPF && !btrfs && !NVMe))) {
    #   $severity = 0; append KPANIC; $pushed_to_high = 1;
    # }
    # REPLACES old >=7.5+HHH approximation; restores AS>=6 and ANY-H.
    if ctx.severity != MOD:
        return None
    score = ctx.actionable_score
    cond = ctx.llm_cvss >= 8.5 or (
        (
            ctx.llm_cvss > 7.8
            or (ctx.llm_cvss >= 5.5 and score is not None and score >= 6)
        )
        and _cia_any_high(ctx)
        and not _blocked_bpf_btrfs_nvme(ctx)
    )
    if not cond:
        return None
    return RuleEffect(
        severity=IMP,
        trace="H2:MOD->IMP(perl_guesscvss)",
        flags={"kpanic_marked": True, "pushed_to_high": True},
    )


def h3(ctx: RuleContext) -> RuleEffect | None:
    # PERL:
    # severity==1 && (sc>=7.5 ||
    #   (sc>=6.5 && (HHH || LLH) && !KPANIC && !BPF && !btrfs))
    # -> keep severity=1, append KPANIC (MODERATE7).
    if ctx.severity != MOD:
        return None
    cond = ctx.llm_cvss >= 7.5 or (
        ctx.llm_cvss >= 6.5
        and _cia_hhh_or_llh(ctx)
        and not ctx.kpanic_marked
        and not _blocked_bpf_btrfs(ctx)
    )
    if not cond:
        return None
    return RuleEffect(trace="H3:MOD->MOD7(perl_guesscvss)", flags={"kpanic_marked": True})


def h4(ctx: RuleContext) -> RuleEffect | None:
    # PERL:
    # severity==1 && sc>=6.0 && alimpactscore>4 && !KPANIC &&
    # (!CWE-476/833/401/NULL || AV:N || AV:A) -> append KPANIC.
    # REPLACES old H4 which omitted ActionableScore > 4.
    score = ctx.actionable_score
    if (
        ctx.severity != MOD
        or ctx.llm_cvss < 6.0
        or score is None
        or score <= 4
        or ctx.kpanic_marked
    ):
        return None
    if ctx.primary_nullptr_related and ctx.llm_vector.get("AV") not in ("N", "A"):
        return None
    return RuleEffect(trace="H4:MOD->MOD7(cvss>=6+AS>4)", flags={"kpanic_marked": True})


def h5(ctx: RuleContext) -> RuleEffect | None:
    # PERL: (severity==2 || severity==1) && sc>8.5 -> HIGH + KPANIC.
    if ctx.severity not in (LOW, MOD) or ctx.llm_cvss <= 8.5:
        return None
    return RuleEffect(
        severity=IMP,
        trace="H5:LOW/MOD->IMP(cvss>8.5)",
        flags={"kpanic_marked": True, "pushed_to_high": True},
    )


def h6(ctx: RuleContext) -> RuleEffect | None:
    # PERL:
    # alimpactscore>=4 && severity==2 &&
    # (sc>=6.7 || (sc>=5.5 && HHH) || AV:[AN]) && !BPF && !btrfs
    # -> MODERATE7/KPANIC.
    score = ctx.actionable_score
    if ctx.severity != LOW or score is None or score < 4 or _blocked_bpf_btrfs(ctx):
        return None
    if not (
        ctx.llm_cvss >= 6.7
        or (ctx.llm_cvss >= 5.5 and ctx.cia_hhh)
        or ctx.llm_vector.get("AV") in ("A", "N")
    ):
        return None
    return RuleEffect(
        severity=MOD,
        trace="H6:LOW->MOD7(cvss+AS>=4)",
        flags={"kpanic_marked": True},
    )


def h7(ctx: RuleContext) -> RuleEffect | None:
    # PERL: severity==1 && sc<=3.9 && !KPANIC && !$lowered -> LOW.
    if ctx.severity != MOD or ctx.llm_cvss > 3.9 or ctx.kpanic_marked or ctx.lowered:
        return None
    return RuleEffect(
        severity=LOW,
        trace="H7:MOD->LOW(cvss<=3.9)",
        flags={"kpanic_marked": False, "lowered": True, "decreased_marker": True},
    )


def h8(ctx: RuleContext) -> RuleEffect | None:
    # PERL: MOD + sc<5.5 + AV:L low-CIA + !HHH +
    # !YES_REQUIRES_MANUAL_CHECK + !KPANIC + !$lowered -> LOW.
    if (
        ctx.severity != MOD
        or ctx.llm_cvss >= 5.5
        or not _cia_local_low_shape(ctx)
        or ctx.cia_hhh
        or ctx.primary_manual_review == "YES"
        or ctx.kpanic_marked
        or ctx.lowered
    ):
        return None
    return RuleEffect(
        severity=LOW,
        trace="H8:MOD->LOW(local_low_CIA+no_required_manual)",
        flags={"kpanic_marked": False, "lowered": True, "decreased_marker": True},
    )


def h9(ctx: RuleContext) -> RuleEffect | None:
    # PERL: severity==1 && sc<=4.5 && !$lowered -> remove KPANIC, set lowered.
    # Perl does not require KPANIC to be present before this branch.
    if ctx.severity != MOD or ctx.llm_cvss > 4.5 or ctx.lowered:
        return None
    return RuleEffect(
        trace="H9:MOD7->MODREG(cvss<=4.5)",
        flags={
            "kpanic_marked": False,
            "lowered": True,
            "decreased_marker": True,
            "decreased": True,
        },
    )


def h10(ctx: RuleContext) -> RuleEffect | None:
    # PERL: MOD + sc<=5.5 + local low-CIA + !HHH + KPANIC + !$lowered
    # -> regular MODERATE, remove KPANIC.
    if (
        ctx.severity != MOD
        or ctx.llm_cvss > 5.5
        or not _cia_local_low_shape(ctx)
        or ctx.cia_hhh
        or not ctx.kpanic_marked
        or ctx.lowered
    ):
        return None
    return RuleEffect(
        trace="H10:MOD7->MODREG(local_low_CIA)",
        flags={
            "kpanic_marked": False,
            "lowered": True,
            "decreased_marker": True,
            "decreased": True,
        },
    )


def h11(ctx: RuleContext) -> RuleEffect | None:
    # PERL: HIGH + sc<8.0 + PR:H + !$lowered -> MODERATE7/KPANIC.
    if ctx.severity != IMP or ctx.llm_cvss >= 8.0 or not ctx.pr_h_only or ctx.lowered:
        return None
    return RuleEffect(
        severity=MOD,
        trace="H11:IMP->MOD7(cvss<8+PR:H)",
        flags={"kpanic_marked": True, "lowered": True},
    )


def h12(ctx: RuleContext) -> RuleEffect | None:
    # PERL: HIGH + sc<8.5 + CWE-476/833/401/NULL + !AV:N + !AV:A +
    # !$lowered -> MODERATE7/KPANIC.
    if (
        ctx.severity != IMP
        or ctx.llm_cvss >= 8.5
        or not ctx.primary_nullptr_related
        or ctx.llm_vector.get("AV") in ("N", "A")
        or ctx.lowered
    ):
        return None
    return RuleEffect(
        severity=MOD,
        trace="H12:IMP->MOD7(nullptr_related_local)",
        flags={"kpanic_marked": True, "lowered": True},
    )


def h13(ctx: RuleContext) -> RuleEffect | None:
    # PERL: LOW + YES REQUIRES MANUAL CHECK -> MODERATE7/KPANIC.
    if ctx.severity != LOW or ctx.primary_manual_review != "YES":
        return None
    return RuleEffect(
        severity=MOD,
        trace="H13:LOW->MOD7(primary_manual_check=YES)",
        flags={"kpanic_marked": True},
    )


def h14(ctx: RuleContext) -> RuleEffect | None:
    # PERL: MOD + sc<4.6 + NO MANUAL CHECK + !DECREASED +
    # !(C:[LH]/I:[LH]/A:[LH]) + !$lowered -> LOW, remove KPANIC.
    if (
        ctx.severity != MOD
        or ctx.llm_cvss >= 4.6
        or ctx.primary_manual_review != "NO"
        or ctx.decreased_marker
        or _cia_all_non_none(ctx)
        or ctx.lowered
    ):
        return None
    return RuleEffect(
        severity=LOW,
        trace="H14:MOD->LOW(primary_manual_check=NO)",
        flags={"kpanic_marked": False, "lowered": True, "decreased_marker": True},
    )


def h15(ctx: RuleContext) -> RuleEffect | None:
    # PERL: LOW + sc>=5.0 + NO MANUAL CHECK -> MODERATE7/KPANIC.
    if ctx.severity != LOW or ctx.llm_cvss < 5.0 or ctx.primary_manual_review != "NO":
        return None
    return RuleEffect(
        severity=MOD,
        trace="H15:LOW->MOD7(cvss>=5+primary_manual_check=NO)",
        flags={"kpanic_marked": True},
    )


# ===========================================================================
# Historical Aegis G1-G4: retained for reference, disabled in parity mode.
# ===========================================================================
IMPACT_LABELS = {v: k for k, v in SEVERITY_ORDER.items()}


def g1(ctx: RuleContext) -> RuleEffect | None:
    if ctx.severity != LOW:
        return None
    llm_band = score_to_band(ctx.llm_cvss)
    if not llm_band or llm_band not in SEVERITY_ORDER:
        return None
    band_rank = SEVERITY_ORDER[llm_band]
    if ctx.has_contained:
        band_rank = max(band_rank, MOD)
    if ctx.severity > band_rank:
        return RuleEffect(severity=band_rank, trace=f"G1:llm_band_floor({IMPACT_LABELS[band_rank]})")
    return None


def g2(ctx: RuleContext) -> RuleEffect | None:
    if ctx.has_corruption and ctx.severity > MOD:
        return RuleEffect(severity=MOD, trace="G2:memory_corruption_floor(MODERATE)")
    return None


def g3(ctx: RuleContext) -> RuleEffect | None:
    if ctx.has_corruption and ctx.has_network and ctx.severity > IMP:
        return RuleEffect(severity=IMP, trace="G3:network_corruption_floor(IMPORTANT)")
    return None


def g4(ctx: RuleContext) -> RuleEffect | None:
    if (
        not math.isnan(ctx.llm_cvss)
        and ctx.h1_fired
        and ctx.severity == MOD
        and ctx.clf_cvss_issuer != "RH"
        and ctx.ext_band
        and ctx.ext_band in SEVERITY_ORDER
        and SEVERITY_ORDER[ctx.ext_band] < MOD
    ):
        return RuleEffect(severity=IMP, trace=f"G4:ext_cvss_confirms_imp({ctx.clf_cvss_score:.1f})")
    return None


# ===========================================================================
# Perl ActionableScore correction block AS1-AS7
#
# BEFORE: semantic recommended_impact + AutoDowngradeAllowed directly changed
# severity in the temporary Aegis AS1/AS2 rules.
# AFTER: numeric conservative ActionableScore drives severity exactly as Perl.
# WHY: $actscorerecommend is report text in the supplied Perl; the actual
# cascade conditions use $alimpactscore.
# ===========================================================================


def as1(ctx: RuleContext) -> RuleEffect | None:
    # PERL: AS>=5 && severity>=1 && !KPANIC -> MODERATE7/KPANIC.
    s = ctx.actionable_score
    if s is None or s < 5 or ctx.severity < MOD or ctx.kpanic_marked:
        return None
    return RuleEffect(severity=MOD, trace="AS1:score>=5->MOD7", flags={"kpanic_marked": True})


def as2(ctx: RuleContext) -> RuleEffect | None:
    # PERL: AS>5 && severity>=1 && KPANIC -> HIGH; pushed_to_high=1.
    s = ctx.actionable_score
    if s is None or s <= 5 or ctx.severity < MOD or not ctx.kpanic_marked:
        return None
    return RuleEffect(severity=IMP, trace="AS2:score>5+KPANIC->IMP", flags={"pushed_to_high": True})


def as3(ctx: RuleContext) -> RuleEffect | None:
    # PERL: AS>=6 && severity>=1 -> HIGH + KPANIC; pushed_to_high=1.
    s = ctx.actionable_score
    if s is None or s < 6 or ctx.severity < MOD:
        return None
    return RuleEffect(
        severity=IMP,
        trace="AS3:score>=6->IMP",
        flags={"kpanic_marked": True, "pushed_to_high": True},
    )


def as4(ctx: RuleContext) -> RuleEffect | None:
    # PERL: AS<6 && HIGH && sc<=7 -> MODERATE7/KPANIC; dec_cnt++.
    s = ctx.actionable_score
    if s is None or s >= 6 or ctx.severity != IMP or ctx.llm_cvss > 7.0:
        return None
    return RuleEffect(
        severity=MOD,
        trace="AS4:IMP->MOD7(score<6+cvss<=7)",
        flags={
            "kpanic_marked": True,
            "decrease_count": ctx.decrease_count + 1,
            "decreased_marker": True,
        },
    )


def as5(ctx: RuleContext) -> RuleEffect | None:
    # PERL: AS>=3 && LOW -> MODERATE7/KPANIC.
    s = ctx.actionable_score
    if s is None or s < 3 or ctx.severity != LOW:
        return None
    return RuleEffect(severity=MOD, trace="AS5:LOW->MOD7(score>=3)", flags={"kpanic_marked": True})


def as6(ctx: RuleContext) -> RuleEffect | None:
    # PERL: AS<4 && severity<=1 && KPANIC -> regular MODERATE; remove KPANIC;
    #       lowered=1; dec_cnt++.
    s = ctx.actionable_score
    if s is None or s >= 4 or ctx.severity > MOD or not ctx.kpanic_marked:
        return None
    return RuleEffect(
        severity=MOD,
        trace="AS6:IMP/MOD7->MODREG(score<4)",
        flags={
            "kpanic_marked": False,
            "lowered": True,
            "decrease_count": ctx.decrease_count + 1,
            "decreased_marker": True,
        },
    )


def as7(ctx: RuleContext) -> RuleEffect | None:
    # PERL: AS<3 && MOD && !YES REQUIRES MANUAL CHECK && dec_cnt<2 -> LOW;
    #       remove KPANIC; lowered=1; dec_cnt++.
    s = ctx.actionable_score
    if (
        s is None
        or s >= 3
        or ctx.severity != MOD
        or ctx.primary_manual_review == "YES"
        or ctx.decrease_count >= 2
    ):
        return None
    return RuleEffect(
        severity=LOW,
        trace="AS7:MOD->LOW(score<3+no_required_manual)",
        flags={
            "kpanic_marked": False,
            "lowered": True,
            "decrease_count": ctx.decrease_count + 1,
            "decreased_marker": True,
        },
    )


THRESHOLD_RULES: list[Callable[[RuleContext], RuleEffect | None]] = [
    h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15,
]

# BEFORE: [g1, g2, g3, g4].
# AFTER: disabled for NN parity.
# WHY: supplied Perl block has no equivalent unconditional G1-G4 floors.
GUARDRAIL_RULES: list[Callable[[RuleContext], RuleEffect | None]] = []

ACTIONABLE_RULES: list[Callable[[RuleContext], RuleEffect | None]] = [
    as1, as2, as3, as4, as5, as6, as7,
]


def apply_actionable_rules(ctx: RuleContext) -> list[str]:
    if ctx.actionable_score is None:
        return ["no_actionable_score"]
    # Exact Perl block entry: my $dec_cnt = 0;
    ctx.decrease_count = 0
    return run_rules(ctx, ACTIONABLE_RULES)


# ===========================================================================
# Pipeline entry points
# ===========================================================================
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
    """NN+LLM parity path: historical Aegis G1-G4 are intentionally disabled.

    BEFORE: G1-G4 could add LLM-band/memory/network floors and external-CVSS
    reversals after the H rules.
    AFTER: GUARDRAIL_RULES is empty; ext_band is retained only for diagnostics.
    WHY: no equivalent unconditional rules exist in the supplied Perl block.
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
    actionable_applied: list[str],
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
        f"cvss_source={ctx.llm_cvss_source}",
    ]
    if ctx.ext_band:
        issuer_tag = f",{ctx.clf_cvss_issuer}" if ctx.clf_cvss_issuer else ""
        parts.append(f"ext_cvss={ctx.clf_cvss_score:.1f}({ctx.ext_band}{issuer_tag})")
    if rules_applied:
        parts.append(f"rules=[{', '.join(rules_applied)}]")
    if guardrails_applied:
        parts.append(f"guardrails=[{', '.join(guardrails_applied)}]")

    if ctx.actionable_score is not None:
        parts.append(f"actionable_score={ctx.actionable_score}")
        if ctx.actionable_score_lower is not None:
            parts.append(f"actionable_lower={ctx.actionable_score_lower}")
        if ctx.actionable_primitive:
            parts.append(f"actionable_primitive={ctx.actionable_primitive}")
        if ctx.actionable_recommended_impact:
            parts.append(
                f"actionable_recommended={ctx.actionable_recommended_impact}"
            )
        # AutoDowngradeAllowed is retained for diagnostics only in the
        # Perl-parity path; it no longer directly changes severity.

    if actionable_applied:
        parts.append(f"actionable_rules=[{', '.join(actionable_applied)}]")

    # Perl mutable state, exposed explicitly for one-to-one log comparison.
    parts.append(f"kpanic_marked={'YES' if ctx.kpanic_marked else 'NO'}")
    parts.append(f"lowered={'YES' if ctx.lowered else 'NO'}")
    parts.append(f"dec_cnt={ctx.decrease_count}")
    parts.append(f"pushed_to_high={'YES' if ctx.pushed_to_high else 'NO'}")
    parts.append(f"primary_manual_review={ctx.primary_manual_review}")
    parts.append(
        f"primary_nullptr_related={'YES' if ctx.primary_nullptr_related else 'NO'}"
    )
    parts.append(
        f"primary_btrfs_context={'YES' if ctx.primary_btrfs_context else 'NO'}"
    )
    if ctx.actionable_score is not None:
        parts.append(
            "actionable_auto_downgrade="
            + ("YES" if ctx.actionable_auto_downgrade_allowed else "NO")
        )

    parts.append(f"result={final}")
    return "; ".join(parts)


# ===========================================================================
# Kernel reconciliation orchestrator
# ===========================================================================



def _effective_primary_nullptr_related(output, active_features: set[str] | list[str]) -> bool:
    """Return the Perl/H12-compatible root-cause NULL/CWE predicate.

    The structured field can be over-broad: a UAF/race may later make
    vmalloc_to_page() return NULL and produce vm_insert_page(NULL). H12 should
    represent the vulnerability mechanism itself being CWE-476/833/401 or a
    NULL-pointer dereference, not an incidental NULL consequence.
    """
    claimed = bool(getattr(output, "kernel_nullptr_related", False))
    if not claimed:
        return False

    explanation = str(getattr(output, "explanation", "") or "")
    if re.search(r"\bCWE-(?:476|833|401)\b", explanation, re.IGNORECASE):
        return True

    root_null = re.search(
        r"\b(?:root\s+cause|vulnerability|bug|flaw|issue|mechanism)\b"
        r".{0,120}?\bNULL[- ]pointer\s+dereference\b",
        explanation,
        re.IGNORECASE | re.DOTALL,
    )
    if root_null:
        return True

    active = {str(x).lower() for x in (active_features or [])}
    alternative_feature = bool(
        active
        & {
            "uaf",
            "kernel_panic_plus_uaf",
            "race",
            "outofbounds",
        }
    )
    alternative_text = re.search(
        r"\b(?:use[- ]after[- ]free|UAF|double[- ]free|race(?: condition)?|"
        r"out[- ]of[- ]bounds|OOB)\b",
        explanation,
        re.IGNORECASE,
    )

    if alternative_feature and alternative_text:
        logger.info(
            "Suppressing incidental primary kernel_nullptr_related=YES: "
            "primary explanation identifies UAF/race/OOB/double-free root mechanism"
        )
        return False

    return True


def reconcile_kernel(
    output,
    call_str: str,
    classifier_result: dict,
    second_opinion=None,
) -> str:
    """Threshold-based severity reconciliation for kernel CVEs.

    A.Larkin second-opinion selected CVSS plumbing.
    A.Larkin NN+LLM parity POC. The raw XGBoost prediction is the starting
    severity when available. The primary LLM CVSS/hint fields and numeric
    ActionableScore then flow through the supplied Perl-compatible H1-H15 and
    AS1-AS7 rules. Historical G1-G4 are disabled here. The asynchronous
    request_llm_kpanic()-equivalent and request_llm_afterpushedtohigh()-
    equivalent are applied by SuggestImpact.exec() after this function returns.

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

    # Primary SuggestImpact CVSS is the fail-open fallback. Prefer the
    # independently computed selected CVSS from the second-opinion pass for
    # the Perl-compatible deterministic cascade when available.
    try:
        primary_llm_cvss = float(output.cvss3_score)
    except (ValueError, TypeError):
        primary_llm_cvss = float("nan")

    primary_llm_vector = parse_cvss_vector(output.cvss3_vector or "")

    llm_cvss = primary_llm_cvss
    llm_vector = primary_llm_vector
    llm_cvss_source = "primary"

    if second_opinion is not None:
        selected_score = getattr(second_opinion, "cvss_selected_score", None)
        selected_vector_raw = getattr(second_opinion, "cvss_selected_vector", None)

        if selected_score is not None and selected_vector_raw:
            try:
                selected_score_float = float(selected_score)
                selected_vector = parse_cvss_vector(selected_vector_raw)
                required_metrics = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
                missing = required_metrics - set(selected_vector)
                if missing:
                    raise ValueError(
                        "selected CVSS vector missing base metrics: "
                        f"{sorted(missing)}"
                    )

                llm_cvss = selected_score_float
                llm_vector = selected_vector
                llm_cvss_source = "second_opinion_selected"
            except Exception as exc:
                logger.warning(
                    "%s: invalid second-opinion selected CVSS at reconciliation "
                    "boundary; using primary CVSS: %s",
                    call_str,
                    exc,
                )

    logger.info(
        "%s: kernel reconciliation CVSS source=%s score=%s "
        "selected_vector=%s primary_score=%s primary_vector=%s",
        call_str,
        llm_cvss_source,
        llm_cvss,
        getattr(second_opinion, "cvss_selected_vector", None)
        if second_opinion is not None
        else None,
        primary_llm_cvss,
        output.cvss3_vector,
    )

    # --------------------------------------------------------------
    # A.Larkin NN+LLM parity POC.
    # BEFORE: start from classifier_result["impact"], already changed by
    #         Aegis R5-R12 using external CVSS.
    # AFTER:  start from raw_prediction when available.
    # WHY:    Perl applies one post-LLM cascade to the pre-hints model
    #         severity; stacking R5-R12 + the Perl port obscures parity.
    # --------------------------------------------------------------
    adjusted_clf_impact = classifier_result.get("impact")
    clf_impact = classifier_result.get("raw_prediction") or adjusted_clf_impact
    active_features: set[str] = set(classifier_result.get("active_features", []))

    severity = (
        SEVERITY_ORDER[clf_impact]
        if clf_impact and clf_impact in SEVERITY_ORDER
        else MOD
    )
    start_label = IMPACT_LABELS.get(severity, clf_impact)

    # Deterministic AS consistency invariant:
    # CLASS_C + ImportantCandidate=NO + AutoDowngradeAllowed=YES => AS <= 2.
    effective_actionable_score = (
        getattr(second_opinion, "actionable_score", None)
        if second_opinion is not None else None
    )
    if (
        effective_actionable_score is not None
        and str(getattr(second_opinion, "primitive_class", "")).upper() == "CLASS_C"
        and getattr(second_opinion, "important_candidate", "NO") == "NO"
        and getattr(second_opinion, "auto_downgrade_allowed", "NO") == "YES"
        and effective_actionable_score > 2
    ):
        logger.info(
            "%s: deterministic CLASS_C ActionableScore cap %s -> 2 "
            "(ImportantCandidate=NO, AutoDowngradeAllowed=YES)",
            call_str, effective_actionable_score,
        )
        effective_actionable_score = 2

    ctx = RuleContext(
        severity=severity,
        llm_cvss=llm_cvss,
        llm_vector=llm_vector,
        llm_cvss_source=llm_cvss_source,
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

        actionable_score=effective_actionable_score,
        actionable_score_lower=(
            getattr(second_opinion, "actionable_score_lower", None)
            if second_opinion is not None
            else None
        ),
        actionable_primitive=(
            getattr(second_opinion, "primitive_class", "")
            if second_opinion is not None
            else ""
        ),
        actionable_important_candidate=(
            getattr(second_opinion, "important_candidate", "NO") == "YES"
            if second_opinion is not None
            else False
        ),
        actionable_manual_review=(
            getattr(second_opinion, "manual_review", "")
            if second_opinion is not None
            else ""
        ),
        actionable_auto_downgrade_allowed=(
            getattr(second_opinion, "auto_downgrade_allowed", "NO") == "YES"
            if second_opinion is not None
            else False
        ),
        actionable_recommended_impact=(
            getattr(second_opinion, "recommended_impact", "")
            if second_opinion is not None
            else ""
        ),

        # Structured equivalents of Perl $rs text predicates.
        primary_manual_review=getattr(output, "kernel_manual_review", "UNKNOWN"),
        # H12 parity: use a root-cause NULL predicate, not incidental NULL
        # consequences inside a UAF/race/OOB crash path.
        primary_nullptr_related=_effective_primary_nullptr_related(
            output,
            active_features,
        ),
        primary_btrfs_context=bool(
            getattr(output, "kernel_btrfs_context", False)
        ),

        # Perl enters this block with existing $flags{$cve}. Seed the mutable
        # KPANIC state from real classifier crash flags, then allow H/AS rules
        # to add/remove the operational marker.
        has_real_kpanic=(
            "kernel_panic" in active_features
            or "kernel_panic_plus_uaf" in active_features
        ),
        kpanic_marked=(
            "kernel_panic" in active_features
            or "kernel_panic_plus_uaf" in active_features
        ),

        # Perl:
        # my $pushed_to_high = 0;
        # if($severity == 0) { $pushed_to_high = 1; }
        pushed_to_high=(severity == IMP),
    )

    # Phase 1: supplied Perl CVSS/hint rules, in original order.
    rules_applied = apply_threshold_rules(ctx)

    # Phase 2: G1-G4 intentionally disabled for this parity experiment.
    guardrails_applied = apply_guardrails(ctx)

    # Phase 3: supplied Perl numeric ActionableScore correction block.
    actionable_applied = apply_actionable_rules(ctx)

    final = IMPACT_LABELS.get(ctx.severity, clf_impact)

    trace = build_trace(
        ctx,
        start_label,
        rules_applied,
        guardrails_applied,
        actionable_applied,
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

    # Preserve final Perl-style mutable state for the asynchronous KPANIC
    # false-positive review and the later afterpushedtohigh parity stage.
    output._kernel_kpanic_marked = ctx.kpanic_marked
    output._kernel_lowered = ctx.lowered
    output._kernel_decrease_count = ctx.decrease_count
    output._kernel_pushed_to_high = ctx.pushed_to_high

    # NEW29_AS4_DOWNGRADE_STATE: record literal AS4 execution only.
    output._kernel_as4_downgraded_from_important = any(
        str(item).startswith("AS4:IMP->MOD7") for item in actionable_applied
    )

    _sync_output_operational_kpanic_flag(output)
    return trace


# ===========================================================================
# NN+LLM-compatible KPANIC false-positive review result application
# ===========================================================================


def apply_kpanic_llm_review(
    output,
    call_str: str,
    review,
    second_opinion=None,
) -> str:
    """Apply the structured request_llm_kpanic()-equivalent decision.

    This stage runs only after H1-H15 and AS1-AS7 have produced the mutable
    operational KPANIC state.

    The supplied modern KPANIC prompt intentionally separates two decisions:
      1. whether KERNEL_PANIC itself is supported;
      2. whether HIGH can safely become MODERATE7 after crash/DoS is removed
         from the independent severity analysis.

    Therefore this port does not collapse the response back into the old
    opaque integer ``$rv``.  It uses each structured decision only for the
    branch it semantically controls while retaining the original Perl numeric
    gates (CVSS, AV:N, ActionableScore, current severity).
    """
    if getattr(output, "_kernel_kpanic_marked", None) is not True:
        return ""

    # Effective CVSS follows the same source precedence as H1-H15 and the
    # kpanic CVSS override: selected second-opinion CVSS first, primary fallback.
    try:
        effective_score = float(output.cvss3_score)
    except (TypeError, ValueError):
        effective_score = float("nan")
    effective_vector_raw = str(output.cvss3_vector or "")
    cvss_source = "primary"

    if second_opinion is not None:
        selected_score = getattr(second_opinion, "cvss_selected_score", None)
        selected_vector = getattr(second_opinion, "cvss_selected_vector", None)
        if selected_score is not None and selected_vector:
            try:
                parsed_selected = cvss.CVSS3(str(selected_vector))
                effective_score = float(parsed_selected.scores()[0])
                effective_vector_raw = str(selected_vector)
                cvss_source = "second_opinion_selected"
            except Exception as exc:
                logger.warning(
                    "%s: KPANIC_REVIEW invalid selected CVSS; "
                    "using primary fallback: %s",
                    call_str,
                    exc,
                )

    try:
        parsed_metrics = cvss.CVSS3(effective_vector_raw).metrics
        av_network = parsed_metrics.get("AV") == "N"
    except Exception:
        av_network = False

    actionable_score = (
        getattr(second_opinion, "actionable_score", None)
        if second_opinion is not None
        else None
    )
    if (
        actionable_score is not None
        and str(getattr(second_opinion, "primitive_class", "")).upper() == "CLASS_C"
        and getattr(second_opinion, "important_candidate", "NO") == "NO"
        and getattr(second_opinion, "auto_downgrade_allowed", "NO") == "YES"
        and actionable_score > 2
    ):
        actionable_score = 2

    lowered = bool(getattr(output, "_kernel_lowered", False))
    dec_cnt = int(getattr(output, "_kernel_decrease_count", 0) or 0)
    kpanic_marked = bool(getattr(output, "_kernel_kpanic_marked", False))
    traces: list[str] = []

    # Perl branch 1:
    #
    # if($rv == 0 && KPANIC && severity == MODERATE &&
    #    $sc <= 7.8 && $rs !~ /AV:N/ && $alimpactscore < 5)
    #
    # Structured interpretation:
    # this branch is specifically the false-positive KPANIC removal branch,
    # so gate it on kernel_panic_supported == false.
    if (
        not review.kernel_panic_supported
        and kpanic_marked
        and output.impact == "MODERATE"
        and effective_score <= 7.8
        and not av_network
        and actionable_score is not None
        and actionable_score < 5
    ):
        kpanic_marked = False
        lowered = True
        dec_cnt += 1
        traces.append(
            "KPANIC_LLM:DECREASED_TO_MODERATEREG_BASED_ON_FALSEPOSCHECKOFKP"
        )

    # Perl branch 2:
    #
    # if($rv == 0 && KPANIC && severity == IMPORTANT &&
    #    $sc < 9 && $rs !~ /AV:N/ && $alimpactscore <= 8)
    #
    # Structured interpretation:
    # allow_high_to_moderate7_downgrade controls the HIGH->MODERATE7 decision.
    # If panic itself was also rejected, do not preserve a false KPANIC marker.
    if (
        review.allow_high_to_moderate7_downgrade
        and kpanic_marked
        and output.impact == "IMPORTANT"
        and effective_score < 9.0
        and not av_network
        and actionable_score is not None
        and actionable_score <= 8
    ):
        output.impact = "MODERATE"
        kpanic_marked = bool(review.kernel_panic_supported)
        lowered = True
        dec_cnt += 1
        traces.append(
            "KPANIC_LLM:DECREASED_TO_MODERATE7_BASED_ON_FALSEPOSCHECKOFKP"
        )

    # NEW29_POST_KPANIC_AS4_CONSISTENCY_RESTORE:
    # AS4 stays unchanged. Restore only after the specialized KPANIC review.
    primitive_class = (str(getattr(second_opinion, "primitive_class", "") or "").upper()
                       if second_opinion is not None else "")
    important_candidate = (str(getattr(second_opinion, "important_candidate", "") or "").upper()
                           if second_opinion is not None else "")
    auto_downgrade_allowed = (str(getattr(second_opinion, "auto_downgrade_allowed", "") or "").upper()
                              if second_opinion is not None else "")

    restore_as4_important = (
        bool(getattr(output, "_kernel_as4_downgraded_from_important", False))
        and output.impact == "MODERATE"
        and kpanic_marked
        and not review.allow_high_to_moderate7_downgrade
        and primitive_class == "CLASS_B"
        and important_candidate == "YES"
        and auto_downgrade_allowed == "NO"
    )
    if restore_as4_important:
        output.impact = "IMPORTANT"
        traces.append("NEW29:RESTORED_IMPORTANT_AFTER_AS4_FROM_KPANIC_CONSISTENCY")
        logger.info(
            "%s: NEW29 restored IMPORTANT after AS4: CLASS_B + "
            "ImportantCandidate=YES + AutoDowngradeAllowed=NO + "
            "KPANIC allow_high_to_mod7=NO", call_str
        )

    output._kernel_kpanic_marked = kpanic_marked
    output._kernel_lowered = lowered
    output._kernel_decrease_count = dec_cnt
    _sync_output_operational_kpanic_flag(output)

    summary = (
        "kpanic_llm_review("
        f"panic_supported={'YES' if review.kernel_panic_supported else 'NO'},"
        f" evidence_level={review.evidence_level},"
        f" high_without_panic="
        f"{'YES' if review.high_severity_still_supported_without_kpanic else 'NO'},"
        f" allow_high_to_mod7="
        f"{'YES' if review.allow_high_to_moderate7_downgrade else 'NO'},"
        f" cvss_source={cvss_source},"
        f" llm_cvss={effective_score},"
        f" actionable_score={actionable_score},"
        f" kpanic_marked={'YES' if kpanic_marked else 'NO'},"
        f" lowered={'YES' if lowered else 'NO'},"
        f" dec_cnt={dec_cnt}"
        ")"
    )
    if traces:
        summary += "; " + "; ".join(traces)

    logger.info("%s: %s", call_str, summary)
    return summary


# ===========================================================================
# NN+LLM-compatible request_llm_afterpushedtohigh() result application
# ===========================================================================


def apply_afterpushed_llm_review(
    output,
    call_str: str,
    review,
    second_opinion=None,
) -> str:
    """Apply the old after-pushed-to-HIGH false-positive correction.

    Legacy Perl inner gate:
        rv == 1
        && KPANIC
        && severity == HIGH
        && sc < 10
        && ActionableScore <= 9

    ``review.downgrade_to_moderate7`` is the structured equivalent of rv == 1.
    """
    if not review.downgrade_to_moderate7:
        return (
            "afterpushed_llm_review(downgrade=NO, result=IMPORTANT-retained)"
        )

    if not getattr(output, "_kernel_pushed_to_high", False):
        return ""
    if output.impact != "IMPORTANT":
        return ""
    if getattr(output, "_kernel_kpanic_marked", None) is not True:
        return ""

    # NEW28_BROAD_AFTERPUSHED_GUARD_REMOVED
    # The dedicated AFTERPUSHED review is later and more specific than
    # the early ActionableScore CLASS_B/ImportantCandidate fields.
    # Do not veto its downgrade solely from that early triple.
    try:
        effective_score = float(output.cvss3_score)
    except (TypeError, ValueError):
        effective_score = float("nan")
    effective_vector_raw = str(output.cvss3_vector or "")
    cvss_source = "primary"

    if second_opinion is not None:
        selected_score = getattr(second_opinion, "cvss_selected_score", None)
        selected_vector = getattr(second_opinion, "cvss_selected_vector", None)
        if selected_score is not None and selected_vector:
            try:
                parsed_selected = cvss.CVSS3(str(selected_vector))
                effective_score = float(parsed_selected.scores()[0])
                effective_vector_raw = str(selected_vector)
                cvss_source = "second_opinion_selected"
            except Exception as exc:
                logger.warning(
                    "%s: AFTERPUSHED_REVIEW invalid selected CVSS; using primary fallback: %s",
                    call_str,
                    exc,
                )

    actionable_score = (
        getattr(second_opinion, "actionable_score", None)
        if second_opinion is not None
        else None
    )
    if (
        actionable_score is not None
        and str(getattr(second_opinion, "primitive_class", "")).upper() == "CLASS_C"
        and getattr(second_opinion, "important_candidate", "NO") == "NO"
        and getattr(second_opinion, "auto_downgrade_allowed", "NO") == "YES"
        and actionable_score > 2
    ):
        actionable_score = 2

    if not math.isfinite(effective_score):
        return ""
    if not (effective_score < 10.0):
        return ""
    if actionable_score is None or actionable_score > 9:
        return ""

    output.impact = "MODERATE"
    output._kernel_lowered = True
    output._kernel_decrease_count = int(
        getattr(output, "_kernel_decrease_count", 0) or 0
    ) + 1
    # Legacy afterpushed downgrade is specifically HIGH -> MODERATE7.
    output._kernel_kpanic_marked = True
    _sync_output_operational_kpanic_flag(output)

    trace = (
        "afterpushed_llm_review("
        "downgrade=YES,"
        f" cvss_source={cvss_source},"
        f" llm_cvss={effective_score},"
        f" actionable_score={actionable_score},"
        " kpanic_marked=YES,"
        f" dec_cnt={output._kernel_decrease_count}"
        "); "
        "AFTERPUSHED_LLM:DECREASED_TO_MODERATE7_BASED_ON_FALSEPOSCHECKOFDH"
    )
    logger.info("%s: %s", call_str, trace)
    return trace


# ===========================================================================
# CVSS override for kernel panic / IMPORTANT impact
# ===========================================================================

#: Canonical ordering of CVSS v3.1 base metric keys used when
#: reconstructing a vector string from individual metric values.
_CVSS_BASE_KEYS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def apply_kpanic_cvss_override(
    output,
    call_str: str,
    classifier_result: dict | None,
    second_opinion=None,
) -> str | None:
    """Override CVSS components when kernel_panic is detected or impact
    is IMPORTANT.

    Forces ``AC:H``, ``S:U``, ``A:H`` to reflect kernel-panic
    reachability without assuming user-data exposure.

    A.Larkin effective-CVSS plumbing:
    use the independently computed second-opinion ``CVSSSelected`` pair
    when it is present and valid. The primary SuggestImpact CVSS is a
    fail-open fallback only. This keeps final kpanic normalization on
    the same CVSS source already consumed by H1-H15 / AS1-AS7.

    Returns a trace fragment when the override fires, or ``None``.
    """
    # -------------------------------------------------------------
    # A.Larkin operational-KPANIC CVSS override gate v2.
    #
    # The classifier's literal kernel_panic/kernel_panic_plus_uaf
    # feature is only initial evidence. reconcile_kernel() maintains
    # the Perl-compatible mutable operational KPANIC state and stores
    # its FINAL value in output._kernel_kpanic_marked.
    #
    # If reconciliation explicitly removed KPANIC, do not let this
    # later CVSS post-processing step resurrect stale classifier panic
    # semantics and rewrite CVSS.
    #
    # None means reconciliation did not provide final state; in that
    # compatibility case the existing function behavior is preserved.
    # -------------------------------------------------------------
    final_kpanic = getattr(output, "_kernel_kpanic_marked", None)
    if final_kpanic is False:
        logger.info(
            "%s: skipping kpanic CVSS override because final "
            "operational kpanic_marked=NO",
            call_str,
        )
        return ""

    if not classifier_result or not isinstance(classifier_result, dict):
        return None

    active_features: set[str] = set(classifier_result.get("active_features", []))
    literal_kpanic = (
        "kernel_panic" in active_features
        or "kernel_panic_plus_uaf" in active_features
    )
    # Final mutable state is authoritative; None keeps compatibility fallback.
    has_kpanic = final_kpanic is True or (final_kpanic is None and literal_kpanic)
    is_important = output.impact == "IMPORTANT"

    if output.impact == "CRITICAL":
        return None

    if not (has_kpanic or is_important):
        return None

    # -------------------------------------------------------------
    # A.Larkin effective selected-CVSS input for kpanic override.
    #
    # BEFORE:
    #   H1-H15/AS1-AS7 used second_opinion.cvss_selected_* when valid,
    #   but this later override restarted from output.cvss3_* (primary).
    #   That could resurrect primary C/I/AC decisions after reconciliation.
    #
    # AFTER:
    #   Prefer the exact selected vector produced by the second-opinion
    #   parser. Re-validate it at this boundary and derive score from
    #   the vector. Missing/malformed selected data fails open to the
    #   historical primary output.cvss3_* values.
    # -------------------------------------------------------------
    primary_vector = str(output.cvss3_vector or "")
    primary_score = output.cvss3_score

    effective_vector = primary_vector
    effective_score = primary_score
    cvss_source = "primary"

    if second_opinion is not None:
        selected_score = getattr(second_opinion, "cvss_selected_score", None)
        selected_vector = getattr(second_opinion, "cvss_selected_vector", None)

        if selected_score is not None and selected_vector:
            try:
                selected_vector = str(selected_vector).strip()
                selected_parsed = cvss.CVSS3(selected_vector)
                selected_score_from_vector = float(selected_parsed.scores()[0])
                selected_score_float = float(selected_score)

                if abs(selected_score_float - selected_score_from_vector) > 1e-9:
                    logger.info(
                        "%s: kpanic override selected CVSS score/vector mismatch "
                        "%.1f != %.1f; using vector-derived score",
                        call_str,
                        selected_score_float,
                        selected_score_from_vector,
                    )

                effective_vector = selected_vector
                effective_score = selected_score_from_vector
                cvss_source = "second_opinion_selected"
            except Exception as exc:
                logger.warning(
                    "%s: invalid second-opinion selected CVSS at kpanic override "
                    "boundary; using primary CVSS: %s",
                    call_str,
                    exc,
                )
        elif selected_score is not None or selected_vector:
            logger.warning(
                "%s: incomplete second-opinion selected CVSS at kpanic override "
                "boundary; using primary CVSS",
                call_str,
            )

    original_vector = effective_vector
    original_score = effective_score

    parsed = cvss.CVSS3(original_vector)
    parsed.metrics.update({"AC": "H", "S": "U", "A": "H"})
    output.cvss3_vector = "CVSS:3.1/" + "/".join(
        f"{k}:{parsed.metrics[k]}" for k in _CVSS_BASE_KEYS
    )
    output.cvss3_score = str(cvss.CVSS3(output.cvss3_vector).scores()[0])

    reason = "kernel_panic" if has_kpanic else "important_impact"
    trace = (
        f"kpanic_cvss_override({reason},"
        f" cvss_source={cvss_source},"
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
    """Accept when a classifier result is available (eagerly pre-computed or
    via tool call).  Retry only when neither source produced a result and the
    LLM has not yet attempted kernel_impact_tool."""
    use_clf = get_settings().use_kernel_classifier
    is_kernel = getattr(deps, "is_kernel_cve", False)

    if not (use_clf and is_kernel and hasattr(output, "cvss3_vector")):
        return None

    clf_result = getattr(deps, "classifier_result", None)
    if clf_result is not None:
        return None

    attempts = getattr(deps, "classifier_attempts", 0)
    if attempts > 0:
        logger.warning(
            "kernel_impact_tool was called but returned no classifier data for this CVE"
        )
        return None

    logger.warning(
        "kernel_impact_tool was not called for a kernel CVE; requesting retry"
    )
    return (
        "This is a Linux kernel CVE. You MUST call kernel_impact_tool "
        "to obtain patch-level analysis before producing your final answer."
    )
