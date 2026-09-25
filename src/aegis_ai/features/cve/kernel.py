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

# A.Larkin RH-IMPORTANT safety floor: use only concrete patch-level corruption
# evidence here.  Broad hints such as "danger"/"memory" are intentionally not
# sufficient by themselves for this Important-preserving floor.
CONCRETE_MEMORY_CORRUPTION_FLAGS = {
    "uaf",
    "kernel_panic_plus_uaf",
    "write",
    "outofbounds",
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
    # Structured ActionableScore lifetime signal.  Keep this separate from
    # classifier flags so deterministic rules can distinguish a confirmed
    # real UAF from a generic patch-level "uaf" hint.
    actionable_real_uaf: bool = False
    # NEW45 structured old-allocation/new-bound OOB subtype.
    actionable_b5_oob: bool = False
    # NEW46 narrow H1 protection signals. These are deliberately separate:
    # clean-fix evidence and COW/shared-backing evidence are different reasons
    # to preserve a strong CLASS_A result across H1.
    actionable_clean_fix_protection: bool = False
    actionable_cow_ownership_violation: bool = False
    # NEW48: narrow structured authorization-bypass preservation evidence.
    # This is independent of CleanFixProtection so a stable, patch-established
    # authorization decision bypass does not depend on whether the model calls
    # the fix itself "clean".
    actionable_authorization_bypass: bool = False
    actionable_important_candidate: bool = False
    actionable_manual_review: str = ""
    actionable_auto_downgrade_allowed: bool = False
    actionable_recommended_impact: str = ""
    # NEW51: provenance for the narrow AS8 CLASS_A+COW promotion.  This is
    # exported after reconciliation so later precision reviews cannot erase the
    # exact deterministic preservation decision that created IMPORTANT.
    as8_cow_preservation: bool = False

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
    # NEW47 provenance bit: H11 preserved IMPORTANT because the same narrow
    # strong-CLASS_A + clean-fix evidence used by NEW46 explicitly vetoed the
    # PR:H/CVSS<8 downgrade. AS4 must not immediately erase that preservation.
    h11_clean_fix_preserved: bool = False
    # NEW48 provenance bit: H11 preserved IMPORTANT because a narrow concrete
    # authorization decision/security-check bypass was established.
    h11_authorization_bypass_preserved: bool = False
    # NEW41 provenance bit: H13 created MODERATE7 specifically because the
    # primary structured analysis required manual review.  AS6 must not
    # immediately erase that operational review decision.
    h13_fired: bool = False
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


def _second_opinion_b5_oob(second_opinion) -> bool:
    """Read NEW45 B5OOB without scraping free-form reasoning prose.

    Prefer a parsed ``b5_oob`` attribute when the second-opinion schema exposes
    it. For compatibility with the current parser, accept only the exact
    mandatory machine-header line ``B5OOB=YES|NO`` retained in raw_response.
    """
    if second_opinion is None:
        return False
    parsed = getattr(second_opinion, "b5_oob", None)
    if parsed is not None:
        return str(parsed).strip().upper() == "YES"
    raw = str(getattr(second_opinion, "raw_response", "") or "")
    match = re.search(r"(?m)^[ \t]*B5OOB[ \t]*=[ \t]*(YES|NO)[ \t]*$", raw)
    return bool(match and match.group(1) == "YES")


def _second_opinion_clean_fix_protection(second_opinion) -> bool:
    """Read NEW46 CleanFixProtection without scraping free-form prose.

    Prefer a parsed ``clean_fix_protection`` attribute when the second-opinion
    schema exposes it. For compatibility with the current parser, accept only
    the exact mandatory machine-header line ``CleanFixProtection=YES|NO``.
    """
    if second_opinion is None:
        return False
    parsed = getattr(second_opinion, "clean_fix_protection", None)
    if parsed is not None:
        return str(parsed).strip().upper() == "YES"
    raw = str(getattr(second_opinion, "raw_response", "") or "")
    match = re.search(
        r"(?m)^[ \t]*CleanFixProtection[ \t]*=[ \t]*(YES|NO)[ \t]*$",
        raw,
    )
    return bool(match and match.group(1) == "YES")


def _second_opinion_cow_ownership_violation(second_opinion) -> bool:
    """Read NEW46 COWOwnershipViolation without scraping free-form prose.

    Prefer a parsed ``cow_ownership_violation`` attribute when available.
    Otherwise accept only the exact mandatory machine-header line
    ``COWOwnershipViolation=YES|NO`` retained in raw_response.
    """
    if second_opinion is None:
        return False
    parsed = getattr(second_opinion, "cow_ownership_violation", None)
    if parsed is not None:
        return str(parsed).strip().upper() == "YES"
    raw = str(getattr(second_opinion, "raw_response", "") or "")
    match = re.search(
        r"(?m)^[ \t]*COWOwnershipViolation[ \t]*=[ \t]*(YES|NO)[ \t]*$",
        raw,
    )
    return bool(match and match.group(1) == "YES")


def _second_opinion_authorization_bypass(second_opinion) -> bool:
    """Read NEW48 AuthorizationBypass without scraping free-form prose.

    Prefer a parsed ``authorization_bypass`` attribute when the second-opinion
    schema exposes it. Otherwise accept only the exact mandatory machine-header
    line ``AuthorizationBypass=YES|NO`` retained in raw_response.
    """
    if second_opinion is None:
        return False
    parsed = getattr(second_opinion, "authorization_bypass", None)
    if parsed is not None:
        return str(parsed).strip().upper() == "YES"
    raw = str(getattr(second_opinion, "raw_response", "") or "")
    match = re.search(
        r"(?m)^[ \t]*AuthorizationBypass[ \t]*=[ \t]*(YES|NO)[ \t]*$",
        raw,
    )
    return bool(match and match.group(1) == "YES")


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

    # NEW46: do not use CLASS_A itself as a generic H1 veto.  H1 is protected
    # only when CLASS_A is accompanied by one of two independently structured,
    # narrowly defined patch-mechanics signals plus the existing conservative
    # Important-preservation decision.
    strong_class_a = (
        ctx.actionable_primitive.upper() == "CLASS_A"
        and ctx.actionable_important_candidate
        and ctx.actionable_manual_review.upper() == "REQUIRED"
        and not ctx.actionable_auto_downgrade_allowed
    )

    # NEW46 / 64600 regression target: a clean/minimal fix is NOT sufficient.
    # The second opinion must explicitly say that the fix itself cleanly exposes
    # and removes the concrete CLASS_A security mechanism.
    if strong_class_a and ctx.actionable_clean_fix_protection:
        return RuleEffect(
            trace="H1_GUARD:clean_fix_protection",
        )

    # NEW46 / 46333 regression target: preserve separately when the established
    # CLASS_A primitive is a concrete cross-boundary COW/shared-backing ownership
    # violation. Keep this distinct from the clean-fix reason for diagnostics.
    if strong_class_a and ctx.actionable_cow_ownership_violation:
        return RuleEffect(
            trace="H1_GUARD:COW_ownership_violation",
        )

    # NEW48 / 46333: preserve when technical evidence independently establishes
    # that a concrete existing authorization decision/security check was bypassed
    # and the patch directly restores that same check. This does not depend on
    # the model also deciding CleanFixProtection=YES.
    if strong_class_a and ctx.actionable_authorization_bypass:
        return RuleEffect(
            trace="H1_GUARD:authorization_bypass",
        )

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
    return RuleEffect(
        trace="H3:MOD->MOD7(perl_guesscvss)", flags={"kpanic_marked": True}
    )


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
    #
    # NEW41: do not auto-close a second-opinion-confirmed real UAF that is
    # classified as CLASS_B.  Host-admin requirements may keep the issue out
    # of IMPORTANT, but they do not turn a real CLASS_B lifetime primitive
    # into an automatically safe LOW.
    if (
        ctx.severity != MOD
        or ctx.llm_cvss >= 5.5
        or not _cia_local_low_shape(ctx)
        or ctx.cia_hhh
        or ctx.primary_manual_review == "YES"
        or ctx.kpanic_marked
        or ctx.lowered
        or (ctx.actionable_primitive.upper() == "CLASS_B" and ctx.actionable_real_uaf)
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
        trace="H9:MOD7->MODREG(cvss<=4.5,preserve_kpanic)",
        flags={
            # NEW54: H9 may lower policy state, but it must not destroy the
            # operational KPANIC/MODERATE7 provenance.  NEW53's specialized
            # review owns the explicit decision to remove that marker.
            "lowered": True,
            "decreased_marker": True,
            "decreased": True,
        },
    )


def h10(ctx: RuleContext) -> RuleEffect | None:
    # PERL: MOD + sc<=5.5 + local low-CIA + !HHH + KPANIC + !$lowered
    # -> regular MODERATE, remove KPANIC.
    #
    # NEW41: H10 is a false-positive KPANIC remover, so do not let it erase
    # MODERATE7 when the independent ActionableScore analysis says CLASS_B
    # and patch/structured evidence independently establishes concrete memory
    # corruption (OOB write/write/UAF).  This preserves analyst review; it
    # does NOT promote the CVE to IMPORTANT.
    actionable_class_b_concrete_corruption = (
        ctx.actionable_primitive.upper() == "CLASS_B"
        and (
            ctx.actionable_real_uaf
            or bool(ctx.active_features & CONCRETE_MEMORY_CORRUPTION_FLAGS)
        )
    )
    if (
        ctx.severity != MOD
        or ctx.llm_cvss > 5.5
        or not _cia_local_low_shape(ctx)
        or ctx.cia_hhh
        or not ctx.kpanic_marked
        or ctx.lowered
        or actionable_class_b_concrete_corruption
    ):
        return None
    return RuleEffect(
        trace="H10:MOD7->MODREG(local_low_CIA,preserve_kpanic)",
        flags={
            # NEW54: preserve the operational marker through H10.  Whether
            # extended KPANIC/MODERATE7 review is no longer needed is now an
            # explicit NEW53 review decision (remove_operational_kpanic=true).
            "lowered": True,
            "decreased_marker": True,
            "decreased": True,
        },
    )


def h11(ctx: RuleContext) -> RuleEffect | None:
    # PERL: HIGH + sc<8.0 + PR:H + !$lowered -> MODERATE7/KPANIC.
    if ctx.severity != IMP or ctx.llm_cvss >= 8.0 or not ctx.pr_h_only or ctx.lowered:
        return None

    # NEW47 / 46333: H11's broad PR:H reduction must not erase an independently
    # established CLASS_A authorization/security-boundary primitive when the
    # second opinion also says that the patch directly and cleanly exposes and
    # fixes that SAME primitive. CleanFixProtection alone is intentionally not
    # sufficient: require the full conservative Important-preservation state.
    #
    # Keep this narrower than NEW46/H1: COWOwnershipViolation is not a generic
    # H11 veto. The observed 46333 regression is specifically the clean-fix
    # authorization-bypass case.
    strong_class_a_clean_fix = (
        ctx.actionable_primitive.upper() == "CLASS_A"
        and ctx.actionable_important_candidate
        and ctx.actionable_manual_review.upper() == "REQUIRED"
        and not ctx.actionable_auto_downgrade_allowed
        and ctx.actionable_clean_fix_protection
    )
    if strong_class_a_clean_fix:
        return RuleEffect(
            trace="H11_GUARD:clean_fix_protection",
            flags={"h11_clean_fix_preserved": True},
        )

    # NEW48: the same narrow concrete authorization-bypass evidence that may
    # preserve H1 must also survive H11's generic PR:H/CVSS<8 reduction.
    # Require the complete strong CLASS_A preservation state; the structured
    # AuthorizationBypass flag alone is never sufficient.
    strong_class_a_authorization_bypass = (
        ctx.actionable_primitive.upper() == "CLASS_A"
        and ctx.actionable_important_candidate
        and ctx.actionable_manual_review.upper() == "REQUIRED"
        and not ctx.actionable_auto_downgrade_allowed
        and ctx.actionable_authorization_bypass
    )
    if strong_class_a_authorization_bypass:
        return RuleEffect(
            trace="H11_GUARD:authorization_bypass",
            flags={"h11_authorization_bypass_preserved": True},
        )

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
    #
    # NEW41: remember that H13 itself created MODERATE7.  AS6 runs later and
    # must not immediately cancel a manual-review promotion made by H13.
    if ctx.severity != LOW or ctx.primary_manual_review != "YES":
        return None
    return RuleEffect(
        severity=MOD,
        trace="H13:LOW->MOD7(primary_manual_check=YES)",
        flags={"kpanic_marked": True, "h13_fired": True},
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
        return RuleEffect(
            severity=band_rank, trace=f"G1:llm_band_floor({IMPACT_LABELS[band_rank]})"
        )
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
        return RuleEffect(
            severity=IMP, trace=f"G4:ext_cvss_confirms_imp({ctx.clf_cvss_score:.1f})"
        )
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
    return RuleEffect(
        severity=MOD, trace="AS1:score>=5->MOD7", flags={"kpanic_marked": True}
    )


def as2(ctx: RuleContext) -> RuleEffect | None:
    # PERL: AS>5 && severity>=1 && KPANIC -> HIGH; pushed_to_high=1.
    s = ctx.actionable_score
    if s is None or s <= 5 or ctx.severity < MOD or not ctx.kpanic_marked:
        return None
    return RuleEffect(
        severity=IMP, trace="AS2:score>5+KPANIC->IMP", flags={"pushed_to_high": True}
    )


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
    #
    # NEW47: if H11 just preserved IMPORTANT on the narrow strong-CLASS_A +
    # clean-fix condition, AS4 must not immediately erase the same decision
    # solely because the numeric ActionableScore is <6. This provenance veto
    # applies only to the H11 preservation path; ordinary AS4 behavior is
    # unchanged.
    s = ctx.actionable_score
    if (
        s is None
        or s >= 6
        or ctx.severity != IMP
        or ctx.llm_cvss > 7.0
        or ctx.h11_clean_fix_preserved
        or ctx.h11_authorization_bypass_preserved
    ):
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
    return RuleEffect(
        severity=MOD, trace="AS5:LOW->MOD7(score>=3)", flags={"kpanic_marked": True}
    )


def as6(ctx: RuleContext) -> RuleEffect | None:
    # PERL originally used AS<4 to collapse HIGH/MODERATE7 to regular MODERATE
    # and remove KPANIC.  In the staged Aegis pipeline that conflates two
    # independent decisions: ActionableScore may reject Important-grade impact,
    # but it does not adjudicate whether the operational KPANIC/MODERATE7 review
    # state is still required.  Preserve an already-established kpanic_marked so
    # the dedicated KPANIC review can make that later decision.
    #
    # NEW41 preservation guards remain unchanged:
    #   1. ManualReview=REQUIRED + AutoDowngradeAllowed=NO is an explicit
    #      second-opinion veto against automatic reduction.
    #   2. If H13 just promoted LOW -> MOD7 because the primary analysis
    #      required manual review, AS6 must not immediately undo H13 merely
    #      because the numeric ActionableScore is below 4.
    #
    # NEW52: AS6 may still reduce IMPORTANT -> MODERATE, set lowered/decrease
    # bookkeeping, and leave an existing MODERATE severity unchanged; however,
    # it MUST NOT clear kpanic_marked.  Omitting that flag from RuleEffect keeps
    # the current operational marker intact.
    s = ctx.actionable_score
    if (
        s is None
        or s >= 4
        or ctx.severity > MOD
        or not ctx.kpanic_marked
        or (
            ctx.actionable_manual_review.upper() == "REQUIRED"
            and not ctx.actionable_auto_downgrade_allowed
        )
        or ctx.h13_fired
    ):
        return None
    return RuleEffect(
        severity=MOD,
        trace="AS6:IMP/MOD7->MOD7(score<4,preserve_kpanic)",
        flags={
            "lowered": True,
            "decrease_count": ctx.decrease_count + 1,
            "decreased_marker": True,
        },
    )


def as7(ctx: RuleContext) -> RuleEffect | None:
    # A.Larkin false-LOW calibration v1.
    #
    # Legacy Perl only vetoed AS7 on the primary "YES REQUIRES MANUAL CHECK"
    # text predicate.  In the structured two-opinion pipeline that is too weak:
    # ManualReview=RECOMMENDED from the independent ActionableScore pass was
    # effectively treated the same as NO, so a low numeric score could become
    # the final authority and auto-close an otherwise Moderate case.
    #
    # LOW is an auto-close class, therefore AS7 now requires affirmative
    # agreement from the second opinion that:
    #   * ManualReview == NO; and
    #   * AutoDowngradeAllowed == YES.
    #
    # REQUIRED and RECOMMENDED are both vetoes for AS7.  This intentionally
    # changes only the MODERATE->LOW boundary; it does not introduce the broader
    # feature/CVSS hard veto discussed separately.
    s = ctx.actionable_score
    if (
        s is None
        or s >= 3
        or ctx.severity != MOD
        or ctx.primary_manual_review == "YES"
        or ctx.actionable_manual_review == "REQUIRED"
        or ctx.primary_nullptr_related
        or not ctx.actionable_auto_downgrade_allowed
        or ctx.decrease_count >= 2
    ):
        return None
    return RuleEffect(
        severity=LOW,
        trace="AS7:MOD->LOW(score<3+primary_no_required_manual"
        "+actionable_manual!=REQUIRED+not_primary_nullptr"
        "+auto_downgrade=YES)",
        flags={
            "kpanic_marked": False,
            "lowered": True,
            "decrease_count": ctx.decrease_count + 1,
            "decreased_marker": True,
        },
    )


def as8(ctx: RuleContext) -> RuleEffect | None:
    """NEW51: promote the narrow strong CLASS_A shared-backing/COW state.

    This rule is intentionally independent of numeric ActionableScore and CVSS.
    The second opinion must simultaneously establish the concrete COW/ownership
    primitive and its conservative Important-preservation policy state.
    """
    if (
        ctx.severity != MOD
        or ctx.actionable_primitive.upper() != "CLASS_A"
        or not ctx.actionable_cow_ownership_violation
        or not ctx.actionable_important_candidate
        or ctx.actionable_manual_review.upper() != "REQUIRED"
        or ctx.actionable_auto_downgrade_allowed
    ):
        return None
    return RuleEffect(
        severity=IMP,
        trace="AS8:CLASS_A+COW+important_preserving->IMP",
        flags={
            "pushed_to_high": True,
            "as8_cow_preservation": True,
        },
    )


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
    h12,
    h13,
    h14,
    h15,
]

# BEFORE: [g1, g2, g3, g4].
# AFTER: disabled for NN parity.
# WHY: supplied Perl block has no equivalent unconditional G1-G4 floors.
GUARDRAIL_RULES: list[Callable[[RuleContext], RuleEffect | None]] = []

# NEW56: AS7 is deliberately deferred until AFTER the specialized KPANIC and
# AFTERPUSHED reviews.  LOW is an auto-close terminal state, so a single
# ActionableScore turn must not have destructive authority before independent
# review has had a chance to inspect the same kernel/patch evidence.
ACTIONABLE_RULES: list[Callable[[RuleContext], RuleEffect | None]] = [
    as1,
    as2,
    as3,
    as4,
    as5,
    as6,
    as8,
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
            parts.append(f"actionable_recommended={ctx.actionable_recommended_impact}")
        parts.append(
            "actionable_clean_fix_protection="
            + ("YES" if ctx.actionable_clean_fix_protection else "NO")
        )
        parts.append(
            "actionable_cow_ownership_violation="
            + ("YES" if ctx.actionable_cow_ownership_violation else "NO")
        )
        parts.append(
            "actionable_authorization_bypass="
            + ("YES" if ctx.actionable_authorization_bypass else "NO")
        )
        # AutoDowngradeAllowed is retained for diagnostics and participates
        # only in narrowly defined preservation guards such as NEW46.

    if actionable_applied:
        parts.append(f"actionable_rules=[{', '.join(actionable_applied)}]")

    # Perl mutable state, exposed explicitly for one-to-one log comparison.
    parts.append(f"kpanic_marked={'YES' if ctx.kpanic_marked else 'NO'}")
    parts.append(f"lowered={'YES' if ctx.lowered else 'NO'}")
    parts.append(f"dec_cnt={ctx.decrease_count}")
    parts.append(f"pushed_to_high={'YES' if ctx.pushed_to_high else 'NO'}")
    parts.append(
        "h11_clean_fix_preserved=" + ("YES" if ctx.h11_clean_fix_preserved else "NO")
    )
    parts.append(
        "h11_authorization_bypass_preserved="
        + ("YES" if ctx.h11_authorization_bypass_preserved else "NO")
    )
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


def _effective_primary_nullptr_related(
    output, active_features: set[str] | list[str]
) -> bool:
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
    AS1-AS6/AS8 rules; AS7 is deferred post-review. Historical G1-G4 are disabled here. The asynchronous
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
                        f"selected CVSS vector missing base metrics: {sorted(missing)}"
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

    # A.Larkin false-LOW calibration v1.
    #
    # The old CLASS_C consistency cap forced every qualifying score >2 down to
    # 2.  Because AS7 uses score <3 as its LOW threshold, the cap itself could
    # manufacture an auto-close condition (e.g. a score of 3 became 2).
    #
    # Keep the cap only for clearly bounded CLASS_C cases:
    #   * second opinion explicitly says no manual review is needed;
    #   * automatic downgrade is explicitly allowed;
    #   * selected/effective CVSS is below 5.5;
    #   * neither confidentiality nor integrity impact is present.
    #
    # This still permits the intended CLASS_C normalization for genuinely
    # low-impact correctness/DoS-like cases, but prevents the cap from turning
    # cryptographic or otherwise security-significant C/I cases into LOW.
    effective_actionable_score = (
        getattr(second_opinion, "actionable_score", None)
        if second_opinion is not None
        else None
    )
    class_c_cap_safe = (
        second_opinion is not None
        and str(getattr(second_opinion, "primitive_class", "")).upper() == "CLASS_C"
        and getattr(second_opinion, "important_candidate", "NO") == "NO"
        and getattr(second_opinion, "auto_downgrade_allowed", "NO") == "YES"
        and getattr(second_opinion, "manual_review", "") == "NO"
        and not math.isnan(llm_cvss)
        and llm_cvss < 5.5
        and llm_vector.get("C") == "N"
        and llm_vector.get("I") == "N"
    )
    if (
        effective_actionable_score is not None
        and effective_actionable_score > 2
        and class_c_cap_safe
    ):
        logger.info(
            "%s: deterministic CLASS_C ActionableScore cap %s -> 2 "
            "(bounded CLASS_C, ManualReview=NO, AutoDowngradeAllowed=YES, "
            "CVSS<5.5, C:N/I:N)",
            call_str,
            effective_actionable_score,
        )
        effective_actionable_score = 2
    elif (
        effective_actionable_score is not None
        and effective_actionable_score > 2
        and second_opinion is not None
        and str(getattr(second_opinion, "primitive_class", "")).upper() == "CLASS_C"
        and getattr(second_opinion, "important_candidate", "NO") == "NO"
        and getattr(second_opinion, "auto_downgrade_allowed", "NO") == "YES"
    ):
        logger.info(
            "%s: CLASS_C ActionableScore cap suppressed for false-LOW safety "
            "(score=%s manual_review=%s cvss=%s C=%s I=%s)",
            call_str,
            effective_actionable_score,
            getattr(second_opinion, "manual_review", ""),
            llm_cvss,
            llm_vector.get("C"),
            llm_vector.get("I"),
        )

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
        actionable_real_uaf=(
            getattr(second_opinion, "real_uaf", "NO") == "YES"
            if second_opinion is not None
            else False
        ),
        actionable_b5_oob=_second_opinion_b5_oob(second_opinion),
        actionable_clean_fix_protection=(
            _second_opinion_clean_fix_protection(second_opinion)
        ),
        actionable_cow_ownership_violation=(
            _second_opinion_cow_ownership_violation(second_opinion)
        ),
        actionable_authorization_bypass=(
            _second_opinion_authorization_bypass(second_opinion)
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
        primary_btrfs_context=bool(getattr(output, "kernel_btrfs_context", False)),
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

    # A.Larkin RH-IMPORTANT + CLASS_B concrete-corruption safety floor.
    #
    # This is deliberately narrow and runs AFTER H1-H15/AS1-AS7 so those rules
    # remain diagnostically visible.  Preserve IMPORTANT only when the independent
    # signals agree that an automatic downgrade is unsafe:
    #   1) Red Hat external CVSS is in the IMPORTANT band;
    #   2) second opinion says PrimitiveClass=CLASS_B;
    #   3) patch features contain concrete memory-corruption evidence;
    #   4) second opinion marks it ImportantCandidate=YES, ManualReview=REQUIRED,
    #      and AutoDowngradeAllowed=NO; and
    #   5) host-admin-equivalent privilege is NOT positively established.
    # HostAdminRequired=UNKNOWN is allowed here only with the strong structured
    # Important-preserving signals above; HostAdminRequired=YES vetoes the floor.
    host_admin_required = str(
        getattr(second_opinion, "host_admin_required", "UNKNOWN")
        if second_opinion is not None
        else "UNKNOWN"
    ).upper()
    rh_important_class_b_corruption_floor = (
        score_to_band(ctx.clf_cvss_score) == "IMPORTANT"
        and ctx.actionable_primitive.upper() == "CLASS_B"
        and bool(active_features & CONCRETE_MEMORY_CORRUPTION_FLAGS)
        and second_opinion is not None
        and ctx.actionable_important_candidate
        and ctx.actionable_manual_review.upper() == "REQUIRED"
        and not ctx.actionable_auto_downgrade_allowed
        and host_admin_required != "YES"
    )
    if rh_important_class_b_corruption_floor and ctx.severity > IMP:
        previous = IMPACT_LABELS.get(ctx.severity, str(ctx.severity))
        ctx.severity = IMP
        ctx.pushed_to_high = True
        actionable_applied.append(
            "SAFETY_FLOOR:RH_IMPORTANT+CLASS_B+concrete_corruption+important_preserving"
        )
        logger.info(
            "%s: RH IMPORTANT safety floor %s -> IMPORTANT "
            "(primitive=CLASS_B concrete_corruption=YES ImportantCandidate=YES "
            "ManualReview=REQUIRED AutoDowngradeAllowed=NO HostAdminRequired=%s)",
            call_str,
            previous,
            host_admin_required,
        )

    # NEW45: structured B5-OOB IMPORTANT-preservation floor.
    # Exact gate requested; no RH/NIST issuer or CVSS threshold participates.
    b5_oob_important_floor = (
        second_opinion is not None
        and ctx.actionable_primitive.upper() == "CLASS_B"
        and ctx.actionable_b5_oob
        and ctx.actionable_important_candidate
        and ctx.actionable_manual_review.upper() == "REQUIRED"
        and not ctx.actionable_auto_downgrade_allowed
        and host_admin_required == "NO"
    )
    if b5_oob_important_floor and ctx.severity > IMP:
        previous = IMPACT_LABELS.get(ctx.severity, str(ctx.severity))
        ctx.severity = IMP
        ctx.pushed_to_high = True
        actionable_applied.append(
            "SAFETY_FLOOR:B5_OOB+CLASS_B+important_preserving+non_host_admin"
        )
        logger.info(
            "%s: NEW45 B5-OOB safety floor %s -> IMPORTANT "
            "(PrimitiveClass=CLASS_B B5OOB=YES ImportantCandidate=YES "
            "ManualReview=REQUIRED AutoDowngradeAllowed=NO HostAdminRequired=NO)",
            call_str,
            previous,
        )

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
    output._kernel_as8_cow_preservation = ctx.as8_cow_preservation

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
        pr_none = parsed_metrics.get("PR") == "N"
    except Exception:
        av_network = False
        pr_none = False

    # NEW44 deterministic B8 preservation floor.
    #
    # The prompt is still responsible for the technical assessment, but once the
    # structured review and selected CVSS jointly establish the narrow B8 facts,
    # do not allow later stochastic false-positive stages to erase IMPORTANT:
    #   * demonstrated/explicit kernel crash,
    #   * direct network vector (AV:N),
    #   * unauthenticated attacker (PR:N),
    #   * ActionableScore says host-admin is not required,
    #   * no additional crash assumptions were reported.
    #
    # This deliberately does NOT infer C:H/I:H and does not promote severity.
    # It only preserves an IMPORTANT result that already exists.
    evidence_level = str(getattr(review, "evidence_level", "") or "").lower()
    additional_assumptions = getattr(review, "additional_assumptions_required", None)
    no_additional_assumptions = not additional_assumptions
    host_admin_required = (
        str(
            getattr(second_opinion, "host_admin_required", "UNKNOWN") or "UNKNOWN"
        ).upper()
        if second_opinion is not None
        else "UNKNOWN"
    )
    remote_crash_preservation = (
        bool(getattr(review, "kernel_panic_supported", False))
        and evidence_level in {"demonstrated", "explicit"}
        and av_network
        and pr_none
        and host_admin_required == "NO"
        and no_additional_assumptions
    )
    output._kernel_remote_crash_preservation = remote_crash_preservation

    if remote_crash_preservation and bool(
        getattr(review, "allow_high_to_moderate7_downgrade", False)
    ):
        logger.info(
            "%s: NEW44 B8 deterministic guard overrides "
            "allow_high_to_moderate7_downgrade=YES -> NO "
            "(panic_supported=YES evidence=%s AV=N PR=N HostAdminRequired=NO "
            "additional_assumptions=NONE)",
            call_str,
            evidence_level,
        )

    allow_high_to_moderate7_downgrade = bool(
        getattr(review, "allow_high_to_moderate7_downgrade", False)
    )
    if remote_crash_preservation:
        allow_high_to_moderate7_downgrade = False

    actionable_score = (
        getattr(second_opinion, "actionable_score", None)
        if second_opinion is not None
        else None
    )

    # Keep the specialized-review score consistent with reconcile_kernel().
    # The historical unconditional CLASS_C cap (>2 -> 2) could silently turn a
    # real ActionableScore=3 into 2 after reconciliation had deliberately
    # suppressed that cap for false-LOW safety.  Apply the same narrow cap here:
    # only bounded CLASS_C, ManualReview=NO, AutoDowngradeAllowed=YES,
    # selected/effective CVSS < 5.5, and C:N/I:N.
    try:
        actionable_metrics = (
            cvss.CVSS3(effective_vector_raw).metrics if effective_vector_raw else {}
        )
    except Exception:
        actionable_metrics = {}
    class_c_cap_safe = (
        second_opinion is not None
        and str(getattr(second_opinion, "primitive_class", "")).upper() == "CLASS_C"
        and getattr(second_opinion, "important_candidate", "NO") == "NO"
        and getattr(second_opinion, "auto_downgrade_allowed", "NO") == "YES"
        and getattr(second_opinion, "manual_review", "") == "NO"
        and math.isfinite(effective_score)
        and effective_score < 5.5
        and actionable_metrics.get("C") == "N"
        and actionable_metrics.get("I") == "N"
    )
    if actionable_score is not None and actionable_score > 2 and class_c_cap_safe:
        logger.info(
            "%s: specialized-review deterministic CLASS_C ActionableScore cap "
            "%s -> 2 (bounded CLASS_C, ManualReview=NO, "
            "AutoDowngradeAllowed=YES, CVSS<5.5, C:N/I:N)",
            call_str,
            actionable_score,
        )
        actionable_score = 2

    lowered = bool(getattr(output, "_kernel_lowered", False))
    dec_cnt = int(getattr(output, "_kernel_decrease_count", 0) or 0)
    kpanic_marked = bool(getattr(output, "_kernel_kpanic_marked", False))
    traces: list[str] = []

    # NEW51: B8 is not merely a HIGH-downgrade veto.  When the KPANIC review
    # explicitly classifies the case as the narrow B8 operational profile, let
    # that profile promote an existing MODERATE+KPANIC result to IMPORTANT.
    # Keep the deterministic gate deliberately stricter than free-form B8 prose:
    # machine profile B8, demonstrated/explicit panic, >=0.90 confidence, AV:N,
    # PR:N, HostAdminRequired=NO, and no additional crash assumptions.
    preservation_profile = str(
        getattr(review, "preservation_profile", "NONE") or "NONE"
    ).upper()
    b8_promote = (
        preservation_profile == "B8"
        and bool(getattr(review, "kernel_panic_supported", False))
        and evidence_level in {"demonstrated", "explicit"}
        and float(getattr(review, "confidence", 0.0) or 0.0) >= 0.90
        and av_network
        and pr_none
        and host_admin_required == "NO"
        and no_additional_assumptions
        and kpanic_marked
        and output.impact == "MODERATE"
    )
    if b8_promote:
        output.impact = "IMPORTANT"
        output._kernel_pushed_to_high = True
        # Share NEW44's deterministic AFTERPUSHED veto: the stricter NEW51 B8
        # promotion is a subset of that remote-crash preservation state.
        output._kernel_remote_crash_preservation = True
        traces.append("NEW51:B8_REMOTE_UNAUTHENTICATED_KERNEL_CRASH->IMPORTANT")
        logger.info(
            "%s: NEW51 B8 promoted MODERATE_KPANIC -> IMPORTANT "
            "(profile=B8 panic=YES evidence=%s confidence=%.2f AV=N PR=N "
            "HostAdminRequired=NO additional_assumptions=NONE)",
            call_str,
            evidence_level,
            float(review.confidence),
        )

    # NEW53: the old Perl branch 1 used rv==0 to collapse MODERATE7 to
    # regular MODERATE.  In the structured pipeline, factual
    # kernel_panic_supported=NO is not equivalent to the operational decision
    # that the KPANIC/MODERATE7 review marker is unnecessary.  Do not remove the
    # marker here.  A separate explicit removal rule runs after the HIGH->MOD7
    # branch below, so both pre-existing MOD7 and newly downgraded HIGH can be
    # considered by the same independent policy decision.

    # Perl branch 2:
    #
    # if($rv == 0 && KPANIC && severity == IMPORTANT &&
    #    $sc < 9 && $rs !~ /AV:N/ && $alimpactscore <= 8)
    #
    # Structured interpretation:
    # allow_high_to_moderate7_downgrade controls the HIGH->MODERATE7 decision.
    # If panic itself was also rejected, do not preserve a false KPANIC marker.
    if (
        allow_high_to_moderate7_downgrade
        and kpanic_marked
        and output.impact == "IMPORTANT"
        and effective_score < 9.0
        and not av_network
        and actionable_score is not None
        and actionable_score <= 8
    ):
        # NEW52: AS8 IMPORTANT is based on an independently established narrow
        # CLASS_A+COW preservation state, not on the KPANIC signal.  The KPANIC
        # review may therefore remove a false operational panic marker, but it
        # must not erase the severity decision created by AS8.  Keep the review
        # diagnostic state truthful and let AFTERPUSHED run for an independent
        # diagnostic review; its existing AS8 provenance guard owns the later
        # severity-preservation decision.
        if bool(getattr(output, "_kernel_as8_cow_preservation", False)):
            # NEW53: AS8 vetoes only the severity downgrade.  Preserve the
            # existing operational marker here as well; factual panic support is
            # carried independently by review.kernel_panic_supported.
            traces.append("NEW52:AS8_COW_VETOED_KPANIC_SEVERITY_DOWNGRADE")
            logger.info(
                "%s: NEW52 AS8 COW deterministic guard vetoed KPANIC severity "
                "downgrade (panic_supported=%s; operational KPANIC marker preserved=%s)",
                call_str,
                "YES" if review.kernel_panic_supported else "NO",
                "YES" if kpanic_marked else "NO",
            )
        else:
            output.impact = "MODERATE"
            # NEW53: HIGH->MODERATE7 means exactly that.  Do not silently turn
            # the same decision into MODREG merely because factual panic was not
            # established.  The explicit removal rule below owns MOD7->MODREG.
            lowered = True
            dec_cnt += 1
            traces.append(
                "KPANIC_LLM:DECREASED_TO_MODERATE7_BASED_ON_FALSEPOSCHECKOFKP"
            )

    # NEW53: independent MODERATE7 -> regular MODERATE decision.
    #
    # The KPANIC model must explicitly say that the extended operational review
    # marker is no longer warranted.  Retain the old branch-1 numeric/AV safety
    # gates so this new signal cannot broaden historical automatic removal.
    remove_operational_kpanic = bool(
        getattr(review, "remove_operational_kpanic", False)
    )
    # Operational KPANIC is a triage/manual-review verdict, deliberately separate
    # from factual proof of a panic/oops.  It may preserve MODERATE+KPANIC but
    # MUST NOT promote severity to IMPORTANT.
    operational_kpanic_supported = bool(
        getattr(review, "operational_kpanic_supported", False)
    )
    if operational_kpanic_supported and remove_operational_kpanic:
        logger.info(
            "%s: KPANIC review requested operational preservation; "
            "ignoring remove_operational_kpanic=YES",
            call_str,
        )
        remove_operational_kpanic = False
    # NEW57: review routing is independent from factual panic and from
    # IMPORTANT preservation.  A specialized reread may correctly conclude
    # "no panic" and "regular MODERATE severity", while still finding a
    # concrete security-boundary/corruption/etc. mechanism that requires a
    # human analyst.  In that state, do not let NEW53 erase the operational
    # MODERATE7 review marker.
    manual_review_still_required = bool(
        getattr(review, "manual_review_still_required", False)
    )
    try:
        manual_review_confidence = float(
            getattr(review, "manual_review_confidence", 0.0) or 0.0
        )
    except (TypeError, ValueError):
        manual_review_confidence = 0.0
    independent_review_required = (
        manual_review_still_required and manual_review_confidence >= 0.85
    )
    if operational_kpanic_supported and kpanic_marked:
        traces.append("KPANIC_LLM:OPERATIONAL_KPANIC_PRESERVED")
    if (
        remove_operational_kpanic
        and not independent_review_required
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
        traces.append("NEW53:KPANIC_EXPLICITLY_REMOVED_OPERATIONAL_MODERATE7_TO_MODREG")
    elif remove_operational_kpanic and kpanic_marked and independent_review_required:
        traces.append(
            "NEW57:OPERATIONAL_REVIEW_PRESERVED_INDEPENDENT_OF_KPANIC"
            f"(confidence={manual_review_confidence:.2f})"
        )
    elif remove_operational_kpanic and kpanic_marked and av_network:
        # Preserve the historical remote-network safety gate.  Do not replace
        # it with a generic ActionableScore>=4 rule: numeric AS is context, not
        # factual KPANIC evidence.  This trace makes the deliberate veto visible
        # instead of silently leaving the operational marker set.
        traces.append(
            "NEW53:REMOVE_OPERATIONAL_KPANIC_BLOCKED_REMOTE_NETWORK"
            f"(actionable_score={actionable_score},cvss={effective_score})"
        )

    # NEW29_POST_KPANIC_AS4_CONSISTENCY_RESTORE:
    # AS4 stays unchanged. Restore only after the specialized KPANIC review.
    primitive_class = (
        str(getattr(second_opinion, "primitive_class", "") or "").upper()
        if second_opinion is not None
        else ""
    )
    important_candidate = (
        str(getattr(second_opinion, "important_candidate", "") or "").upper()
        if second_opinion is not None
        else ""
    )
    auto_downgrade_allowed = (
        str(getattr(second_opinion, "auto_downgrade_allowed", "") or "").upper()
        if second_opinion is not None
        else ""
    )

    restore_as4_important = (
        bool(getattr(output, "_kernel_as4_downgraded_from_important", False))
        and output.impact == "MODERATE"
        and kpanic_marked
        and not allow_high_to_moderate7_downgrade
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
            "KPANIC allow_high_to_mod7=NO",
            call_str,
        )

    # NEW58: preserve the specialized KPANIC review's explicit IMPORTANT
    # retention verdict across the later AFTERPUSHED false-positive pass.
    #
    # The KPANIC contract has two distinct IMPORTANT-retention states:
    #   Outcome A: high_without_panic=YES, allow_high_to_mod7=NO
    #   Outcome B: named B1-B8 profile, high_without_panic=NO,
    #              allow_high_to_mod7=NO
    #
    # NEW55 accidentally required the Outcome-A boolean even for Outcome B.
    # That made a valid B3/B1/etc. preservation verdict internally
    # contradictory: the specialized review could explicitly veto downgrade,
    # yet AFTERPUSHED was still allowed to undo it.  A named B1-B8 profile plus
    # allow_high_to_mod7=NO is itself the machine-readable Outcome-B verdict.
    # Do not infer preservation from a profile alone: the explicit downgrade
    # veto remains mandatory.
    kpanic_preserve_important = (
        output.impact == "IMPORTANT"
        and preservation_profile != "NONE"
        and not allow_high_to_moderate7_downgrade
    )
    output._kernel_kpanic_preserve_important = kpanic_preserve_important
    output._kernel_kpanic_preservation_profile = preservation_profile
    if kpanic_preserve_important:
        traces.append(f"NEW58:KPANIC_PRESERVE_IMPORTANT({preservation_profile})")
        logger.info(
            "%s: NEW58 KPANIC preservation latch set "
            "(profile=%s allow_high_to_mod7=NO high_without_panic=%s)",
            call_str,
            preservation_profile,
            "YES"
            if bool(
                getattr(review, "high_severity_still_supported_without_kpanic", False)
            )
            else "NO",
        )

    output._kernel_kpanic_marked = kpanic_marked
    output._kernel_lowered = lowered
    output._kernel_decrease_count = dec_cnt
    _sync_output_operational_kpanic_flag(output)

    summary = (
        "kpanic_llm_review("
        f"panic_supported={'YES' if review.kernel_panic_supported else 'NO'},"
        f" operational_kpanic_supported={'YES' if operational_kpanic_supported else 'NO'},"
        f" evidence_level={review.evidence_level},"
        f" high_without_panic="
        f"{'YES' if review.high_severity_still_supported_without_kpanic else 'NO'},"
        f" preservation_profile={preservation_profile},"
        f" allow_high_to_mod7="
        f"{'YES' if allow_high_to_moderate7_downgrade else 'NO'},"
        f" remove_operational_kpanic="
        f"{'YES' if bool(getattr(review, 'remove_operational_kpanic', False)) else 'NO'},"
        f" manual_review_still_required="
        f"{'YES' if bool(getattr(review, 'manual_review_still_required', False)) else 'NO'},"
        f" manual_review_confidence="
        f"{float(getattr(review, 'manual_review_confidence', 0.0) or 0.0):.2f},"
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
    # NEW55: the specialized KPANIC review has precedence when it already
    # established that IMPORTANT survives independently of panic under a named
    # preservation profile and explicitly vetoed HIGH->MODERATE7.  Still run
    # AFTERPUSHED upstream for diagnostics, but do not apply its contradictory
    # downgrade here.
    if bool(getattr(output, "_kernel_kpanic_preserve_important", False)):
        profile = str(getattr(output, "_kernel_kpanic_preservation_profile", "") or "")
        # Older/current objects do not need the diagnostic attribute above; the
        # trace remains useful even when only the latch itself was exported.
        profile_suffix = f"({profile})" if profile else ""
        logger.info(
            "%s: NEW55 KPANIC preservation guard vetoed AFTERPUSHED downgrade%s",
            call_str,
            profile_suffix,
        )
        return (
            "afterpushed_llm_review(downgrade=NO,"
            " result=IMPORTANT-retained,"
            " guard=NEW55_KPANIC_PRESERVATION)"
        )

    # NEW51: AS8 is itself a narrow deterministic CLASS_A+COW preservation
    # decision.  AFTERPUSHED must not erase that same established state merely
    # because a later stochastic review is more conservative.
    if bool(getattr(output, "_kernel_as8_cow_preservation", False)):
        logger.info(
            "%s: NEW51 AS8 COW deterministic guard vetoed AFTERPUSHED downgrade",
            call_str,
        )
        return (
            "afterpushed_llm_review(downgrade=NO,"
            " result=IMPORTANT-retained,"
            " guard=NEW51_AS8_CLASS_A_COW)"
        )

    # NEW44: B8 is a deterministic preservation floor shared with the KPANIC
    # stage.  AFTERPUSHED must not independently undo it.
    if bool(getattr(output, "_kernel_remote_crash_preservation", False)):
        logger.info(
            "%s: NEW44 B8 deterministic guard vetoed AFTERPUSHED downgrade",
            call_str,
        )
        return (
            "afterpushed_llm_review(downgrade=NO,"
            " result=IMPORTANT-retained,"
            " guard=NEW44_B8_REMOTE_UNAUTHENTICATED_KERNEL_CRASH)"
        )

    if not review.downgrade_to_moderate7:
        return "afterpushed_llm_review(downgrade=NO, result=IMPORTANT-retained)"

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

    # Keep the specialized-review score consistent with reconcile_kernel().
    # The historical unconditional CLASS_C cap (>2 -> 2) could silently turn a
    # real ActionableScore=3 into 2 after reconciliation had deliberately
    # suppressed that cap for false-LOW safety.  Apply the same narrow cap here:
    # only bounded CLASS_C, ManualReview=NO, AutoDowngradeAllowed=YES,
    # selected/effective CVSS < 5.5, and C:N/I:N.
    try:
        actionable_metrics = (
            cvss.CVSS3(effective_vector_raw).metrics if effective_vector_raw else {}
        )
    except Exception:
        actionable_metrics = {}
    class_c_cap_safe = (
        second_opinion is not None
        and str(getattr(second_opinion, "primitive_class", "")).upper() == "CLASS_C"
        and getattr(second_opinion, "important_candidate", "NO") == "NO"
        and getattr(second_opinion, "auto_downgrade_allowed", "NO") == "YES"
        and getattr(second_opinion, "manual_review", "") == "NO"
        and math.isfinite(effective_score)
        and effective_score < 5.5
        and actionable_metrics.get("C") == "N"
        and actionable_metrics.get("I") == "N"
    )
    if actionable_score is not None and actionable_score > 2 and class_c_cap_safe:
        logger.info(
            "%s: specialized-review deterministic CLASS_C ActionableScore cap "
            "%s -> 2 (bounded CLASS_C, ManualReview=NO, "
            "AutoDowngradeAllowed=YES, CVSS<5.5, C:N/I:N)",
            call_str,
            actionable_score,
        )
        actionable_score = 2

    if not math.isfinite(effective_score):
        return ""
    if not (effective_score < 10.0):
        return ""
    if actionable_score is None or actionable_score > 9:
        return ""

    output.impact = "MODERATE"
    output._kernel_lowered = True
    output._kernel_decrease_count = (
        int(getattr(output, "_kernel_decrease_count", 0) or 0) + 1
    )
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
# NEW56 deferred LOW / auto-close gate
# ===========================================================================


def apply_deferred_low_review(
    output,
    call_str: str,
    review,
    classifier_result: dict | None,
    second_opinion=None,
) -> str:
    """NEW59: apply deferred LOW after the independent specialized review.

    NEW59 restores the useful legacy AS<3 LOW signal without restoring legacy
    blindness.  ActionableScore is still only eligibility: LOW requires
    AutoDowngradeAllowed=YES, no named preservation profile, no independent
    high-impact primitive, no mandatory manual-review verdict, and affirmative
    specialized LOW approval.

    AS==0 is a stronger fast path.  When the specialized reviewer independently
    rejects factual panic, affirmatively approves LOW auto-close, finds no
    preservation/high-impact/manual-review blocker, an inconsistent stale
    operational marker may be consumed even if remove_operational_kpanic was
    accidentally left false.  This is the deterministic form of NEW56.2's
    one-way consistency rule; it never treats AS==0 itself as technical proof.
    """
    if second_opinion is None or review is None:
        return ""
    if output.impact != "MODERATE":
        return ""

    score = getattr(second_opinion, "actionable_score", None)
    if score is None or score >= 3:
        return ""

    if str(getattr(second_opinion, "auto_downgrade_allowed", "NO")).upper() != "YES":
        return ""

    actionable_manual = str(getattr(second_opinion, "manual_review", "")).upper()
    if actionable_manual == "REQUIRED":
        return ""

    preservation_profile = str(
        getattr(review, "preservation_profile", "NONE") or "NONE"
    ).upper()
    if preservation_profile != "NONE":
        return ""

    independent_strength = str(
        getattr(review, "independent_high_impact_strength", "none") or "none"
    ).lower()
    if independent_strength not in {"weak", "none"}:
        return ""
    if bool(getattr(review, "high_severity_still_supported_without_kpanic", False)):
        return ""

    try:
        manual_review_confidence = float(
            getattr(review, "manual_review_confidence", 0.0) or 0.0
        )
    except (TypeError, ValueError):
        manual_review_confidence = 0.0
    manual_review_still_required = bool(
        getattr(review, "manual_review_still_required", False)
    )
    if manual_review_still_required and manual_review_confidence >= 0.85:
        return ""

    # NEW59.3: the specialized KPANIC review runs later and rereads the same
    # technical evidence specifically for LOW auto-close/manual-review safety.
    # Allow that later verdict to supersede an older primary
    # kernel_manual_review=YES for AS=1/2 only in the narrow bounded CLASS_C
    # profile.  This does NOT bypass a negative specialized LOW verdict:
    # low_auto_close_supported must itself be true with >=0.85 confidence, and
    # the specialized reviewer must affirmatively say manual review is no longer
    # required with >=0.90 confidence.  All preservation/high-impact/semantic
    # blockers below remain hard vetoes.
    primary_manual_yes = (
        str(getattr(output, "kernel_manual_review", "UNKNOWN")).upper() == "YES"
    )

    low_supported = bool(getattr(review, "low_auto_close_supported", False))
    try:
        low_confidence = float(getattr(review, "low_auto_close_confidence", 0.0) or 0.0)
    except (TypeError, ValueError):
        low_confidence = 0.0
    if not low_supported or low_confidence < 0.85:
        return ""

    primitive_for_primary_supersede = str(
        getattr(second_opinion, "primitive_class", "") or ""
    ).upper()
    primary_manual_superseded = (
        primary_manual_yes
        and score in {1, 2}
        and primitive_for_primary_supersede == "CLASS_C"
        and actionable_manual == "NO"
        and not bool(getattr(review, "kernel_panic_supported", False))
        and not bool(getattr(review, "operational_kpanic_supported", False))
        and not manual_review_still_required
        and manual_review_confidence >= 0.90
        and low_supported
        and low_confidence >= 0.85
        and preservation_profile == "NONE"
        and independent_strength in {"weak", "none"}
        and not bool(
            getattr(review, "high_severity_still_supported_without_kpanic", False)
        )
    )
    if primary_manual_yes and not (
        (
            score == 0
            and not manual_review_still_required
            and manual_review_confidence >= 0.85
        )
        or primary_manual_superseded
    ):
        return ""

    # Strong patch/semantic signals remain hard vetoes.  NEW59 intentionally
    # does NOT use kernel_nullptr_related as a blanket veto: a bounded NULL
    # dereference can itself be LOW when the independent reviewer confirms that
    # no fatal/review-worthy mechanism remains.
    raw = str(getattr(second_opinion, "raw_response", "") or "")
    strong_headers = (
        "CleanFixProtection=YES",
        "COWOwnershipViolation=YES",
        "AuthorizationBypass=YES",
        "RealUAF=YES",
        "B5OOB=YES",
    )
    if any(h in raw for h in strong_headers):
        return ""
    if str(getattr(second_opinion, "primitive_class", "")).upper() == "CLASS_A":
        return ""
    if str(getattr(second_opinion, "important_candidate", "NO")).upper() == "YES":
        return ""

    # NEW97 / NEW59 structured-context safety split:
    # AS<3 is eligibility, not proof that a candidate is safe to auto-close.
    #
    # A known UNPRIVILEGED_RUNTIME path is not, by itself, a reason to reject
    # NEW59 when the independent KPANIC review says there is no factual panic,
    # no high-impact/preservation blocker, and LOW auto-close is safe.  This
    # keeps bounded resource-leak/correctness cases eligible for LOW.
    #
    # Conversely, a completely unresolved CLASS_C context must not authorize
    # automatic LOW closure.  UNKNOWN/UNKNOWN/UNKNOWN therefore fails closed.
    # Factual crash cases retain the NEW61a.2 safety requirement below:
    # CrashOnlyLowEligible must be affirmative.  NEW61a.2 itself remains stricter
    # and still rejects UNPRIVILEGED_RUNTIME crash routing.
    primitive = str(getattr(second_opinion, "primitive_class", "") or "").upper()
    crash_reachability = str(
        getattr(second_opinion, "crash_reachability", "UNKNOWN") or "UNKNOWN"
    ).upper()
    crash_privilege = str(
        getattr(second_opinion, "crash_trigger_privilege", "UNKNOWN") or "UNKNOWN"
    ).upper()
    crash_low_eligible = str(
        getattr(second_opinion, "crash_only_low_eligible", "UNKNOWN") or "UNKNOWN"
    ).upper()

    # NEW59.1: UNKNOWN crash-context fields normally fail closed, but they are
    # irrelevant for a positively established non-crash CLASS_C candidate.
    # CVE-2026-52960 exposed this gap: the specialized review independently
    # rejected factual panic, approved LOW auto-close with high confidence, and
    # required no manual review, yet the resource/reference-leak case remained
    # MODERATE solely because all three crash-only routing fields were UNKNOWN.
    #
    # Keep the exception deliberately narrow.  UNKNOWN/UNKNOWN/UNKNOWN is
    # tolerated only when the specialized reviewer says this is not a factual
    # panic, LOW is safe at >=0.90 confidence, and no manual review remains at
    # >=0.85 confidence.  All preservation/high-impact/strong-header gates above
    # still apply, and factual crash cases remain subject to CrashOnlyLowEligible.
    unknown_crash_context = (
        primitive == "CLASS_C"
        and crash_reachability == "UNKNOWN"
        and crash_privilege == "UNKNOWN"
        and crash_low_eligible == "UNKNOWN"
    )
    proven_noncrash_low = (
        not bool(getattr(review, "kernel_panic_supported", False))
        and low_supported
        and low_confidence >= 0.90
        and not manual_review_still_required
        and manual_review_confidence >= 0.85
    )

    # NEW59.2: the UNKNOWN-context relaxation above must not auto-close a
    # remotely reachable, unauthenticated candidate.  CVE-2022-50865 showed
    # that AV:N/PR:N can otherwise satisfy the same CLASS_C + strong
    # non-crash LOW-review gates as a bounded local resource leak while still
    # belonging in MODERATE.  Scope this veto only to the UNKNOWN-context
    # exception; known/proven NEW59 crash-context paths are unchanged.
    selected_cvss_vector = str(
        getattr(second_opinion, "cvss_selected_vector", None)
        or getattr(output, "cvss3_vector", "")
        or ""
    )
    remote_unauthenticated = (
        "/AV:N/" in selected_cvss_vector and "/PR:N/" in selected_cvss_vector
    )
    if unknown_crash_context and (not proven_noncrash_low or remote_unauthenticated):
        return ""

    if bool(getattr(review, "kernel_panic_supported", False)) and (
        crash_low_eligible != "YES"
    ):
        return ""

    # NEW59 deliberately does not use classifier severity or an external CVSS
    # number as a hard LOW veto.  They are correlated/summary severity signals,
    # not independently established high-impact primitives.  Concrete semantic
    # blockers above and the specialized review verdicts own LOW safety.

    had_operational_kpanic = bool(getattr(output, "_kernel_kpanic_marked", False))
    remove_operational_kpanic = bool(
        getattr(review, "remove_operational_kpanic", False)
    )

    # NEW59 AS==0 fast path: repair only the narrow contradictory state where
    # the specialized reviewer itself says panic is unsupported, LOW auto-close
    # is safe with high confidence, no review/high-impact/preservation blocker
    # remains, but the operational-removal boolean was left false.
    as0_marker_fast_path = (
        score == 0
        and had_operational_kpanic
        and not bool(getattr(review, "kernel_panic_supported", False))
        and low_supported
        and low_confidence >= 0.85
        and not manual_review_still_required
        and manual_review_confidence >= 0.85
        and preservation_profile == "NONE"
        and independent_strength in {"weak", "none"}
        and not bool(
            getattr(review, "high_severity_still_supported_without_kpanic", False)
        )
    )

    # NEW59.3: AS=1/2 primary-manual supersede may also consume a stale
    # operational KPANIC marker when the SAME specialized review independently
    # establishes the full safe-LOW/no-review profile.
    #
    # This closes the narrow state exposed by CVE-2025-38193:
    #
    #   primary_manual_review=YES
    #   ActionableScore=1/2, CLASS_C, ManualReview=NO
    #   kernel_panic_supported=NO
    #   operational_kpanic_supported=NO
    #   low_auto_close_supported=YES
    #   manual_review_still_required=NO
    #   preservation_profile=NONE
    #
    # In that state NEW53.2 would consume the marker immediately afterwards
    # anyway. Requiring remove_operational_kpanic=YES here therefore prevented
    # NEW59 from using an otherwise complete specialized LOW verdict solely
    # because the older operational marker had not yet been synchronized.
    #
    # Keep this tied to primary_manual_superseded so it cannot become a generic
    # AS=1/2 marker-removal path.
    specialized_marker_consistency = (
        primary_manual_superseded
        and had_operational_kpanic
        and not bool(getattr(review, "kernel_panic_supported", False))
        and not bool(getattr(review, "operational_kpanic_supported", False))
        and low_supported
        and low_confidence >= 0.85
        and not manual_review_still_required
        and manual_review_confidence >= 0.90
        and preservation_profile == "NONE"
        and independent_strength in {"weak", "none"}
        and not bool(
            getattr(review, "high_severity_still_supported_without_kpanic", False)
        )
    )

    effective_remove_operational_kpanic = (
        remove_operational_kpanic
        or as0_marker_fast_path
        or specialized_marker_consistency
    )
    if had_operational_kpanic and not effective_remove_operational_kpanic:
        return ""

    output.impact = "LOW"
    output._kernel_lowered = True
    output._kernel_decrease_count = (
        int(getattr(output, "_kernel_decrease_count", 0) or 0) + 1
    )
    output._kernel_kpanic_marked = False
    _sync_output_operational_kpanic_flag(output)

    reason = str(getattr(review, "low_auto_close_reason", "") or "").strip()
    if as0_marker_fast_path and not remove_operational_kpanic:
        trace = (
            "NEW59:AS0_FASTPATH_MOD7_TO_LOW("
            f"score=0,review_confidence={low_confidence:.2f},"
            "panic_supported=NO,preservation=NONE,high_impact=NONE,"
            "manual_review=NO,repair_stale_operational_marker=YES)"
        )
    elif had_operational_kpanic:
        trace = (
            "NEW59:ASLT3_MOD7_TO_LOW("
            f"score={score},review_confidence={low_confidence:.2f},"
            f"remove_operational_kpanic={'YES' if remove_operational_kpanic else 'NO'},"
            f"specialized_marker_consistency={'YES' if specialized_marker_consistency else 'NO'},"
            "preservation=NONE,"
            f"high_impact={independent_strength.upper()},"
            f"primary_manual_superseded={'YES' if primary_manual_superseded else 'NO'},"
            "blockers=NONE)"
        )
    else:
        trace = (
            "NEW59:ASLT3_MOD_TO_LOW("
            f"score={score},review_confidence={low_confidence:.2f},"
            "preservation=NONE,"
            f"high_impact={independent_strength.upper()},"
            f"primary_manual_superseded={'YES' if primary_manual_superseded else 'NO'},"
            "blockers=NONE)"
        )
    logger.info("%s: %s reason=%s", call_str, trace, reason)
    return trace


def apply_crash_only_no_review_low_override(
    output,
    call_str: str,
    review,
    second_opinion=None,
) -> str:
    """NEW61a.2: permit a narrowly proven crash-only LOW despite KPANIC review routing.

    NEW61a required the KPANIC reviewer itself to say that manual review was not
    required.  That remained correlated with factual crash detection and was
    stochastic on the target case.  NEW61a.2 instead requires an independent,
    machine-readable ActionableScore classification of crash reachability,
    privilege, and LOW eligibility.

    Factual ``kernel_panic_supported`` remains true.  The exception changes only
    operational routing when the crash is CLASS_C, AS<=1, no Important/preservation
    or independent high-impact primitive exists, and CrashOnlyLowEligible=YES is
    backed by a constrained INIT/PROBE/CONFIG, ERROR/RECOVERY, or privileged-runtime
    context.  UNPRIVILEGED_RUNTIME and UNKNOWN reachability can never authorize it.
    """
    if second_opinion is None or review is None:
        return ""
    if output.impact != "MODERATE":
        return ""

    score = getattr(second_opinion, "actionable_score", None)
    if score not in {0, 1}:
        return ""
    if str(getattr(second_opinion, "primitive_class", "")).upper() != "CLASS_C":
        return ""
    if str(getattr(second_opinion, "important_candidate", "NO")).upper() != "NO":
        return ""
    if str(getattr(second_opinion, "auto_downgrade_allowed", "NO")).upper() != "YES":
        return ""
    if str(getattr(second_opinion, "manual_review", "")).upper() != "NO":
        return ""
    if str(getattr(output, "kernel_manual_review", "UNKNOWN")).upper() != "NO":
        return ""

    # This override exists only for a real factual crash/oops. Non-crash LOW
    # candidates remain owned by NEW59/NEW60.
    if not bool(getattr(review, "kernel_panic_supported", False)):
        return ""
    evidence_level = str(getattr(review, "evidence_level", "") or "").lower()
    if evidence_level not in {"demonstrated", "explicit", "strongly_implied"}:
        return ""

    preservation_profile = str(
        getattr(review, "preservation_profile", "NONE") or "NONE"
    ).upper()
    if preservation_profile != "NONE":
        return ""

    independent_strength = str(
        getattr(review, "independent_high_impact_strength", "none") or "none"
    ).lower()
    if independent_strength not in {"weak", "none"}:
        return ""
    if bool(getattr(review, "high_severity_still_supported_without_kpanic", False)):
        return ""

    crash_reachability = str(
        getattr(second_opinion, "crash_reachability", "UNKNOWN") or "UNKNOWN"
    ).upper()
    crash_privilege = str(
        getattr(second_opinion, "crash_trigger_privilege", "UNKNOWN") or "UNKNOWN"
    ).upper()
    crash_low_eligible = str(
        getattr(second_opinion, "crash_only_low_eligible", "UNKNOWN") or "UNKNOWN"
    ).upper()

    if crash_low_eligible != "YES":
        return ""
    if crash_reachability not in {
        "INIT_PROBE_CONFIG",
        "ERROR_RECOVERY",
        "PRIVILEGED_RUNTIME",
    }:
        return ""
    if crash_privilege == "UNPRIVILEGED":
        return ""

    # PRIVILEGED_RUNTIME must be positively privilege-bounded. For init/probe/
    # config and error/recovery paths UNKNOWN privilege is allowed only because
    # CrashOnlyLowEligible=YES itself requires the prompt to establish that no
    # ordinary unprivileged runtime trigger exists.
    if crash_reachability == "PRIVILEGED_RUNTIME" and crash_privilege not in {
        "HOST_ADMIN",
        "NAMESPACE_PRIVILEGED",
    }:
        return ""

    raw = str(getattr(second_opinion, "raw_response", "") or "")
    strong_headers = (
        "CleanFixProtection=YES",
        "COWOwnershipViolation=YES",
        "AuthorizationBypass=YES",
        "RealUAF=YES",
    )
    if any(h in raw for h in strong_headers):
        return ""

    if not bool(getattr(output, "_kernel_kpanic_marked", False)):
        return ""

    # Deliberately do NOT require manual_review_still_required=false here.
    # NEW61a.2 exists because that KPANIC-review axis was observed to follow the
    # mere existence of a demonstrated crash. The independent crash-context proof
    # above is the narrow superseding signal. All high-impact/preservation gates
    # remain hard vetoes.
    manual_required = bool(getattr(review, "manual_review_still_required", False))
    try:
        manual_confidence = float(
            getattr(review, "manual_review_confidence", 0.0) or 0.0
        )
    except (TypeError, ValueError):
        manual_confidence = 0.0

    output.impact = "LOW"
    output._kernel_lowered = True
    output._kernel_decrease_count = (
        int(getattr(output, "_kernel_decrease_count", 0) or 0) + 1
    )
    output._kernel_kpanic_marked = False
    _sync_output_operational_kpanic_flag(output)

    trace = (
        "NEW61a.2:CRASH_CONTEXT_PROVEN_MOD7_TO_LOW("
        f"score={score},panic_supported=YES,evidence={evidence_level},"
        "class=CLASS_C,primary_manual=NO,actionable_manual=NO,"
        f"crash_reachability={crash_reachability},"
        f"crash_privilege={crash_privilege},crash_low_eligible=YES,"
        f"kpanic_manual_required={'YES' if manual_required else 'NO'},"
        f"kpanic_manual_confidence={manual_confidence:.2f},"
        "preservation=NONE,high_impact="
        f"{independent_strength.upper()},operational_kpanic_consumed=YES)"
    )
    logger.info("%s: %s", call_str, trace)
    return trace


def apply_as0_safe_low_marker_consistency(
    output,
    call_str: str,
    review,
    second_opinion=None,
) -> str:
    """NEW53.1: consume a stale operational KPANIC marker on safe existing LOW.

    Some older reconciliation branches can reach LOW before the specialized
    KPANIC review runs.  In that state NEW59 has no downgrade left to perform,
    but a classifier-derived operational KPANIC marker can survive until NEW54
    and mechanically floor the already-LOW result back to MODERATE7.

    This is a marker-consistency repair, not a severity heuristic: impact is
    never changed here.  Consume the marker only when the specialized review
    independently rejects both factual and operational KPANIC, positively
    approves LOW auto-close with high confidence, requires no manual review,
    and no preservation/high-impact/strong ActionableScore blocker survives.

    ``remove_operational_kpanic`` is intentionally not required.  The four
    validation false-LOW escalations showed that this older policy field can
    remain false even when the review's stronger structured conclusions are
    jointly unambiguous.  NEW54 remains unchanged and fail-closes every LOW
    whose marker survives this narrow consistency gate.
    """
    if second_opinion is None or review is None:
        return ""
    if output.impact != "LOW":
        return ""
    if not bool(getattr(output, "_kernel_kpanic_marked", False)):
        return ""

    score = getattr(second_opinion, "actionable_score", None)
    if score is None or score > 2:
        return ""
    if str(getattr(second_opinion, "auto_downgrade_allowed", "NO")).upper() != "YES":
        return ""
    if str(getattr(second_opinion, "manual_review", "")).upper() == "REQUIRED":
        return ""

    preservation_profile = str(
        getattr(review, "preservation_profile", "NONE") or "NONE"
    ).upper()
    if preservation_profile != "NONE":
        return ""

    independent_strength = str(
        getattr(review, "independent_high_impact_strength", "none") or "none"
    ).lower()
    if independent_strength not in {"weak", "none"}:
        return ""
    if bool(getattr(review, "high_severity_still_supported_without_kpanic", False)):
        return ""
    if bool(getattr(review, "kernel_panic_supported", False)):
        return ""
    if bool(getattr(review, "operational_kpanic_supported", False)):
        return ""

    low_supported = bool(getattr(review, "low_auto_close_supported", False))
    try:
        low_confidence = float(getattr(review, "low_auto_close_confidence", 0.0) or 0.0)
    except (TypeError, ValueError):
        low_confidence = 0.0
    if not low_supported or low_confidence < 0.90:
        return ""

    # The boolean verdict owns this axis.  Do not require high confidence in a
    # negative manual-review verdict: CVE-2025-71315 correctly emitted
    # manual_review_still_required=false with low confidence while separately
    # giving the affirmative safe-LOW decision 0.95 confidence.
    if bool(getattr(review, "manual_review_still_required", False)):
        return ""

    # Preserve the same concrete semantic vetoes used by deferred LOW.  A low
    # numeric score must never erase independently established dangerous state.
    raw = str(getattr(second_opinion, "raw_response", "") or "")
    strong_headers = (
        "CleanFixProtection=YES",
        "COWOwnershipViolation=YES",
        "AuthorizationBypass=YES",
        "RealUAF=YES",
        "B5OOB=YES",
    )
    if any(h in raw for h in strong_headers):
        return ""
    if str(getattr(second_opinion, "primitive_class", "")).upper() == "CLASS_A":
        return ""
    if str(getattr(second_opinion, "important_candidate", "NO")).upper() == "YES":
        return ""

    output._kernel_kpanic_marked = False
    _sync_output_operational_kpanic_flag(output)

    trace = (
        "NEW53.1:LOW_SPECIALIZED_REVIEW_CONSUMED_OPERATIONAL_KPANIC("
        f"score={score},low_confidence={low_confidence:.2f},"
        "panic_supported=NO,operational_kpanic_supported=NO,"
        "manual_review_still_required=NO,preservation=NONE,"
        f"high_impact={independent_strength.upper()},blockers=NONE)"
    )
    logger.info("%s: %s", call_str, trace)
    return trace


def apply_moderate_no_review_marker_consistency(
    output,
    call_str: str,
    review,
    second_opinion=None,
) -> str:
    """NEW53.2: consume stale operational KPANIC on ordinary MODERATE.

    This is deliberately NOT a LOW heuristic and never changes impact.  It
    handles the narrow state where reconciliation already selected ordinary
    MODERATE, but an older classifier-derived KPANIC marker survived even
    though the specialized review independently rejects factual panic,
    operational KPANIC, manual-review routing, preservation, and independent
    high-impact evidence.

    ``low_auto_close_supported`` is intentionally irrelevant here: a review may
    correctly reject destructive LOW auto-close while also concluding that
    MODERATE needs no KPANIC/manual-review marker.  NEW53.2 therefore improves
    review-routing precision without weakening LOW safety.
    """
    if second_opinion is None or review is None:
        return ""
    if output.impact != "MODERATE":
        return ""
    if not bool(getattr(output, "_kernel_kpanic_marked", False)):
        return ""

    score = getattr(second_opinion, "actionable_score", None)
    if score is None or score > 2:
        return ""
    if str(getattr(second_opinion, "auto_downgrade_allowed", "NO")).upper() != "YES":
        return ""
    if str(getattr(second_opinion, "manual_review", "")).upper() == "REQUIRED":
        return ""

    if bool(getattr(review, "kernel_panic_supported", False)):
        return ""
    if bool(getattr(review, "operational_kpanic_supported", False)):
        return ""
    if bool(getattr(review, "manual_review_still_required", False)):
        return ""
    try:
        manual_confidence = float(
            getattr(review, "manual_review_confidence", 0.0) or 0.0
        )
    except (TypeError, ValueError):
        manual_confidence = 0.0
    if manual_confidence < 0.90:
        return ""

    preservation_profile = str(
        getattr(review, "preservation_profile", "NONE") or "NONE"
    ).upper()
    if preservation_profile != "NONE":
        return ""

    independent_strength = str(
        getattr(review, "independent_high_impact_strength", "none") or "none"
    ).lower()
    if independent_strength != "none":
        return ""
    if bool(getattr(review, "high_severity_still_supported_without_kpanic", False)):
        return ""

    # Keep the same deterministic strong-signal vetoes as NEW53.1.  This gate
    # must never erase review routing in the presence of independently parsed
    # corruption/ownership/authorization evidence merely because the review is
    # stochastic or incomplete.
    raw = str(getattr(second_opinion, "raw_response", "") or "")
    strong_headers = (
        "CleanFixProtection=YES",
        "COWOwnershipViolation=YES",
        "AuthorizationBypass=YES",
        "RealUAF=YES",
        "B5OOB=YES",
    )
    if any(h in raw for h in strong_headers):
        return ""
    if str(getattr(second_opinion, "primitive_class", "")).upper() == "CLASS_A":
        return ""
    if str(getattr(second_opinion, "important_candidate", "NO")).upper() == "YES":
        return ""

    output._kernel_kpanic_marked = False
    _sync_output_operational_kpanic_flag(output)

    trace = (
        "NEW53.2:MODERATE_SPECIALIZED_REVIEW_CONSUMED_OPERATIONAL_KPANIC("
        f"score={score},manual_confidence={manual_confidence:.2f},"
        "panic_supported=NO,operational_kpanic_supported=NO,"
        "manual_review_still_required=NO,preservation=NONE,"
        "high_impact=NONE,blockers=NONE)"
    )
    logger.info("%s: %s", call_str, trace)
    return trace


def apply_final_low_safety_invariant(
    output,
    call_str: str,
    review,
) -> str:
    """Fail closed when the independent post-reconciliation review rejects LOW.

    NEW56 made creation of deferred LOW depend on an affirmative specialized
    safe-auto-close verdict.  An older reconciliation path can nevertheless
    arrive at LOW *before* that review runs.  NEW58 closes that asymmetric gap:
    after KPANIC and AFTERPUSHED have both completed, a high-confidence
    independent veto cannot be exported as destructive LOW/auto-close.

    This function never promotes above MODERATE.  ``manual_review_still_required``
    controls only the operational MODERATE7 marker; a high-confidence LOW veto
    without mandatory review restores ordinary MODERATE.
    """
    if review is None or output.impact != "LOW":
        return ""

    try:
        low_confidence = float(getattr(review, "low_auto_close_confidence", 0.0) or 0.0)
    except (TypeError, ValueError):
        low_confidence = 0.0
    low_supported = bool(getattr(review, "low_auto_close_supported", False))
    low_veto = (not low_supported) and low_confidence >= 0.85

    try:
        manual_confidence = float(
            getattr(review, "manual_review_confidence", 0.0) or 0.0
        )
    except (TypeError, ValueError):
        manual_confidence = 0.0
    manual_required = bool(getattr(review, "manual_review_still_required", False))
    review_veto = manual_required and manual_confidence >= 0.85

    if not (low_veto or review_veto):
        return ""

    output.impact = "MODERATE"

    # NEW57's independent review verdict owns routing only.  Preserve/create
    # MODERATE7 when that verdict is strong; otherwise the LOW-safety veto
    # restores ordinary MODERATE without inventing a review requirement.
    if review_veto:
        output._kernel_kpanic_marked = True

    _sync_output_operational_kpanic_flag(output)

    bucket = "MODERATE7" if review_veto else "MODERATE"
    trace = (
        "NEW58:FINAL_LOW_SAFETY_VETO"
        f"(result={bucket},low_supported={'YES' if low_supported else 'NO'},"
        f"low_confidence={low_confidence:.2f},"
        f"manual_review={'YES' if manual_required else 'NO'},"
        f"manual_confidence={manual_confidence:.2f})"
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

    Forces ``S:U`` and ``A:H`` for kernel-panic normalization without
    assuming user-data exposure. Preserve the effective CVSS ``AC`` metric:
    this post-processing stage must not manufacture ``AC:H`` when the selected
    technical CVSS assessment already established ``AC:L``. A positively
    established hard race/timing condition must therefore be represented by
    ``AC:H`` in the effective selected CVSS before this override runs.

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
        "kernel_panic" in active_features or "kernel_panic_plus_uaf" in active_features
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
    # A.Larkin kpanic CVSS AC-preservation calibration.
    #
    # BEFORE: this late normalization unconditionally forced AC:H, even when
    # the independently selected/effective CVSS had already established AC:L.
    # That could turn a deterministic attacker-driven sequence into a
    # synthetic "hard timing" condition with no supporting technical evidence.
    #
    # AFTER: preserve AC exactly as assessed by the effective CVSS source.
    # If a hard race/timing condition is positively established, the selected
    # technical CVSS should already carry AC:H and it remains H here.  This
    # stage only normalizes the kernel-panic-specific S/A metrics.
    parsed.metrics.update({"S": "U", "A": "H"})
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

    # The eager path already ran but produced no result (low confidence,
    # no patches, etc.).  Don't force the LLM to call the tool just to
    # get an error back.
    if getattr(deps, "classifier_attempted", False):
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
