import cvss
import logging
from typing import Any

from aegis_ai import get_settings, remove_keys
from aegis_ai.data_models import CVEID
from aegis_ai.features import Feature
from aegis_ai.features.cve.data_models import (
    CVSSDiffExplainerModel,
    SuggestAffectedComponentsModel,
    SuggestImpactModel,
    SuggestCWEModel,
    PIIReportModel,
    SuggestStatementModel,
    SuggestDescriptionModel,
)
from aegis_ai.features.cve.data_models import CVEFeatureInput
from aegis_ai.features.data_models import feature_deps

from aegis_ai.kernel_classifier import is_kernel_component
from aegis_ai.prompt import AegisPrompt
from aegis_ai.toolsets.tools.cwe import cwe_manager
import aegis_ai.toolsets.tools.osidb as osidb_tool

logger = logging.getLogger(__name__)


class SuggestImpact(Feature):
    """Based on current CVE information and context assert an aggregated impact."""

    @staticmethod
    def post_process_cvss(output, call_str):
        # read the suggested cvss3_score
        try:
            cvss3_score = float(output.cvss3_score)
        except ValueError:
            cvss3_score = float("nan")

        # compute CVSS3 score from the suggested cvss3_vector
        try:
            cvss3_score_by_vector = cvss.CVSS3(output.cvss3_vector).scores()[0]
        except Exception:
            cvss3_score_by_vector = float("nan")

        if cvss3_score == cvss3_score_by_vector:
            # already consistent
            return

        logger.info(
            f"{call_str}: adjusting cvss3_score to match cvss3_vector: {cvss3_score} -> {cvss3_score_by_vector}"
        )
        output.cvss3_score = f"{cvss3_score_by_vector}"

    @staticmethod
    def post_process_impact(output, call_str):
        try:
            cvss3_score = float(output.cvss3_score)
        except ValueError:
            cvss3_score = float("nan")

        # check which impact corresponds to cvss3_score (same bands as _score_to_band)
        impact_by_cvss3 = SuggestImpact._score_to_band(cvss3_score)
        if impact_by_cvss3 is None:
            logger.warning(f"{call_str}: invalid cvss3_score: {cvss3_score}")
            return

        impact = output.impact
        if impact == impact_by_cvss3:
            return

        sev = SuggestImpact.SEVERITY_ORDER
        impact_rank = sev.get(impact, 99)
        band_rank = sev.get(impact_by_cvss3, 99)
        has_rationale = getattr(output, "deescalation_rationale", None)

        if impact_rank > band_rank and has_rationale:
            gap = impact_rank - band_rank

            if gap <= 1:
                logger.info(
                    f"{call_str}: LLM de-escalated impact below CVSS band "
                    f"({impact_by_cvss3} -> {impact}), respecting deescalation_rationale"
                )
                return
            # LLM tried to de-escalate more than 1 level — cap and mark
            # rationale as unreliable so the floor is not suppressed.
            sev_by_rank = {v: k for k, v in SuggestImpact.SEVERITY_ORDER.items()}
            capped = sev_by_rank.get(band_rank + 1, impact_by_cvss3)
            logger.info(
                f"{call_str}: LLM de-escalated {gap} levels below CVSS band "
                f"({impact_by_cvss3} -> {impact}), capping to {capped}"
            )
            output.impact = capped
            output.deescalation_rationale = None
            return

        logger.info(
            f"{call_str}: adjusting impact to match cvss3_score: {impact} -> {impact_by_cvss3}"
        )
        output.impact = impact_by_cvss3

    SEVERITY_ORDER = {"CRITICAL": 0, "IMPORTANT": 1, "MODERATE": 2, "LOW": 3, "": 4}

    _CONTAINED_SUBSYSTEM_FLAGS = {"bpf", "nvme", "debugfs", "notincludedcomponent"}
    _MEMORY_CORRUPTION_FLAGS = {
        "uaf",
        "kernel_panic_plus_uaf",
        "danger",
        "write",
        "outofbounds",
    }
    _NETWORK_EXPOSURE_FLAGS = {"remote", "networking", "servertoclientfail"}
    _RULES_BASE = """
                - Output format (must follow exactly):
                    - cvss3_vector: "CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X"
                      where AV in [N,A,L,P], AC in [L,H], PR in [N,L,H], UI in [N,R], S in [U,C], C/I/A in [N,L,H].
                    - cvss3_score: numeric string matching the vector (we will verify and adjust if needed).
                    - impact: Critical/Important/Moderate/Low based on the score.
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
                    - If cisa_kev_tool is available, check for known exploits.
                - Confidence:
                    - Calibrate confidence to the fraction of base metrics you are ≥80% sure about (e.g., 0.75 if 6/8 are certain).
                - Explanation must match the vector (mandatory):
                    - Do not write that exploitation requires admin capabilities, mount privileges, or privileged syscalls and output PR:L; use PR:H when those are required to trigger the flaw.
                    - If you revise the narrative and it implies stricter privileges than your draft vector, update PR in the vector before finalizing.
                - Output
                    - Provide the vector and score first, then impact, then a concise explanation with metric-by-metric rationale.
                    - Keep explanations concise.
            """
    _RULES_KERNEL = """
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

    def _check_output(self, result, deps) -> str | None:
        use_clf = get_settings().use_kernel_classifier
        is_kernel = getattr(deps, "is_kernel_cve", False)
        tool_called = getattr(deps, "kernel_tool_called", False)
        clf_result = getattr(deps, "classifier_result", None)

        if use_clf and is_kernel and hasattr(result.output, "cvss3_vector"):
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

    @staticmethod
    def _score_to_band(score: float) -> str | None:
        """Map a CVSS v3.1 base score to the Red Hat impact band."""
        if score > 9.0:
            return "CRITICAL"
        # This allows for MODERATE to be set to 7.0, but often these may be IMPORTANT.
        if score > 7.0:
            return "IMPORTANT"
        if score >= 4.0:
            return "MODERATE"
        if score > 0.0:
            return "LOW"
        if score == 0.0:
            return ""
        return None

    @staticmethod
    def _reconcile_kernel(output, call_str, classifier_result: dict) -> str:
        """Threshold-based reconciliation for kernel CVEs (al-kernel port).

        The classifier's cascade-adjusted prediction is the starting
        severity.  The LLM's own CVSS score drives bidirectional
        adjustments through deterministic threshold rules (H1–H11).
        Classifier confidence is logged but does not affect the outcome.

        Rule reference: see al-kernel-spec.md Phase 4 for daemon
        originals.  Rules H12–H14 are deferred (require CWE extraction
        and manual-check signal not yet in SuggestImpactModel).
        """
        from aegis_ai.kernel_classifier.cascade import parse_cvss_vector

        SEV = SuggestImpact.SEVERITY_ORDER
        LABELS = {v: k for k, v in SEV.items()}
        IMP, MOD, LOW = SEV["IMPORTANT"], SEV["MODERATE"], SEV["LOW"]

        try:
            llm_cvss = float(output.cvss3_score)
        except (ValueError, TypeError):
            llm_cvss = float("nan")

        llm_vector = parse_cvss_vector(output.cvss3_vector or "")

        clf_impact = classifier_result.get("impact")
        clf_confidence = classifier_result.get("confidence", 0.0) or 0.0
        clf_cvss_score = classifier_result.get("cvss_score", 0.0) or 0.0
        active_features: set[str] = set(classifier_result.get("active_features", []))

        severity = SEV[clf_impact] if clf_impact and clf_impact in SEV else MOD
        start_label = LABELS.get(severity, clf_impact)

        has_contained = bool(active_features & SuggestImpact._CONTAINED_SUBSYSTEM_FLAGS)
        has_corruption = bool(active_features & SuggestImpact._MEMORY_CORRUPTION_FLAGS)
        has_network = bool(active_features & SuggestImpact._NETWORK_EXPOSURE_FLAGS)

        cia_hhh = (
            llm_vector.get("C") == "H"
            and llm_vector.get("I") == "H"
            and llm_vector.get("A") == "H"
        )
        av_local = llm_vector.get("AV") == "L"
        pr_h_only = llm_vector.get("PR") == "H"

        import math

        if math.isnan(llm_cvss):
            rules_applied: list[str] = ["no_llm_cvss"]
        else:
            rules_applied = []
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
                or (
                    llm_cvss >= 6.5
                    and cia_hhh
                    and not kpanic_marked
                    and not has_contained
                )
            ):
                kpanic_marked = True
                rules_applied.append("H3:kpanic_set")

            # H4: annotation — block H7 for moderate-range CVSS without
            # local NULL-ptr pattern (approximates daemon CWE-476 gating)
            is_local_nullptr = "nullptr" in active_features and llm_vector.get(
                "AV"
            ) not in ("N", "A")
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
                kpanic_marked = False
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
                kpanic_marked = False
                decreased = True  # noqa: F841
                rules_applied.append("H10:decreased_set")

            # H11: IMPORTANT -> MODERATE when PR:H with moderate CVSS
            if severity == IMP and llm_cvss < 8.0 and pr_h_only:
                severity = MOD
                rules_applied.append("H11:IMP->MOD(cvss<8.0+PR:H)")

        # --- Guardrails (applied after threshold rules) ---
        guardrails_applied: list[str] = []

        # G4: LLM band floor for LOW severity.  Al-kernel's thresholds
        # assume the NN starting point is close to the final answer, so
        # small CVSS-based adjustments work.  Aegis's XGBoost cascade
        # can produce a starting severity that diverges from the LLM by
        # 2 levels, causing H1+H8 chains that push severity to LOW
        # even when the LLM's own CVSS says MODERATE.  This guardrail
        # prevents the final result from dropping below the LLM's band
        # when severity landed at LOW.  For contained subsystems the
        # promotion caps at MODERATE (containment still suppresses
        # escalation above that).
        if severity == LOW:
            llm_band = SuggestImpact._score_to_band(llm_cvss)
            if llm_band and llm_band in SEV:
                band_rank = SEV[llm_band]
                if has_contained:
                    band_rank = max(band_rank, MOD)
                if severity > band_rank:
                    severity = band_rank
                    guardrails_applied.append(f"llm_band_floor({LABELS[band_rank]})")

        # G2: memory corruption floor
        if has_corruption and severity > MOD:
            severity = MOD
            guardrails_applied.append("memory_corruption_floor(MODERATE)")

        # G3: network + corruption floor
        if has_corruption and has_network and severity > IMP:
            severity = IMP
            guardrails_applied.append("network_corruption_floor(IMPORTANT)")

        # G5: external CVSS confirmation for H1 de-escalation.
        #
        # Context — al-kernel uses only 2 signals: NN prediction +
        # LLM CVSS.  It has no external/NVD CVSS in reconciliation
        # (spec §"Key architectural principles", principle 4).  When
        # the LLM underscores a CVE, H1 de-escalates and that's
        # final.  Al-kernel accepts this because it evaluates each
        # CVE once and doesn't observe its own non-determinism.
        #
        # Aegis has a third signal the daemon lacks: the NVD/OSIDB
        # CVSS carried in classifier_result["cvss_score"].  This
        # score is deterministic and independent of the LLM.
        #
        # Problem — stability testing (20 iterations) showed that
        # for certain CVEs the LLM's CVSS swings across a 4+ point
        # range (e.g. 4.7–8.8), straddling H1's 6.5 threshold.  On
        # low rolls H1 fires (IMP→MOD) even though the classifier
        # predicted IMPORTANT and the NVD CVSS is solidly in the
        # IMPORTANT band (≥ 7.0).  This made evals non-deterministic:
        # CVE-2025-40248 failed 40% of runs, CVE-2025-38352 35%.
        #
        # Fix — when H1 fired and the external CVSS independently
        # confirms IMPORTANT (band rank < MOD, i.e. IMP or CRIT),
        # two stable signals (classifier + NVD) outweigh one noisy
        # signal (LLM CVSS), so we reverse H1's de-escalation.
        #
        # Conditions (all must hold):
        #   1. LLM CVSS was available (not NaN)
        #   2. H1 actually fired this evaluation (h1_fired flag)
        #   3. Severity is still MODERATE (no later rule already
        #      re-escalated or further de-escalated)
        #   4. External CVSS maps to IMPORTANT or higher band
        #
        # This is aegis-specific — it intentionally departs from
        # al-kernel's single-CVSS-source principle to exploit the
        # additional signal aegis has access to.
        ext_band = (
            SuggestImpact._score_to_band(clf_cvss_score) if clf_cvss_score else None
        )
        if (
            not math.isnan(llm_cvss)
            and h1_fired
            and severity == MOD
            and ext_band
            and ext_band in SEV
            and SEV[ext_band] < MOD
        ):
            severity = IMP
            guardrails_applied.append(f"ext_cvss_confirms_imp({clf_cvss_score:.1f})")

        final = LABELS.get(severity, clf_impact)

        trace_parts = [
            "path=kernel_threshold",
            f"start={start_label}(clf_conf={clf_confidence:.2f})",
            f"llm_cvss={llm_cvss:.1f}",
        ]
        if ext_band:
            trace_parts.append(f"ext_cvss={clf_cvss_score:.1f}({ext_band})")
        if rules_applied:
            trace_parts.append(f"rules=[{', '.join(rules_applied)}]")
        if guardrails_applied:
            trace_parts.append(f"guardrails=[{', '.join(guardrails_applied)}]")
        trace_parts.append(f"result={final}")
        trace = "; ".join(trace_parts)

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

    @staticmethod
    def reconcile_severity(output, call_str, classifier_result=None) -> str:
        """Bidirectional severity reconciliation.

        Dispatches to one of two paths:

        **Kernel path** (classifier_result present): threshold-based
        reconciliation ported from al-kernel.  The classifier's
        cascade-adjusted prediction is the starting severity; the LLM's
        own CVSS score drives deterministic threshold rules (H1–H11).

        **Non-kernel path** (no classifier): LLM self-consistency check.
        If the LLM's stated impact matches its CVSS band, keep it.  If
        they disagree, trust the CVSS band (quantitative > qualitative).

        The kernel path additionally applies specific guardrails
        (G2–G5) based on classifier-provided feature flags (memory
        corruption, network exposure, contained subsystems, etc.).

        Returns a trace string explaining the decision.
        """
        if classifier_result and isinstance(classifier_result, dict):
            return SuggestImpact._reconcile_kernel(output, call_str, classifier_result)

        # --- Non-kernel path: LLM self-consistency ---
        SEV = SuggestImpact.SEVERITY_ORDER

        try:
            llm_cvss = float(output.cvss3_score)
        except (ValueError, TypeError):
            llm_cvss = float("nan")

        llm_cvss_band = SuggestImpact._score_to_band(llm_cvss)
        llm_impact = (output.impact or "").strip().upper()

        if not llm_cvss_band or llm_cvss_band not in SEV:
            return ""
        if llm_impact not in SEV:
            return ""

        if llm_impact == llm_cvss_band:
            trace = (
                f"path=non_kernel; llm_cvss={llm_cvss:.1f}; "
                f"band={llm_cvss_band}; stated={llm_impact}; "
                f"consistent=true; result={llm_impact}"
            )
            logger.info(
                "%s: reconciliation confirmed %s (%s)",
                call_str,
                llm_impact,
                trace,
            )
            return trace

        final = llm_cvss_band
        trace = (
            f"path=non_kernel; llm_cvss={llm_cvss:.1f}; "
            f"band={llm_cvss_band}; stated={llm_impact}; "
            f"consistent=false; result={final}"
        )
        logger.info(
            "%s: reconciled %s -> %s (%s)",
            call_str,
            output.impact,
            final,
            trace,
        )
        output.impact = final
        return trace

    @staticmethod
    def post_process(output, call_str, classifier_result=None):
        SuggestImpact.post_process_cvss(output, call_str)
        return SuggestImpact.reconcile_severity(
            output, call_str, classifier_result=classifier_result
        )

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        use_kernel_classifier = get_settings().use_kernel_classifier

        use_static = (
            static_context
            and isinstance(static_context, dict)
            and static_context.get("cvss_scores") is not None
        )
        resolved_static_context = static_context if use_static else None
        is_kernel = False

        if use_kernel_classifier:
            components = []
            if isinstance(static_context, dict):
                components = static_context.get("components") or []

            if not components:
                cve_data = await osidb_tool.cve_retrieve(cve_id)
                components = cve_data.components
                resolved_static_context = cve_data.model_dump()
                use_static = True

            is_kernel = is_kernel_component(components)

        deps = feature_deps(
            exclude_osidb_fields=["impact", "rh_cvss_score"],
            static_context=resolved_static_context if use_static else None,
            is_kernel_cve=is_kernel,
        )
        if is_kernel:
            deps._is_kernel_cve = True
        output_schema = SuggestImpactModel.model_json_schema()
        if not is_kernel:
            output_schema.get("properties", {}).pop(
                "classifier_disagreement_rationale", None
            )

        prompt = AegisPrompt(
            user_instruction="Analyze the CVE JSON and derive a CVSS v3.1 base vector and score with metric-by-metric rationale from the perspective of Red Hat customers. Based on the score, select the impact (LOW/MODERATE/IMPORTANT/CRITICAL). Ignore any pre-labeled impact/CVSS and decide independently.",
            goals="""
                - Return exactly one CVSS:3.1 base vector and score consistent with each other.
                - Provide short reasoning for each base metric (AV, AC, PR, UI, S, C, I, A).
                - Prefer AV:L for local-only flaws; use AV:N only if remote/network reachable without local access; AV:A when limited to same-link/adjacent network; AV:P for physical.
                - For DoS-only flaws, emphasize A over C/I; for LPE, emphasize PR>UI and I (and C when secrets are exposed).
                - Do not base metric choices on which RH products are affected; reason from technical preconditions and exploit mechanics.
                - Pick impact (Critical/Important/Moderate/Low) from the computed score.
            """,
            rules=self._RULES_KERNEL if is_kernel else self._RULES_BASE,
            context=CVEFeatureInput(cve_id=cve_id),
            static_context=remove_keys(
                resolved_static_context, keys_to_remove=deps.exclude_osidb_fields
            ),
            output_schema=output_schema,
        )

        run_kwargs: dict = dict(deps=deps, output_type=SuggestImpactModel)

        if use_kernel_classifier and is_kernel:
            from pydantic_ai.toolsets import FunctionToolset
            from aegis_ai.toolsets.tools.kernel_classifier import kernel_impact_tool

            kernel_tools: list = [kernel_impact_tool]
            if get_settings().use_linux_cve_tool:
                from aegis_ai.toolsets.tools.kernel_cves import kernel_cve_tool

                kernel_tools.append(kernel_cve_tool)

            run_kwargs["toolsets"] = [FunctionToolset[feature_deps](tools=kernel_tools)]

        result = await self.guarded_run(prompt, **run_kwargs)
        call_str = f"{self.__class__.__name__}({cve_id})"
        classifier_result = deps.classifier_result
        trace = SuggestImpact.post_process(
            result.output,
            call_str,
            classifier_result=classifier_result,
        )

        result.output._classifier_diagnostics = classifier_result
        result.output._reconciliation_trace = trace

        return result


class SuggestCWE(Feature):
    """Based on current CVE information and context assert CWE(s)."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        deps = feature_deps(exclude_osidb_fields=["cwe_id"])

        prompt = AegisPrompt(
            user_instruction="From the CVE JSON, identify the most specific CWE that matches the root cause of software weakness. Ignore any pre-labeled CWE.",
            goals="""
                - Prefer the most specific CWE over broad parents.
                - Return a short explanation and confidence.
            """,
            rules="""
                - When CVE component is kernel always use kernel_cve tool to retrieve additional context.
                - Retrieve and summarise additional context strictly from vulnerability reference URLs and CWE tool outputs.
                    - Prefer mitre_cwe tools (retrieve_allowed_cwe_ids, search_cwes, retrieve_cwes) for CWE selection and definitions.
                    - Use github mcp tool to resolve vulnerability reference URLs if present.
                    - Avoid using general-purpose web search or encyclopedic tools for CWE selection unless references are insufficient.
                - Identify set of candidate CWEs - always use the mitre cwe tool retrieve_allowed_cwe_ids to filter candidate CWE list.
                    - Analyze vulnerability, identify CWE that matches root cause of weakness, being careful about memory management and buffer overflows.
                    - Perform search using mitre cwe tool cwe_searches to identify candidate CWEs (perform cwe_searches with 2-3 different queries).
                - Use mitre cwe retrieve_cwes tool to get additional information on candidate CWEs.
                - Select the top 2-3 most applicable CWEs (preference on applicability and higher similarity score) from the final set of candidate CWEs.
                - The final list of suggested CWEs should be ranked from most to least applicable to the vulnerability. For example, the first item in the array should be the most applicable CWE based on entire vulnerability analysis.
                Output should include:
                - cwe: Return ordered list of top 2–3 applicable CWE IDs (ex. ["CWE-94"])
                - explanation: 1–2 sentences connecting CVE details to the CWE.
                - confidence: [0.00..1.00].
            """,
            context=CVEFeatureInput(cve_id=cve_id),
            static_context=remove_keys(
                static_context, keys_to_remove=deps.exclude_osidb_fields
            ),
            output_schema=SuggestCWEModel.model_json_schema(),
        )

        run_kwargs: dict = dict(deps=deps, output_type=SuggestCWEModel)
        result = await self.guarded_run(prompt, **run_kwargs)
        # Post-process: filter out any disallowed CWE IDs (guardrail in case LLM misses rules)
        await cwe_manager.initialize()
        allowed_cwe_ids = set(cwe_manager.get_allowed_cwe_ids())
        suggested_cwes = result.output.cwe
        filtered_out = [cwe for cwe in suggested_cwes if cwe not in allowed_cwe_ids]
        if filtered_out:
            logger.warning(
                f"{self.__class__.__name__}({cve_id}): filtering out disallowed CWE IDs: {filtered_out}"
            )
            result.output.cwe = [
                cwe for cwe in suggested_cwes if cwe in allowed_cwe_ids
            ]
        return result


class IdentifyPII(Feature):
    """Based on current CVE information (public comments, description, statement) and context assert if it contains any PII."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        deps = feature_deps(exclude_osidb_fields=[])
        prompt = AegisPrompt(
            user_instruction="Examine the CVE JSON and identify any PII (names, emails, phone numbers, IDs, IPs, health/genetic info, etc.).",
            goals="""
                - Traverse all fields; consider both keys and values.
                - Prefer precise matches; avoid speculation.
            """,
            rules="""
                Output rules:
                - explanation: If PII is found, provide a bulleted list using the '-' character. Each item must be in the format: PII type: "exact string". Example: - Gender: "male".
                  - The PII type must be a concise description (e.g., "Gender", "Race", "Email Address", "Phone Number").
                  - The "exact string" must be the literal value from the JSON.
                  - Create a new bullet point for each unique instance of PII found.
                  - If no PII is found, this field should be an empty string ("").
                - confidence: [0.00..1.00].
                - contains_PII: true if any PII found, else false.
                
                Only report PII present in the JSON. Do not add extra text or line breaks like \n inside items.
            """,
            context=CVEFeatureInput(cve_id=cve_id),
            static_context=static_context,
            output_schema=PIIReportModel.model_json_schema(),
        )
        return await self.guarded_run(prompt, deps=deps, output_type=PIIReportModel)


class SuggestDescriptionText(Feature):
    """Based on current CVE information and context suggest a description and title."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        deps = feature_deps(exclude_osidb_fields=["title", "cve_description"])
        prompt = AegisPrompt(
            user_instruction="Analyze the CVE JSON and suggest the CVE description and title to be brief, clear, and accurate. If missing, propose them. Write for a non-technical/executive audience (e.g., a CISO) using plain English; avoid jargon and define unavoidable terms briefly.",
            goals="""
                - Provide a concise description and a short title.
                - Include confidence and quality scores.
                - The description should be 2–5 sentences and easy to read.
                - The title should briefly summarize the core issue in one line; keep headline-level detail only (do not mirror the full description).
            """,
            rules="""
                'description': one short paragraph.
                - Begin with: "A flaw was found in <component>."
                - Clearly state: who can exploit the flaw (e.g., a remote attacker, a local user, a malicious server), how it can be exploited (method/conditions), and the concrete consequences.
                - Include the vulnerability type when clear (use CWE category when obvious), the affected component, the trigger/cause, and the primary impact.
                - Highlight the most important consequence first. Prefer domain phrases such as "arbitrary code execution", "privilege escalation", "information disclosure", or "Denial of Service (DoS)".
                - Use plain English; avoid deep implementation jargon. If a function or symbol name is central to exploitation, you may mention a single example and explain it briefly.
                - If a term or acronym is needed, briefly define it and expand the acronym in parentheses on first use.
                - Do not include product/version lists, package names, or mitigation/update guidance.
                - Do not mention exploit availability or public disclosure status (e.g., "The exploit has been publicly disclosed").
                - Avoid generic CIA boilerplate; name the concrete impact (e.g., data disclosure, code execution, denial of service).
                - When upstream or reference text in the CVE is well written, prefer clarity and professional advisory tone over adding redundant phrasing.
                - Ambiguity and uncertainty:
                  - Do NOT invent a specific component, function, trigger, CWE, or impact if the source data and references do not clearly support it.
                  - If a single component or trigger cannot be reliably identified, use neutral wording (e.g., "in the affected component") and describe the mechanism at a high level.
                  - Prefer calibrated phrasing when evidence is weak (e.g., "may allow", "can enable") rather than asserting specifics.
                  - Only include a CWE category or precise impact (e.g., "arbitrary code execution", "privilege escalation") when it is well-supported; otherwise, use a generic but accurate type (e.g., "input validation vulnerability", "memory corruption vulnerability") or simply "vulnerability".
                'title': <= 20 words, summarize the description; include product/component and vulnerability type or consequence.
                - Style: "<Component>: <primary consequence> via <trigger/cause>" when applicable.
                - Prefer one primary consequence in the title (the worst plausible or the one the advisory emphasizes). Avoid stacking multiple unrelated impact types (e.g. several "and" clauses for different CIA outcomes); use one umbrella phrase in the title and put nuance in the description.
                - The title may include a specific function or primitive if it is the salient trigger; avoid extraneous implementation details and avoid stuffing multiple impact dimensions into the title—those belong in the description.
                - If the trigger is unclear, omit the "via <trigger/cause>" clause. If the component is unclear, name the project/product or keep a consequence-first title without fabricating specifics.
                - Strictly exclude versions: never include any version numbers or ranges (e.g., "5.0.0", "v2", "2.x", "9.x and earlier") in the title.
                - Keep it focused and professional.
                - 'description' and 'title' need to be consistent with each other.
                - Never output meta-diagnostic text such as "information is inconsistent", "insufficient data", "cannot determine", or similar. Provide the best-supported description instead with calibrated confidence.
            """,
            context=CVEFeatureInput(cve_id=cve_id),
            static_context=remove_keys(
                static_context, keys_to_remove=deps.exclude_osidb_fields
            ),
            output_schema=SuggestDescriptionModel.model_json_schema(),
        )
        return await self.guarded_run(
            prompt, deps=deps, output_type=SuggestDescriptionModel
        )


class SuggestStatementText(Feature):
    """Based on current CVE information and context suggest a statement and mitigation."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        deps = feature_deps(exclude_osidb_fields=["statement", "mitigation"])
        NO_MITIGATION_TEXT = (
            "Mitigation for this issue is either not available or the currently available "
            "options do not meet the Red Hat Product Security criteria comprising ease of use and deployment, "
            "applicability to widespread installation base, or stability."
        )

        prompt = AegisPrompt(
            user_instruction=f"Analyze the provided CVE context ({cve_id}) and generate a Red Hat specific Statement and Mitigation.",
            goals="""
            - Provide two fields tailored for Red Hat products:
              1) Suggested Statement: brief rationale of impact in RH context
              2) Suggested Mitigation: practical configuration or operational workaround tailored to Red Hat
            - Keep outputs concise and consistent; avoid contradiction between fields.
            """,
            rules=f"""
            ### STATEMENT (suggested_statement)
            - Focus on impact and RH relevance (deployment model, defaults, hardening).
            - Start with a concise severity-and-why sentence tailored for Red Hat that is consistent with the provided 'impact' field if available:
              - If 'impact' is present in context, reuse that label but in Title Case (Low/Moderate/Important/Critical) and do not contradict it.
              - If 'impact' is not present, avoid assigning an explicit severity label; describe impact qualitatively instead.
            - Add value beyond the CVE description and public comments: explain *why* that severity label fits the risk (e.g., why Important rather than Moderate), not a restatement of comment #0 alone.
            - When you include an explicit severity label (Low/Moderate/Important/Critical), add at least one short clause that justifies that band (e.g. local-only vs remote, prerequisites, blast radius, or why not the next lower severity)—not only a description of the bug mechanics.
            - Differentiate from the CVE description: lead with Red Hat deployment context (defaults, exposure on typical installs) where possible; do not reuse the same sentence structure or chain of nouns as cve_description (reorder ideas and change phrasing so the statement is not a light paraphrase).
            - Explain briefly why impact applies (e.g., feature disabled by default, needs uncommon configuration, requires physical access, short-lived CLI use).
            - Applicability without duplicating the advisory "Affects" list:
              - Do not paste product/version matrices; readers can see those elsewhere. At most one short clause when defaults or preconditions are essential (e.g., "disabled by default on RHEL 8 and 9").
              - If the vulnerability requires a feature that is disabled by default on common RH releases, say so briefly; avoid enumerating every unaffected release unless a single contrast is needed.
              - If exploit requires physical access or specialized hardware, highlight that requirement; mention if virtualized/emulated devices could still enable exploitation.
            - When applicable, note preconditions and what is not affected (e.g., roles, disabled-by-default features) without turning the statement into a component version manifest.
            - Must NOT:
              - Duplicate the CVE description verbatim or copy any sentence or 7+ consecutive words from it; paraphrase and focus on RH-specific context.
              - Lead with or emphasize upstream component version strings (e.g., "Foo 1.2.3"); severity narrative comes first.
              - Include code-level details or command examples.
              - Mention mitigation steps or software updates/patching.
            - Style: 2–4 concise sentences, < 1000 characters total.
            
            ### MITIGATION (suggested_mitigation)
            - **Definition:** A configuration or operational control that reduces exposure without patching (e.g., config file, environment variable or feature toggle, sysctl, service disable, or removing optional packages). Prefer a conservative, documented mitigation over declaring that none exists.
            - **Prohibitions:**
                - **NEVER** suggest updating/patching software.
                - **NEVER** invent config flags or commands.
                - **NEVER** use the term 'update'.
                - **NEVER** suggest dangerous commands (`rm -rf`, `chmod 777`, disabling SELinux globally) without explicit, dire warnings.
            - **Decision process (use before considering fallback):**
                1. Identify what exposes the vulnerable component in RH context (network daemon, optional plugin/format, kernel module/driver, desktop-only feature).
                2. Check for documented, supported controls to reduce exposure: restrict network reachability, disable optional features/plugins/filters, sandbox, or blacklist/avoid autoloading kernel modules.
                3. If any safe, documented configuration or operational control exists, provide it even if it only partially reduces risk; clearly note caveats.
                4. Only if no such control exists or the CVE does not affect RH products, proceed to the fallback.
            - **Structure:**
                1. Summary of action ("Disable the X service").
                2. Command examples (`sysctl`, `systemctl`).
                3. Caveats ("This may impact performance").
                4. Always warn if there is a potential for reload and restarts (If CVE is related to a service and mitigation provides concrete command line instructions, always provide a warning)
            - Prefer configuration-only or operational hardening patterns when applicable:
                - Limit service exposure: restrict access to trusted networks, apply rate limiting or firewall rules, and enable protocol validation features if available (e.g., DNSSEC for resolvers).
                - Disable optional features required to trigger the flaw: use configuration or environment toggles to turn off risky engines or modes; remove optional packages that provide the risky component if not needed.
                - Web content engines or embedded browsers (e.g., WebKitGTK): advise avoiding untrusted web content; if exploitation depends on JIT, disable it via a documented toggle when available (example for WebKitGTK: set environment variable JavaScriptCoreUseJIT=0 on affected systems).
                - If exposure is introduced by optional desktop/GUI packages, list common packages that pull in the vulnerable component and suggest removing them if not needed; clearly warn that removing these may also remove GNOME or related packages and break functionality; note that servers remain usable via terminal.
                - For components that process untrusted content (browsers, renderers, document viewers), advise operational controls such as avoiding untrusted content and sandboxing. If a JIT or optional execution engine can be disabled via a documented environment variable or config flag, suggest disabling it (e.g., an environment variable toggle).
                - Kernel driver vulnerabilities: prevent autoloading of the affected module via an /etc/modprobe.d rule (install/blacklist); note that a restart or service reload may be required and may impact functionality.
                - Network daemons (e.g., CUPS, dnsmasq, httpd): restrict service to localhost or trusted networks, disable remote administration, and firewall the relevant port(s) if feasible in your environment.
            - **Fallback:** Use only after the decision process above confirms that no safe, documented configuration or operational control exists in Red Hat products, or if the CVE does not affect Red Hat products (e.g., Windows-only). If any partial risk reduction is possible (e.g., firewalling, limiting to localhost, disabling optional plugins/filters, sandboxing, or blacklisting a kernel module), DO NOT use the fallback. When applicable, YOU MUST USE EXACTLY THIS TEXT:
              "{NO_MITIGATION_TEXT}"
            - Length: < 2000 characters.
            """,
            context=CVEFeatureInput(cve_id=cve_id),
            static_context=remove_keys(
                static_context, keys_to_remove=deps.exclude_osidb_fields
            ),
            output_schema=SuggestStatementModel.model_json_schema(),
        )
        return await self.guarded_run(
            prompt, deps=deps, output_type=SuggestStatementModel
        )


def _has_sufficient_static_context(static_context: Any) -> bool:
    """True when static_context has enough data to infer components without OSIDB."""
    if not static_context or not isinstance(static_context, dict):
        return False
    desc = (
        static_context.get("comment_zero")
        or static_context.get("cve_description")
        or ""
    )
    return bool(desc)


class SuggestAffectedComponents(Feature):
    """Infer affected components from CVE data using all available OSIDB fields."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        use_static = _has_sufficient_static_context(static_context)
        deps = feature_deps(
            exclude_osidb_fields=["affects", "components"],
            static_context=static_context if use_static else None,
        )
        prompt = AegisPrompt(
            user_instruction="From the provided CVE data (title, description, statement, references, affects, comments, etc.), identify the affected software component(s). "
            "Use the OSIDB tool to retrieve flaw data when cve_id is provided; when full context is already provided, the tool returns that data. Leverage all available fields to infer components.",
            goals="""
                - From all available CVE/OSIDB data (title, comment_zero, description, statement, mitigation, comments, references, affects, cvss_scores, cwe_id, impact), identify the affected software component(s).
                - List component names (package names) in the output 'components' field.
                - Where a Package URL (PURL) is identified use the name part of the PURL. For maven or golang types include the namespace in the component name but no PURL protocol or type.
                - If the component is from the Python standard library, use 'python' as the component name.
                - If the component is from the Go ecosystem and not in the standard library, include the namespace (e.g. github.com/containerd/containerd).
                - If the component is from the Go standard library, use a specific package name and return it first in the components array in addition to the component 'golang'.
                - For vulnerabilities in Google Chrome, Chromium, or any Chromium sub-component (V8, Blink, ANGLE, PDFium, Skia, DevTools, WebGL, WebML, Compositing, etc.), use 'chromium-browser' as the single component name.
                - Provide a concise explanation of the rationale.
            """,
            rules="""
                - Use the osidb_tool with the provided cve_id to retrieve CVE flaw data.
                - Leverage title, description (or comment_zero), statement, references, affects, comments, and any other fields to infer affected components.
                - Use github mcp tool to resolve vulnerability reference URLs if present (e.g. to confirm repo/component names).
                - Follow GitHub/golang-style naming: use full import paths for Go packages outside stdlib.
                - Output format: components (list of strings), explanation (string), confidence (0.00–1.00).
            """,
            context=CVEFeatureInput(cve_id=cve_id),
            static_context=remove_keys(
                static_context, keys_to_remove=deps.exclude_osidb_fields
            ),
            output_schema=SuggestAffectedComponentsModel.model_json_schema(),
        )
        return await self.guarded_run(
            prompt, deps=deps, output_type=SuggestAffectedComponentsModel
        )


class CVSSDiffExplainer(Feature):
    """Based on current CVE information and context explain CVSS score diff between nvd and rh."""

    async def exec(self, cve_id: CVEID, static_context: Any = None):
        deps = feature_deps(exclude_osidb_fields=[])
        prompt = AegisPrompt(
            user_instruction="Compare Red Hat CVSS3 vs NVD CVSS3 for the CVE and explain any differences.",
            goals="""
                - Report both base vectors/scores.
                - If identical, explanation must be empty.
            """,
            rules="""
                - Be specific about which metrics drive the difference (AV, AC, PR, UI, CIA).
                - Expand especially on *why* the metrics are different in the Red Hat context.
                - Keep the rationale brief and factual. If no difference, return an empty explanation.
            """,
            context=CVEFeatureInput(cve_id=cve_id),
            static_context=static_context,
            output_schema=CVSSDiffExplainerModel.model_json_schema(),
        )
        return await self.guarded_run(
            prompt, deps=deps, output_type=CVSSDiffExplainerModel
        )
