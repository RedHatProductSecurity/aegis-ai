"""Kernel-specific CVSS overrides and LLM prompt rules.

This module provides:

- ``RULES_KERNEL`` — LLM prompt rules injected for kernel CVEs.
- ``apply_kpanic_cvss_override()`` — forces AC:H, S:U, A:H when kernel
  panic is detected or impact is IMPORTANT.
- ``check_kernel_output()`` — retry enforcement ensuring the LLM calls
  ``kernel_impact_tool`` for kernel CVEs.
"""

from __future__ import annotations

import logging

import cvss

from aegis_ai import get_settings

logger = logging.getLogger(__name__)

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
                - After calling osidb_flaw_tool, you MUST pass the flaw's reference URLs to external_references_tool to retrieve upstream CVSS vectors, security advisories, and commit details. This is critical for accurate scoring.
                - Retrieve and summarize additional context from vulnerability references:
                    - Use github mcp and web search tools for additional context if needed.
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
