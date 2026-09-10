"""Kernel-specific CVSS overrides and LLM prompt rules.

This module provides:

- ``RULES_KERNEL_ADDENDUM`` — extra LLM prompt rules appended to the
  base rules when the CVE is a kernel component.
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
# Kernel-specific addendum appended to _RULES_BASE for kernel CVEs.
#
# This is NOT a standalone prompt — it extends _RULES_BASE with kernel-
# specific output fields, metric guidance, and tool instructions.  All
# base rules (output format, metric selection, data quality, confidence,
# external_references_tool, etc.) come from _RULES_BASE.
# ---------------------------------------------------------------------------

RULES_KERNEL_ADDENDUM = """
                - Kernel-specific output fields:
                    - deescalation_rationale: If contextual factors (contained subsystem, restricted attack surface, high privilege requirements) suggest a lower severity than the CVSS band, note the justification here. Leave null otherwise.
                    - classifier_disagreement_rationale: If kernel_impact_tool returned patch signals and your CVSS-based assessment implies a different severity, explain the technical basis for your assessment. Leave null when you agree or no classifier result was available.
                - Kernel-specific metric guidance:
                    - Network filesystem worker races (e.g., oplock/lease break handlers, deferred close): when the trigger is normal file I/O on an already-mounted share, use PR:L — the attacker needs only ordinary file access, not mount privileges.
                    - OOB write with attacker-controlled data (e.g., malicious USB device, crafted packet): corrupting kernel structures that mediate user-visible state (fs metadata, security descriptors, memory mappings) compromises system integrity and can expose user-data — use I:H and name the control mechanism and target structures in the explanation.
                - Kernel-specific tools:
                    - Always use kernel_cve tool if the component is the Linux kernel.
                    - If kernel_impact_tool is available, you MUST call it to obtain patch-level analysis (active feature flags and severity class probabilities). Treat the returned signals as informative context alongside your own technical assessment. Report any disagreement in classifier_disagreement_rationale.
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
