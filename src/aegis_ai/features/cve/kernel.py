"""Kernel-specific LLM prompt rules and output checks.

This module provides:

- ``RULES_KERNEL_ADDENDUM`` — extra LLM prompt rules appended to the
  base rules when the CVE is a kernel component.
- ``check_kernel_output()`` — retry enforcement ensuring the LLM calls
  ``kernel_impact_tool`` for kernel CVEs.
"""

from __future__ import annotations

import logging

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
                - Kernel-specific tools:
                    - If kernel_impact_tool is available, you MUST call it and use its classification of impact.  Then assign cvss3_vector such that cvss3_score matches the classified impact value.
                - Kernel-specific metric guidance:
                    - Network-facing kernel subsystems (network drivers, netfilter/nftables, Open vSwitch, VXLAN/GRE/Geneve tunnels, traffic control, SKB/packet processing): when the vulnerable code path processes or is reachable via network packets, use AV:A or AV:N — the attack vector reflects how the exploit is delivered, not the subsystem's location in the kernel source tree.
                    - Hardware-triggered kernel parsing (USB class drivers, Bluetooth HCI, input device drivers): use AV:L, not AV:P — the kernel parses device data locally regardless of how the device was connected, so the attack surface is local code processing, not physical manipulation of the device.
                    - Use-after-free or race conditions: when the advisory or existing CVSS vectors from authoritative issuers (RH, CVEOrg) indicate C:H/I:H, do not downgrade to C:N/I:N — UAF primitives in kernel subsystems (networking, filesystems, device drivers) provide controlled memory access that enables privilege escalation or data disclosure, even when the advisory does not explicitly say "privilege escalation."
                    - Network filesystem worker races (e.g., oplock/lease break handlers, deferred close): when the trigger is normal file I/O on an already-mounted share, use PR:L — the attacker needs only ordinary file access, not mount privileges.
                    - OOB write with attacker-controlled data (e.g., malicious USB device, crafted packet): corrupting kernel structures that mediate user-visible state (fs metadata, security descriptors, memory mappings) compromises system integrity and can expose user-data — use I:H and name the control mechanism and target structures in the explanation.
            """


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
        logger.info(
            f"[kernel_impact_tool] no classifier data returned for {output.cve_id}"
        )
        return None

    logger.warning(
        "kernel_impact_tool was not called for a kernel CVE; requesting retry"
    )
    return (
        "This is a Linux kernel CVE. You MUST call kernel_impact_tool "
        "to obtain patch-level analysis before producing your final answer."
    )
