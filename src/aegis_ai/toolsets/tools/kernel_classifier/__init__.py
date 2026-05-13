"""Kernel impact classifier tool for the suggest-impact LLM agent.

Wraps :class:`KernelImpactClassifier` as a pydantic-ai ``@Tool`` so that
the LLM can request a patch-feature analysis during its reasoning loop.

The tool returns active patch-feature flags, per-class severity
probabilities, and **raw patch diffs** so the LLM can reason about
the actual code changes when producing its CVSS assessment.  It
deliberately omits the predicted impact label and any CVSS vector to
avoid anchoring the LLM on the classifier's output.
"""

import logging
import re
from typing import Dict, List, Optional

from pydantic import Field
from pydantic_ai import RunContext, Tool

from aegis_ai.data_models import CVEID
from aegis_ai.features.data_models import feature_deps
from aegis_ai.toolsets.tools import BaseToolInput, BaseToolOutput

logger = logging.getLogger(__name__)


class KernelImpactToolInput(BaseToolInput):
    cve_id: CVEID = Field(
        ...,
        description="The CVE identifier for a Linux kernel vulnerability.",
    )


class KernelImpactToolResponse(BaseToolOutput):
    """Patch-level analysis of a kernel CVE.

    Contains factual signals derived from the fix patches — the active
    feature flags (e.g. ``uaf``, ``networking``, ``kernel_panic``), the
    XGBoost severity class probabilities, and raw patch diffs.  No CVSS
    vector or single impact label is included to avoid anchoring the LLM.
    """

    cve_id: CVEID = Field(
        ...,
        description="The CVE identifier that was analysed.",
    )
    active_features: List[str] = Field(
        default_factory=list,
        description=(
            "Patch-derived binary feature flags that were detected "
            "(e.g. 'uaf', 'networking', 'kernel_panic', 'bpf'). "
            "If 'kernel_panic' is present, the bug can crash the kernel — "
            "the CVSS base score should typically be at least 7.0."
        ),
    )
    severity_probabilities: Dict[str, float] = Field(
        default_factory=dict,
        description=(
            "Per-class probabilities from the XGBoost model, "
            "e.g. {'IMPORTANT': 0.78, 'MODERATE': 0.15, 'LOW': 0.07}."
        ),
    )
    patches_analyzed: int = Field(
        default=0,
        description="Number of git patches that were fetched and analysed.",
    )
    patch_context: str = Field(
        default="",
        description=(
            "Raw patch diffs for the fix commits. "
            "Contains commit messages, diffstats, and unified diffs. "
            "Use this to inform your CVSS assessment."
        ),
    )


async def _fetch_osidb_cvss(cve_id: str) -> list[dict]:
    """Best-effort retrieval of CVSS scores from OSIDB for the cascade."""
    try:
        from aegis_ai.toolsets.tools.osidb import cve_retrieve

        cve = await cve_retrieve(cve_id)
        return cve.cvss_scores or []
    except Exception as exc:
        logger.debug("Could not fetch OSIDB CVSS for %s: %s", cve_id, exc)
        return []


async def _resolve_cvss_scores(
    cve_id: str, static_context: Optional[dict]
) -> list[dict]:
    """Return CVSS scores from static_context when available, else OSIDB."""
    if static_context and isinstance(static_context, dict):
        scores = static_context.get("cvss_scores")
        if scores is not None:
            logger.debug("Using CVSS scores from static_context for %s", cve_id)
            return scores
    return await _fetch_osidb_cvss(cve_id)


async def kernel_impact_classify(
    cve_id: CVEID,
    static_context: Optional[dict] = None,
) -> Optional[dict]:
    """Run the full kernel classifier pipeline for *cve_id*.

    Returns the raw classifier dict (including ``impact``) or ``None``.

    When *static_context* contains ``cvss_scores``, those are used for
    the cascade instead of making a separate OSIDB call.
    """
    from aegis_ai.kernel_classifier import KernelImpactClassifier
    from aegis_ai.toolsets.tools.kernel_cves import kernel_cve_lookup

    try:
        classifier = KernelImpactClassifier()
    except Exception as exc:
        logger.warning("kernel classifier init failed: %s", exc)
        return None

    if not classifier.available:
        logger.info("kernel classifier model not available")
        return None

    try:
        kcve_result = await kernel_cve_lookup(cve_id)
        raw_hashes = kcve_result.metadata.commit_hashes if kcve_result.metadata else []
    except Exception as exc:
        logger.warning("kernel_cve_lookup failed for %s: %s", cve_id, exc)
        return None

    commit_hashes = []
    for href in raw_hashes:
        m = re.search(r"([0-9a-fA-F]{40})", href)
        if m:
            commit_hashes.append(m.group(1))

    if not commit_hashes:
        logger.info("No commit hashes found for %s", cve_id)
        return None

    cvss_scores = await _resolve_cvss_scores(cve_id, static_context)

    return await classifier.classify(
        cve_id=cve_id,
        commit_hashes=commit_hashes,
        cvss_scores=cvss_scores,
    )


def _response_from_result(cve_id: CVEID, result: dict) -> KernelImpactToolResponse:
    """Build a tool response from a classifier result dict."""
    patch_summaries = result.get("patch_summaries", [])
    return KernelImpactToolResponse(
        cve_id=cve_id,
        active_features=result.get("active_features", []),
        severity_probabilities=result.get("probabilities", {}),
        patches_analyzed=result.get("patches_analyzed", 0),
        patch_context="\n---\n".join(patch_summaries),
    )


@Tool
async def kernel_impact_tool(
    ctx: RunContext[feature_deps], input: KernelImpactToolInput
) -> KernelImpactToolResponse:
    """Analyse fix patches for a Linux kernel CVE and return security-relevant
    signals: which patch feature flags fired and the model's per-class severity
    probabilities.  Use this when the CVE component is the Linux kernel."""

    ctx.deps.classifier_attempts += 1

    if not ctx.deps.is_kernel_cve:
        return KernelImpactToolResponse(
            cve_id=input.cve_id,
            status="error",
            error_message="Not a kernel CVE; tool not applicable.",
        )

    # Fast path: return pre-computed result when available (mirrors flaw_tool
    # static_context pattern).  exec() eagerly runs kernel_impact_classify
    # before the LLM call and stores the result on deps.
    if ctx.deps.classifier_result is not None:
        logger.info("Using pre-computed classifier result for %s", input.cve_id)
        return _response_from_result(input.cve_id, ctx.deps.classifier_result)

    # Slow path: run classifier on demand
    logger.info("Analysing kernel patch features for %s...", input.cve_id)
    static_context = getattr(ctx.deps, "static_context", None)
    result = await kernel_impact_classify(input.cve_id, static_context=static_context)

    if result is None:
        return KernelImpactToolResponse(
            cve_id=input.cve_id,
            status="error",
            error_message="Kernel classifier could not produce a result for this CVE.",
        )

    ctx.deps.classifier_result = result
    return _response_from_result(input.cve_id, result)
