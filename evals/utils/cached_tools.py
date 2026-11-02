import logging

from pydantic_ai.tools import RunContext, Tool

from aegis_ai.features.data_models import feature_deps
from aegis_ai.toolsets.tools.osidb import CVE, OSIDBToolInput, cve_exclude_fields
from aegis_ai.toolsets.tools.osv_common import filter_osv_response
from aegis_ai.toolsets.tools.osv_dev_cve import OSVToolInput as OSVCVEToolInput
from aegis_ai.toolsets.tools.osv_dev_ghsa import GHSAToolInput, extract_ghsa_ids
from evals.utils.ghsa_cache import ghsa_cache_retrieve
from evals.utils.osidb_cache import osidb_cache_retrieve

logger = logging.getLogger(__name__)

_osidb_field_masks: dict[str, list[str]] = {}


def mask_osidb_fields(cve_id: str, fields: list[str]) -> None:
    """Register extra fields to mask when the cached osidb_tool returns data for *cve_id*."""
    _osidb_field_masks.setdefault(cve_id, []).extend(fields)


_disabled_tools: dict[str, set[str]] = {}


def disable_tools(cve_id: str, tool_names: list[str]) -> None:
    """Register tools to hide from the agent when evaluating *cve_id*."""
    _disabled_tools.setdefault(cve_id, set()).update(tool_names)


def is_tool_disabled(cve_id: str | None, tool_name: str) -> bool:
    """Return True if *tool_name* should be filtered out for *cve_id*."""
    if cve_id is None:
        return False
    return tool_name in _disabled_tools.get(cve_id, set())


@Tool
async def osidb_tool(ctx: RunContext[feature_deps], input: OSIDBToolInput) -> CVE:
    """wrapper around aegis.tools.osidb that caches OSIDB responses"""
    deps = ctx.deps
    if deps.cve_id is not None and str(input.cve_id) != deps.cve_id:
        logger.info(
            f"osidb_tool: rejecting lookup for {input.cve_id} (expected {deps.cve_id})"
        )
        return CVE(
            cve_id=input.cve_id,
            title=f"Flaw {input.cve_id} lookup rejected (unrelated to {deps.cve_id})",
            description="",
        )
    try:
        cve = await osidb_cache_retrieve(input.cve_id)
    except Exception:
        logger.info(f"OSIDB cache miss for {input.cve_id}, returning empty CVE")
        return CVE(
            cve_id=input.cve_id,
            title=f"Flaw {input.cve_id} was not found in OSIDB cache",
            description="",
        )
    if ctx.deps.allowed_reference_urls is None and cve.references:
        ctx.deps.allowed_reference_urls = {
            ref["url"]
            for ref in cve.references
            if isinstance(ref, dict) and ref.get("url")
        }

    cve = cve_exclude_fields(
        cve,
        ctx.deps.exclude_osidb_fields,
        strip_component_prefix_for_osidb_cache=True,
    )
    extra_mask = _osidb_field_masks.get(str(input.cve_id))
    if extra_mask:
        cve = cve_exclude_fields(cve, extra_mask)
    return cve


@Tool
async def osv_dev_ghsa_tool(ctx: RunContext[feature_deps], input: GHSAToolInput):
    """wrapper around osv_dev_ghsa that caches OSV.dev responses"""
    ghsa_ids = extract_ghsa_ids(input.references)
    if not ghsa_ids:
        return []
    results = []
    for ghsa_id in ghsa_ids:
        raw = await ghsa_cache_retrieve(ghsa_id)
        filtered = filter_osv_response(raw)
        if filtered:
            results.append(filtered)
    return results


@Tool
async def osv_dev_cve_tool(ctx: RunContext[feature_deps], input: OSVCVEToolInput):
    """wrapper around osv_dev_cve that caches OSV.dev responses"""
    deps = ctx.deps
    if deps.cve_id is not None and str(input.cve_id) != deps.cve_id:
        logger.info(
            f"osv_dev_cve_tool: rejecting lookup for {input.cve_id} "
            f"(expected {deps.cve_id})"
        )
        return {}
    raw = await ghsa_cache_retrieve(str(input.cve_id))
    return filter_osv_response(raw)
