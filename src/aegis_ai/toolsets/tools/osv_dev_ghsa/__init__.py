"""
Tool for fetching GHSA (GitHub Security Advisory) data from OSV.dev.

Extracts GHSA identifiers from CVE reference URLs and retrieves structured
vulnerability data — affected packages, ecosystems, and version ranges —
from the OSV.dev API.
"""

import re

from pydantic import Field
from pydantic_ai import RunContext, Tool

from aegis_ai import logger
from aegis_ai.toolsets.tools import BaseToolInput
from aegis_ai.toolsets.tools.osv_common import filter_osv_response
from aegis_ai.toolsets.tools.osv_dev_cve import OSVClient

_GHSA_RE = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}")


class GHSAToolInput(BaseToolInput):
    references: list[str] = Field(
        ...,
        description="List of reference URLs from CVE/OSIDB data to scan for GHSA identifiers.",
    )


def extract_ghsa_ids(urls: list[str]) -> list[str]:
    """Extract unique GHSA identifiers from a list of URLs."""
    seen: set[str] = set()
    result: list[str] = []
    for url in urls:
        for m in _GHSA_RE.finditer(url):
            ghsa_id = m.group(0)
            if ghsa_id not in seen:
                seen.add(ghsa_id)
                result.append(ghsa_id)
    return result


@Tool
async def osv_dev_ghsa_tool(ctx: RunContext, input: GHSAToolInput):
    """
    Extract GHSA identifiers from CVE reference URLs and fetch structured
    vulnerability data from OSV.dev for each one.  Returns affected package
    names, ecosystems, PURLs, and version ranges.  If no GHSA identifiers
    are found in the provided references, returns an empty list without
    making any HTTP requests.
    """
    ghsa_ids = extract_ghsa_ids(input.references)
    if not ghsa_ids:
        logger.info("No GHSA identifiers found in references")
        return []

    client = OSVClient()
    results = []
    for ghsa_id in ghsa_ids:
        logger.info(f"Fetching GHSA data from OSV.dev for {ghsa_id}...")
        raw = client.get_vuln_by_id(ghsa_id)
        filtered = filter_osv_response(raw)
        if filtered:
            results.append(filtered)

    return results
