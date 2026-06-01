#!/usr/bin/env python3
"""Populate evals/external_references_cache from OSIDB-cached reference URLs.

Reads CVE IDs from a file (one per line), loads their OSIDB cache entries,
extracts all reference URLs, and fetches each through the external references
tool.  Results are written to the eval cache so evals can run without live
HTTP requests.
"""

import asyncio
import json
import sys
from pathlib import Path

from aegis_ai import config_logging
from aegis_ai.toolsets.tools.external_references import (
    fetch_reference,
    validate_url,
)
from evals.utils.external_references_cache import (
    CACHE_DIR,
    cache_key_for_url,
    write_cache_entry,
)

OSIDB_CACHE_DIR = "evals/osidb_cache"


async def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <cve_ids_file>", file=sys.stderr)
        print("  Each line should contain one CVE ID.", file=sys.stderr)
        sys.exit(1)

    config_logging(level="INFO")

    with open(sys.argv[1]) as f:
        cve_ids = [line.strip() for line in f if line.strip()]

    urls_to_fetch: list[str] = []
    skipped_cves: list[str] = []

    for cve_id in cve_ids:
        osidb_file = Path(OSIDB_CACHE_DIR) / f"{cve_id}.json"
        if not osidb_file.exists():
            skipped_cves.append(cve_id)
            continue
        with open(osidb_file) as f:
            data = json.load(f)
        for ref in data.get("references", []):
            url = ref.get("url", "")
            if not url:
                continue
            cache_file = Path(CACHE_DIR) / f"{cache_key_for_url(url)}.json"
            if cache_file.exists():
                continue
            if validate_url(url):
                urls_to_fetch.append(url)

    if skipped_cves:
        print(
            f"Skipped {len(skipped_cves)} CVE(s) not in OSIDB cache: "
            f"{', '.join(skipped_cves[:5])}{'...' if len(skipped_cves) > 5 else ''}",
            file=sys.stderr,
        )

    total = len(urls_to_fetch)
    print(f"Fetching {total} external reference(s)...", file=sys.stderr)

    success = 0
    failed = []

    for i, url in enumerate(urls_to_fetch, 1):
        try:
            result = await fetch_reference(url)
            write_cache_entry(url, result)
            if result.status == "success":
                success += 1
            else:
                failed.append(f"{url} ({result.status})")
        except Exception as e:
            print(f"[{i}/{total}] FAILED {url}: {e}", file=sys.stderr)
            failed.append(url)
            continue

        if i % 20 == 0:
            print(f"[{i}/{total}] progress: {success} cached", file=sys.stderr)

    print(f"\nDone: {success}/{total} fetched, {len(failed)} failed", file=sys.stderr)
    if failed:
        print("\nFailed URLs:", file=sys.stderr)
        for url in failed:
            print(f"  {url}", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())
