#!/usr/bin/env python3
"""Pre-populate evals caches for all CVEs in evals/osidb_cache.

Iterates every CVE-*.json in the OSIDB cache and populates two caches:

1. **External references** — fetches allowed reference URLs through the
   external references tool and writes results to evals/external_references_cache.
2. **GHSA / OSV.dev** — looks up each CVE ID and any GHSA IDs found in
   references on OSV.dev and writes results to evals/ghsa_cache.

Skips entries that are already cached.  Safe to re-run at any time.
"""

import asyncio
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from aegis_ai import config_logging
from aegis_ai.toolsets.tools.external_references import (
    fetch_reference,
    validate_url,
)
from aegis_ai.toolsets.tools.osv_dev_cve import OSVClient
from evals.utils.external_references_cache import (
    CACHE_DIR as EXTREF_CACHE_DIR,
)
from evals.utils.external_references_cache import (
    cache_key_for_url,
)
from evals.utils.external_references_cache import (
    write_cache_entry as write_extref_cache_entry,
)
from evals.utils.ghsa_cache import GHSA_CACHE_DIR, write_ghsa_cache_entry

OSIDB_CACHE_DIR = Path("evals/osidb_cache")

_GHSA_RE = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}")


def _collect_osidb_entries() -> list[tuple[str, dict]]:
    """Load all OSIDB cache entries, returning (cve_id, data) pairs."""
    entries = []
    for json_file in sorted(OSIDB_CACHE_DIR.glob("CVE-*.json")):
        cve_id = json_file.stem
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            print(f"  skip {cve_id}: {e}", file=sys.stderr)
            continue
        entries.append((cve_id, data))
    return entries


async def _populate_external_references(
    entries: list[tuple[str, dict]],
) -> tuple[int, int, list[str]]:
    """Phase 1: populate external references cache. Returns (fetched, skipped, failed)."""
    urls_to_fetch: list[str] = []
    skipped = 0

    for _cve_id, data in entries:
        for ref in data.get("references", []):
            url = ref.get("url", "")
            if not url:
                continue
            cache_file = Path(EXTREF_CACHE_DIR) / f"{cache_key_for_url(url)}.json"
            if cache_file.exists():
                skipped += 1
                continue
            if validate_url(url):
                urls_to_fetch.append(url)

    # deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for url in urls_to_fetch:
        if url not in seen:
            seen.add(url)
            unique.append(url)
    urls_to_fetch = unique

    total = len(urls_to_fetch)
    print(
        f"[extref] {total} URL(s) to fetch, {skipped} already cached",
        file=sys.stderr,
    )

    fetched = 0
    failed: list[str] = []

    for i, url in enumerate(urls_to_fetch, 1):
        try:
            result = await fetch_reference(url)
            write_extref_cache_entry(url, result)
            if result.status == "success":
                fetched += 1
            else:
                failed.append(f"{url} ({result.status})")
        except Exception as e:
            print(f"  [{i}/{total}] FAILED {url}: {e}", file=sys.stderr)
            failed.append(url)
            continue

        if i % 20 == 0:
            print(f"  [{i}/{total}] progress: {fetched} cached", file=sys.stderr)

    return fetched, skipped, failed


def _populate_ghsa(
    entries: list[tuple[str, dict]],
) -> tuple[int, int, list[str]]:
    """Phase 2: populate GHSA / OSV.dev cache. Returns (fetched, skipped, failed)."""
    ghsa_cache_dir = Path(GHSA_CACHE_DIR)
    ghsa_cache_dir.mkdir(parents=True, exist_ok=True)

    client = OSVClient()
    fetched = 0
    skipped = 0
    failed: list[str] = []

    # collect all vuln IDs to look up: CVE IDs + GHSA IDs from references
    vuln_ids: list[str] = []
    seen: set[str] = set()

    for cve_id, data in entries:
        if cve_id not in seen:
            seen.add(cve_id)
            vuln_ids.append(cve_id)
        text = json.dumps(data)
        for ghsa_id in _GHSA_RE.findall(text):
            if ghsa_id not in seen:
                seen.add(ghsa_id)
                vuln_ids.append(ghsa_id)

    total = len(vuln_ids)
    to_fetch: list[str] = []
    for vuln_id in vuln_ids:
        cache_file = ghsa_cache_dir / f"{vuln_id}.json"
        if cache_file.exists():
            skipped += 1
        else:
            to_fetch.append(vuln_id)

    total_fetch = len(to_fetch)
    print(
        f"[ghsa] {total_fetch} ID(s) to fetch, {skipped} already cached "
        f"(out of {total} total)",
        file=sys.stderr,
    )

    for i, vuln_id in enumerate(to_fetch, 1):
        try:
            data = client.get_vuln_by_id(vuln_id)
            write_ghsa_cache_entry(vuln_id, data)
            fetched += 1
            if not data:
                print(f"  cached {vuln_id} (empty — not found on OSV.dev)")
        except Exception as e:
            print(f"  [{i}/{total_fetch}] FAILED {vuln_id}: {e}", file=sys.stderr)
            failed.append(vuln_id)
            continue

        if i % 50 == 0:
            print(f"  [{i}/{total_fetch}] progress: {fetched} cached", file=sys.stderr)

    return fetched, skipped, failed


async def main() -> None:
    config_logging(level="INFO")

    entries = _collect_osidb_entries()
    print(f"Loaded {len(entries)} OSIDB cache entries\n", file=sys.stderr)

    # Phase 1: external references
    print("Phase 1: external references", file=sys.stderr)
    ext_fetched, ext_skipped, ext_failed = await _populate_external_references(entries)
    print(
        f"  done: {ext_fetched} fetched, {ext_skipped} skipped, "
        f"{len(ext_failed)} failed\n",
        file=sys.stderr,
    )

    # Phase 2: GHSA / OSV.dev
    print("Phase 2: GHSA / OSV.dev", file=sys.stderr)
    ghsa_fetched, ghsa_skipped, ghsa_failed = _populate_ghsa(entries)
    print(
        f"  done: {ghsa_fetched} fetched, {ghsa_skipped} skipped, "
        f"{len(ghsa_failed)} failed\n",
        file=sys.stderr,
    )

    if ext_failed:
        print("Failed external references:", file=sys.stderr)
        for url in ext_failed:
            print(f"  {url}", file=sys.stderr)

    if ghsa_failed:
        print("Failed GHSA lookups:", file=sys.stderr)
        for vuln_id in ghsa_failed:
            print(f"  {vuln_id}", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())
