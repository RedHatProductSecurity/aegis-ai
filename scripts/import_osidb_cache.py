#!/usr/bin/env python3
"""Import CVE data into evals/osidb_cache from OSIDB for a list of CVE IDs."""

import asyncio
import sys

from aegis_ai import config_logging
from aegis_ai.toolsets.tools.osidb import cve_retrieve
from evals.utils.osidb_cache import write_cache_entry


async def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <cve_ids_file>", file=sys.stderr)
        print("  Each line should contain one CVE ID.", file=sys.stderr)
        sys.exit(1)

    config_logging(level="INFO")

    with open(sys.argv[1]) as f:
        cve_ids = [line.strip() for line in f if line.strip()]

    total = len(cve_ids)
    success = 0
    failed = []

    for i, cve_id in enumerate(cve_ids, 1):
        try:
            cve_data = await cve_retrieve(cve_id)
            write_cache_entry(cve_id, cve_data)
            success += 1
        except Exception as e:
            print(f"[{i}/{total}] FAILED {cve_id}: {e}", file=sys.stderr)
            failed.append(cve_id)
            continue

        if i % 50 == 0:
            print(f"[{i}/{total}] progress: {success} cached", file=sys.stderr)

    print(f"\nDone: {success}/{total} cached, {len(failed)} failed", file=sys.stderr)
    if failed:
        print("\nFailed CVEs:", file=sys.stderr)
        for cve_id in failed:
            print(f"  {cve_id}", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())
