#!/usr/bin/env python3
"""
Populate osidb_cache with CVEs listed in a CSV file.

Usage:
  python -m evals.scripts.populate_cache_from_csv /path/to/eval_sample.csv

CSV format: lines with comma-separated fields; CVE IDs are in the 3rd column,
semicolon-separated (e.g. from component_intelligence_mismatched_components.csv).
"""

import asyncio
import csv
import logging
import sys
from pathlib import Path

# Run from repo root so evals and aegis_ai are importable
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from evals.utils.osidb_cache import osidb_cache_retrieve

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


def extract_cve_ids_from_csv(csv_path: Path) -> set[str]:
    """Parse CSV; assume column index 2 contains semicolon-separated CVE IDs."""
    cve_ids = set()
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.reader(f):
            if len(row) < 3:
                continue
            for part in row[2].split(";"):
                cve_id = part.strip()
                if cve_id.startswith("CVE-"):
                    cve_ids.add(cve_id)
    return cve_ids


async def main():
    if len(sys.argv) < 2:
        print(
            "Usage: python -m evals.scripts.populate_cache_from_csv <path/to/file.csv>",
            file=sys.stderr,
        )
        sys.exit(1)
    csv_path = Path(sys.argv[1])
    if not csv_path.is_file():
        print(f"Not a file: {csv_path}", file=sys.stderr)
        sys.exit(1)

    cve_ids = sorted(extract_cve_ids_from_csv(csv_path))
    logger.info("Found %d CVE IDs in %s", len(cve_ids), csv_path)

    for cve_id in cve_ids:
        try:
            await osidb_cache_retrieve(cve_id)
            logger.info("Cached %s", cve_id)
        except Exception as e:
            logger.warning("Failed %s: %s", cve_id, e)

    logger.info("Done.")


if __name__ == "__main__":
    asyncio.run(main())
