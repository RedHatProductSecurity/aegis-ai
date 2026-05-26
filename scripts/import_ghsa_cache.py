#!/usr/bin/env python3
"""Populate the GHSA eval cache by scanning OSIDB cache files for GHSA IDs."""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from aegis_ai.toolsets.tools.osv_dev_cve import OSVClient  # noqa: E402
from evals.utils.ghsa_cache import GHSA_CACHE_DIR, write_ghsa_cache_entry  # noqa: E402

_GHSA_RE = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}")

OSIDB_CACHE_DIR = Path("evals/osidb_cache")


def main() -> None:
    ghsa_ids: set[str] = set()
    for json_file in sorted(OSIDB_CACHE_DIR.glob("CVE-*.json")):
        text = json_file.read_text(encoding="utf-8")
        ghsa_ids.update(_GHSA_RE.findall(text))

    print(f"Found {len(ghsa_ids)} unique GHSA IDs in OSIDB cache")

    cache_dir = Path(GHSA_CACHE_DIR)
    cache_dir.mkdir(parents=True, exist_ok=True)

    client = OSVClient()
    fetched = 0
    skipped = 0
    for ghsa_id in sorted(ghsa_ids):
        cache_file = cache_dir / f"{ghsa_id}.json"
        if cache_file.exists():
            skipped += 1
            continue
        data = client.get_vuln_by_id(ghsa_id)
        write_ghsa_cache_entry(ghsa_id, data)
        fetched += 1
        if data:
            print(f"  cached {ghsa_id}")
        else:
            print(f"  cached {ghsa_id} (empty — not found on OSV.dev)")

    print(f"Done: {fetched} fetched, {skipped} already cached")


if __name__ == "__main__":
    main()
