import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any

from aegis_ai.toolsets.tools.osv_dev_cve import OSVClient

logger = logging.getLogger(__name__)

GHSA_CACHE_DIR = os.getenv("GHSA_CACHE_DIR", "evals/ghsa_cache")

cache_lock = asyncio.Lock()

cache_misses: list[str] = []


def write_ghsa_cache_entry(vuln_id: str, data: dict[str, Any]) -> Path:
    """Serialize a raw OSV.dev response to the GHSA cache."""
    cache_file = Path(GHSA_CACHE_DIR) / f"{vuln_id}.json"
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(json.dumps(data, indent=4) + "\n", encoding="utf-8")
    return cache_file


async def ghsa_cache_retrieve(vuln_id: str) -> dict[str, Any]:
    """Return cached OSV.dev data if available.  If not, fetch from
    OSV.dev and store to cache for subsequent runs."""
    cache_file = Path(GHSA_CACHE_DIR, f"{vuln_id}.json")

    async with cache_lock:
        try:
            with open(cache_file, "r") as f:
                data: dict[str, Any] = json.load(f)
            logger.debug('read GHSA data from "%s"', cache_file)

        except OSError:
            client = OSVClient()
            data = client.get_vuln_by_id(vuln_id)

            path = write_ghsa_cache_entry(vuln_id, data)
            logger.info('writing GHSA data cache to "%s"', path)
            cache_misses.append(vuln_id)

    return data


def write_misses_report() -> Path | None:
    """Write cache-miss IDs to a file so the user knows what was fetched live."""
    if not cache_misses:
        return None
    report = Path(GHSA_CACHE_DIR) / "MISSES.txt"
    report.write_text("\n".join(sorted(cache_misses)) + "\n", encoding="utf-8")
    return report
