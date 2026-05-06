import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any

from aegis_ai.toolsets.tools.osidb import CVE, CVEID, cve_retrieve

logger = logging.getLogger(__name__)

# directory where we cache CVE data retrieved from OSIDB
OSIDB_CACHE_DIR = os.getenv("OSIDB_CACHE_DIR", "evals/osidb_cache")

# global mutex for access to OSIDB_CACHE_DIR
# Note that cache hits (which is the most common case) are handle very quickly.
# So there is no need to implement any per-file locking for the OSIDB cache.
cache_lock = asyncio.Lock()


def read_cache_json(cve_id: str) -> dict[str, Any] | None:
    """Read a CVE's cached JSON as a raw dict, or None on miss/error."""
    cache_file = Path(OSIDB_CACHE_DIR) / f"{cve_id}.json"
    try:
        return json.loads(cache_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


async def osidb_cache_retrieve(cve_id: CVEID) -> CVE:
    """Return cached CVE data if available.  If not, retrieve CVE data
    from OSIDB and store them to cache for subsequent runs."""
    cache_file = Path(OSIDB_CACHE_DIR, f"{cve_id}.json")

    # acquire global mutex to access OSIDB_CACHE_DIR
    async with cache_lock:
        try:
            # check whether the CVE data is cached already
            with open(cache_file, "r") as f:
                json_data = f.read()

            # try to load data from the existing JSON file
            cve_data = CVE.model_validate_json(json_data)
            logger.debug(f'read CVE data from "{cache_file}"')

        except OSError:
            # cached CVE data not available -> query OSIDB
            cve_data = await cve_retrieve(cve_id)

            logger.info(f'writing CVE data cache to "{cache_file}"')
            with open(cache_file, "w") as f:
                f.write(cve_data.model_dump_json(indent=4))
                f.write("\n")

    return cve_data
