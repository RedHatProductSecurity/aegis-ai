import asyncio
import logging
import os
from pathlib import Path

from aegis_ai.toolsets.tools.osidb import CVE, CVEID, cve_retrieve_for_evals

logger = logging.getLogger(__name__)

# directory where we cache CVE data retrieved from OSIDB
OSIDB_CACHE_DIR = os.getenv("OSIDB_CACHE_DIR", "evals/osidb_cache")


# In CI we must not call live OSIDB; all required CVE data must be in the cache (committed).
def _is_ci() -> bool:
    return os.getenv("GITHUB_ACTIONS") == "true" or os.getenv("CI") == "true"


def cve_ids_in_cache() -> set[str]:
    """Return the set of CVE IDs that have a cache file under OSIDB_CACHE_DIR.
    Evals should only run cases for CVEs in this set so CI can run without OSIDB access."""
    cache_path = Path(OSIDB_CACHE_DIR)
    if not cache_path.is_dir():
        return set()
    return {f.stem for f in cache_path.glob("CVE-*.json")}


# global mutex for access to OSIDB_CACHE_DIR
# Note that cache hits (which is the most common case) are handle very quickly.
# So there is no need to implement any per-file locking for the OSIDB cache.
cache_lock = asyncio.Lock()


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
            # cached CVE data not available
            if _is_ci():
                raise FileNotFoundError(
                    f"CVE {cve_id} not in osidb_cache; evals in CI require cache files to be committed. "
                    f"Add evals/osidb_cache/{cve_id}.json (e.g. by running evals locally with OSIDB access)."
                ) from None
            # query OSIDB and populate cache for local runs (evals path omits affects)
            cve_data = await cve_retrieve_for_evals(cve_id)
            # strip affects before write (belt and suspenders; cve_retrieve_for_evals already omits)
            cve_for_cache = cve_data.model_copy(update={"affects": []})
            logger.info(f'writing CVE data cache to "{cache_file}"')
            with open(cache_file, "w") as f:
                f.write(cve_for_cache.model_dump_json(indent=4))
                f.write("\n")

    return cve_data
