import logging
import os
from pathlib import Path

from aegis_ai.data_models import CVEID
from aegis_ai.toolsets.tools.kernel_cves import LINUXCVEToolResponse

logger = logging.getLogger(__name__)

KERNEL_CVE_CACHE_DIR = Path(
    os.getenv("KERNEL_CVE_CACHE_DIR", "evals/kernel_cve_context_cache")
)

CACHE_MISSES_FILE = KERNEL_CVE_CACHE_DIR / "cache_misses.txt"

cache_misses: set[str] = set()


async def kernel_cve_cache_lookup(cve_id: CVEID) -> LINUXCVEToolResponse:
    """Return cached kernel CVE data, or an empty response on cache miss.

    This is strictly read-only: eval runs never perform live lookups or
    mutate the cache.  The cache is populated by a separate pipeline
    (``populate_kernel_cve_cache.py``).

    Misses are recorded in :data:`cache_misses` and written to
    :data:`CACHE_MISSES_FILE` at session end by :func:`write_misses_report`.
    """
    cache_file = KERNEL_CVE_CACHE_DIR / f"{cve_id}.json"

    try:
        json_data = cache_file.read_text()
        response = LINUXCVEToolResponse.model_validate_json(json_data)

        if response.metadata is None:
            logger.warning("cache hit but metadata is null for %s", cve_id)
            cache_misses.add(str(cve_id))
        else:
            logger.debug('read kernel CVE data from "%s"', cache_file)

        return response

    except OSError:
        logger.warning("kernel CVE context cache miss: %s", cve_id)
        cache_misses.add(str(cve_id))
        return LINUXCVEToolResponse(cve_id=cve_id, metadata=None)


def write_misses_report() -> Path | None:
    """Write :data:`cache_misses` to :data:`CACHE_MISSES_FILE`.

    Returns the path written, or ``None`` if there were no misses.
    The populate script reads this file to know which CVEs to retry.
    """
    if not cache_misses:
        if CACHE_MISSES_FILE.exists():
            CACHE_MISSES_FILE.unlink()
        return None

    CACHE_MISSES_FILE.parent.mkdir(parents=True, exist_ok=True)
    CACHE_MISSES_FILE.write_text("\n".join(sorted(cache_misses)) + "\n")
    logger.info("wrote %d cache miss(es) to %s", len(cache_misses), CACHE_MISSES_FILE)
    return CACHE_MISSES_FILE
