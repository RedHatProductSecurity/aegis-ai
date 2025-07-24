import asyncio
import inspect
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

# directory where we cache CVE data retrieved from OSIDB
LLM_CACHE_DIR = os.getenv("TEST_LLM_CACHE_DIR", "tests/llm_cache")

# global mutex for access to LLM_CACHE_DIR
# Note that cache hits (which is the most common case) are handle very quickly.
# So there is no need to implement any per-file locking for the OSIDB cache.
cache_lock = asyncio.Lock()


async def llm_cache_retrieve(feature):
    """Return cached LLM data if available.  If not, retrieve LLM data"""

    # use test function name as name of related cache file
    test_name = inspect.stack()[1].function
    cache_file = Path(LLM_CACHE_DIR, f"{test_name}.json")

    # acquire global mutex to access LLM_CACHE_DIR
    async with cache_lock:
        try:
            # check whether the LLM data is cached already
            with open(cache_file, "r") as f:
                json_data = f.read()

            # try to load data from the existing JSON file
            data = json_data
            logger.info(f'read LLM data from "{cache_file}"')

        except OSError:
            # cached LLM data not available -> query LLM
            llm_result = await feature()
            data = llm_result.output
            logger.info(data)
            logger.info(f'writing LLM data cache to "{cache_file}"')
            with open(cache_file, "w") as f:
                f.write(data.model_dump_json(indent=4))
                f.write("\n")
    return data
