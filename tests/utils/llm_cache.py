"""
Caching utility for test responses to avoid LLM costs.
Supports both web API tests and core library tests.
"""

import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

# directory where we cache LLM data
LLM_CACHE_DIR = os.getenv("TEST_LLM_CACHE_DIR", "tests/llm_cache")


def get_cached_response(test_name: str):
    """
    Retrieve cached response if available.

    Args:
        test_name: Name of the test function (used as cache key)

    Returns:
        Cached response as JSON string, or None if not cached
    """
    cache_file = Path(LLM_CACHE_DIR, f"{test_name}.json")

    try:
        with open(cache_file, "r") as f:
            content = f.read()
        logger.info(f'Read cached response from "{cache_file}"')
        return content
    except OSError as e:
        logger.debug(f'Cache miss for "{cache_file}": {e}')
        return None


def cache_response(test_name: str, response_data):
    """
    Cache a response for future test runs.

    Args:
        test_name: Name of the test function (used as cache key)
        response_data: Response to cache (dict, str, or object with model_dump_json)
    """
    cache_dir = Path(LLM_CACHE_DIR)
    cache_dir.mkdir(parents=True, exist_ok=True)

    cache_file = cache_dir / f"{test_name}.json"

    with open(cache_file, "w") as f:
        if isinstance(response_data, dict):
            # Web API responses (already dicts)
            json.dump(response_data, f, indent=2)
        elif isinstance(response_data, str):
            # Already a JSON string
            f.write(response_data)
        elif hasattr(response_data, "model_dump_json"):
            # Pydantic models
            f.write(response_data.model_dump_json(indent=4))
        else:
            # Fallback to json.dump
            json.dump(response_data, f, indent=2)
        f.write("\n")

    logger.info(f'Cached response to "{cache_file}"')
