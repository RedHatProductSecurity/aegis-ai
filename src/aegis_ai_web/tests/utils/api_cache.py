"""
Caching utility for web API test responses to avoid LLM costs.
"""
import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

# directory where we cache API responses
API_CACHE_DIR = os.getenv("TEST_API_CACHE_DIR", "src/aegis_ai_web/tests/api_cache")


def get_cached_response(test_name: str):
    """
    Retrieve cached API response if available.
    
    Args:
        test_name: Name of the test function (used as cache key)
        
    Returns:
        Cached response dict or None if not cached
    """
    cache_file = Path(API_CACHE_DIR, f"{test_name}.json")
    
    try:
        with open(cache_file, "r") as f:
            data = json.load(f)
        logger.info(f'Read cached API response from "{cache_file}"')
        return data
    except (OSError, json.JSONDecodeError) as e:
        logger.debug(f'Cache miss for "{cache_file}": {e}')
        return None


def cache_response(test_name: str, response_data: dict):
    """
    Cache an API response for future test runs.
    
    Args:
        test_name: Name of the test function (used as cache key)
        response_data: Response dict to cache
    """
    cache_dir = Path(API_CACHE_DIR)
    cache_dir.mkdir(parents=True, exist_ok=True)
    
    cache_file = cache_dir / f"{test_name}.json"
    
    with open(cache_file, "w") as f:
        json.dump(response_data, f, indent=2)
        f.write("\n")
    
    logger.info(f'Cached API response to "{cache_file}"')

