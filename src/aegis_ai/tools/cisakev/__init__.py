# https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

import requests
import asyncio
import logging
import json
import time
import pathlib
from typing import Dict, Any, Optional, TypeAlias
from requests import RequestException

from pydantic import BaseModel
from pydantic_ai import RunContext, Tool

from aegis_ai import config_dir

logger = logging.getLogger(__name__)

cache_dir = pathlib.Path(f"{config_dir}/cisakev")
cache_dir.mkdir(parents=True, exist_ok=True)

CVEID: TypeAlias = str
JsonBlob = Dict[str, Any]


class BaseToolOutput(BaseModel):
    """Base model for tool outputs."""

    pass


class CISAClient:
    """
    Python client for the CISA Known Exploited Vulnerabilities (KEV) catalog.

    This client fetches the entire KEV catalog JSON feed and provides
    methods for searching it. It uses a persistent on-disk cache.
    """

    def __init__(
        self,
        base_url: str = "https://www.cisa.gov",
        catalog_path: str = "/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        cache_file_path: str = f"{cache_dir}/cisa_kev_catalog.json",
        cache_ttl_seconds: int = 14400,  # Default: 4 hours (4 * 60 * 60)
    ):
        """
        Initializes CISAClient.

        Args:
            base_url: The base URL for the CISA API.
            catalog_path: The path to the KEV JSON data feed.
            cache_file_path: Local path to store the JSON cache file.
            cache_ttl_seconds: How long the cache is considered valid.
        """
        self.base_url = base_url.rstrip("/")
        self.catalog_url = f"{self.base_url}/{catalog_path.lstrip('/')}"
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "py-cisa-client/1.0"})

        # --- Cache config ---
        self.cache_path = pathlib.Path(cache_file_path)
        self.cache_ttl = cache_ttl_seconds

    def _get(self, url: str) -> JsonBlob:
        """Helper for GET requests."""
        try:
            response = self._session.get(url)
            response.raise_for_status()
            return response.json()
        except RequestException as e:
            logger.error(f"API request failed: {e}")
            raise

    def get_full_catalog(self, force_refresh: bool = False) -> JsonBlob:
        """
        Retrieves the entire KEV catalog, using a time-based disk cache.

        Args:
            force_refresh: If True, bypass the cache and fetch a fresh copy.
        """
        if self.cache_path.is_file() and not force_refresh:
            try:
                mod_time = self.cache_path.stat().st_mtime
                current_time = time.time()

                # 2. Check if cache is still fresh (within TTL)
                if (current_time - mod_time) < self.cache_ttl:
                    logger.info(
                        f"Using cached CISA KEV catalog from: {self.cache_path}"
                    )
                    with self.cache_path.open("r", encoding="utf-8") as f:
                        return json.load(f)
                else:
                    logger.info("Cache file found but is stale. Fetching fresh data.")
            except (IOError, json.JSONDecodeError) as e:
                logger.warning(
                    f"Could not read cache file {self.cache_path}: {e}. Fetching fresh data."
                )

        logger.info("Fetching fresh CISA KEV catalog from API...")

        try:
            catalog_data = self._get(self.catalog_url)
        except RequestException:
            # If API fails, try to use the stale cache as a last resort
            if self.cache_path.is_file():
                logger.warning(
                    "API fetch failed. Returning stale data from cache as fallback."
                )
                with self.cache_path.open("r", encoding="utf-8") as f:
                    return json.load(f)
            else:
                raise  # If no cache and API fails, we must raise the error

        try:
            with self.cache_path.open("w", encoding="utf-8") as f:
                json.dump(catalog_data, f)
            logger.info(f"Wrote fresh catalog data to cache: {self.cache_path}")
        except IOError as e:
            logger.warning(f"Failed to write to cache file {self.cache_path}: {e}")

        return catalog_data

    def get_vuln_by_cve(self, cve_id: str) -> Optional[JsonBlob]:
        """
        Searches the loaded KEV catalog for a specific CVE ID.
        (This method remains the same, it just relies on the newly cached get_full_catalog)
        """
        catalog_data = self.get_full_catalog()
        all_vulnerabilities = catalog_data.get("vulnerabilities", [])

        search_id = cve_id.strip().lower()

        found_vuln = next(
            (
                vuln
                for vuln in all_vulnerabilities
                if vuln.get("cveID", "").lower() == search_id
            ),
            None,
        )
        return found_vuln


cisa_client_instance = CISAClient()


async def cisa_kev_lookup(cve_id: CVEID) -> Optional[JsonBlob]:
    """
    Async wrapper to run the synchronous client's search method in a thread pool.
    """
    try:
        vulnerability_data = await asyncio.to_thread(
            cisa_client_instance.get_vuln_by_cve, cve_id
        )
        return vulnerability_data
    except Exception as e:
        logger.error(f"CISA KEV lookup failed: {e}")
        return None


@Tool
async def cisa_kev_tool(ctx: RunContext, cve_id: CVEID) -> Optional[JsonBlob]:
    """
    Checks if a specific CVE ID exists in the CISA Known Exploited Vulnerabilities (KEV)
    catalog. This tool ONLY returns data if the CVE is known to be actively exploited.
    """
    logger.info(f"Checking CISA KEV catalog for {cve_id}...")
    return await cisa_kev_lookup(cve_id)
