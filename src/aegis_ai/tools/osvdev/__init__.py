"""
Python module to provide programmatic bindings for the OSV.dev REST API.

This module provides an OSVClient class for querying the Open Source
Vulnerability (OSV) database API.

Requires the 'requests' library: pip install requests
"""

import requests
from typing import Dict, Any, List

from pydantic_ai import RunContext, Tool
from requests import RequestException

from aegis_ai import logger
from aegis_ai.data_models import CVEID

JsonBlob = Dict[str, Any]


class OSVClient:
    """
    python client for the https://osv.dev REST API.

    Provides methods for querying vulnerabilities by ID, package, commit,
    and batch queries.
    """

    def __init__(self, base_url: str = "https://api.osv.dev/v1"):
        """
        Initializes the OSVClient.

        Args:
            base_url: The base URL for the OSV API. Defaults to v1.
        """
        self.base_url = base_url.rstrip("/")
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "aegis"})

    def _get(self, endpoint: str) -> JsonBlob:
        """Helper for GET requests."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        try:
            response = self._session.get(url)
            response.raise_for_status()
            return response.json()
        except RequestException as e:
            print(f"API request failed: {e}")
            raise

    def _post(self, endpoint: str, data: JsonBlob) -> JsonBlob:
        """manage POST requests."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        try:
            response = self._session.post(url, json=data)
            response.raise_for_status()
            # The query endpoints return an empty body with a 200 OK if no vulns are found.
            if not response.content:
                return {}
            return response.json()
        except RequestException as e:
            print(f"API request failed: {e}")
            raise

    def get_vuln_by_id(self, vuln_id: str) -> JsonBlob:
        """
        Retrieves the full vulnerability details for a specific OSV ID.

        Args:
            vuln_id: The OSV vulnerability ID (e.g., "OSV-2020-4048").

        Returns:
            A dictionary containing the vulnerability data.
        """
        print(f"Querying for vulnerability ID: {vuln_id}")
        return self._get(f"vulns/{vuln_id}")

    def query(self, payload: JsonBlob) -> JsonBlob:
        """
        Submits a single query to the /v1/query endpoint.

        This is a generic method. For easier use, see:
        - build_package_query()
        - build_commit_query()

        Args:
            payload: A dictionary matching the OSV /query schema.

        Returns:
            A dictionary of vulnerabilities, or {} if none are found.
        """
        return self._post("query", data=payload)

    def query_batch(self, queries: List[JsonBlob]) -> JsonBlob:
        """
        Submits multiple queries to the /v1/querybatch endpoint.
        This is the most efficient way to query many packages at once.

        Args:
            queries: A list of individual query payloads.

        Returns:
            A dictionary containing the "results" key, which holds a list
            of vulnerability responses corresponding to the queries.
        """
        print(f"Querying a batch of {len(queries)} items...")
        batch_payload = {"queries": queries}
        return self._post("querybatch", data=batch_payload)

    @staticmethod
    def build_package_query(
        package_name: str, version: str, ecosystem: str
    ) -> JsonBlob:
        """
        A helper to build a well-formed query payload for a package.
        """
        return {
            "version": version,
            "package": {"name": package_name, "ecosystem": ecosystem},
        }

    @staticmethod
    def build_commit_query(commit_hash: str) -> JsonBlob:
        """
        A helper to build a well-formed query payload for a commit hash.
        """
        return {"commit": commit_hash}


async def osv_vulnerability_lookup(cve_id: CVEID):
    """ """
    client = OSVClient()
    return client.get_vuln_by_id(cve_id)


@Tool
async def osv_dev_cve_tool(ctx: RunContext, cve_id: CVEID):
    """"""
    logger.info(f"Looking up osv.dev vulnerability for {cve_id}...")
    return await osv_vulnerability_lookup(cve_id)
