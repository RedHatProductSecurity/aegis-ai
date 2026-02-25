import asyncio
import os
import logging
from typing import Any, Dict, List

import osidb_bindings

logger = logging.getLogger(__name__)

OSIDB_SERVER_URI = os.getenv("AEGIS_OSIDB_SERVER_URL", "https://localhost:8000")


def _list_component_flaws_sync(component_name: str) -> List[dict]:
    """
    Run in a thread: osidb_bindings.retrieve_list_iterator_async() uses asyncio.run()
    internally, which cannot be called from an already-running event loop.
    Consuming the iterator here allows asyncio.run() to run in this thread.
    Returns a list of JSON-serializable dicts (tool return values must be serializable).
    """
    session = osidb_bindings.new_session(osidb_server_uri=OSIDB_SERVER_URI)
    iterator = session.flaws.retrieve_list_iterator_async(
        affects__ps_component=component_name,
        include_fields="cve_id,title,cve_description,impact,statement,comment_zero,embargoed",
    )
    return [flaw.to_dict() for flaw in iterator]


class OSIDBClient:
    """A client for interacting with OSIDB API."""

    def __init__(self):
        self._session = None
        self._session_lock = asyncio.Lock()

    async def _get_session(self):
        async with self._session_lock:
            if self._session is None:
                try:
                    self._session = osidb_bindings.new_session(
                        osidb_server_uri=OSIDB_SERVER_URI
                    )
                except Exception as e:
                    logger.warning(
                        f"Failed to connect OSIDB at {OSIDB_SERVER_URI}: {e.__class__.__name__}"
                    )
                    raise
        return self._session

    # Fields needed for evals cache (excludes affects to reduce payload size)
    _EVALS_INCLUDE_FIELDS = "cve_id,impact,cwe_id,title,cve_description,cvss_scores,statement,mitigation,components,comments,comment_zero,references,embargoed"
    _FULL_INCLUDE_FIELDS = _EVALS_INCLUDE_FIELDS + ",affects"

    async def get_flaw_data(
        self, cve_id: str, include_embargoed: bool, include_affects: bool = True
    ):
        """
        Retrieves raw flaw data from OSIDB for a given CVE ID.

        When include_affects is False, the affects field is omitted from the API request
        to reduce payload size (affects arrays can be very large). Use for evals cache.
        """
        logger.info(f"Retrieving raw flaw data for {cve_id} from OSIDB.")
        session = await self._get_session()
        fields = (
            self._EVALS_INCLUDE_FIELDS
            if not include_affects
            else self._FULL_INCLUDE_FIELDS
        )
        flaw_data = session.flaws.retrieve(
            id=cve_id,
            include_fields=fields,
        )

        if not include_embargoed and flaw_data.embargoed:
            logger.info(f"Flaw {cve_id} is embargoed and retrieval is disabled.")
            raise ValueError(f"Could not retrieve {cve_id}")

        return flaw_data

    async def list_component_flaws(self, component_name: str) -> List[Dict[str, Any]]:
        """
        Retrieves flaws related to a specific component. Runs the OSIDB bindings
        call in a thread because retrieve_list_iterator_async() uses asyncio.run()
        internally, which cannot be used inside an existing event loop.
        """
        logger.info(f"Listing flaws for component '{component_name}'.")
        return await asyncio.to_thread(
            _list_component_flaws_sync,
            component_name,
        )

    async def count_component_flaws(self, component_name: str) -> Any:
        """
        Retrieves count of flaws related to a specific component.
        """
        logger.info(f"Listing flaws for component '{component_name}'.")
        session = await self._get_session()
        return session.flaws.count(
            affects__ps_component=component_name,
            include_fields="cve_id,title,cve_description,impact,statement,comment_zero,embargoed",
        )
