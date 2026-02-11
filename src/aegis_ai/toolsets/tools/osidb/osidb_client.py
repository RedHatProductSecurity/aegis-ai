import asyncio
import logging
from typing import AsyncGenerator
import osidb_bindings

from aegis_ai import get_settings

logger = logging.getLogger(__name__)


class OSIDBClient:
    """A client for interacting with OSIDB API."""

    def __init__(self):
        self._session = None
        self._session_lock = asyncio.Lock()

    async def _get_session(self):
        async with self._session_lock:
            if self._session is None:
                osidb_server_url = get_settings().osidb_server_url
                try:
                    self._session = osidb_bindings.new_session(
                        osidb_server_uri=osidb_server_url
                    )
                except Exception as e:
                    logger.warning(
                        f"Failed to connect OSIDB at {osidb_server_url}: {e.__class__.__name__}"
                    )
                    raise
        return self._session

    async def get_flaw_data(self, cve_id: str, include_embargoed: bool):
        """
        Retrieves raw flaw data from OSIDB for a given CVE ID.
        """
        logger.info(f"Retrieving raw flaw data for {cve_id} from OSIDB.")
        session = await self._get_session()
        flaw_data = session.flaws.retrieve(
            id=cve_id,
            include_fields="cve_id,impact,cwe_id,title,cve_description,cvss_scores,statement,mitigation,components,comments,comment_zero,affects,references,embargoed",
        )

        if not include_embargoed and flaw_data.embargoed:
            logger.info(f"Flaw {cve_id} is embargoed and retrieval is disabled.")
            raise ValueError(f"Could not retrieve {cve_id}")

        return flaw_data

    async def list_component_flaws(self, component_name: str) -> AsyncGenerator:
        """
        Retrieves flaws related to a specific component using an async iterator.
        """
        logger.info(f"Listing flaws for component '{component_name}'.")
        session = await self._get_session()
        return session.flaws.retrieve_list_iterator_async(
            affects__ps_component=component_name,
            include_fields="cve_id,title,cve_description,impact,statement,comment_zero,embargoed",
        )

    async def count_component_flaws(self, component_name: str) -> AsyncGenerator:
        """
        Retrieves count of flaws related to a specific component using an async iterator.
        """
        logger.info(f"Listing flaws for component '{component_name}'.")
        session = await self._get_session()
        return session.flaws.count(
            affects__ps_component=component_name,
            include_fields="cve_id,title,cve_description,impact,statement,comment_zero,embargoed",
        )
