import os
import logging
from typing import AsyncGenerator
import osidb_bindings

logger = logging.getLogger(__name__)

OSIDB_SERVER_URI = os.getenv("AEGIS_OSIDB_SERVER_URL", "https://localhost:8000")


class OSIDBClient:
    """A client for interacting with OSIDB API."""

    def __init__(self):
        self._session = osidb_bindings.new_session(osidb_server_uri=OSIDB_SERVER_URI)

    async def get_flaw_data(self, cve_id: str, include_embargoed: bool):
        """
        Retrieves raw flaw data from OSIDB for a given CVE ID.
        """
        logger.info(f"Retrieving raw flaw data for {cve_id} from OSIDB.")
        flaw_data = self._session.flaws.retrieve(
            id=cve_id,
            include_fields="cve_id,title,cve_description,cvss_scores,statement,components,comments,comment_zero,affects,references,embargoed",
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
        return self._session.flaws.retrieve_list_iterator_async(
            affects__ps_component=component_name,
            include_fields="cve_id,title,cve_description,impact,statement,comment_zero,embargoed",
        )

    async def count_component_flaws(self, component_name: str) -> AsyncGenerator:
        """
        Retrieves count of flaws related to a specific component using an async iterator.
        """
        logger.info(f"Listing flaws for component '{component_name}'.")
        return self._session.flaws.count(
            affects__ps_component=component_name,
            include_fields="cve_id,title,cve_description,impact,statement,comment_zero,embargoed",
        )
