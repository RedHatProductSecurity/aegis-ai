import asyncio
import logging
from typing import Any, AsyncGenerator, Optional, Tuple, cast
import httpx
import osidb_bindings

from aegis_ai import get_settings
from aegis_ai.request_context import get_request_scope

logger = logging.getLogger(__name__)

# Single source of truth for OSIDB field selection
_FLAW_RETRIEVE_FIELDS = (
    "cve_id,impact,cwe_id,title,cve_description,cvss_scores,statement,"
    "mitigation,components,comments,comment_zero,affects,references,embargoed"
)
_FLAW_LIST_FIELDS = (
    "cve_id,title,cve_description,impact,statement,comment_zero,embargoed"
)
_FLAW_COUNT_FIELDS = "cve_id"

# Cache key in request scope for the OSIDB JWT when using delegated creds
_OSIDB_DELEGATED_TOKEN_KEY = "_osidb_delegated_token"


class OSIDBAuthError(Exception):
    """Raised when no OSIDB session or delegated token is available for API calls.

    This can occur when:
    - The request is not Kerberos-authenticated with delegation (no gssapi_context),
    - OSIDB is not configured for process-level auth (no keytab/env),
    - Delegated token acquisition failed (e.g. OSIDB /auth/token rejected the creds).
    """

    pass


class OSIDBClient:
    """A client for interacting with OSIDB API."""

    def __init__(self):
        self._session = None
        self._session_lock = asyncio.Lock()

    async def _get_delegated_token(self) -> Optional[str]:
        """If the current request has GSSAPI delegated creds, return an OSIDB JWT for that user."""
        scope = get_request_scope()
        if not scope:
            return None
        cached = scope.get(_OSIDB_DELEGATED_TOKEN_KEY)
        if cached is not None:
            return cached
        ctx = scope.get("gssapi_context")
        if not ctx or not getattr(ctx, "delegated_creds", None):
            return None
        from aegis_ai.toolsets.tools.osidb.osidb_delegation import (
            _prepare_delegated_creds_for_thread,
            get_osidb_token_for_delegated_cred,
        )

        delegated_creds = ctx.delegated_creds
        ccache_name = _prepare_delegated_creds_for_thread(delegated_creds)
        creds_arg = ccache_name if ccache_name is not None else delegated_creds

        token = await asyncio.to_thread(
            get_osidb_token_for_delegated_cred,
            creds_arg,
            get_settings().osidb_server_url,
        )
        if token:
            scope[_OSIDB_DELEGATED_TOKEN_KEY] = token
        return token

    async def _get_session_or_token(
        self,
    ) -> Tuple[Optional[object], Optional[str]]:
        """
        Return (session, token). Exactly one is non-None.
        session: process-level bindings session for API calls.
        token: JWT from delegated Kerberos creds when web request has gssapi_context.
        """
        token = await self._get_delegated_token()
        if token is not None:
            return (None, token)
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
        return (self._session, None)

    async def get_flaw_data(self, cve_id: str, include_embargoed: bool):
        """
        Retrieves raw flaw data from OSIDB for a given CVE ID.
        Uses delegated Kerberos credentials when present (web request with delegation).
        """
        logger.info(f"Retrieving raw flaw data for {cve_id} from OSIDB.")
        session, token = await self._get_session_or_token()
        if session is None and not token:
            raise OSIDBAuthError(
                "No OSIDB session or delegated token available. "
                "Ensure Kerberos delegation (kinit -f) for web requests or configure "
                "process-level OSIDB auth."
            )
        if token:
            logger.info(
                "Using delegated Kerberos credentials for OSIDB (pass-through auth)"
            )
            base = get_settings().osidb_server_url.rstrip("/")
            url = f"{base}/osidb/api/v2/flaws/{cve_id}"
            params = {"include_fields": _FLAW_RETRIEVE_FIELDS}
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    url,
                    params=params,
                    headers={"Authorization": f"Bearer {token}"},
                )
                resp.raise_for_status()
                data = resp.json()
            from osidb_bindings.bindings.python_client.models.osidb_api_v1_flaws_retrieve_response_200 import (
                OsidbApiV1FlawsRetrieveResponse200,
            )

            flaw_data = OsidbApiV1FlawsRetrieveResponse200.from_dict(data)
        else:
            session = cast(Any, session)  # token was None, so session is not None
            flaw_data = session.flaws.retrieve(
                id=cve_id,
                include_fields=_FLAW_RETRIEVE_FIELDS,
            )

        if not include_embargoed and flaw_data.embargoed:
            logger.info(f"Flaw {cve_id} is embargoed and retrieval is disabled.")
            raise ValueError(f"Could not retrieve {cve_id}")

        return flaw_data

    async def _get_process_session(self):
        """Return the process-level bindings session (used when delegated token path doesn't apply)."""
        async with self._session_lock:
            if self._session is None:
                self._session = osidb_bindings.new_session(
                    osidb_server_uri=get_settings().osidb_server_url
                )
        return self._session

    async def _list_component_flaws_with_token(
        self, component_name: str, token: str
    ) -> AsyncGenerator:
        """Paginate OSIDB v2 flaws list with Bearer token and yield flaw-like objects."""
        base = get_settings().osidb_server_url.rstrip("/")
        url = f"{base}/osidb/api/v2/flaws"
        limit = 100
        offset = 0
        async with httpx.AsyncClient(timeout=60.0) as client:
            while True:
                params = {
                    "affects__ps_component": component_name,
                    "include_fields": _FLAW_LIST_FIELDS,
                    "limit": limit,
                    "offset": offset,
                }
                resp = await client.get(
                    url,
                    params=params,
                    headers={"Authorization": f"Bearer {token}"},
                )
                resp.raise_for_status()
                data = resp.json()
                from osidb_bindings.bindings.python_client.models.osidb_api_v1_flaws_list_response_200 import (
                    OsidbApiV1FlawsListResponse200,
                )

                parsed = OsidbApiV1FlawsListResponse200.from_dict(data)
                results = parsed.results or []
                for item in results:
                    yield item
                count = getattr(parsed, "count", None)
                if count is None:
                    count = len(results)
                offset += len(results)
                if offset >= count or len(results) < limit:
                    break

    async def _count_component_flaws_with_token(
        self, component_name: str, token: str
    ) -> int:
        """Return OSIDB flaw count for component using Bearer token."""
        base = get_settings().osidb_server_url.rstrip("/")
        url = f"{base}/osidb/api/v2/flaws"
        params = {
            "affects__ps_component": component_name,
            "include_fields": _FLAW_COUNT_FIELDS,
            "limit": 1,
            "offset": 0,
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                url,
                params=params,
                headers={"Authorization": f"Bearer {token}"},
            )
            resp.raise_for_status()
            data = resp.json()
        return int(data.get("count", 0))

    async def list_component_flaws(self, component_name: str) -> AsyncGenerator:
        """
        Retrieves flaws related to a specific component using an async iterator.
        Uses delegated Kerberos credentials when present (same as get_flaw_data).
        """
        logger.info(f"Listing flaws for component '{component_name}'.")
        session, token = await self._get_session_or_token()
        if token:
            async for flaw in self._list_component_flaws_with_token(
                component_name, token
            ):
                yield flaw
            return
        if session is None:
            session = await self._get_process_session()
        session = cast(Any, session)  # _get_process_session never returns None
        async for flaw in session.flaws.retrieve_list_iterator_async(
            affects__ps_component=component_name,
            include_fields=_FLAW_LIST_FIELDS,
        ):
            yield flaw

    async def count_component_flaws(self, component_name: str):
        """
        Retrieves count of flaws related to a specific component.
        Uses delegated Kerberos credentials when present (same as get_flaw_data).
        """
        logger.info(f"Counting flaws for component '{component_name}'.")
        session, token = await self._get_session_or_token()
        if token:
            return await self._count_component_flaws_with_token(component_name, token)
        if session is None:
            session = await self._get_process_session()
        session = cast(Any, session)  # _get_process_session never returns None
        return session.flaws.count(
            affects__ps_component=component_name,
            include_fields=_FLAW_LIST_FIELDS,
        )
