"""
Obtain an OSIDB JWT using delegated GSSAPI credentials (client's Kerberos).

Used when aegis-web authenticates the client with Kerberos and delegation;
we use the delegated credential to call OSIDB GET /auth/token and get a JWT
for that user, then use the JWT for OSIDB API calls (pass-through auth).
"""

import logging
from typing import Any, Optional, cast

from osidb_bindings.bindings.python_client import AuthenticatedClient
from osidb_bindings.bindings.python_client.api import auth as auth_api
from osidb_bindings.bindings.python_client.types import Unset
from requests_gssapi import HTTPSPNEGOAuth

logger = logging.getLogger(__name__)


def get_osidb_token_for_delegated_cred(
    delegated_creds,
    osidb_base_url: str,
) -> Optional[str]:
    """
    Call OSIDB GET /auth/token with Negotiate using delegated_creds.
    Uses osidb_bindings AuthenticatedClient for consistent layering.
    Passes credentials directly to requests_gssapi; no env var or temp file.
    """
    base = osidb_base_url.rstrip("/")
    try:
        client = AuthenticatedClient(
            base_url=base,
            auth=cast(Any, HTTPSPNEGOAuth(creds=delegated_creds)),
            timeout=30.0,
        )
        response = auth_api.auth_token_retrieve.sync(client=client)
        if response is None or response.access in (Unset, None):
            return None
        return str(response.access)
    except Exception as e:
        logger.warning("OSIDB token fetch with delegated cred failed: %s", e)
        return None
