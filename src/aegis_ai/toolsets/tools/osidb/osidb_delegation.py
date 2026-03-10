"""
Obtain an OSIDB JWT using delegated GSSAPI credentials (client's Kerberos).

Used when aegis-web authenticates the client with Kerberos and delegation;
we use the delegated credential to call OSIDB GET /auth/token and get a JWT
for that user, then use the JWT for OSIDB API calls (pass-through auth).

Delegated creds are passed via a MEMORY ccache rather than the raw Credentials
object, because GSS-API credential handles may not be valid when used from a
different thread (e.g. asyncio thread pool). We store into MEMORY:{uuid} in the
main thread, then in the worker thread set KRB5CCNAME to that ccache so
HTTPSPNEGOAuth() (without explicit creds) uses it as the default. This avoids
both cross-thread handle usage and credential-store keytab lookup, since the
default ccache path does not trigger keytab merging.
"""

import logging
import os
import threading
import uuid
from typing import Any, Optional, Union, cast

from osidb_bindings.bindings.python_client import AuthenticatedClient
from osidb_bindings.bindings.python_client.api import auth as auth_api
from osidb_bindings.bindings.python_client.types import Unset
from requests_gssapi import HTTPSPNEGOAuth

logger = logging.getLogger(__name__)

# Lock for ccache-based token fetches. Serializes concurrent calls to
# _fetch_token_via_ccache() so they do not overwrite each other's
# KRB5CCNAME/KRB5_KTNAME and thus use the wrong credentials. Does not
# isolate os.environ from other code in the process; other threads may
# still read or use these env vars while the lock is held.
_ccache_env_lock = threading.Lock()


def _fetch_token_via_ccache(ccache_name: str, base: str) -> Optional[str]:
    """
    Call OSIDB GET /auth/token using KRB5CCNAME to force credential use from
    the given MEMORY ccache. HTTPSPNEGOAuth() without creds uses the default
    ccache (KRB5CCNAME), avoiding keytab merging.
    """
    with _ccache_env_lock:
        old_ccname = os.environ.pop("KRB5CCNAME", None)
        old_ktname = os.environ.pop("KRB5_KTNAME", None)
        old_client_ktname = os.environ.pop("KRB5_CLIENT_KTNAME", None)
        os.environ["KRB5CCNAME"] = ccache_name
        # Prevent keytab lookup; use nonexistent paths so only ccache is used
        os.environ["KRB5_KTNAME"] = "FILE:/nonexistent_aegis_deleg"
        os.environ["KRB5_CLIENT_KTNAME"] = "FILE:/nonexistent_aegis_deleg_client"
        try:
            client = AuthenticatedClient(
                base_url=base,
                auth=cast(Any, HTTPSPNEGOAuth()),
                timeout=30.0,
            )
            response = auth_api.auth_token_retrieve.sync(client=client)
            if response is None or response.access in (Unset, None):
                return None
            return str(response.access)
        except Exception as e:
            logger.warning("OSIDB token fetch via ccache failed: %s", e)
            return None
        finally:
            if old_ccname is not None:
                os.environ["KRB5CCNAME"] = old_ccname
            else:
                os.environ.pop("KRB5CCNAME", None)
            if old_ktname is not None:
                os.environ["KRB5_KTNAME"] = old_ktname
            else:
                os.environ.pop("KRB5_KTNAME", None)
            if old_client_ktname is not None:
                os.environ["KRB5_CLIENT_KTNAME"] = old_client_ktname
            else:
                os.environ.pop("KRB5_CLIENT_KTNAME", None)


def _prepare_delegated_creds_for_thread(delegated_creds) -> Optional[str]:
    """
    Store delegated creds in a MEMORY ccache for use in the worker thread.
    Returns the ccache name (e.g. MEMORY:abc123) or None if storage fails.

    The worker thread will set KRB5CCNAME to this value so HTTPSPNEGOAuth()
    uses it as the default credential source (no keytab merging).
    """
    try:
        ccache_name = f"MEMORY:{uuid.uuid4().hex}"
        store = {"ccache": ccache_name}
        delegated_creds.store(store, usage="initiate", overwrite=True)
        return ccache_name
    except Exception as e:
        logger.debug("Could not store delegated creds in MEMORY ccache: %s", e)
        return None


def get_osidb_token_for_delegated_cred(
    delegated_creds_or_ccache: Union[Any, str],
    osidb_base_url: str,
) -> Optional[str]:
    """
    Call OSIDB GET /auth/token with Negotiate using delegated creds.

    delegated_creds_or_ccache: either a ccache name (str) from
    _prepare_delegated_creds_for_thread (e.g. MEMORY:abc123), or the raw
    delegated_creds object (fallback when store is unavailable).
    """
    base = osidb_base_url.rstrip("/")
    logger.info(
        "Attempting OSIDB token fetch with delegated credentials (target=%s)",
        base,
    )

    if isinstance(delegated_creds_or_ccache, str):
        # Use KRB5CCNAME so HTTPSPNEGOAuth uses only the MEMORY ccache
        return _fetch_token_via_ccache(delegated_creds_or_ccache, base)

    # Fallback: pass creds directly (may fail cross-thread or with keytab)
    creds = delegated_creds_or_ccache
    if creds is None:
        return None
    try:
        client = AuthenticatedClient(
            base_url=base,
            auth=cast(Any, HTTPSPNEGOAuth(creds=creds)),
            timeout=30.0,
        )
        response = auth_api.auth_token_retrieve.sync(client=client)
        if response is None or response.access in (Unset, None):
            return None
        return str(response.access)
    except Exception as e:
        logger.warning("OSIDB token fetch with delegated cred failed: %s", e)
        return None
