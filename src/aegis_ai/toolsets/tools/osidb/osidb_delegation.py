"""
Obtain an OSIDB JWT using delegated GSSAPI credentials (client's Kerberos).

Used when aegis-web authenticates the client with Kerberos and delegation;
we use the delegated credential to call OSIDB GET /auth/token and get a JWT
for that user, then use the JWT for OSIDB API calls (pass-through auth).

Delegated creds are passed via a MEMORY ccache rather than the raw Credentials
object, because GSS-API credential handles may not be valid when used from a
different thread (e.g. asyncio thread pool). We store into MEMORY:{uuid} in the
main thread, then acquire a new credential handle from that cache in the worker
thread. Passing the handle explicitly avoids changing process-wide Kerberos
environment variables while other requests are authenticating.
"""

import ctypes
import ctypes.util
import logging
import uuid
from typing import Any, cast

from gssapi import Credentials
from osidb_bindings.bindings.python_client import AuthenticatedClient
from osidb_bindings.bindings.python_client.api import auth as auth_api
from osidb_bindings.bindings.python_client.types import Unset
from requests_gssapi import HTTPSPNEGOAuth

logger = logging.getLogger(__name__)


def _fetch_token_via_ccache(ccache_name: str, base: str) -> str | None:
    """
    Call OSIDB GET /auth/token with credentials acquired only from the given
    MEMORY ccache.
    """
    try:
        creds = Credentials(store={"ccache": ccache_name}, usage="initiate")
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
        logger.warning("OSIDB token fetch via ccache failed: %s", e)
        return None


def _prepare_delegated_creds_for_thread(delegated_creds) -> str | None:
    """
    Store delegated creds in a MEMORY ccache for use in the worker thread.
    Returns the ccache name (e.g. MEMORY:abc123) or None if storage fails.

    The worker thread will acquire an explicit credential handle from this
    cache, without changing the process's default credential source.
    """
    try:
        ccache_name = f"MEMORY:{uuid.uuid4().hex}"
        store = {"ccache": ccache_name}
        delegated_creds.store(store, usage="initiate", overwrite=True)
        return ccache_name
    except Exception as e:
        logger.debug("Could not store delegated creds in MEMORY ccache: %s", e)
        return None


def destroy_kerberos_ccache(ccache_name: str) -> None:
    """Destroy a temporary delegated credential cache."""
    try:
        library_name = ctypes.util.find_library("krb5")
        if library_name is None:
            raise OSError("libkrb5 not found")
        library = ctypes.CDLL(library_name)
        library.krb5_init_context.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        library.krb5_init_context.restype = ctypes.c_int
        library.krb5_cc_resolve.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        library.krb5_cc_resolve.restype = ctypes.c_int
        library.krb5_cc_destroy.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        library.krb5_cc_destroy.restype = ctypes.c_int
        library.krb5_free_context.argtypes = [ctypes.c_void_p]

        context = ctypes.c_void_p()
        result = library.krb5_init_context(ctypes.byref(context))
        if result:
            raise OSError(result, "krb5_init_context failed")
        try:
            cache = ctypes.c_void_p()
            result = library.krb5_cc_resolve(
                context,
                ccache_name.encode(),
                ctypes.byref(cache),
            )
            if result:
                raise OSError(result, "krb5_cc_resolve failed")
            result = library.krb5_cc_destroy(context, cache)
            if result:
                raise OSError(result, "krb5_cc_destroy failed")
        finally:
            library.krb5_free_context(context)
    except (AttributeError, OSError):
        logger.warning(
            "Could not destroy delegated ccache %s", ccache_name, exc_info=True
        )


def get_osidb_token_for_delegated_cred(
    delegated_creds_or_ccache: Any | str,
    osidb_base_url: str,
) -> str | None:
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
