"""
Request-scope context for the web layer.

When aegis_ai_web handles a request, it sets the current ASGI scope here so that
downstream code (e.g. OSIDB client) can use request-scoped data such as
GSSAPI delegated credentials for pass-through authentication to OSIDB.
"""

from contextvars import ContextVar
from typing import Any

OSIDB_ACCESS_TOKEN_KEY = "_osidb_access_token"

# Current request's ASGI scope (set by web middleware, read by OSIDB client).
# Scope may contain "gssapi_context" with delegated_creds when Kerberos delegation is used.
request_scope_var: ContextVar[dict[str, Any] | None] = ContextVar(
    "request_scope",
    default=None,
)


def get_request_scope() -> dict[str, Any] | None:
    """Return the current request's ASGI scope, if any (web context only)."""
    return request_scope_var.get()


def set_request_scope(scope: dict[str, Any] | None) -> None:
    """Set the current request scope (called by web middleware)."""
    request_scope_var.set(scope)
