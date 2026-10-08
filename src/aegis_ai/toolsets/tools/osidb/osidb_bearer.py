"""Synchronous OSIDB helpers backed by an existing bearer token."""

import base64
import json
import logging
from typing import Any

from osidb_bindings.bindings.python_client import AuthenticatedClient, Client
from osidb_bindings.bindings.python_client.api import auth as auth_api
from osidb_bindings.bindings.python_client.api import osidb as osidb_api
from osidb_bindings.bindings.python_client.models.token_verify_request import (
    TokenVerifyRequest,
)
from osidb_bindings.bindings.python_client.types import Unset

logger = logging.getLogger(__name__)

_LIST_PARAMS = {"cve_id", "components", "workflow_state", "include_fields"}


def _normalize_list_params(params: dict[str, Any]) -> dict[str, Any]:
    # SessionOperationsGroup accepts Django-style filter names, while the
    # generated v2 client flattens them into Python keyword names.
    normalized = {name.replace("__", "_"): value for name, value in params.items()}
    for name in _LIST_PARAMS:
        value = normalized.get(name)
        if isinstance(value, str):
            normalized[name] = value.split(",") if name == "include_fields" else [value]
    return normalized


class _BearerFlawOperations:
    def __init__(self, base_url: str, token: str) -> None:
        self._client = AuthenticatedClient(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {token}"},
        )

    def retrieve_list_iterator(self, **params: Any):
        normalized = _normalize_list_params(params)
        while True:
            response = osidb_api.osidb_api_v2_flaws_list.sync(
                client=self._client,
                **normalized,
            )
            if response is None or not response.results:
                return
            yield from response.results
            if isinstance(response.next_, Unset) or not response.next_:
                return
            normalized["offset"] = normalized.get("offset", 0) + len(response.results)


class BearerOSIDBSession:
    """Small session-compatible facade for the read-only KPI queries."""

    def __init__(self, base_url: str, token: str) -> None:
        self.flaws = _BearerFlawOperations(base_url, token)


def validate_osidb_token(base_url: str, token: str) -> str | None:
    """Validate an OSIDB token and return its asserted identity."""
    try:
        response = auth_api.auth_token_verify_create.sync(
            client=Client(base_url=base_url.rstrip("/")),
            body=TokenVerifyRequest(token=token),
        )
        if response is None:
            return None
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
        for claim in ("preferred_username", "username", "email", "sub", "user_id"):
            if value := claims.get(claim):
                return str(value)
        return "verified-osidb-user"
    except Exception:
        logger.debug("OSIDB bearer token validation failed", exc_info=True)
        return None
