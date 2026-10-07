"""Synchronous OSIDB bindings session backed by an existing bearer token."""

from typing import Any

from osidb_bindings.bindings.python_client import AuthenticatedClient
from osidb_bindings.bindings.python_client.api import osidb as osidb_api

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
        response = osidb_api.osidb_api_v2_flaws_list.sync(
            client=self._client,
            **normalized,
        )
        return iter(response.results if response is not None else ())


class BearerOSIDBSession:
    """Small session-compatible facade for the read-only KPI queries."""

    def __init__(self, base_url: str, token: str) -> None:
        self.flaws = _BearerFlawOperations(base_url, token)
