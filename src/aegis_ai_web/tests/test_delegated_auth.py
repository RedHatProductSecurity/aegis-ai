"""
Unit tests for the delegated credentials auth flow.

When a client authenticates to Aegis with Kerberos and delegates credentials,
the request scope contains gssapi_context (with delegated_creds) and the OSIDB
client uses those credentials to obtain an OSIDB JWT and call OSIDB as that user.

These tests cover:
- Request-scope context (set/get/clear) used by the middleware.
- OSIDBClient using a delegated token from request scope (Bearer token path)
  when scope has a cached token, without requiring real GSSAPI or OSIDB.
- Delegated-cred path when token is not yet cached (gssapi_context.delegated_creds).
- Error and embargo-handling branches in get_flaw_data.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aegis_ai.request_context import get_request_scope, set_request_scope
from aegis_ai.toolsets.tools.osidb import osidb_client
from aegis_ai.toolsets.tools.osidb.osidb_client import (
    OSIDBAuthError,
    OSIDBUnauthorizedError,
)

# Must match OSIDBClient._OSIDB_DELEGATED_TOKEN_KEY (scope key for cached JWT)
_OSIDB_DELEGATED_TOKEN_KEY = "_osidb_delegated_token"


def _flaw(cve_id):
    return {
        "cve_id": cve_id,
        "title": "Component flaw",
        "cve_description": "",
        "impact": "",
        "statement": "",
        "comment_zero": "",
        "embargoed": False,
        "comments": [],
        "affects": [],
        "references": [],
        "cvss_scores": [],
    }


class TestRequestScopeContext:
    """Test request-scope contextvar used by delegated auth middleware."""

    def test_get_request_scope_default_none(self):
        """Without setting scope, get_request_scope returns None."""
        set_request_scope(None)
        assert get_request_scope() is None

    def test_set_and_get_request_scope(self):
        """Setting scope makes it visible to get_request_scope."""
        scope = {"path": "/api/v1/analysis/cve/suggest-impact"}
        set_request_scope(scope)
        assert get_request_scope() is scope
        set_request_scope(None)

    def test_clear_request_scope(self):
        """Setting None clears the scope."""
        set_request_scope({"key": "value"})
        set_request_scope(None)
        assert get_request_scope() is None

    def test_scope_with_gssapi_context_key(self):
        """Scope can carry gssapi_context key (used by OSIDB client)."""
        scope = {"username": "user@REALM", "gssapi_context": MagicMock()}
        set_request_scope(scope)
        current_scope = get_request_scope()
        assert current_scope is not None
        assert current_scope["username"] == "user@REALM"
        assert "gssapi_context" in current_scope
        set_request_scope(None)


@pytest.mark.asyncio
class TestOSIDBClientDelegatedTokenPath:
    """
    Test OSIDBClient when request scope has a cached delegated token.

    Simulates the flow after delegation: scope already has _osidb_delegated_token
    (e.g. from a previous get_osidb_token_for_delegated_cred call). The client
    should use that token for get_flaw_data (Bearer token path) without calling
    osidb_bindings.
    """

    @pytest.fixture(autouse=True)
    def set_scope_with_token(self):
        """Set request scope with a cached token so client uses Bearer path."""
        scope = {_OSIDB_DELEGATED_TOKEN_KEY: "test-delegated-jwt"}
        set_request_scope(scope)
        yield
        set_request_scope(None)

    async def test_get_flaw_data_uses_bearer_token_when_scope_has_token(self):
        """When scope has cached token, get_flaw_data calls OSIDB with Authorization: Bearer."""
        client = osidb_client.OSIDBClient()
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "cve_id": "CVE-2024-1234",
            "title": "Test flaw",
            "cwe_id": "CWE-123",
            "impact": "MODERATE",
            "statement": "",
            "mitigation": "",
            "comment_zero": "",
            "cve_description": "A test flaw",
            "components": [],
            "comments": [],
            "affects": [],
            "references": [],
            "cvss_scores": [],
            "embargoed": False,
        }

        mock_get = AsyncMock(return_value=mock_response)
        mock_client_ctx = AsyncMock()
        mock_http_client = MagicMock()
        mock_http_client.get = mock_get
        mock_client_ctx.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_client_ctx.__aexit__ = AsyncMock(return_value=None)

        with patch.object(
            osidb_client.httpx,
            "AsyncClient",
            return_value=mock_client_ctx,
        ):
            result = await client.get_flaw_data(
                "CVE-2024-1234", include_embargoed=False
            )

        assert result.cve_id == "CVE-2024-1234"
        assert result.title == "Test flaw"
        assert result.embargoed is False
        mock_get.assert_called_once()
        call_kwargs = mock_get.call_args.kwargs
        assert call_kwargs["headers"]["Authorization"] == "Bearer test-delegated-jwt"

    async def test_get_flaw_data_uses_session_when_no_scope(self):
        """When no request scope, client uses process session (osidb_bindings)."""
        set_request_scope(None)
        client = osidb_client.OSIDBClient()
        mock_session = MagicMock()
        mock_flaw = MagicMock()
        mock_flaw.cve_id = "CVE-2024-5678"
        mock_flaw.embargoed = False
        mock_session.flaws.retrieve.return_value = mock_flaw

        with patch.object(
            osidb_client.osidb_bindings,
            "new_session",
            return_value=mock_session,
        ):
            result = await client.get_flaw_data(
                "CVE-2024-5678", include_embargoed=False
            )

        assert result.cve_id == "CVE-2024-5678"
        mock_session.flaws.retrieve.assert_called_once()

    async def test_new_session_401_raises_osidb_unauthorized(self):
        """
        When new_session fails with HTTP 401 (e.g. OSIDB /auth/token), propagate
        OSIDBUnauthorizedError so the API can return 401 instead of a wrapped 500.
        """
        from requests import HTTPError

        set_request_scope(None)
        resp = MagicMock()
        resp.status_code = 401
        err = HTTPError(
            "401 Client Error: Unauthorized for url: https://osidb.example/auth/token"
        )
        err.response = resp

        client = osidb_client.OSIDBClient()
        with (
            patch.object(
                osidb_client.osidb_bindings,
                "new_session",
                side_effect=err,
            ),
            pytest.raises(OSIDBUnauthorizedError),
        ):
            await client.get_flaw_data("CVE-2026-4404", include_embargoed=False)

    async def test_list_component_flaws_uses_token_when_scope_has_token(self):
        """When scope has token, list_component_flaws uses Bearer token for list API."""
        client = osidb_client.OSIDBClient()
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "count": 1,
            "results": [
                {
                    "cve_id": "CVE-2024-9999",
                    "title": "Component flaw",
                    "cve_description": "",
                    "impact": "",
                    "statement": "",
                    "comment_zero": "",
                    "embargoed": False,
                    "comments": [],
                    "affects": [],
                    "references": [],
                    "cvss_scores": [],
                }
            ],
        }

        mock_get = AsyncMock(return_value=mock_response)
        mock_http_client = MagicMock()
        mock_http_client.get = mock_get
        mock_client_ctx = MagicMock()
        mock_client_ctx.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_client_ctx.__aexit__ = AsyncMock(return_value=None)

        with patch.object(
            osidb_client.httpx,
            "AsyncClient",
            return_value=mock_client_ctx,
        ):
            flaws = []
            async for flaw in client.list_component_flaws("curl"):
                flaws.append(flaw)

        assert len(flaws) == 1
        assert flaws[0].cve_id == "CVE-2024-9999"
        assert mock_get.call_args.kwargs["headers"]["Authorization"] == (
            "Bearer test-delegated-jwt"
        )

    async def test_list_component_flaws_follows_pages_until_no_next(self):
        client = osidb_client.OSIDBClient()
        pages = [
            {
                "count": 3,
                "next": "https://osidb.example/flaws?offset=2",
                "results": [_flaw("CVE-2024-0001"), _flaw("CVE-2024-0002")],
            },
            {"count": 3, "results": [_flaw("CVE-2024-0003")]},
        ]
        offsets = []

        async def get_page(**kwargs):
            offsets.append(kwargs["params"].get("offset", 0))
            return pages.pop(0)

        with patch.object(client, "_token_get", get_page):
            flaws = [flaw async for flaw in client.list_component_flaws("curl")]

        assert [flaw.cve_id for flaw in flaws] == [
            "CVE-2024-0001",
            "CVE-2024-0002",
            "CVE-2024-0003",
        ]
        assert offsets == [0, 2]

    async def test_list_component_flaws_stops_on_empty_page(self):
        client = osidb_client.OSIDBClient()
        get_page = AsyncMock(
            side_effect=[
                {
                    "count": 2,
                    "next": "https://osidb.example/flaws?offset=1",
                    "results": [_flaw("CVE-2024-0001")],
                },
                {
                    "count": 2,
                    "next": "https://osidb.example/flaws?offset=2",
                    "results": [],
                },
            ]
        )

        with patch.object(client, "_token_get", get_page):
            flaws = [flaw async for flaw in client.list_component_flaws("curl")]

        assert [flaw.cve_id for flaw in flaws] == ["CVE-2024-0001"]
        assert get_page.await_count == 2

    @pytest.mark.parametrize(
        "limit, expected, expected_requests", [(3, 3, 2), (0, 0, 0), (-1, 0, 0)]
    )
    async def test_list_component_flaws_applies_limit_across_pages(
        self, limit, expected, expected_requests
    ):
        client = osidb_client.OSIDBClient()
        get_page = AsyncMock(
            side_effect=[
                {
                    "count": 4,
                    "next": "https://osidb.example/flaws?offset=2",
                    "results": [_flaw("CVE-2024-0001"), _flaw("CVE-2024-0002")],
                },
                {
                    "count": 4,
                    "next": None,
                    "results": [_flaw("CVE-2024-0003"), _flaw("CVE-2024-0004")],
                },
            ]
        )

        with patch.object(client, "_token_get", get_page):
            flaws = [
                flaw async for flaw in client.list_component_flaws("curl", limit=limit)
            ]

        assert len(flaws) == expected
        assert get_page.await_count == expected_requests
        assert all(
            call.kwargs["params"]["limit"] == limit for call in get_page.call_args_list
        )

    async def test_list_component_flaws_maps_later_page_401(self):
        client = osidb_client.OSIDBClient()
        request = osidb_client.httpx.Request("GET", "https://osidb.example/flaws")
        response = osidb_client.httpx.Response(401, request=request)
        unauthorized = osidb_client.httpx.HTTPStatusError(
            "unauthorized", request=request, response=response
        )
        get_page = AsyncMock(
            side_effect=[
                {
                    "count": 2,
                    "next": "https://osidb.example/flaws?offset=1",
                    "results": [_flaw("CVE-2024-0001")],
                },
                unauthorized,
            ]
        )

        with (
            patch.object(client, "_token_get", get_page),
            pytest.raises(OSIDBUnauthorizedError),
        ):
            _ = [flaw async for flaw in client.list_component_flaws("curl")]

    async def test_count_component_flaws_uses_token_when_scope_has_token(self):
        """When scope has token, count_component_flaws uses Bearer token and returns count."""
        client = osidb_client.OSIDBClient()
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"count": 42}

        mock_get = AsyncMock(return_value=mock_response)
        mock_http_client = MagicMock()
        mock_http_client.get = mock_get
        mock_client_ctx = MagicMock()
        mock_client_ctx.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_client_ctx.__aexit__ = AsyncMock(return_value=None)

        with patch.object(
            osidb_client.httpx,
            "AsyncClient",
            return_value=mock_client_ctx,
        ):
            count = await client.count_component_flaws("curl")

        assert count == 42
        assert mock_get.call_args.kwargs["headers"]["Authorization"] == (
            "Bearer test-delegated-jwt"
        )

    async def test_get_flaw_data_raises_when_no_session_or_token(self, mocker):
        """When there is no OSIDB session and no delegated token, get_flaw_data raises OSIDBAuthError."""
        set_request_scope(None)
        client = osidb_client.OSIDBClient()
        mocker.patch.object(
            client,
            "_get_session_or_token",
            new_callable=AsyncMock,
            return_value=(None, None),
        )

        with pytest.raises(
            OSIDBAuthError, match="No OSIDB session or delegated token available"
        ):
            await client.get_flaw_data("CVE-2024-0001", include_embargoed=False)

    async def test_get_flaw_data_embargoed_raises_without_flag(self, mocker):
        """When an embargoed flaw is returned and include_embargoed=False, get_flaw_data raises ValueError."""
        client = osidb_client.OSIDBClient()
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "cve_id": "CVE-2024-1234",
            "title": "Embargoed flaw",
            "cwe_id": "CWE-999",
            "impact": "CRITICAL",
            "statement": "",
            "cve_description": "",
            "components": [],
            "comments": [],
            "affects": [],
            "references": [],
            "cvss_scores": [],
            "embargoed": True,
        }

        mock_get = AsyncMock(return_value=mock_response)
        mock_http_client = MagicMock()
        mock_http_client.get = mock_get
        mock_client_ctx = AsyncMock()
        mock_client_ctx.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_client_ctx.__aexit__ = AsyncMock(return_value=None)

        with (
            patch.object(
                osidb_client.httpx,
                "AsyncClient",
                return_value=mock_client_ctx,
            ),
            pytest.raises(ValueError, match="Could not retrieve CVE-2024-1234"),
        ):
            await client.get_flaw_data("CVE-2024-1234", include_embargoed=False)

    async def test_get_flaw_data_embargoed_returned_with_flag(self, mocker):
        """When include_embargoed=True, an embargoed flaw is returned as-is (Bearer path)."""
        client = osidb_client.OSIDBClient()
        embargoed_data = {
            "cve_id": "CVE-2024-1234",
            "title": "Embargoed flaw",
            "cwe_id": "CWE-999",
            "impact": "CRITICAL",
            "statement": "",
            "cve_description": "",
            "components": [],
            "comments": [],
            "affects": [],
            "references": [],
            "cvss_scores": [],
            "embargoed": True,
        }
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = embargoed_data

        mock_get = AsyncMock(return_value=mock_response)
        mock_http_client = MagicMock()
        mock_http_client.get = mock_get
        mock_client_ctx = AsyncMock()
        mock_client_ctx.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_client_ctx.__aexit__ = AsyncMock(return_value=None)

        with patch.object(
            osidb_client.httpx,
            "AsyncClient",
            return_value=mock_client_ctx,
        ):
            result = await client.get_flaw_data("CVE-2024-1234", include_embargoed=True)

        assert result.embargoed is True
        assert result.cve_id == "CVE-2024-1234"

    async def test_get_flaw_data_embargoed_session_flow(self):
        """Embargo handling for process-session flow: raises without flag, returns with flag."""
        set_request_scope(None)
        mock_session = MagicMock()
        embargoed_flaw = MagicMock()
        embargoed_flaw.cve_id = "CVE-2024-5678"
        embargoed_flaw.embargoed = True
        mock_session.flaws.retrieve.return_value = embargoed_flaw

        with patch.object(
            osidb_client.osidb_bindings,
            "new_session",
            return_value=mock_session,
        ):
            client = osidb_client.OSIDBClient()
            with pytest.raises(ValueError, match="Could not retrieve CVE-2024-5678"):
                await client.get_flaw_data("CVE-2024-5678", include_embargoed=False)

            result = await client.get_flaw_data("CVE-2024-5678", include_embargoed=True)
            assert result.embargoed is True
            assert result.cve_id == "CVE-2024-5678"


@pytest.mark.asyncio
class TestOSIDBClientDelegatedTokenAcquisition:
    """
    Test OSIDBClient when request scope has gssapi_context.delegated_creds but
    no cached delegated token. Exercises the main delegated-credentials flow.
    """

    async def test_get_delegated_token_caches_token_in_scope(self, mocker):
        """_get_delegated_token should call delegation helper and cache result in scope."""
        gssapi_context = MagicMock()
        gssapi_context.delegated_creds = MagicMock()
        scope = {
            "username": "user@REALM",
            "gssapi_context": gssapi_context,
        }
        set_request_scope(scope)

        fake_jwt = "delegated-jwt-from-helper"
        get_token_mock = mocker.patch(
            "aegis_ai.toolsets.tools.osidb.osidb_delegation.get_osidb_token_for_delegated_cred",
            return_value=fake_jwt,
        )

        try:
            token = await osidb_client.OSIDBClient()._get_delegated_token()
            assert token == fake_jwt
            get_token_mock.assert_called_once()
            scope = get_request_scope()
            assert scope is not None
            assert scope[_OSIDB_DELEGATED_TOKEN_KEY] == fake_jwt
        finally:
            set_request_scope(None)

    async def test_client_uses_delegated_token_for_flaw_requests(self, mocker):
        """
        get_flaw_data obtains delegated token from gssapi_context.delegated_creds,
        caches it in scope, and uses Bearer token without calling osidb_bindings.
        """
        gssapi_context = MagicMock()
        gssapi_context.delegated_creds = MagicMock()
        scope = {"username": "user@REALM", "gssapi_context": gssapi_context}
        set_request_scope(scope)

        fake_jwt = "delegated-jwt-from-helper"
        get_token_mock = mocker.patch(
            "aegis_ai.toolsets.tools.osidb.osidb_delegation.get_osidb_token_for_delegated_cred",
            return_value=fake_jwt,
        )
        bindings_spy = mocker.spy(osidb_client.osidb_bindings, "new_session")

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "cve_id": "CVE-2024-0002",
            "title": "Flaw",
            "cwe_id": "",
            "impact": "",
            "statement": "",
            "cve_description": "",
            "components": [],
            "comments": [],
            "affects": [],
            "references": [],
            "cvss_scores": [],
            "embargoed": False,
        }

        mock_http_client = MagicMock()
        mock_http_client.get = AsyncMock(return_value=mock_response)
        mock_client_ctx = MagicMock()
        mock_client_ctx.__aenter__ = AsyncMock(return_value=mock_http_client)
        mock_client_ctx.__aexit__ = AsyncMock(return_value=None)

        try:
            with patch.object(
                osidb_client.httpx,
                "AsyncClient",
                return_value=mock_client_ctx,
            ):
                client = osidb_client.OSIDBClient()
                await client.get_flaw_data("CVE-2024-0002", include_embargoed=False)

            get_token_mock.assert_called_once()
            bindings_spy.assert_not_called()
            scope = get_request_scope()
            assert scope is not None
            assert scope[_OSIDB_DELEGATED_TOKEN_KEY] == fake_jwt
            call_headers = mock_http_client.get.call_args.kwargs["headers"]
            assert call_headers["Authorization"] == f"Bearer {fake_jwt}"
        finally:
            set_request_scope(None)

    async def test_delegated_token_none_falls_back_to_session(self, mocker):
        """
        When get_osidb_token_for_delegated_cred returns None (e.g. OSIDB rejected),
        client falls back to process session and does not cache None in scope.
        """
        gssapi_context = MagicMock()
        gssapi_context.delegated_creds = MagicMock()
        scope = {"username": "user@REALM", "gssapi_context": gssapi_context}
        set_request_scope(scope)

        mocker.patch(
            "aegis_ai.toolsets.tools.osidb.osidb_delegation.get_osidb_token_for_delegated_cred",
            return_value=None,
        )
        mock_session = MagicMock()
        mock_flaw = MagicMock()
        mock_flaw.cve_id = "CVE-2024-0003"
        mock_flaw.embargoed = False
        mock_session.flaws.retrieve.return_value = mock_flaw

        try:
            with patch.object(
                osidb_client.osidb_bindings,
                "new_session",
                return_value=mock_session,
            ):
                client = osidb_client.OSIDBClient()
                result = await client.get_flaw_data(
                    "CVE-2024-0003", include_embargoed=False
                )

            assert result.cve_id == "CVE-2024-0003"
            scope = get_request_scope()
            assert scope is not None
            assert _OSIDB_DELEGATED_TOKEN_KEY not in scope
        finally:
            set_request_scope(None)
