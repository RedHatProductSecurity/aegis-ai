from unittest.mock import AsyncMock

import pytest

from aegis_ai.request_context import OSIDB_ACCESS_TOKEN_KEY
from aegis_ai_web.src import gssapi_delegation


def _middleware(app):
    middleware = object.__new__(gssapi_delegation.GSSAPIDelegationMiddleware)
    middleware.app = app
    return middleware


@pytest.mark.asyncio
async def test_verified_bearer_token_establishes_identity(monkeypatch):
    app = AsyncMock()
    monkeypatch.setattr(
        gssapi_delegation, "validate_osidb_token", lambda *_: "user@example.com"
    )
    scope = {
        "type": "http",
        "headers": [(b"authorization", b"Bearer valid-token")],
    }

    await _middleware(app)(scope, AsyncMock(), AsyncMock())

    assert scope[OSIDB_ACCESS_TOKEN_KEY] == "valid-token"
    assert scope["username"] == "user@example.com"
    app.assert_awaited_once()


@pytest.mark.asyncio
async def test_invalid_bearer_token_does_not_bypass_authentication(monkeypatch):
    app = AsyncMock()
    monkeypatch.setattr(gssapi_delegation, "validate_osidb_token", lambda *_: None)
    send = AsyncMock()
    scope = {
        "type": "http",
        "headers": [(b"authorization", b"Bearer invalid-token")],
    }

    await _middleware(app)(scope, AsyncMock(), send)

    app.assert_not_awaited()
    assert send.await_args_list[0].args[0]["status"] == 401
