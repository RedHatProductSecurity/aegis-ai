import base64
import json
from types import SimpleNamespace
from unittest.mock import MagicMock

from osidb_bindings.bindings.python_client.types import UNSET

from aegis_ai.toolsets.tools.osidb import osidb_bearer


def test_bearer_session_forwards_token_and_normalizes_filters(mocker):
    flaw = MagicMock()
    list_call = mocker.patch(
        "aegis_ai.toolsets.tools.osidb.osidb_bearer.osidb_api.osidb_api_v2_flaws_list.sync",
        return_value=SimpleNamespace(results=[flaw], next_=UNSET),
    )

    session = osidb_bearer.BearerOSIDBSession(
        "https://osidb.example.com/", "user-access-token"
    )
    result = list(
        session.flaws.retrieve_list_iterator(
            workflow_state="DONE",
            include_fields="cve_id,updated_dt",
            components="kernel",
            cve_id__isempty=False,
        )
    )

    assert result == [flaw]
    assert session.flaws._client.get_headers()["Authorization"] == (
        "Bearer user-access-token"
    )
    assert list_call.call_args.kwargs["client"] is session.flaws._client
    assert list_call.call_args.kwargs["workflow_state"] == ["DONE"]
    assert list_call.call_args.kwargs["include_fields"] == ["cve_id", "updated_dt"]
    assert list_call.call_args.kwargs["components"] == ["kernel"]
    assert list_call.call_args.kwargs["cve_id_isempty"] is False


def test_bearer_session_follows_pagination(mocker):
    flaws = [MagicMock(), MagicMock(), MagicMock()]
    list_call = mocker.patch(
        "aegis_ai.toolsets.tools.osidb.osidb_bearer.osidb_api.osidb_api_v2_flaws_list.sync",
        side_effect=[
            SimpleNamespace(results=flaws[:2], next_="next-page"),
            SimpleNamespace(results=flaws[2:], next_=None),
        ],
    )

    session = osidb_bearer.BearerOSIDBSession(
        "https://osidb.example.com", "user-access-token"
    )

    assert list(session.flaws.retrieve_list_iterator(limit=2)) == flaws
    assert list_call.call_args_list[1].kwargs["offset"] == 2


def test_validate_osidb_token_returns_verified_identity(mocker):
    verify = mocker.patch(
        "aegis_ai.toolsets.tools.osidb.osidb_bearer.auth_api.auth_token_verify_create.sync",
        return_value=SimpleNamespace(),
    )
    payload = (
        base64.urlsafe_b64encode(
            json.dumps({"preferred_username": "user@example.com"}).encode()
        )
        .decode()
        .rstrip("=")
    )
    token = f"header.{payload}.signature"

    assert (
        osidb_bearer.validate_osidb_token("https://osidb.example.com/", token)
        == "user@example.com"
    )
    assert verify.call_args.kwargs["body"].token == token
