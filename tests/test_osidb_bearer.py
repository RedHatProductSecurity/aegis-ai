from types import SimpleNamespace
from unittest.mock import MagicMock

from aegis_ai.toolsets.tools.osidb import osidb_bearer


def test_bearer_session_forwards_token_and_normalizes_filters(mocker):
    flaw = MagicMock()
    list_call = mocker.patch(
        "aegis_ai.toolsets.tools.osidb.osidb_bearer.osidb_api.osidb_api_v2_flaws_list.sync",
        return_value=SimpleNamespace(results=[flaw]),
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
    assert list_call.call_args.kwargs["workflow_state"] == ["DONE"]
    assert list_call.call_args.kwargs["include_fields"] == ["cve_id", "updated_dt"]
    assert list_call.call_args.kwargs["components"] == ["kernel"]
    assert list_call.call_args.kwargs["cve_id_isempty"] is False
