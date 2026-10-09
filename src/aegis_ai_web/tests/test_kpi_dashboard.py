"""Cross-endpoint dashboard contract and historical provenance regressions."""

import os
import time
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from aegis_ai.features.data_models import AegisFeatureModel
from aegis_ai.osidb_bot.suggest import record_aegis_meta
from aegis_ai_web.src import main
from aegis_ai_web.src.endpoints import bot_kpi, kpi
from aegis_ai_web.src.main import app

client = TestClient(app)


@pytest.fixture
def dashboard(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_BOT_KPI_CACHE_DIR", str(tmp_path))
    records = [
        {"type": "AI-Bot", "value": "LOW", "timestamp": "2026-08-01T00:00:00Z"},
        {
            "type": "AI-Bot-Skipped",
            "timestamp": "2026-09-01T00:00:00Z",
            "aegis_version": "0.9.2",
        },
        {
            "type": "AI-Bot",
            "value": "IMPORTANT",
            "timestamp": "2026-09-02T00:00:00Z",
            "aegis_version": "0.9.2",
        },
    ]
    flaws = [
        {
            "cve_id": "CVE-2026-1000",
            "updated_dt": "2026-10-01T00:00:00Z",
            "components": ["kernel", "kernel"],
            "impact": "IMPORTANT",
            "aegis_meta": {"processed": True, "impact": records},
        },
        {
            "cve_id": "CVE-2026-1001",
            "updated_dt": "2026-10-01T00:00:00Z",
            "components": ["openssl"],
            "impact": "LOW",
            "aegis_meta": {"processed": True, "impact": [records[0]]},
        },
    ]
    session = MagicMock()

    def retrieve(**kwargs):
        selected = [
            flaw
            for flaw in flaws
            if (not kwargs.get("cve_id") or flaw["cve_id"] in kwargs["cve_id"])
            and (
                not kwargs.get("components")
                or kwargs["components"] in flaw["components"]
            )
        ]
        return [MagicMock(to_dict=MagicMock(return_value=flaw)) for flaw in selected]

    session.flaws.retrieve_list_iterator.side_effect = retrieve
    monkeypatch.setattr(bot_kpi.osidb_bindings, "new_session", lambda **_: session)
    monkeypatch.setattr(
        kpi.feedback_logger,
        "read",
        lambda: [
            {
                "feature": "suggest-impact",
                "cve_id": flaw["cve_id"],
                "accept": "true",
                "datetime": "2026-09-02T00:00:00Z",
                "version": "0.9.2",
            }
            for flaw in flaws
        ],
    )
    monkeypatch.setattr(kpi.programmatic_feedback_logger, "read", list)
    return session, flaws


def test_bot_detail_matches_aggregate_and_preserves_unknown_versions(dashboard):
    response = client.get("/api/v1/analysis/kpi/osidb-bot?detail=true")
    assert response.status_code == 200
    body = response.json()
    assert body["total_flaws_processed"] == 2
    assert body["features"]["impact"]["suggested"] == 2
    assert body["features"]["impact"]["kept"] == 2
    assert body["features"]["impact"]["skipped"] == 1
    assert len(body["entries"]) == 4  # history remains available, not extra decisions
    assert {entry["aegis_version"] for entry in body["entries"]} == {"", "0.9.2"}
    assert body["available_components"] == ["kernel", "openssl"]
    legacy = client.get("/api/v1/analysis/kpi/osidb-bot").json()
    assert set(legacy) == {"total_flaws_processed", "features"}


def test_bot_kpi_uses_process_credentials_without_delegation(dashboard, monkeypatch):
    monkeypatch.setattr(main, "kerberos_spn", "HTTP/aegis.example.com@REALM")

    response = client.get("/api/v1/analysis/kpi/osidb-bot")

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_delegated_token_cache_is_destroyed_on_failure(monkeypatch):
    from aegis_ai.toolsets.tools.osidb import osidb_delegation

    monkeypatch.setattr(
        main,
        "get_request_scope",
        lambda: {
            "gssapi_context": SimpleNamespace(delegated_creds=MagicMock()),
        },
    )
    monkeypatch.setattr(
        osidb_delegation,
        "_prepare_delegated_creds_for_thread",
        lambda _: "MEMORY:test-cache",
    )

    def fail_token_exchange(*_):
        raise RuntimeError("token exchange failed")

    monkeypatch.setattr(
        osidb_delegation,
        "get_osidb_token_for_delegated_cred",
        fail_token_exchange,
    )
    destroy = MagicMock()
    monkeypatch.setattr(osidb_delegation, "destroy_kerberos_ccache", destroy)

    with pytest.raises(RuntimeError, match="token exchange failed"):
        await main._get_request_osidb_token()

    destroy.assert_called_once_with("MEMORY:test-cache")


@pytest.mark.parametrize("endpoint", ["cve?feature=all&", "osidb-bot?"])
def test_component_version_and_recorded_time_intersection(dashboard, endpoint):
    session, _ = dashboard
    response = client.get(
        f"/api/v1/analysis/kpi/{endpoint}detail=true&component=kernel"
        "&aegis_version=0.9.2&recorded_after=2026-09-02T00:00:00Z"
        "&recorded_before=2026-09-02T00:00:00Z"
    )
    assert response.status_code == 200
    body = response.json()
    entries = (
        body["suggest-impact"]["entries"]
        if endpoint.startswith("cve")
        else body["entries"]
    )
    assert len(entries) == 1
    assert entries[0]["cve_id"] == "CVE-2026-1000"
    assert entries[0]["aegis_version"] == "0.9.2"
    # A flaw edited in October still contributes a September suggestion.
    for call in session.flaws.retrieve_list_iterator.call_args_list:
        assert "updated_dt_lte" not in call.kwargs
        assert "updated_dt_gte" not in call.kwargs


def test_unknown_version_filter_recomputes_bot_decisions(dashboard):
    body = client.get(
        "/api/v1/analysis/kpi/osidb-bot?detail=true&aegis_version="
    ).json()
    assert body["features"]["impact"]["kept"] == 1
    assert body["features"]["impact"]["modified"] == 1
    assert body["features"]["impact"]["acceptance_rate"] == 50
    assert all(entry["aegis_version"] == "" for entry in body["entries"])


@pytest.mark.parametrize(
    "query", ["aegis_version=0.9.1", "recorded_before=2026-08-31T23:59:59Z"]
)
def test_feedback_keeps_latest_matching_programmatic_record(
    dashboard, monkeypatch, query
):
    monkeypatch.setattr(kpi.feedback_logger, "read", list)
    monkeypatch.setattr(
        kpi.programmatic_feedback_logger,
        "read",
        lambda: [
            {
                "feature": "suggest-impact",
                "cve_id": "CVE-2026-1000",
                "version": version,
                "datetime": timestamp,
                "acceptance_score": score,
            }
            for version, timestamp, score in [
                ("0.9.1", "2026-08-01 00:00:00", "1"),
                ("0.9.2", "2026-09-01 00:00:00", "0"),
            ]
        ],
    )
    response = client.get(f"/api/v1/analysis/kpi/cve?feature=all&detail=true&{query}")
    assert response.status_code == 200
    metrics = response.json()["suggest-impact"]
    assert metrics["acceptance_percentage"] == 100
    assert [entry["aegis_version"] for entry in metrics["entries"]] == ["0.9.1"]


def test_legacy_cache_is_refreshed_even_with_same_watermark(dashboard):
    session, flaws = dashboard
    legacy = bot_kpi.BotKPICacheEntry.model_validate(
        {
            "flaws": {
                flaw["cve_id"]: {
                    "updated_dt": flaw["updated_dt"],
                    "bot_processed": True,
                    "fields": {},
                }
                for flaw in flaws
            }
        }
    )
    with bot_kpi._cache_handler() as handler:
        handler.write(legacy)
    body = client.get(
        "/api/v1/analysis/kpi/osidb-bot?detail=true&component=kernel"
    ).json()
    assert len(body["entries"]) == 3
    # A narrow request rewrites the shared cache but must preserve the old marker
    # for the unselected flaw so it, too, gets refreshed when later selected.
    body = client.get(
        "/api/v1/analysis/kpi/osidb-bot?detail=true&component=openssl"
    ).json()
    assert len(body["entries"]) == 1
    batch_calls = [
        call
        for call in session.flaws.retrieve_list_iterator.call_args_list
        if "cve_id" in call.kwargs
    ]
    assert len(batch_calls) == 2


@pytest.mark.parametrize("endpoint", ["cve?feature=all&", "osidb-bot?"])
def test_invalid_record_window_is_422(endpoint):
    response = client.get(
        f"/api/v1/analysis/kpi/{endpoint}recorded_after=2026-09-03"
        "&recorded_before=2026-09-02T00:00:00Z"
    )
    assert response.status_code == 422


def test_naive_record_timestamps_use_local_timezone(monkeypatch):
    old_timezone = os.environ.get("TZ")
    monkeypatch.setenv("TZ", "Etc/GMT+4")
    time.tzset()
    try:
        assert kpi.KPIRecordFilters(
            recorded_after=datetime(2026, 9, 2, 16, tzinfo=UTC),
            recorded_before=datetime(2026, 9, 2, 16, tzinfo=UTC),
        ).matches("2026-09-02T12:00:00", "")
    finally:
        if old_timezone is None:
            monkeypatch.delenv("TZ")
        else:
            monkeypatch.setenv("TZ", old_timezone)
        time.tzset()


def test_feedback_component_lookup_failure_is_not_empty_success(dashboard, monkeypatch):
    def unavailable(**_):
        raise OSError("offline")

    monkeypatch.setattr(kpi.osidb_bindings, "new_session", unavailable)
    response = client.get("/api/v1/analysis/kpi/cve?feature=all&component=kernel")
    assert response.status_code == 503


def test_cve_kpi_uses_forwarded_osidb_token_for_component_lookup(
    dashboard, monkeypatch
):
    session, _ = dashboard
    monkeypatch.setattr(
        kpi,
        "get_settings",
        lambda: MagicMock(osidb_server_url="https://osidb.example.com"),
    )
    bearer_session = MagicMock(return_value=session)
    monkeypatch.setattr(kpi, "BearerOSIDBSession", bearer_session)

    kpi.get_cve_kpi("all", component="kernel", osidb_token="user-access-token")

    bearer_session.assert_called_once_with(
        "https://osidb.example.com", "user-access-token"
    )


def test_new_bot_records_include_running_version(monkeypatch):
    monkeypatch.setattr(
        "aegis_ai.osidb_bot.suggest.get_settings",
        lambda: MagicMock(app_version="0.9.3+build42"),
    )
    flaw = {}
    output = AegisFeatureModel.model_construct(data_quality=0.9, confidence=0.8)
    for kind in ("AI-Bot", "AI-Bot-Skipped"):
        record_aegis_meta(
            flaw, datetime(2026, 10, 1, tzinfo=UTC), "impact", output, type=kind
        )
    assert [entry["aegis_version"] for entry in flaw["aegis_meta"]["impact"]] == [
        "0.9.3+build42"
    ] * 2
