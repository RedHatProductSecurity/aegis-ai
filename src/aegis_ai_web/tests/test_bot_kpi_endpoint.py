"""Integration tests for the osidb-bot KPI endpoint."""

from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from aegis_ai_web.src.main import app

client = TestClient(app)

_PATCH_SAVE = patch("aegis_ai_web.src.endpoints.bot_kpi._save_cache")
_PATCH_LOAD = patch("aegis_ai_web.src.endpoints.bot_kpi._load_cache", return_value=None)


def _make_bot_entry(value, *, dq=0.9, conf=0.85):
    return {
        "type": "AI-Bot",
        "value": value,
        "explanation": "test",
        "timestamp": "2025-03-13T12:00:00",
        "data_quality": dq,
        "confidence": conf,
    }


def _make_skipped_entry(*, dq=0.4, conf=0.3):
    return {
        "type": "AI-Bot-Skipped",
        "skip_reason": "data_quality",
        "skip_description": "too low",
        "timestamp": "2025-03-13T12:00:00",
        "data_quality": dq,
        "confidence": conf,
    }


def _make_flaw_dict(aegis_meta, **overrides):
    flaw = {
        "cve_id": "CVE-2025-0001",
        "components": [],
        "title": "",
        "cve_description": "",
        "cwe_id": "",
        "impact": "",
        "cvss_scores": [],
        "aegis_meta": aegis_meta,
    }
    flaw.update(overrides)
    return flaw


class TestOsidbBotKpiEndpoint:
    @_PATCH_SAVE
    @_PATCH_LOAD
    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_returns_empty_when_no_flaws(
        self, mock_settings, mock_bindings, _mock_load, _mock_save
    ):
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_session = MagicMock()
        mock_session.flaws.retrieve_list_iterator.return_value = iter([])
        mock_bindings.new_session.return_value = mock_session

        response = client.get("/api/v1/analysis/kpi/osidb-bot")
        assert response.status_code == 200
        data = response.json()
        assert data["total_flaws_processed"] == 0
        assert data["features"] == {}

    @_PATCH_SAVE
    @_PATCH_LOAD
    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_returns_kpi_for_processed_flaws(
        self, mock_settings, mock_bindings, _mock_load, _mock_save
    ):
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"

        flaw_data = _make_flaw_dict(
            {
                "processed": True,
                "impact": [_make_bot_entry("LOW")],
                "cwe_id": [_make_bot_entry("CWE-79")],
            },
            impact="LOW",
            cwe_id="CWE-89",
        )
        mock_flaw = MagicMock()
        mock_flaw.to_dict.return_value = flaw_data

        mock_session = MagicMock()
        mock_session.flaws.retrieve_list_iterator.return_value = iter([mock_flaw])
        mock_bindings.new_session.return_value = mock_session

        response = client.get("/api/v1/analysis/kpi/osidb-bot")
        assert response.status_code == 200
        data = response.json()

        assert data["total_flaws_processed"] == 1
        assert data["features"]["impact"]["applied"] == 1
        assert data["features"]["impact"]["kept"] == 1
        assert data["features"]["impact"]["acceptance_rate"] == 100.0
        assert data["features"]["cwe_id"]["modified"] == 1
        assert data["features"]["cwe_id"]["acceptance_rate"] == 0.0

    @_PATCH_SAVE
    @_PATCH_LOAD
    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_includes_skipped_metrics(
        self, mock_settings, mock_bindings, _mock_load, _mock_save
    ):
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"

        flaw_data = _make_flaw_dict(
            {
                "processed": True,
                "impact": [_make_skipped_entry(dq=0.4, conf=0.3)],
            },
        )
        mock_flaw = MagicMock()
        mock_flaw.to_dict.return_value = flaw_data

        mock_session = MagicMock()
        mock_session.flaws.retrieve_list_iterator.return_value = iter([mock_flaw])
        mock_bindings.new_session.return_value = mock_session

        response = client.get("/api/v1/analysis/kpi/osidb-bot")
        assert response.status_code == 200
        data = response.json()

        assert data["features"]["impact"]["skipped"] == 1
        assert data["features"]["impact"]["applied"] == 0
        assert data["features"]["impact"]["avg_data_quality"] == 0.4
        assert data["features"]["impact"]["avg_confidence"] == 0.3

    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_osidb_connection_failure_returns_503(self, mock_settings, mock_bindings):
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_bindings.new_session.side_effect = ConnectionError("unreachable")

        response = client.get("/api/v1/analysis/kpi/osidb-bot")
        assert response.status_code == 503

    def test_invalid_changed_after_returns_422(self):
        response = client.get("/api/v1/analysis/kpi/osidb-bot?changed_after=not-a-date")
        assert response.status_code == 422

    def test_invalid_changed_before_returns_422(self):
        response = client.get(
            "/api/v1/analysis/kpi/osidb-bot?changed_before=not-a-date"
        )
        assert response.status_code == 422

    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_changed_after_passes_to_osidb(self, mock_settings, mock_bindings):
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_session = MagicMock()
        mock_session.flaws.retrieve_list_iterator.return_value = iter([])
        mock_bindings.new_session.return_value = mock_session

        response = client.get(
            "/api/v1/analysis/kpi/osidb-bot?changed_after=2025-06-01T00:00:00"
        )
        assert response.status_code == 200

        call_kwargs = mock_session.flaws.retrieve_list_iterator.call_args[1]
        assert "updated_dt__gte" in call_kwargs

    @_PATCH_SAVE
    @_PATCH_LOAD
    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_multiple_flaws_aggregation(
        self, mock_settings, mock_bindings, _mock_load, _mock_save
    ):
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"

        flaw1 = _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("LOW")]},
            impact="LOW",
        )
        flaw2 = _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("MODERATE")]},
            impact="IMPORTANT",
            cve_id="CVE-2025-0002",
        )

        mock_flaws = [MagicMock(), MagicMock()]
        mock_flaws[0].to_dict.return_value = flaw1
        mock_flaws[1].to_dict.return_value = flaw2

        mock_session = MagicMock()
        mock_session.flaws.retrieve_list_iterator.return_value = iter(mock_flaws)
        mock_bindings.new_session.return_value = mock_session

        response = client.get("/api/v1/analysis/kpi/osidb-bot")
        assert response.status_code == 200
        data = response.json()

        assert data["total_flaws_processed"] == 2
        assert data["features"]["impact"]["applied"] == 2
        assert data["features"]["impact"]["kept"] == 1
        assert data["features"]["impact"]["modified"] == 1
        assert data["features"]["impact"]["acceptance_rate"] == 50.0
