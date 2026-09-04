"""Integration tests for the osidb-bot KPI endpoint."""

from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from aegis_ai_web.src.main import app

client = TestClient(app)


class _FakeCacheHandler:
    """Context-manager stand-in for the real cache handler.

    get_settings() is mocked without a real bot_kpi_cache_dir/config_dir, so the
    tests must never touch the filesystem: reads return no cache and writes are
    dropped.
    """

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return None

    def write(self, entry):
        pass


_PATCH_READ = patch("aegis_ai_web.src.endpoints.bot_kpi._read_cache", return_value=None)
_PATCH_HANDLER = patch(
    "aegis_ai_web.src.endpoints.bot_kpi._cache_handler",
    side_effect=lambda: _FakeCacheHandler(),
)


def _make_bot_entry(value, *, dq=0.9, conf=0.85, timestamp="2025-03-13T12:00:00"):
    return {
        "type": "AI-Bot",
        "value": value,
        "explanation": "test",
        "timestamp": timestamp,
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
        "updated_dt": "2025-06-01T00:00:00+00:00",
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


def _make_session(*flaws):
    """Mock OSIDB session for the two-phase fetch (cheap index + batch fetch).

    The index iterator yields cve_id/updated_dt stubs; a batch call (with
    ``cve_id=[...]``) returns full flaw data for the requested IDs.
    """
    by_cve = {flaw["cve_id"]: flaw for flaw in flaws}

    def _list_iterator(**kwargs):
        requested = kwargs.get("cve_id")
        if requested is not None:
            results = []
            for cve_id in requested:
                if cve_id in by_cve:
                    m = MagicMock()
                    m.to_dict.return_value = by_cve[cve_id]
                    results.append(m)
            return iter(results)
        stubs = []
        for flaw in flaws:
            stub = MagicMock()
            stub.to_dict.return_value = {
                "cve_id": flaw["cve_id"],
                "updated_dt": flaw.get("updated_dt", ""),
            }
            stubs.append(stub)
        return iter(stubs)

    session = MagicMock()
    session.flaws.retrieve_list_iterator.side_effect = _list_iterator
    return session


class TestOsidbBotKpiEndpoint:
    @_PATCH_HANDLER
    @_PATCH_READ
    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_returns_empty_when_no_flaws(
        self, mock_settings, mock_bindings, _mock_read, _mock_handler
    ):
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_bindings.new_session.return_value = _make_session()

        response = client.get("/api/v1/analysis/kpi/osidb-bot")
        assert response.status_code == 200
        data = response.json()
        assert data["total_flaws_processed"] == 0
        assert data["features"] == {}

    @_PATCH_HANDLER
    @_PATCH_READ
    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_returns_kpi_for_processed_flaws(
        self, mock_settings, mock_bindings, _mock_read, _mock_handler
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
        mock_bindings.new_session.return_value = _make_session(flaw_data)

        response = client.get("/api/v1/analysis/kpi/osidb-bot")
        assert response.status_code == 200
        data = response.json()

        assert data["total_flaws_processed"] == 1
        assert data["features"]["impact"]["suggested"] == 1
        assert data["features"]["impact"]["kept"] == 1
        assert data["features"]["impact"]["acceptance_rate"] == 100.0
        assert data["features"]["cwe_id"]["modified"] == 1
        assert data["features"]["cwe_id"]["acceptance_rate"] == 0.0

    @_PATCH_HANDLER
    @_PATCH_READ
    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_includes_skipped_metrics(
        self, mock_settings, mock_bindings, _mock_read, _mock_handler
    ):
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"

        flaw_data = _make_flaw_dict(
            {
                "processed": True,
                "impact": [_make_skipped_entry(dq=0.4, conf=0.3)],
            },
        )
        mock_bindings.new_session.return_value = _make_session(flaw_data)

        response = client.get("/api/v1/analysis/kpi/osidb-bot")
        assert response.status_code == 200
        data = response.json()

        assert data["features"]["impact"]["skipped"] == 1
        assert data["features"]["impact"]["suggested"] == 0
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

    def test_inverted_date_range_returns_422(self):
        """changed_after later than changed_before would silently return zero
        metrics instead of surfacing the caller's mistake."""
        response = client.get(
            "/api/v1/analysis/kpi/osidb-bot"
            "?changed_after=2025-06-01T00:00:00&changed_before=2025-01-01T00:00:00"
        )
        assert response.status_code == 422

    @_PATCH_HANDLER
    @_PATCH_READ
    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_changed_after_filters_from_cache(
        self, mock_settings, mock_bindings, _mock_read, _mock_handler
    ):
        """Filtering keys on each suggestion's own timestamp: the flaw whose
        suggestion predates the window is excluded even though both flaws are
        cached."""
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"

        old_flaw = _make_flaw_dict(
            {
                "processed": True,
                "impact": [_make_bot_entry("LOW", timestamp="2025-05-01T00:00:00")],
            },
            impact="LOW",
            updated_dt="2025-05-01T00:00:00+00:00",
        )
        new_flaw = _make_flaw_dict(
            {
                "processed": True,
                "impact": [
                    _make_bot_entry("MODERATE", timestamp="2025-07-01T00:00:00")
                ],
            },
            impact="MODERATE",
            cve_id="CVE-2025-0002",
            updated_dt="2025-07-01T00:00:00+00:00",
        )
        mock_bindings.new_session.return_value = _make_session(old_flaw, new_flaw)

        response = client.get(
            "/api/v1/analysis/kpi/osidb-bot?changed_after=2025-06-01T00:00:00"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total_flaws_processed"] == 1
        assert data["features"]["impact"]["suggested"] == 1

    @_PATCH_HANDLER
    @_PATCH_READ
    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_changed_before_filters_from_cache(
        self, mock_settings, mock_bindings, _mock_read, _mock_handler
    ):
        """Same per-suggestion-timestamp filtering, upper bound: the flaw whose
        suggestion postdates the window is excluded."""
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"

        old_flaw = _make_flaw_dict(
            {
                "processed": True,
                "impact": [_make_bot_entry("LOW", timestamp="2025-05-01T00:00:00")],
            },
            impact="LOW",
            updated_dt="2025-05-01T00:00:00+00:00",
        )
        new_flaw = _make_flaw_dict(
            {
                "processed": True,
                "impact": [
                    _make_bot_entry("MODERATE", timestamp="2025-07-01T00:00:00")
                ],
            },
            impact="MODERATE",
            cve_id="CVE-2025-0002",
            updated_dt="2025-07-01T00:00:00+00:00",
        )
        mock_bindings.new_session.return_value = _make_session(old_flaw, new_flaw)

        response = client.get(
            "/api/v1/analysis/kpi/osidb-bot?changed_before=2025-06-01T00:00:00"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total_flaws_processed"] == 1
        assert data["features"]["impact"]["suggested"] == 1

    @_PATCH_HANDLER
    @_PATCH_READ
    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_internal_error_returns_500(
        self, mock_settings, mock_bindings, _mock_read, _mock_handler
    ):
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_session = MagicMock()
        mock_session.flaws.retrieve_list_iterator.side_effect = RuntimeError("boom")
        mock_bindings.new_session.return_value = mock_session

        response = client.get("/api/v1/analysis/kpi/osidb-bot")
        assert response.status_code == 500
        assert "internal error" in response.json()["detail"].lower()
        assert "boom" not in response.json()["detail"]

    @_PATCH_HANDLER
    @_PATCH_READ
    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_multiple_flaws_aggregation(
        self, mock_settings, mock_bindings, _mock_read, _mock_handler
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
        mock_bindings.new_session.return_value = _make_session(flaw1, flaw2)

        response = client.get("/api/v1/analysis/kpi/osidb-bot")
        assert response.status_code == 200
        data = response.json()

        assert data["total_flaws_processed"] == 2
        assert data["features"]["impact"]["suggested"] == 2
        assert data["features"]["impact"]["kept"] == 1
        assert data["features"]["impact"]["modified"] == 1
        assert data["features"]["impact"]["acceptance_rate"] == 50.0
