"""Integration tests for the osidb-bot KPI endpoint."""

from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from aegis_ai_web.src.endpoints.bot_kpi import get_osidb_bot_kpi
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


class _StatefulCacheHandler:
    """Context-manager stand-in for the real cache handler that keeps writes.

    Pagination spans several HTTP requests within one test, so a later page
    must observe the cache entry an earlier page wrote; _FakeCacheHandler
    drops writes and always reads None.
    """

    def __init__(self):
        self.entry = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self.entry

    def write(self, entry):
        self.entry = entry


@contextmanager
def _stateful_kpi_cache():
    """Patch the KPI cache with an in-memory handler shared by every request
    of the test, so pagination state survives across client.get calls."""
    handler = _StatefulCacheHandler()
    with patch(
        "aegis_ai_web.src.endpoints.bot_kpi._cache_handler",
        side_effect=lambda: handler,
    ):
        yield handler


_PATCH_READ = patch("aegis_ai_web.src.endpoints.bot_kpi._read_cache", return_value=None)
_PATCH_HANDLER = patch(
    "aegis_ai_web.src.endpoints.bot_kpi._cache_handler",
    side_effect=lambda: _FakeCacheHandler(),
)


@pytest.fixture(autouse=True)
def _isolated_kpi_cache(tmp_path, monkeypatch):
    """Point the KPI cache at a fresh per-test directory so cached aggregates
    from one test cannot leak into another."""
    monkeypatch.setenv("AEGIS_BOT_KPI_CACHE_DIR", str(tmp_path))


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
        "statement": "",
        "mitigation": "",
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


def _make_numbered_flaws(count):
    """Build ``count`` uniformly bot-processed flaws with sortable CVE IDs."""
    return [
        _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("LOW")]},
            impact="LOW",
            cve_id=f"CVE-2025-{i:04d}",
        )
        for i in range(1, count + 1)
    ]


def _make_filtering_session(*flaws):
    """Mock OSIDB session whose index honors the ``components`` filter and the
    ``updated_dt`` bounds, like the real server.

    Each flaw may declare its component membership via a test-only ``_components``
    key. The index phase returns only flaws matching the requested component
    (when given) whose ``updated_dt`` falls within any ``updated_dt_gte`` /
    ``updated_dt_lte`` bounds; the batch phase returns full data for requested
    CVEs. Lets a test prove the request's filters are pushed to the selection
    query.
    """
    from datetime import UTC, datetime

    def _aware(dt):
        # The endpoint parses query dates as naive; normalize both sides to UTC
        # so the comparison never mixes naive and aware datetimes.
        return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt

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
        component = kwargs.get("components")
        gte = kwargs.get("updated_dt_gte")
        lte = kwargs.get("updated_dt_lte")
        stubs = []
        for flaw in flaws:
            if component is not None and component not in flaw.get("_components", []):
                continue
            updated = _aware(datetime.fromisoformat(flaw["updated_dt"]))
            if gte is not None and updated < _aware(gte):
                continue
            if lte is not None and updated > _aware(lte):
                continue
            stub = MagicMock()
            stub.to_dict.return_value = {
                "cve_id": flaw["cve_id"],
                "updated_dt": flaw["updated_dt"],
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

    @patch("aegis_ai_web.src.endpoints.bot_kpi._result_to_response")
    @patch("aegis_ai_web.src.endpoints.bot_kpi._fetch_with_cache")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.BearerOSIDBSession")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_uses_forwarded_osidb_token(
        self, mock_settings, mock_session, mock_fetch, mock_response
    ):
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"

        get_osidb_bot_kpi(osidb_token="user-access-token")

        mock_session.assert_called_once_with(
            "https://osidb.example.com", "user-access-token"
        )

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
    def test_changed_after_filters_via_query(
        self, mock_settings, mock_bindings, _mock_read, _mock_handler
    ):
        """changed_after is pushed to the selection query as an updated_dt lower
        bound: the flaw whose updated_dt predates the window is not selected."""
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
        mock_bindings.new_session.return_value = _make_filtering_session(
            old_flaw, new_flaw
        )

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
    def test_changed_before_filters_via_query(
        self, mock_settings, mock_bindings, _mock_read, _mock_handler
    ):
        """Same updated_dt selection, upper bound: the flaw whose updated_dt
        postdates the window is not selected."""
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
        mock_bindings.new_session.return_value = _make_filtering_session(
            old_flaw, new_flaw
        )

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
    def test_component_param_scopes_osidb_query(
        self, mock_settings, mock_bindings, _mock_read, _mock_handler
    ):
        """The component query param is pushed to OSIDB as a ``components`` filter
        on the single selection index."""
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        session = _make_session()
        mock_bindings.new_session.return_value = session

        response = client.get("/api/v1/analysis/kpi/osidb-bot?component=kernel")
        assert response.status_code == 200

        calls = session.flaws.retrieve_list_iterator.call_args_list
        # The selection index carries the component filter.
        component_calls = [c for c in calls if c.kwargs.get("components") == "kernel"]
        assert component_calls

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


class TestOsidbBotKpiPaginationEndpoint:
    """The paginated wire contract of GET /api/v1/analysis/kpi/osidb-bot."""

    def test_limit_out_of_range_returns_422(self):
        """limit is constrained to 1..1000 at the API layer: out-of-range
        values are rejected before the handler runs."""
        for limit in ("0", "-1", "1001", "99999"):
            response = client.get(f"/api/v1/analysis/kpi/osidb-bot?limit={limit}")
            assert response.status_code == 422

    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_paginated_pages_carry_progress_and_cursor_keys(
        self, mock_settings, mock_bindings
    ):
        """Intermediate pages carry placeholder aggregates plus progress and
        next_cursor and never available_components; the final page carries the
        complete aggregate, drops next_cursor, and is the only page exposing
        available_components."""
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_settings.return_value.bot_kpi_max_refresh_seconds = 60

        flaws = [
            _make_flaw_dict(
                {"processed": True, "impact": [_make_bot_entry("LOW")]},
                impact="LOW",
                cve_id="CVE-2025-0001",
                components=["kernel"],
            ),
            _make_flaw_dict(
                {"processed": True, "impact": [_make_bot_entry("MODERATE")]},
                impact="IMPORTANT",
                cve_id="CVE-2025-0002",
                components=["openssl"],
            ),
            _make_flaw_dict(
                {"processed": True, "impact": [_make_bot_entry("LOW")]},
                impact="LOW",
                cve_id="CVE-2025-0003",
                components=["kernel"],
            ),
        ]
        mock_bindings.new_session.return_value = _make_session(*flaws)

        with _stateful_kpi_cache():
            page1 = client.get("/api/v1/analysis/kpi/osidb-bot?detail=true&limit=1")
            assert page1.status_code == 200
            data = page1.json()
            assert data["total_flaws_processed"] == 0
            assert data["features"] == {}
            assert data["next_cursor"] == "CVE-2025-0001"
            assert data["progress"] == {
                "selected_flaws": 3,
                "refreshed_flaws": 1,
                "complete": False,
            }
            assert [e["cve_id"] for e in data["entries"]] == ["CVE-2025-0001"]
            assert "available_components" not in data

            page2 = client.get(
                "/api/v1/analysis/kpi/osidb-bot?detail=true&limit=1"
                "&cursor=CVE-2025-0001"
            )
            assert page2.status_code == 200
            data = page2.json()
            assert data["next_cursor"] == "CVE-2025-0002"
            assert data["progress"]["refreshed_flaws"] == 2
            assert data["progress"]["complete"] is False
            assert [e["cve_id"] for e in data["entries"]] == ["CVE-2025-0002"]

            page3 = client.get(
                "/api/v1/analysis/kpi/osidb-bot?detail=true&limit=1"
                "&cursor=CVE-2025-0002"
            )
            assert page3.status_code == 200
            data = page3.json()
            # The final page returns no cursor to continue from.
            assert "next_cursor" not in data
            assert data["progress"]["complete"] is True
            assert data["total_flaws_processed"] == 3
            assert data["features"]["impact"]["suggested"] == 3
            assert data["features"]["impact"]["kept"] == 2
            assert data["features"]["impact"]["modified"] == 1
            # available_components covers the whole selection, final page only.
            assert data["available_components"] == ["kernel", "openssl"]
            assert [e["cve_id"] for e in data["entries"]] == ["CVE-2025-0003"]

            # Client accumulation invariant: concatenating the pages' entries
            # yields each flaw's records exactly once.
            all_entries = [
                entry
                for page in (page1, page2, page3)
                for entry in page.json()["entries"]
            ]
            assert [e["cve_id"] for e in all_entries] == [
                "CVE-2025-0001",
                "CVE-2025-0002",
                "CVE-2025-0003",
            ]

    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_fully_cached_request_keeps_legacy_shape(
        self, mock_settings, mock_bindings
    ):
        """A request whose selection is fully cached and passes no cursor is
        indistinguishable from the pre-pagination API: no progress and no
        next_cursor keys, full aggregate and entries. Passing a cursor opts
        back into the paginated shape even when everything is cached."""
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_settings.return_value.bot_kpi_max_refresh_seconds = 60

        flaws = [
            _make_flaw_dict(
                {"processed": True, "impact": [_make_bot_entry("LOW")]},
                impact="LOW",
                cve_id="CVE-2025-0001",
                components=["kernel"],
            ),
            _make_flaw_dict(
                {"processed": True, "impact": [_make_bot_entry("LOW")]},
                impact="LOW",
                cve_id="CVE-2025-0002",
                components=["openssl"],
            ),
        ]
        mock_bindings.new_session.return_value = _make_session(*flaws)

        with _stateful_kpi_cache():
            # Cold request: completes in one final page, progress included.
            cold = client.get("/api/v1/analysis/kpi/osidb-bot?detail=true")
            assert cold.status_code == 200
            assert cold.json()["progress"]["complete"] is True

            # Warm request: the legacy shape, with no pagination keys at all.
            warm = client.get("/api/v1/analysis/kpi/osidb-bot?detail=true")
            assert warm.status_code == 200
            data = warm.json()
            assert "progress" not in data
            assert "next_cursor" not in data
            assert data["total_flaws_processed"] == 2
            assert data["features"]["impact"]["kept"] == 2
            assert [e["cve_id"] for e in data["entries"]] == [
                "CVE-2025-0001",
                "CVE-2025-0002",
            ]
            assert data["available_components"] == ["kernel", "openssl"]

            # A cursor opts into the paginated shape even on a warm cache.
            resumed = client.get(
                "/api/v1/analysis/kpi/osidb-bot?detail=true&cursor=CVE-2025-0001"
            )
            assert resumed.status_code == 200
            data = resumed.json()
            assert data["progress"]["complete"] is True
            assert "next_cursor" not in data
            assert [e["cve_id"] for e in data["entries"]] == ["CVE-2025-0002"]

    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_pages_without_detail_omit_entries(self, mock_settings, mock_bindings):
        """detail=false keeps entries and available_components out of every
        page while the pagination metadata and the final aggregate remain."""
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_settings.return_value.bot_kpi_max_refresh_seconds = 60

        mock_bindings.new_session.return_value = _make_session(*_make_numbered_flaws(2))

        with _stateful_kpi_cache():
            page1 = client.get("/api/v1/analysis/kpi/osidb-bot?limit=1")
            assert page1.status_code == 200
            data = page1.json()
            assert "entries" not in data
            assert "available_components" not in data
            assert data["next_cursor"] == "CVE-2025-0001"
            assert data["total_flaws_processed"] == 0
            assert data["progress"]["complete"] is False

            page2 = client.get(
                "/api/v1/analysis/kpi/osidb-bot?limit=1&cursor=CVE-2025-0001"
            )
            assert page2.status_code == 200
            data = page2.json()
            assert "next_cursor" not in data
            assert "entries" not in data
            assert "available_components" not in data
            assert data["progress"]["complete"] is True
            assert data["total_flaws_processed"] == 2
            assert data["features"]["impact"]["suggested"] == 2

    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_default_limit_serves_400_flaws_per_page(
        self, mock_settings, mock_bindings
    ):
        """Omitting the limit query parameter serves the documented default of
        400 flaws per page: a 401-flaw selection takes two requests."""
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_settings.return_value.bot_kpi_max_refresh_seconds = 60

        mock_bindings.new_session.return_value = _make_session(
            *_make_numbered_flaws(401)
        )

        with _stateful_kpi_cache():
            page1 = client.get("/api/v1/analysis/kpi/osidb-bot")
            assert page1.status_code == 200
            data = page1.json()
            assert data["next_cursor"] == "CVE-2025-0400"
            assert data["progress"] == {
                "selected_flaws": 401,
                "refreshed_flaws": 400,
                "complete": False,
            }

            page2 = client.get("/api/v1/analysis/kpi/osidb-bot?cursor=CVE-2025-0400")
            assert page2.status_code == 200
            data = page2.json()
            assert "next_cursor" not in data
            assert data["progress"]["complete"] is True
            assert data["total_flaws_processed"] == 401
