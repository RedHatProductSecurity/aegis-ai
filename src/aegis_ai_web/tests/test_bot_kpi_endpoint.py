"""Integration tests for the osidb-bot KPI endpoint."""

import time
from types import SimpleNamespace
from unittest.mock import ANY, MagicMock, patch

import pytest
import requests
from fastapi.testclient import TestClient

from aegis_ai_web.src.endpoints import kpi_delivery
from aegis_ai_web.src.endpoints.bot_kpi import get_osidb_bot_kpi
from aegis_ai_web.src.main import app
from tests.kpi_helpers import add_list_page

client = TestClient(app)

URL = "/api/v1/analysis/kpi/osidb-bot"


@pytest.fixture(autouse=True)
def _isolated_kpi_cache(tmp_path, monkeypatch):
    """Point the KPI delivery storage at a fresh per-test directory so runs
    from one test cannot leak into another, and pin the Kerberos principal
    so the authorization scope never depends on the host's tickets."""
    monkeypatch.setenv("AEGIS_BOT_KPI_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(
        "aegis_ai_web.src.endpoints.bot_kpi._get_cache_path",
        lambda: tmp_path / "kpi_cache.json",
    )
    monkeypatch.setattr(
        "osidb_bindings.token_cache.resolve_kerberos_principal",
        lambda: "tester@EXAMPLE.COM",
    )


def _deliver(**params):
    """Drive one delivery run to completion as the OSIM client would.

    Follows run_id + delivery.continue_token until the final page, re-issuing
    the original query on every request, and returns every page body in
    request order together with the entries accumulated across accepted
    pages, so single-shot aggregate assertions keep their shape while page
    delivery counts stay observable.
    """
    pages = []
    entries = []
    for _ in range(100):
        response = client.get(URL, params=params)
        assert response.status_code == 200, response.text
        body = response.json()
        pages.append(body)
        entries.extend(body.get("entries") or [])
        token = body["delivery"]["continue_token"]
        if not token:
            return pages, entries
        params = params | {"run_id": body["delivery"]["run_id"], "cursor": token}
    raise AssertionError("delivery run did not reach a final page")


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


def _make_session(*flaws, index_delay=0.0, batch_delay=0.0):
    """Mock OSIDB session for the two-phase fetch (cheap index + batch fetch).

    The index iterator yields cve_id/updated_dt stubs; a batch call (with
    ``cve_id=[...]``) returns full flaw data for the requested IDs.
    ``index_delay``/``batch_delay`` sleep in the index/batch fetch calls so
    the per-request refresh time budget can be exercised deterministically.
    """
    by_cve = {flaw["cve_id"]: flaw for flaw in flaws}

    def _list_iterator(**kwargs):
        if index_delay:
            time.sleep(index_delay)
        requested = kwargs.get("cve_id")
        if requested is not None:
            if batch_delay:
                time.sleep(batch_delay)
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
    return add_list_page(session)


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
    return add_list_page(session)


def _mock_settings(mock_settings, *, budget=20):
    """Mocked settings carrying the fields the handler reads: the OSIDB server
    URL and a real refresh budget (the documented default), so the deadline
    arithmetic runs on numbers instead of MagicMocks."""
    mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
    mock_settings.return_value.bot_kpi_max_refresh_seconds = budget


def _delivery_settings(*, budget=20):
    """Settings faithful enough for the delivery layer: the OSIDB server URL
    and the cache TTLs it reads, alongside the refresh budget."""
    return SimpleNamespace(
        osidb_server_url="https://osidb.example.com",
        bot_kpi_max_refresh_seconds=budget,
        bot_kpi_index_ttl_seconds=300,
        bot_kpi_run_ttl_seconds=1800,
    )


class TestOsidbBotKpiEndpoint:
    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_returns_empty_when_no_flaws(self, mock_settings, mock_bindings):
        """An empty selection completes on the first response: zero aggregates
        and no continuation to follow."""
        _mock_settings(mock_settings)
        mock_bindings.new_session.return_value = _make_session()

        pages, _entries = _deliver()

        assert len(pages) == 1
        data = pages[0]
        assert data["total_flaws_processed"] == 0
        assert data["features"] == {}
        assert data["delivery"]["selected_flaws"] == 0
        assert data["delivery"]["complete"] is True
        assert data["delivery"]["continue_token"] is None

    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_returns_kpi_for_processed_flaws(self, mock_settings, mock_bindings):
        _mock_settings(mock_settings)

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

        pages, _entries = _deliver()

        data = pages[-1]
        assert data["delivery"]["complete"] is True
        assert data["total_flaws_processed"] == 1
        assert data["features"]["impact"]["suggested"] == 1
        assert data["features"]["impact"]["kept"] == 1
        assert data["features"]["impact"]["acceptance_rate"] == 100.0
        assert data["features"]["cwe_id"]["modified"] == 1
        assert data["features"]["cwe_id"]["acceptance_rate"] == 0.0

    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_includes_skipped_metrics(self, mock_settings, mock_bindings):
        _mock_settings(mock_settings)

        flaw_data = _make_flaw_dict(
            {
                "processed": True,
                "impact": [_make_skipped_entry(dq=0.4, conf=0.3)],
            },
        )
        mock_bindings.new_session.return_value = _make_session(flaw_data)

        pages, _entries = _deliver()

        data = pages[-1]
        assert data["delivery"]["complete"] is True
        assert data["features"]["impact"]["skipped"] == 1
        assert data["features"]["impact"]["suggested"] == 0
        assert data["features"]["impact"]["avg_data_quality"] == 0.4
        assert data["features"]["impact"]["avg_confidence"] == 0.3

    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_osidb_connection_failure_returns_503(self, mock_settings, mock_bindings):
        _mock_settings(mock_settings)
        mock_bindings.new_session.side_effect = ConnectionError("unreachable")

        response = client.get("/api/v1/analysis/kpi/osidb-bot")
        assert response.status_code == 503
        # Connection failures have no HTTP 503 status and must not be retried.
        assert mock_bindings.new_session.call_count == 1
        assert "retry_exhausted" not in response.json()

    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_transient_osidb_http_503_is_retried(
        self, mock_settings, mock_bindings, monkeypatch
    ):
        """A transient OSIDB outage does not abort the request: session
        creation is retried with a fresh session and the run then completes
        normally."""
        _mock_settings(mock_settings)
        monkeypatch.setattr(
            "aegis_ai_web.src.endpoints.kpi_retry.time.sleep", lambda _: None
        )
        unavailable = requests.Response()
        unavailable.status_code = 503
        mock_bindings.new_session.side_effect = [
            requests.HTTPError(response=unavailable),
            _make_session(*_make_numbered_flaws(2)),
            _make_session(*_make_numbered_flaws(2)),
        ]

        pages, _entries = _deliver(detail=True)

        data = pages[-1]
        assert data["delivery"]["complete"] is True
        assert data["total_flaws_processed"] == 2
        # One failed session creation, its retry, and the detail-phase session.
        assert mock_bindings.new_session.call_count == 3

    @patch("aegis_ai_web.src.endpoints.bot_kpi.BearerOSIDBSession")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_uses_forwarded_osidb_token(self, mock_settings, mock_session, monkeypatch):
        """A forwarded OSIDB token selects BearerOSIDBSession, constructed
        with the server's refresh-budget default (the setting when no
        max_refresh_secs query parameter is passed) as its per-call HTTP
        timeout."""
        settings = _delivery_settings()
        mock_settings.return_value = settings
        monkeypatch.setattr(kpi_delivery, "get_settings", lambda: settings)
        mock_session.return_value = _make_session()

        get_osidb_bot_kpi(osidb_token="user-access-token")

        mock_session.assert_called_once_with(
            "https://osidb.example.com", "user-access-token", timeout=ANY
        )
        # The timeout is the budget remaining at session creation, so it is
        # the full 20s budget less only the sub-second setup time before it.
        assert 19 < mock_session.call_args.kwargs["timeout"] <= 20

    @patch("aegis_ai_web.src.endpoints.bot_kpi.BearerOSIDBSession")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_max_refresh_secs_overrides_budget_and_bearer_timeout(
        self, mock_settings, mock_session, monkeypatch
    ):
        """The max_refresh_secs request parameter overrides the server's
        budget default: it reaches BearerOSIDBSession as its per-call HTTP
        timeout and bounds the wall-clock deadline handed to the delivery
        run."""
        settings = _delivery_settings()
        mock_settings.return_value = settings
        monkeypatch.setattr(kpi_delivery, "get_settings", lambda: settings)
        mock_session.return_value = _make_session()

        get_osidb_bot_kpi(osidb_token="user-access-token", max_refresh_secs=7)

        mock_session.assert_called_once_with(
            "https://osidb.example.com", "user-access-token", timeout=ANY
        )
        assert 6 < mock_session.call_args.kwargs["timeout"] <= 7

        with patch("aegis_ai_web.src.endpoints.kpi_delivery.get_delivery") as delivery:
            started = time.monotonic()
            get_osidb_bot_kpi(osidb_token="user-access-token", max_refresh_secs=7)
        # The deadline was set ~7 seconds out, before the delivery run started.
        deadline = delivery.call_args.kwargs["deadline"]
        assert started < deadline <= time.monotonic() + 7

    def test_max_refresh_secs_out_of_range_returns_422(self):
        """max_refresh_secs is constrained to 1..600 at the API layer:
        out-of-range values are rejected before the handler runs."""
        for value in ("0", "-1", "601", "99999"):
            response = client.get(
                f"/api/v1/analysis/kpi/osidb-bot?max_refresh_secs={value}"
            )
            assert response.status_code == 422

    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_max_refresh_secs_bounds_are_inclusive(self, mock_settings, mock_bindings):
        """The budget bounds are inclusive: 1 and 600 seconds are both
        accepted and produce a normal completed run."""
        _mock_settings(mock_settings)
        mock_bindings.new_session.return_value = _make_session(*_make_numbered_flaws(2))

        for value in ("1", "600"):
            pages, _entries = _deliver(max_refresh_secs=value)
            data = pages[-1]
            assert data["delivery"]["complete"] is True
            assert data["total_flaws_processed"] == 2

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

    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_changed_after_filters_via_query(self, mock_settings, mock_bindings):
        """changed_after is pushed to the selection query as an updated_dt lower
        bound: the flaw whose updated_dt predates the window is not selected."""
        _mock_settings(mock_settings)

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

        pages, _entries = _deliver(changed_after="2025-06-01T00:00:00")

        data = pages[-1]
        assert data["delivery"]["selected_flaws"] == 1
        assert data["total_flaws_processed"] == 1
        assert data["features"]["impact"]["suggested"] == 1

    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_changed_before_filters_via_query(self, mock_settings, mock_bindings):
        """Same updated_dt selection, upper bound: the flaw whose updated_dt
        postdates the window is not selected."""
        _mock_settings(mock_settings)

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

        pages, _entries = _deliver(changed_before="2025-06-01T00:00:00")

        data = pages[-1]
        assert data["delivery"]["selected_flaws"] == 1
        assert data["total_flaws_processed"] == 1
        assert data["features"]["impact"]["suggested"] == 1

    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_internal_error_returns_500(self, mock_settings, mock_bindings):
        _mock_settings(mock_settings)
        mock_session = MagicMock()
        mock_session.flaws.retrieve_list.side_effect = RuntimeError("boom")
        mock_bindings.new_session.return_value = mock_session

        response = client.get("/api/v1/analysis/kpi/osidb-bot")
        assert response.status_code == 500
        assert "internal error" in response.json()["detail"].lower()
        assert "boom" not in response.json()["detail"]

    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_component_param_scopes_osidb_query(self, mock_settings, mock_bindings):
        """The component query param is pushed to OSIDB as a ``components`` filter
        on the single selection index."""
        _mock_settings(mock_settings)
        session = _make_session()
        mock_bindings.new_session.return_value = session

        response = client.get("/api/v1/analysis/kpi/osidb-bot?component=kernel")
        assert response.status_code == 200

        calls = session.flaws.retrieve_list_iterator.call_args_list
        # The selection index carries the component filter.
        component_calls = [c for c in calls if c.kwargs.get("components") == "kernel"]
        assert component_calls

    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_multiple_flaws_aggregation(self, mock_settings, mock_bindings):
        _mock_settings(mock_settings)

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

        pages, _entries = _deliver()

        data = pages[-1]
        assert data["delivery"]["complete"] is True
        assert data["total_flaws_processed"] == 2
        assert data["features"]["impact"]["suggested"] == 2
        assert data["features"]["impact"]["kept"] == 1
        assert data["features"]["impact"]["modified"] == 1
        assert data["features"]["impact"]["acceptance_rate"] == 50.0


class TestOsidbBotKpiDeliveryEndpoint:
    """The delivery wire contract of GET /api/v1/analysis/kpi/osidb-bot."""

    def test_limit_out_of_range_returns_422(self):
        """limit is constrained to 1..1000 at the API layer: out-of-range
        values are rejected before the handler runs."""
        for limit in ("0", "-1", "1001", "99999"):
            response = client.get(f"/api/v1/analysis/kpi/osidb-bot?limit={limit}")
            assert response.status_code == 422

    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_default_limit_serves_400_flaws_per_page(
        self, mock_settings, mock_bindings
    ):
        """Omitting the limit query parameter serves the documented default of
        400 flaws per page: a 401-flaw selection takes two delivery pages,
        whose accumulated entries cover each flaw exactly once."""
        _mock_settings(mock_settings)
        mock_bindings.new_session.return_value = _make_session(
            *_make_numbered_flaws(401)
        )

        pages, entries = _deliver(detail=True)

        assert len(pages) == 3  # the initial zero page plus two delivery pages
        assert pages[0]["delivery"]["received_flaws"] == 0
        assert pages[0]["entries"] == []
        assert pages[1]["delivery"]["received_flaws"] == 400
        assert pages[1]["delivery"]["complete"] is False
        assert pages[2]["delivery"]["received_flaws"] == 401
        assert pages[2]["delivery"]["complete"] is True
        assert not pages[2]["delivery"]["continue_token"]
        assert pages[2]["total_flaws_processed"] == 401
        assert pages[2]["features"]["impact"]["suggested"] == 401
        assert [e["cve_id"] for e in entries] == [
            f"CVE-2025-{i:04d}" for i in range(1, 402)
        ]

    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_delivery_param_is_ignored_not_an_error(self, mock_settings, mock_bindings):
        """The former delivery=true opt-in is gone: sending it is ignored by
        FastAPI (unknown query parameters never fail validation) and the
        response is still a delivery run."""
        _mock_settings(mock_settings)
        mock_bindings.new_session.return_value = _make_session(*_make_numbered_flaws(2))

        pages, _entries = _deliver(detail=True, delivery="true")

        data = pages[-1]
        assert data["delivery"]["complete"] is True
        assert data["total_flaws_processed"] == 2
