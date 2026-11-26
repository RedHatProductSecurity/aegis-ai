"""Integration tests for the read-only osidb-bot KPI cache-status endpoint."""

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from aegis_ai_web.src.endpoints import bot_kpi
from aegis_ai_web.src.endpoints.bot_kpi import (
    BotKPICacheEntry,
    FlawCacheData,
    get_osidb_bot_cache_status,
)
from aegis_ai_web.src.main import app

client = TestClient(app)

CACHE_STATUS_URL = "/api/v1/analysis/kpi/osidb-bot/cache-status"


@pytest.fixture
def cache_dir(tmp_path, monkeypatch):
    """Per-test KPI cache directory plus a stubbed OSIDB server setting.

    get_settings() is lru-cached and reads AEGIS_BOT_KPI_CACHE_DIR at import
    time, so setting the env var mid-test cannot redirect the cache; the
    settings lookup used by the endpoint module must be patched instead.
    """
    monkeypatch.setattr(
        bot_kpi,
        "get_settings",
        lambda: MagicMock(
            osidb_server_url="https://osidb.example.com",
            bot_kpi_cache_dir=str(tmp_path),
        ),
    )
    return tmp_path


def _index_flaw(cve_id, updated_dt="2026-10-01T00:00:00Z", components=()):
    """A flaw for the OSIDB index mock; ``_components`` is test-only."""
    return {
        "cve_id": cve_id,
        "updated_dt": updated_dt,
        "_components": list(components),
    }


def _cache_entry(updated_dt="2026-10-01T00:00:00Z"):
    # components=[] (not None) marks a post-provenance cache entry, so the
    # entry is judged purely on its watermark.
    return FlawCacheData(updated_dt=updated_dt, components=[])


def _make_session(*flaws):
    """Mock OSIDB session whose index query honors the pushed-down filters
    (updated_dt bounds, component) like the real server, so a test can prove
    the request's filters drive the selection.

    Batch calls (``cve_id=[...]``) return full flaw data for the requested
    IDs; the cache-status endpoint must never issue them, and tests assert
    on the recorded calls to prove it.
    """

    def _aware(dt):
        # The endpoint parses query dates as naive; normalize both sides to
        # UTC so the comparison never mixes naive and aware datetimes.
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
            if component is not None and component not in flaw["_components"]:
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


def _install_osidb_session(monkeypatch, session):
    """Serve ``session`` as the anonymous OSIDB session for bot_kpi calls."""
    bindings = MagicMock()
    bindings.new_session.return_value = session
    monkeypatch.setattr(bot_kpi, "osidb_bindings", bindings)
    return session


def _seed_cache(flaws):
    """Write a cache file through the production handler (uses the patched
    settings, i.e. the fixture's tmp_path)."""
    with bot_kpi._cache_handler() as handler:
        handler.write(BotKPICacheEntry(flaws=flaws))


def _batch_calls(session):
    """Flaw queries made with explicit CVE IDs, i.e. full-data batch fetches."""
    return [
        call
        for call in session.flaws.retrieve_list_iterator.call_args_list
        if "cve_id" in call.kwargs
    ]


def _assert_invariants(data):
    """Every 200 response must satisfy the documented count identities and
    expose the five count fields only (no CVE ID list)."""
    assert set(data) == {
        "total_flaws_selected",
        "fresh_count",
        "stale_count",
        "uncached_count",
        "outdated_count",
    }
    assert data["total_flaws_selected"] == data["fresh_count"] + data["stale_count"]
    assert data["stale_count"] == data["uncached_count"] + data["outdated_count"]
    assert all(value >= 0 for value in data.values())


class TestOsidbBotCacheStatusEndpoint:
    def test_all_fresh_cache_reports_zero_stale(self, cache_dir, monkeypatch):
        _install_osidb_session(
            monkeypatch,
            _make_session(_index_flaw("CVE-2026-0001"), _index_flaw("CVE-2026-0002")),
        )
        _seed_cache(
            {
                # Cached watermarks equal OSIDB's index watermarks.
                "CVE-2026-0001": _cache_entry(),
                "CVE-2026-0002": _cache_entry(),
            }
        )

        response = client.get(CACHE_STATUS_URL)

        assert response.status_code == 200
        data = response.json()
        _assert_invariants(data)
        assert data["total_flaws_selected"] == 2
        assert data["fresh_count"] == 2
        assert data["stale_count"] == 0
        assert data["uncached_count"] == 0
        assert data["outdated_count"] == 0

    def test_cold_cache_reports_every_flaw_uncached(self, cache_dir, monkeypatch):
        _install_osidb_session(
            monkeypatch,
            _make_session(_index_flaw("CVE-2026-0001"), _index_flaw("CVE-2026-0002")),
        )

        response = client.get(CACHE_STATUS_URL)

        assert response.status_code == 200
        data = response.json()
        _assert_invariants(data)
        assert data["total_flaws_selected"] == 2
        assert data["fresh_count"] == 0
        assert data["stale_count"] == 2
        assert data["uncached_count"] == 2
        assert data["outdated_count"] == 0

    def test_corrupt_cache_file_counts_every_flaw_uncached(
        self, cache_dir, monkeypatch
    ):
        _install_osidb_session(monkeypatch, _make_session(_index_flaw("CVE-2026-0001")))
        cache_file = cache_dir / "kpi_cache.json"
        cache_file.write_text("{not valid json")

        response = client.get(CACHE_STATUS_URL)

        assert response.status_code == 200
        data = response.json()
        _assert_invariants(data)
        assert data["uncached_count"] == 1
        assert data["outdated_count"] == 0
        # A corrupt cache is treated as absent, not repaired or overwritten.
        assert cache_file.read_text() == "{not valid json"

    def test_mixed_selection_splits_uncached_and_outdated(self, cache_dir, monkeypatch):
        session = _install_osidb_session(
            monkeypatch,
            _make_session(
                _index_flaw("CVE-2026-0001"),  # fresh: watermark matches cache
                _index_flaw("CVE-2026-0002", updated_dt="2026-11-01T00:00:00Z"),
                _index_flaw("CVE-2026-0003"),  # uncached: no cache entry
            ),
        )
        _seed_cache(
            {
                "CVE-2026-0001": _cache_entry(),
                # Cached watermark behind OSIDB's 2026-11-01: outdated.
                "CVE-2026-0002": _cache_entry(),
                # Cached but outside the selection: must not be counted.
                "CVE-2026-9999": _cache_entry(),
            }
        )

        response = client.get(CACHE_STATUS_URL)

        assert response.status_code == 200
        data = response.json()
        _assert_invariants(data)
        assert data["total_flaws_selected"] == 3
        assert data["fresh_count"] == 1
        assert data["stale_count"] == 2
        assert data["uncached_count"] == 1
        assert data["outdated_count"] == 1
        # Counts only: the response never lists the CVE IDs behind them.
        assert "CVE-" not in response.text
        # Stale flaws must be reported, not refreshed.
        assert _batch_calls(session) == []

    def test_legacy_entry_without_components_is_outdated(self, cache_dir, monkeypatch):
        """A pre-provenance cache entry (components is None) cannot prove it
        matches the current flaw, so it counts as outdated even when its
        watermark equals OSIDB's exactly."""
        _install_osidb_session(monkeypatch, _make_session(_index_flaw("CVE-2026-0001")))
        _seed_cache(
            # components omitted -> None, the legacy marker.
            {"CVE-2026-0001": FlawCacheData(updated_dt="2026-10-01T00:00:00Z")}
        )

        response = client.get(CACHE_STATUS_URL)

        assert response.status_code == 200
        data = response.json()
        _assert_invariants(data)
        assert data["outdated_count"] == 1
        assert data["uncached_count"] == 0
        assert data["fresh_count"] == 0

    def test_malformed_cached_watermark_is_outdated(self, cache_dir, monkeypatch):
        _install_osidb_session(monkeypatch, _make_session(_index_flaw("CVE-2026-0001")))
        _seed_cache({"CVE-2026-0001": _cache_entry("not-a-timestamp")})

        response = client.get(CACHE_STATUS_URL)

        assert response.status_code == 200
        data = response.json()
        _assert_invariants(data)
        assert data["outdated_count"] == 1
        assert data["uncached_count"] == 0

    def test_empty_selection_reports_zero_counts(self, cache_dir, monkeypatch):
        _install_osidb_session(monkeypatch, _make_session())

        response = client.get(CACHE_STATUS_URL)

        assert response.status_code == 200
        data = response.json()
        _assert_invariants(data)
        assert data == {
            "total_flaws_selected": 0,
            "fresh_count": 0,
            "stale_count": 0,
            "uncached_count": 0,
            "outdated_count": 0,
        }

    def test_changed_after_scopes_selection(self, cache_dir, monkeypatch):
        """changed_after is pushed to the selection query as an updated_dt
        lower bound: only flaws updated inside the window are counted."""
        _install_osidb_session(
            monkeypatch,
            _make_session(
                _index_flaw("CVE-2026-0001", updated_dt="2026-05-01T00:00:00Z"),
                _index_flaw("CVE-2026-0002", updated_dt="2026-07-01T00:00:00Z"),
            ),
        )

        response = client.get(CACHE_STATUS_URL + "?changed_after=2026-06-01T00:00:00")

        assert response.status_code == 200
        data = response.json()
        _assert_invariants(data)
        assert data["total_flaws_selected"] == 1
        assert data["uncached_count"] == 1

    def test_changed_before_scopes_selection(self, cache_dir, monkeypatch):
        """changed_before is pushed to the selection query as an updated_dt
        upper bound: only flaws updated before the cutoff are counted."""
        _install_osidb_session(
            monkeypatch,
            _make_session(
                _index_flaw("CVE-2026-0001", updated_dt="2026-05-01T00:00:00Z"),
                _index_flaw("CVE-2026-0002", updated_dt="2026-07-01T00:00:00Z"),
            ),
        )

        response = client.get(CACHE_STATUS_URL + "?changed_before=2026-06-01T00:00:00")

        assert response.status_code == 200
        data = response.json()
        _assert_invariants(data)
        assert data["total_flaws_selected"] == 1
        assert data["uncached_count"] == 1

    def test_component_scopes_selection(self, cache_dir, monkeypatch):
        """The component query param is pushed to OSIDB as a ``components``
        filter on the selection index, so only that component's flaws count."""
        session = _install_osidb_session(
            monkeypatch,
            _make_session(
                _index_flaw("CVE-2026-0001", components=("kernel",)),
                _index_flaw("CVE-2026-0002", components=("curl",)),
            ),
        )

        response = client.get(CACHE_STATUS_URL + "?component=kernel")

        assert response.status_code == 200
        data = response.json()
        _assert_invariants(data)
        assert data["total_flaws_selected"] == 1
        assert data["uncached_count"] == 1
        component_calls = [
            call
            for call in session.flaws.retrieve_list_iterator.call_args_list
            if call.kwargs.get("components") == "kernel"
        ]
        assert component_calls

    def test_inverted_date_range_returns_422(self):
        """changed_after later than changed_before would silently report an
        empty selection instead of surfacing the caller's mistake."""
        response = client.get(
            CACHE_STATUS_URL
            + "?changed_after=2026-06-01T00:00:00&changed_before=2026-01-01T00:00:00"
        )
        assert response.status_code == 422
        assert response.json()["detail"] == (
            "changed_after must be earlier than changed_before."
        )

    def test_invalid_changed_after_returns_422(self):
        response = client.get(CACHE_STATUS_URL + "?changed_after=not-a-date")
        assert response.status_code == 422

    def test_osidb_connection_failure_returns_503(self, cache_dir, monkeypatch):
        bindings = MagicMock()
        bindings.new_session.side_effect = ConnectionError("unreachable")
        monkeypatch.setattr(bot_kpi, "osidb_bindings", bindings)

        response = client.get(CACHE_STATUS_URL)

        assert response.status_code == 503
        assert response.json()["detail"] == "Unable to connect to OSIDB."

    def test_osidb_failure_during_index_query_returns_503(self, cache_dir, monkeypatch):
        session = MagicMock()
        session.flaws.retrieve_list_iterator.side_effect = OSError("connection reset")
        _install_osidb_session(monkeypatch, session)

        response = client.get(CACHE_STATUS_URL)

        assert response.status_code == 503
        assert response.json()["detail"] == "Unable to connect to OSIDB."

    def test_internal_error_returns_500(self, cache_dir, monkeypatch):
        session = MagicMock()
        session.flaws.retrieve_list_iterator.side_effect = RuntimeError("boom")
        _install_osidb_session(monkeypatch, session)

        response = client.get(CACHE_STATUS_URL)

        assert response.status_code == 500
        assert "internal error" in response.json()["detail"].lower()
        assert "boom" not in response.json()["detail"]

    def test_status_does_not_touch_existing_cache_file_even_when_stale(
        self, cache_dir, monkeypatch
    ):
        """The status request must not refresh what it reports on: with a
        stale flaw in the selection, the cache file's bytes and mtime stay
        untouched and no full-data batch fetch is issued."""
        session = _install_osidb_session(
            monkeypatch,
            _make_session(
                # Watermark advanced past the cache: outdated, the tempting
                # case for an unwanted refresh.
                _index_flaw("CVE-2026-0001", updated_dt="2026-11-01T00:00:00Z"),
                _index_flaw("CVE-2026-0002"),
            ),
        )
        _seed_cache(
            {
                "CVE-2026-0001": _cache_entry(),
                "CVE-2026-0002": _cache_entry(),
            }
        )
        cache_file = cache_dir / "kpi_cache.json"
        content_before = cache_file.read_bytes()
        mtime_before = cache_file.stat().st_mtime_ns

        response = client.get(CACHE_STATUS_URL)

        assert response.status_code == 200
        data = response.json()
        _assert_invariants(data)
        assert data["stale_count"] == 1
        assert data["outdated_count"] == 1
        assert cache_file.read_bytes() == content_before
        assert cache_file.stat().st_mtime_ns == mtime_before
        assert _batch_calls(session) == []

    def test_cold_cache_persists_no_cache_data(self, cache_dir, monkeypatch):
        """A status request on a cold cache must not populate it: whatever
        file state remains carries no cache data, and a repeat request still
        reports every flaw as uncached."""
        session = _install_osidb_session(
            monkeypatch, _make_session(_index_flaw("CVE-2026-0001"))
        )
        cache_file = cache_dir / "kpi_cache.json"

        response = client.get(CACHE_STATUS_URL)

        assert response.status_code == 200
        assert response.json()["uncached_count"] == 1
        assert not cache_file.exists() or cache_file.stat().st_size == 0

        repeat = client.get(CACHE_STATUS_URL)

        assert repeat.status_code == 200
        assert repeat.json()["uncached_count"] == 1
        assert _batch_calls(session) == []

    def test_cold_cache_leaves_no_cache_file(self, cache_dir, monkeypatch):
        """A status request must leave a cold cache fully absent: neither the
        cache file nor its not-yet-existing parent directory is created."""
        _install_osidb_session(monkeypatch, _make_session(_index_flaw("CVE-2026-0001")))
        # Point the cache at a directory that does not exist yet, so the test
        # also catches the endpoint creating the directory on a read.
        cold_dir = cache_dir / "bot-kpi-cache"
        monkeypatch.setattr(
            bot_kpi,
            "get_settings",
            lambda: MagicMock(
                osidb_server_url="https://osidb.example.com",
                bot_kpi_cache_dir=str(cold_dir),
            ),
        )

        response = client.get(CACHE_STATUS_URL)

        assert response.status_code == 200
        assert response.json()["uncached_count"] == 1
        assert not cold_dir.exists()

    def test_uses_forwarded_osidb_token(self, cache_dir, monkeypatch):
        bearer_session = MagicMock(return_value=_make_session())
        monkeypatch.setattr(bot_kpi, "BearerOSIDBSession", bearer_session)

        result = get_osidb_bot_cache_status(osidb_token="user-access-token")

        bearer_session.assert_called_once_with(
            "https://osidb.example.com", "user-access-token"
        )
        assert result.total_flaws_selected == 0
        assert result.stale_count == 0
