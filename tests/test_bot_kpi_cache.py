"""Tests for osidb-bot KPI cache orchestration."""

import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aegis_ai_web.src.data_models import BotKPIEntry, BotKPIProgress, BotKPIResponse
from aegis_ai_web.src.endpoints.bot_kpi import (
    OSIDB_BOT_BIRTHDAY,
    BotKPICacheEntry,
    FlawCacheData,
    _cache_handler,
    _fetch_flaw_index,
    _flaw_cache_data,
    _get_cache_path,
    _merge_fetched,
    _needs_fetch,
    _read_cache,
    get_osidb_bot_kpi,
)

_BOT_KPI_MODULE = "aegis_ai_web.src.endpoints.bot_kpi"

_DEFAULT_DT = "2025-06-01T00:00:00+00:00"


def _make_bot_entry(value, *, dq=0.9, conf=0.85, timestamp="2025-03-13T12:00:00"):
    return {
        "type": "AI-Bot",
        "value": value,
        "explanation": "test",
        "timestamp": timestamp,
        "data_quality": dq,
        "confidence": conf,
    }


def _make_flaw_dict(
    aegis_meta, *, cve_id="CVE-2025-0001", updated_dt=_DEFAULT_DT, **overrides
):
    flaw = {
        "cve_id": cve_id,
        "updated_dt": updated_dt,
        "components": [],
        "title": "",
        "cve_description": "",
        "cwe_id": "",
        "impact": "",
        "aegis_meta": aegis_meta,
    }
    flaw.update(overrides)
    return flaw


def _make_session(*flaws, index_delay=0.0, batch_delay=0.0):
    """Build a mock OSIDB session for the two-phase fetch.

    ``flaws`` are full flaw dicts (each with ``cve_id`` + ``updated_dt``). The
    first-phase index iterator yields ``{cve_id, updated_dt}`` stubs; the
    second-phase batch iterator (called with ``cve_id=[...]``) returns full flaw
    data for the requested IDs. This lets tests assert exactly which flaws were
    fetched in full versus served from the cache via the index alone.
    ``batch_delay`` sleeps in each batch fetch so the per-request refresh time
    budget can be exercised deterministically.
    """
    by_cve = {flaw["cve_id"]: flaw for flaw in flaws}

    def _list_iterator(**kwargs):
        if index_delay:
            time.sleep(index_delay)
        requested = kwargs.get("cve_id")
        if requested is not None:
            if batch_delay:
                time.sleep(batch_delay)
            # Second-phase batch fetch: return full flaw data.
            results = []
            for cve_id in requested:
                if cve_id in by_cve:
                    m = MagicMock()
                    m.to_dict.return_value = by_cve[cve_id]
                    results.append(m)
            return iter(results)
        # First-phase index fetch: return lightweight stubs.
        stubs = []
        for flaw in flaws:
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


def _make_component_session(by_component):
    """Mock OSIDB session whose index phase honors the ``components`` filter.

    ``by_component`` maps a component name to the flaws the server would return
    for that filter (mirroring OSIDB's server-side ``components`` filter).
    An index request with no component filter returns every flaw; the batch
    phase returns full data for any requested CVE regardless of component.
    """
    all_flaws = [flaw for flaws in by_component.values() for flaw in flaws]
    by_cve = {flaw["cve_id"]: flaw for flaw in all_flaws}

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
        flaws = by_component.get(component, []) if component else all_flaws
        stubs = []
        for flaw in flaws:
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


def _make_filtering_session(*flaws):
    """Mock OSIDB session whose index honors the ``components`` filter AND the
    ``updated_dt`` bounds, like the real server.

    Each flaw declares its component membership via a test-only ``_components``
    key. The index phase returns only flaws matching the requested component
    (when given) whose ``updated_dt`` falls within any ``updated_dt_gte`` /
    ``updated_dt_lte`` bounds. The batch phase returns full data for requested
    CVEs. This lets a test prove that the request's date range and component are
    pushed to the selection query and scope which flaws are returned.
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
        component = kwargs.get("components")
        gte = kwargs.get("updated_dt_gte")
        lte = kwargs.get("updated_dt_lte")
        stubs = []
        for flaw in flaws:
            if component is not None and component not in flaw.get("_components", []):
                continue
            updated = datetime.fromisoformat(flaw["updated_dt"])
            if gte is not None and updated < gte:
                continue
            if lte is not None and updated > lte:
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


def _seed_cache(cache_path: Path, flaws: dict[str, FlawCacheData]) -> None:
    """Write a per-flaw cache directly from ``FlawCacheData`` entries."""
    entry = BotKPICacheEntry(flaws=flaws)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(entry.model_dump_json())


def _cached_flaw(
    applied=1,
    *,
    cve_id="CVE-2025-0001",
    updated_dt=_DEFAULT_DT,
    suggestion_dt=None,
    current_impact="LOW",
    components=(),
) -> FlawCacheData:
    """Build a compact cache entry with ``applied`` AI-Bot impact suggestions.

    The cache stores compact per-field suggestion records and re-scores them per
    request, so seed the actual suggestion history via the same
    ``_flaw_cache_data`` production uses. The suggestion timestamp defaults to
    the flaw's ``updated_dt`` so date-filter tests that place a flaw at a given
    instant also place its suggestion there.
    """
    ts = suggestion_dt or updated_dt
    entries = [_make_bot_entry("LOW", timestamp=ts) for _ in range(applied)]
    flaw = _make_flaw_dict(
        {"processed": True, "impact": entries},
        impact=current_impact,
        cve_id=cve_id,
        updated_dt=updated_dt,
        components=list(components),
    )
    return _flaw_cache_data(flaw, updated_dt)


def _numbered_flaws(count, *, start=1):
    """Build ``count`` uniformly bot-processed flaws with sortable CVE IDs.

    Every flaw carries one kept impact suggestion and the default watermark, so
    large selections can be generated for pagination tests.
    """
    return [
        _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("LOW")]},
            impact="LOW",
            cve_id=f"CVE-2025-{i:04d}",
        )
        for i in range(start, start + count)
    ]


def _make_ghost_session(real_flaws, ghost_ids):
    """Mock OSIDB session whose index lists CVEs missing from the batch fetch.

    A ghost is a flaw that was deleted in OSIDB between the index query and
    the batch fetch: the index phase still returns its cve_id/updated_dt stub,
    but the batch phase returns nothing for it.
    """
    by_cve = {flaw["cve_id"]: flaw for flaw in real_flaws}
    index = [
        {"cve_id": flaw["cve_id"], "updated_dt": flaw["updated_dt"]}
        for flaw in real_flaws
    ] + [{"cve_id": cve_id, "updated_dt": _DEFAULT_DT} for cve_id in ghost_ids]

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
        for item in index:
            stub = MagicMock()
            stub.to_dict.return_value = dict(item)
            stubs.append(stub)
        return iter(stubs)

    session = MagicMock()
    session.flaws.retrieve_list_iterator.side_effect = _list_iterator
    return session


def _batch_fetches(session):
    """The cve_id sets requested by full-data batch fetches, in call order."""
    return [
        set(call.kwargs["cve_id"])
        for call in session.flaws.retrieve_list_iterator.call_args_list
        if call.kwargs.get("cve_id") is not None
    ]


def _paginate(**kwargs):
    """Drive get_osidb_bot_kpi as a paginating client would: follow
    next_cursor from page to page until the final page. An initial cursor
    may be passed to resume mid-selection."""
    pages = []
    cursor = kwargs.pop("cursor", None)
    for _ in range(100):
        page = get_osidb_bot_kpi(cursor=cursor, **kwargs)
        pages.append(page)
        if page.next_cursor is None:
            return pages
        cursor = page.next_cursor
    raise AssertionError("pagination did not reach a final page")


def _page_progress(page: BotKPIResponse) -> BotKPIProgress:
    """A paginated page's progress block, asserted present."""
    assert page.progress is not None
    return page.progress


def _page_entries(page: BotKPIResponse) -> list[BotKPIEntry]:
    """A detail page's entries, asserted present."""
    assert page.entries is not None
    return page.entries


@pytest.fixture()
def cache_dir(tmp_path, monkeypatch):
    cache_path = tmp_path / "osidb_bot_kpi" / "kpi_cache.json"
    monkeypatch.setattr(
        "aegis_ai_web.src.endpoints.bot_kpi._get_cache_path",
        lambda: cache_path,
    )
    return cache_path


class TestFlawIndexQuery:
    """The index search must be bounded so it never scrapes all OSIDB history."""

    @staticmethod
    def _captured_kwargs(**call_kwargs) -> dict:
        session = MagicMock()
        session.flaws.retrieve_list_iterator.return_value = iter([])
        _fetch_flaw_index(session, **call_kwargs)
        return session.flaws.retrieve_list_iterator.call_args.kwargs

    def test_always_bounds_creation_to_bot_birthday(self):
        kwargs = self._captured_kwargs()
        assert kwargs["created_dt_gte"] == OSIDB_BOT_BIRTHDAY
        assert kwargs["cve_id__isempty"] is False

    def test_pushes_date_bounds_when_given(self):
        # The request's date range drives selection: it is pushed to the index
        # as updated_dt bounds so the query returns exactly the selected flaws.
        after = datetime(2025, 6, 1, tzinfo=UTC)
        before = datetime(2025, 7, 1, tzinfo=UTC)
        kwargs = self._captured_kwargs(changed_after=after, changed_before=before)
        assert kwargs["updated_dt_gte"] == after
        assert kwargs["updated_dt_lte"] == before

    def test_no_date_bounds_when_absent(self):
        kwargs = self._captured_kwargs()
        assert "updated_dt_gte" not in kwargs
        assert "updated_dt_lte" not in kwargs

    def test_pushes_component_as_components_filter(self):
        kwargs = self._captured_kwargs(component="kernel")
        assert kwargs["created_dt_gte"] == OSIDB_BOT_BIRTHDAY
        # Filter on the flaw-level ``components`` field the KPI scores against,
        # not the affects-level ps_component.
        assert kwargs["components"] == "kernel"
        assert "affects__ps_component" not in kwargs

    def test_no_component_filter_when_absent(self):
        kwargs = self._captured_kwargs()
        assert "components" not in kwargs


class TestGetCachePath:
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_defaults_to_config_dir(self, mock_settings, tmp_path):
        mock_settings.return_value.bot_kpi_cache_dir = ""
        mock_settings.return_value.config_dir = str(tmp_path)
        path = _get_cache_path()
        assert path.name == "kpi_cache.json"
        assert "osidb_bot_kpi" in path.parts

    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_uses_setting_when_set(self, mock_settings, tmp_path):
        mock_settings.return_value.bot_kpi_cache_dir = str(tmp_path / "custom")
        path = _get_cache_path()
        assert path == tmp_path / "custom" / "kpi_cache.json"


class TestCacheIO:
    def test_load_nonexistent_returns_none(self, cache_dir):
        assert _read_cache() is None

    def test_save_and_load_round_trip(self, cache_dir):
        entry = BotKPICacheEntry(
            flaws={
                "CVE-2025-0001": _cached_flaw(applied=3),
            }
        )
        with _cache_handler() as handler:
            handler.write(entry)
        loaded = _read_cache()
        assert loaded is not None
        assert loaded.total_flaws_processed == 1
        # The impact field was re-suggested 3 times on one flaw, counted once.
        assert loaded.to_kpi_result().features["impact"].suggested == 1

    def test_corrupt_cache_returns_none(self, cache_dir):
        cache_dir.parent.mkdir(parents=True, exist_ok=True)
        cache_dir.write_text("not valid json {{{")
        assert _read_cache() is None

    def test_old_schema_cache_returns_none(self, cache_dir):
        """A cache file from before the per-flaw schema (flat aggregate sums
        + a seen-IDs list, no `flaws` key) fails validation and is treated as
        absent, so the next request simply re-fetches from OSIDB."""
        import json

        old_format_json = json.dumps(
            {
                "cutoff": "2025-07-01T12:00:00Z",
                "total_flaws_processed": 10,
                "features": {"impact": {"applied": 5, "kept": 3}},
                "flaw_ids": ["CVE-2025-0001"],
            }
        )
        cache_dir.parent.mkdir(parents=True, exist_ok=True)
        cache_dir.write_text(old_format_json)
        assert _read_cache() is None

    def test_previous_raw_flaw_schema_cache_returns_none(self, cache_dir):
        """A cache from the prior schema that stored the whole raw flaw under a
        ``flaw`` key must fail validation (not parse as an empty entry), so it is
        treated as absent and cleanly re-fetched rather than silently
        undercounting until every flaw's watermark advances."""
        import json

        raw_flaw_json = json.dumps(
            {
                "flaws": {
                    "CVE-2025-0001": {
                        "updated_dt": "2025-06-01T00:00:00+00:00",
                        "bot_processed": True,
                        "flaw": {
                            "cve_id": "CVE-2025-0001",
                            "impact": "LOW",
                            "aegis_meta": {
                                "processed": True,
                                "impact": [{"type": "AI-Bot", "value": "LOW"}],
                            },
                        },
                    }
                }
            }
        )
        cache_dir.parent.mkdir(parents=True, exist_ok=True)
        cache_dir.write_text(raw_flaw_json)
        assert _read_cache() is None


class TestMergeFetched:
    """``_merge_fetched`` applies fetched entries onto the live cache per CVE,
    without discarding concurrent writes it never observed and without evicting
    unselected entries."""

    def test_applies_fetched_and_keeps_concurrent_insert(self):
        # This request indexed an empty cache (snapshot == {}) and fetched flaw
        # A; a concurrent request has since written flaw B into the live cache.
        # Both must survive -- selection never evicts.
        snapshot: dict[str, FlawCacheData] = {}
        existing = {"CVE-B": _cached_flaw()}  # concurrent insert
        fetched = {"CVE-A": _cached_flaw()}

        merged = _merge_fetched(existing, fetched, snapshot)

        assert set(merged) == {"CVE-A", "CVE-B"}

    def test_does_not_evict_unselected_cached_flaw(self):
        # Flaw A is cached but not in this request's fetched set; it is retained,
        # not pruned -- a narrow request never drops another selection's flaws.
        snapshot = {"CVE-A": _cached_flaw()}
        existing = {"CVE-A": _cached_flaw()}
        fetched: dict[str, FlawCacheData] = {}

        merged = _merge_fetched(existing, fetched, snapshot)

        assert set(merged) == {"CVE-A"}

    def test_stale_fetch_does_not_clobber_newer_concurrent_write(self):
        # We fetched flaw A at an old watermark; a concurrent request has since
        # written a newer watermark. Our stale fetch must not overwrite it.
        old = "2025-05-01T00:00:00+00:00"
        new = "2025-07-01T00:00:00+00:00"
        snapshot = {"CVE-A": _cached_flaw(updated_dt=old)}
        existing = {"CVE-A": _cached_flaw(updated_dt=new)}  # concurrent update
        fetched = {"CVE-A": _cached_flaw(updated_dt=old)}

        merged = _merge_fetched(existing, fetched, snapshot)

        assert merged["CVE-A"].updated_dt == new

    def test_newer_fetch_replaces_older_concurrent_write(self):
        old = "2025-05-01T00:00:00+00:00"
        new = "2025-07-01T00:00:00+00:00"
        snapshot = {"CVE-A": _cached_flaw(updated_dt=old)}
        existing = {"CVE-A": _cached_flaw(updated_dt="2025-06-01T00:00:00+00:00")}
        fetched = {"CVE-A": _cached_flaw(updated_dt=new)}

        merged = _merge_fetched(existing, fetched, snapshot)

        assert merged["CVE-A"].updated_dt == new


class TestNeedsFetch:
    def test_fetches_when_osidb_watermark_is_newer(self):
        cached = _cached_flaw(updated_dt="2025-06-01T00:00:00+00:00")
        assert _needs_fetch(cached, "2025-07-01T00:00:00+00:00")

    def test_does_not_fetch_when_cache_watermark_is_newer(self):
        cached = _cached_flaw(updated_dt="2025-07-01T00:00:00+00:00")
        assert not _needs_fetch(cached, "2025-06-01T00:00:00+00:00")

    def test_does_not_fetch_when_watermarks_match(self):
        cached = _cached_flaw(updated_dt="2025-06-01T00:00:00+00:00")
        assert not _needs_fetch(cached, "2025-06-01T00:00:00+00:00")


class TestGetOsidbBotKpiCaching:
    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_first_request_no_cache(self, mock_settings, mock_bindings, cache_dir):
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_settings.return_value.config_dir = str(cache_dir.parent.parent)

        flaw_data = _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("LOW")]},
            impact="LOW",
        )
        mock_bindings.new_session.return_value = _make_session(flaw_data)

        response = get_osidb_bot_kpi()
        assert response.total_flaws_processed == 1
        assert response.features["impact"].kept == 1

        assert cache_dir.is_file()
        cached = BotKPICacheEntry.model_validate_json(cache_dir.read_text())
        assert cached.total_flaws_processed == 1

    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_incremental_only_fetches_changed_flaws(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """An unchanged cached flaw is served from the index alone; only the
        new flaw's full data is fetched via retrieve()."""
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_settings.return_value.config_dir = str(cache_dir.parent.parent)

        _seed_cache(cache_dir, {"CVE-2025-0001": _cached_flaw(applied=1)})

        cached_flaw = _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("LOW")]},
            impact="LOW",
            cve_id="CVE-2025-0001",
        )
        new_flaw = _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("MODERATE")]},
            impact="MODERATE",
            cve_id="CVE-2025-0002",
            updated_dt="2025-07-01T00:00:00+00:00",
        )
        session = _make_session(cached_flaw, new_flaw)
        mock_bindings.new_session.return_value = session

        response = get_osidb_bot_kpi()
        assert response.total_flaws_processed == 2
        assert response.features["impact"].suggested == 2

        # Only the new flaw is fetched in full; the unchanged one is not.
        # The second retrieve_list_iterator call is the batch fetch.
        batch_call = session.flaws.retrieve_list_iterator.call_args_list[1]
        assert set(batch_call.kwargs["cve_id"]) == {"CVE-2025-0002"}

    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_date_filter_selects_subset_via_query_without_altering_cache(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """The date range is pushed to the OSIDB query as updated_dt bounds, so
        only in-window flaws are selected. Selected flaws already cached at the
        same watermark are served from the cache without a re-fetch or a write."""
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_settings.return_value.config_dir = str(cache_dir.parent.parent)

        _seed_cache(
            cache_dir,
            {
                "CVE-2025-0001": _cached_flaw(updated_dt="2025-05-01T00:00:00+00:00"),
                "CVE-2025-0002": _cached_flaw(updated_dt="2025-07-01T00:00:00+00:00"),
            },
        )
        cached_json_before = cache_dir.read_text()

        # The filtering session honors updated_dt bounds like the real server, so
        # changed_after=June selects only the July flaw.
        session = _make_filtering_session(
            _make_flaw_dict(
                {"processed": True, "impact": [_make_bot_entry("LOW")]},
                cve_id="CVE-2025-0001",
                updated_dt="2025-05-01T00:00:00+00:00",
            ),
            _make_flaw_dict(
                {"processed": True, "impact": [_make_bot_entry("LOW")]},
                cve_id="CVE-2025-0002",
                updated_dt="2025-07-01T00:00:00+00:00",
            ),
        )
        mock_bindings.new_session.return_value = session

        response = get_osidb_bot_kpi(changed_after=datetime(2025, 6, 1, tzinfo=UTC))
        assert response.total_flaws_processed == 1

        # Only the index call; the selected flaw is already cached, so no batch.
        assert session.flaws.retrieve_list_iterator.call_count == 1
        assert cache_dir.read_text() == cached_json_before

    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_corrupt_cache_falls_back_to_full_query(
        self, mock_settings, mock_bindings, cache_dir
    ):
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_settings.return_value.config_dir = str(cache_dir.parent.parent)

        cache_dir.parent.mkdir(parents=True, exist_ok=True)
        cache_dir.write_text("corrupted data!!!")

        flaw_data = _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("LOW")]},
            impact="LOW",
        )
        mock_bindings.new_session.return_value = _make_session(flaw_data)

        response = get_osidb_bot_kpi()
        assert response.total_flaws_processed == 1
        assert response.features["impact"].kept == 1

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_unchanged_flaw_is_not_refetched(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """A cached flaw whose watermark is unchanged is neither re-fetched nor
        double-counted, and the cache file is left untouched."""
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_settings.return_value.config_dir = str(cache_dir.parent.parent)

        _seed_cache(cache_dir, {"CVE-2025-0001": _cached_flaw(applied=1)})
        cached_json_before = cache_dir.read_text()

        session = _make_session(
            _make_flaw_dict(
                {"processed": True, "impact": [_make_bot_entry("LOW")]},
                cve_id="CVE-2025-0001",
            )
        )
        mock_bindings.new_session.return_value = session

        response = get_osidb_bot_kpi()
        assert response.total_flaws_processed == 1
        assert response.features["impact"].suggested == 1
        assert response.features["impact"].kept == 1

        # Only the index call; no batch fetch for unchanged flaws.
        assert session.flaws.retrieve_list_iterator.call_count == 1
        # No change means no write, so the cache file is left untouched.
        assert cache_dir.read_text() == cached_json_before

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_reseen_flaw_with_advanced_watermark_is_rescored_not_frozen(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """Regression test for the staleness bug: a flaw whose updated_dt
        advanced since it was cached (e.g. an analyst edited it after the bot's
        initial pass) must be re-fetched and re-scored using the new value, not
        permanently frozen at its first-seen classification."""
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_settings.return_value.config_dir = str(cache_dir.parent.parent)

        _seed_cache(
            cache_dir,
            {"CVE-2025-0001": _cached_flaw(updated_dt="2025-06-01T00:00:00+00:00")},
        )

        # Bot suggested LOW and it was initially kept; an analyst has since
        # changed the flaw's impact to MODERATE, bumping its watermark.
        edited_flaw = _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("LOW")]},
            impact="MODERATE",
            cve_id="CVE-2025-0001",
            updated_dt="2025-08-01T00:00:00+00:00",
        )
        mock_bindings.new_session.return_value = _make_session(edited_flaw)

        response = get_osidb_bot_kpi()
        assert response.total_flaws_processed == 1
        assert response.features["impact"].suggested == 1
        assert response.features["impact"].kept == 0
        assert response.features["impact"].modified == 1

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_non_bot_processed_flaw_cached_as_skip_marker(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """A DONE flaw with no bot suggestions is cached as a skip marker so its
        full data isn't re-fetched next time, and it doesn't inflate the KPI."""
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_settings.return_value.config_dir = str(cache_dir.parent.parent)

        processed = _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("LOW")]},
            impact="LOW",
            cve_id="CVE-2025-0001",
        )
        not_processed = _make_flaw_dict(
            {"processed": False},
            cve_id="CVE-2025-0002",
        )
        session = _make_session(processed, not_processed)
        mock_bindings.new_session.return_value = session

        response = get_osidb_bot_kpi()
        assert response.total_flaws_processed == 1
        assert response.features["impact"].suggested == 1

        cached = BotKPICacheEntry.model_validate_json(cache_dir.read_text())
        assert set(cached.flaws) == {"CVE-2025-0001", "CVE-2025-0002"}
        assert cached.flaws["CVE-2025-0002"].bot_processed is False
        assert cached.total_flaws_processed == 1

        # A second request must not re-fetch the skip-marked flaw.
        session.flaws.retrieve_list_iterator.reset_mock()
        get_osidb_bot_kpi()
        # Only the index call; no batch fetch for unchanged flaws.
        assert session.flaws.retrieve_list_iterator.call_count == 1

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_flaw_absent_from_index_is_not_selected_nor_evicted(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """A cached flaw absent from the selection index (it left DONE, or falls
        outside the request's window) is simply not counted. Selection never
        evicts, so its cache entry is retained for a later request that does
        select it."""
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_settings.return_value.config_dir = str(cache_dir.parent.parent)

        _seed_cache(
            cache_dir,
            {
                "CVE-2025-0001": _cached_flaw(),
                "CVE-2025-0002": _cached_flaw(),
            },
        )

        # The index lists only CVE-2025-0001; CVE-2025-0002 is not selected.
        session = _make_session(
            _make_flaw_dict(
                {"processed": True, "impact": [_make_bot_entry("LOW")]},
                cve_id="CVE-2025-0001",
            )
        )
        mock_bindings.new_session.return_value = session

        response = get_osidb_bot_kpi()

        # Only the selected flaw is counted...
        assert response.total_flaws_processed == 1
        # ...but the unselected flaw is retained in the cache, not pruned.
        cached = BotKPICacheEntry.model_validate_json(cache_dir.read_text())
        assert set(cached.flaws) == {"CVE-2025-0001", "CVE-2025-0002"}

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_refetch_bot_to_non_bot_transition_stops_counting(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """A previously bot-processed flaw whose watermark advanced and is now
        un-processed must overwrite its old records with a skip marker and stop
        contributing, rather than staying frozen at its bot-processed state."""
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_settings.return_value.config_dir = str(cache_dir.parent.parent)

        _seed_cache(
            cache_dir,
            {"CVE-2025-0001": _cached_flaw(updated_dt="2025-06-01T00:00:00+00:00")},
        )

        # Same flaw, watermark advanced, no longer bot-processed.
        unprocessed = _make_flaw_dict(
            {"processed": False},
            cve_id="CVE-2025-0001",
            updated_dt="2025-08-01T00:00:00+00:00",
        )
        mock_bindings.new_session.return_value = _make_session(unprocessed)

        response = get_osidb_bot_kpi()
        assert response.total_flaws_processed == 0
        assert response.features == {}

        cached = BotKPICacheEntry.model_validate_json(cache_dir.read_text())
        assert cached.flaws["CVE-2025-0001"].bot_processed is False

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_disjoint_date_ranges_do_not_evict_each_other(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """Querying two non-overlapping date ranges in turn must not flush each
        other's flaws from the shared cache.

        Each request's index is date-scoped (updated_dt bounds pushed to the
        query), so range A selects only flaw A and range B only flaw B. Selection
        never evicts, so flaw A remains cached after range B's request, and a
        repeat of range A is served from the cache without a re-fetch.
        """
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_settings.return_value.config_dir = str(cache_dir.parent.parent)

        range_a = (datetime(2026, 8, 23, tzinfo=UTC), datetime(2026, 8, 26, tzinfo=UTC))
        range_b = (datetime(2026, 8, 27, tzinfo=UTC), datetime(2026, 8, 30, tzinfo=UTC))

        flaw_a = _make_flaw_dict(
            {
                "processed": True,
                "impact": [_make_bot_entry("LOW", timestamp="2026-08-24T10:00:00")],
            },
            impact="LOW",
            cve_id="CVE-2026-0001",
            updated_dt="2026-08-24T10:00:00+00:00",
        )
        flaw_b = _make_flaw_dict(
            {
                "processed": True,
                "impact": [_make_bot_entry("LOW", timestamp="2026-08-28T10:00:00")],
            },
            impact="LOW",
            cve_id="CVE-2026-0002",
            updated_dt="2026-08-28T10:00:00+00:00",
        )

        # A fresh session per request; the filtering session honors updated_dt
        # bounds, so each range selects only its own flaw.
        session_a1 = _make_filtering_session(flaw_a, flaw_b)
        session_b = _make_filtering_session(flaw_a, flaw_b)
        session_a2 = _make_filtering_session(flaw_a, flaw_b)
        mock_bindings.new_session.side_effect = [session_a1, session_b, session_a2]

        # 1. Range A selects and fetches only flaw A.
        response_a = get_osidb_bot_kpi(
            changed_after=range_a[0], changed_before=range_a[1]
        )
        assert response_a.total_flaws_processed == 1
        # 2. Range B selects only flaw B; it must not evict flaw A.
        get_osidb_bot_kpi(changed_after=range_b[0], changed_before=range_b[1])

        cached = BotKPICacheEntry.model_validate_json(cache_dir.read_text())
        assert set(cached.flaws) == {"CVE-2026-0001", "CVE-2026-0002"}

        # 3. Range A again: flaw A still cached, so only the index is queried --
        # no full re-fetch.
        response = get_osidb_bot_kpi(
            changed_after=range_a[0], changed_before=range_a[1]
        )
        assert response.total_flaws_processed == 1
        assert session_a2.flaws.retrieve_list_iterator.call_count == 1

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_component_query_scopes_result_and_retains_cache(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """A component-scoped request counts only that component's flaws and, like
        a date filter, never prunes the shared cache of other components' flaws."""
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_settings.return_value.config_dir = str(cache_dir.parent.parent)

        _seed_cache(
            cache_dir,
            {
                "CVE-2025-0001": _cached_flaw(),  # kernel
                "CVE-2025-0002": _cached_flaw(),  # a different component
            },
        )
        cached_json_before = cache_dir.read_text()

        # The single selection query carries the ``components`` filter, so OSIDB
        # returns only the kernel flaw; it is cached at the same watermark, so no
        # re-fetch or write occurs.
        kernel_flaw = _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("LOW")]},
            cve_id="CVE-2025-0001",
        )
        other_flaw = _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("LOW")]},
            cve_id="CVE-2025-0002",
        )
        session = _make_component_session(
            {"kernel": [kernel_flaw], "other": [other_flaw]}
        )
        mock_bindings.new_session.return_value = session

        response = get_osidb_bot_kpi(component="kernel")

        # Only the kernel flaw is counted, even though both are cached...
        assert response.total_flaws_processed == 1
        # ...and the other component's flaw is retained (component filtering only
        # selects which flaws to score, it never prunes the shared cache).
        cached = BotKPICacheEntry.model_validate_json(cache_dir.read_text())
        assert set(cached.flaws) == {"CVE-2025-0001", "CVE-2025-0002"}
        assert cache_dir.read_text() == cached_json_before

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_component_and_date_select_by_updated_dt_via_query(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """A component + date query composes both filters in the selection query
        and scopes dates by the flaw's ``updated_dt``. Of two kernel flaws, only
        the one whose updated_dt falls in the window is selected and counted."""
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_settings.return_value.config_dir = str(cache_dir.parent.parent)

        may_flaw = _make_flaw_dict(
            {
                "processed": True,
                "impact": [_make_bot_entry("LOW", timestamp="2025-05-15T00:00:00")],
            },
            impact="LOW",
            cve_id="CVE-2025-0001",
            updated_dt="2025-05-15T00:00:00+00:00",
        )
        may_flaw["_components"] = ["kernel"]
        july_flaw = _make_flaw_dict(
            {
                "processed": True,
                "impact": [_make_bot_entry("LOW", timestamp="2025-07-15T00:00:00")],
            },
            impact="LOW",
            cve_id="CVE-2025-0002",
            updated_dt="2025-07-15T00:00:00+00:00",
        )
        july_flaw["_components"] = ["kernel"]
        mock_bindings.new_session.return_value = _make_filtering_session(
            may_flaw, july_flaw
        )

        response = get_osidb_bot_kpi(
            component="kernel", changed_after=datetime(2025, 6, 1, tzinfo=UTC)
        )
        # Only the July flaw (updated_dt in window) is selected; the May flaw is
        # excluded by the query's updated_dt lower bound.
        assert response.total_flaws_processed == 1
        assert response.features["impact"].suggested == 1

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_concurrent_requests_do_not_corrupt_cache(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """Regression test: concurrent requests must not race on the cache's
        read-modify-write cycle and clobber each other's results."""
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_settings.return_value.config_dir = str(cache_dir.parent.parent)

        flaws = [
            _make_flaw_dict(
                {"processed": True, "impact": [_make_bot_entry("LOW")]},
                impact="LOW",
                cve_id="CVE-2025-0001",
            ),
            _make_flaw_dict(
                {"processed": True, "impact": [_make_bot_entry("LOW")]},
                impact="LOW",
                cve_id="CVE-2025-0002",
            ),
        ]
        # Both requests hit the same OSIDB, so both see the full two-flaw index;
        # the index delay forces their read-modify-write cycles to overlap.
        mock_bindings.new_session.side_effect = lambda **kwargs: _make_session(
            *flaws, index_delay=0.05
        )

        responses = []

        def run_and_collect():
            responses.append(get_osidb_bot_kpi())

        threads = [threading.Thread(target=run_and_collect) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # The lock serializes the writes; neither response should be corrupted
        # and both must see the complete two-flaw result.
        assert len(responses) == 2
        assert [r.total_flaws_processed for r in responses] == [2, 2]
        for response in responses:
            assert (
                response.features["impact"].suggested == response.total_flaws_processed
            )

        cached = BotKPICacheEntry.model_validate_json(cache_dir.read_text())
        assert cached.total_flaws_processed == 2
        assert set(cached.flaws.keys()) == {"CVE-2025-0001", "CVE-2025-0002"}


class TestGetOsidbBotKpiPagination:
    """The paginated contract of get_osidb_bot_kpi.

    The selection is served in ``limit``-sized pages of sorted CVE IDs: each
    intermediate page refreshes only its own slice, carries placeholder
    aggregates, its own ``entries`` slice, a ``progress`` block over the whole
    selection, and the ``next_cursor`` to continue from; the final page adds
    the complete aggregate. A client that follows the cursor and concatenates
    ``entries`` ends with exactly one copy of every selected flaw's records.
    """

    def _mock_settings(self, mock_settings, cache_dir, *, budget=60):
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_settings.return_value.config_dir = str(cache_dir.parent.parent)
        # A MagicMock budget makes the deadline comparison raise TypeError on
        # any page needing a second batch, so always pin a real int.
        mock_settings.return_value.bot_kpi_max_refresh_seconds = budget

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_pages_slice_sorted_selection_with_placeholder_aggregates(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """Intermediate pages carry placeholders (0 / {}), their own entries
        slice, progress over the whole selection, and next_cursor; the final
        page carries the complete aggregate but still only its own slice."""
        self._mock_settings(mock_settings, cache_dir)

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
            _make_flaw_dict(
                {"processed": True, "impact": [_make_bot_entry("MODERATE")]},
                impact="IMPORTANT",
                cve_id="CVE-2025-0003",
                components=["kernel"],
            ),
            _make_flaw_dict(
                {"processed": True, "impact": [_make_bot_entry("LOW")]},
                impact="LOW",
                cve_id="CVE-2025-0004",
                components=["firefox"],
            ),
            _make_flaw_dict(
                {"processed": True, "impact": [_make_bot_entry("LOW")]},
                impact="MODERATE",
                cve_id="CVE-2025-0005",
                components=["kernel"],
            ),
        ]
        session = _make_session(*flaws)
        mock_bindings.new_session.return_value = session

        page1 = get_osidb_bot_kpi(detail=True, limit=2)
        assert page1.total_flaws_processed == 0
        assert page1.features == {}
        assert page1.next_cursor == "CVE-2025-0002"
        assert _page_progress(page1).selected_flaws == 5
        assert _page_progress(page1).refreshed_flaws == 2
        assert _page_progress(page1).complete is False
        assert page1.available_components is None
        assert {e.cve_id for e in _page_entries(page1)} == {
            "CVE-2025-0001",
            "CVE-2025-0002",
        }

        page2 = get_osidb_bot_kpi(detail=True, limit=2, cursor="CVE-2025-0002")
        assert page2.next_cursor == "CVE-2025-0004"
        assert _page_progress(page2).refreshed_flaws == 4
        assert _page_progress(page2).complete is False
        assert {e.cve_id for e in _page_entries(page2)} == {
            "CVE-2025-0003",
            "CVE-2025-0004",
        }

        page3 = get_osidb_bot_kpi(detail=True, limit=2, cursor="CVE-2025-0004")
        assert page3.next_cursor is None
        assert _page_progress(page3).complete is True
        # The final page carries the aggregate over the whole selection...
        assert page3.total_flaws_processed == 5
        assert page3.features["impact"].suggested == 5
        assert page3.features["impact"].kept == 3
        assert page3.features["impact"].modified == 2
        assert page3.available_components == ["firefox", "kernel", "openssl"]
        # ...but only its own slice of entries, so accumulating clients don't
        # double-count the final page.
        assert {e.cve_id for e in _page_entries(page3)} == {"CVE-2025-0005"}

        # Client accumulation invariant: every selected flaw's records appear
        # exactly once across the concatenated pages.
        accumulated = [e for page in (page1, page2, page3) for e in _page_entries(page)]
        assert len(accumulated) == 5
        assert {e.cve_id for e in accumulated} == {
            f"CVE-2025-{i:04d}" for i in range(1, 6)
        }

        # Each request refreshed only its own page's stale flaws.
        assert _batch_fetches(session) == [
            {"CVE-2025-0001", "CVE-2025-0002"},
            {"CVE-2025-0003", "CVE-2025-0004"},
            {"CVE-2025-0005"},
        ]

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_default_limit_slices_400_flaws(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """Omitting limit serves the documented default of 400 flaws per page:
        a 401-flaw selection takes two requests, the first ending at flaw
        #400."""
        self._mock_settings(mock_settings, cache_dir)
        session = _make_session(*_numbered_flaws(401))
        mock_bindings.new_session.return_value = session

        page1 = get_osidb_bot_kpi()
        assert page1.next_cursor == "CVE-2025-0400"
        assert _page_progress(page1).selected_flaws == 401
        assert _page_progress(page1).refreshed_flaws == 400
        assert _page_progress(page1).complete is False
        assert page1.total_flaws_processed == 0

        page2 = get_osidb_bot_kpi(cursor="CVE-2025-0400")
        assert page2.next_cursor is None
        assert _page_progress(page2).complete is True
        assert page2.total_flaws_processed == 401
        assert page2.features["impact"].suggested == 401

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_time_budget_defers_remainder_to_later_requests(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """When the refresh budget trips mid-page, only the fetched prefix is
        delivered and the cursor stops at the last delivered flaw; the
        remainder is picked up by later page requests. At least one batch
        always runs, so progress cannot stall."""
        self._mock_settings(mock_settings, cache_dir, budget=0)
        session = _make_session(*_numbered_flaws(250), batch_delay=0.05)
        mock_bindings.new_session.return_value = session

        page1 = get_osidb_bot_kpi(detail=True, limit=250)
        assert page1.next_cursor == "CVE-2025-0100"
        assert _page_progress(page1).selected_flaws == 250
        assert _page_progress(page1).refreshed_flaws == 100
        assert _page_progress(page1).complete is False
        assert page1.total_flaws_processed == 0
        assert {e.cve_id for e in _page_entries(page1)} == {
            f"CVE-2025-{i:04d}" for i in range(1, 101)
        }

        page2 = get_osidb_bot_kpi(detail=True, limit=250, cursor="CVE-2025-0100")
        assert page2.next_cursor == "CVE-2025-0200"
        assert _page_progress(page2).refreshed_flaws == 200
        assert _page_progress(page2).complete is False
        assert {e.cve_id for e in _page_entries(page2)} == {
            f"CVE-2025-{i:04d}" for i in range(101, 201)
        }

        page3 = get_osidb_bot_kpi(detail=True, limit=250, cursor="CVE-2025-0200")
        assert page3.next_cursor is None
        assert _page_progress(page3).complete is True
        assert page3.total_flaws_processed == 250
        assert {e.cve_id for e in _page_entries(page3)} == {
            f"CVE-2025-{i:04d}" for i in range(201, 251)
        }

        # One batch per request even with an exhausted budget: the first batch
        # always runs (so every request makes progress), the budget stops the
        # rest.
        assert _batch_fetches(session) == [
            {f"CVE-2025-{i:04d}" for i in range(1, 101)},
            {f"CVE-2025-{i:04d}" for i in range(101, 201)},
            {f"CVE-2025-{i:04d}" for i in range(201, 251)},
        ]

        accumulated = [e for page in (page1, page2, page3) for e in _page_entries(page)]
        assert len(accumulated) == 250
        assert {e.cve_id for e in accumulated} == {
            f"CVE-2025-{i:04d}" for i in range(1, 251)
        }

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_budget_delivers_only_contiguous_fresh_prefix(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """A flaw that is already fresh but sorts after an unrefreshed flaw
        must wait for a later page: delivering past a stale flaw would place
        the cursor beyond it and skip it forever."""
        self._mock_settings(mock_settings, cache_dir, budget=0)
        session = _make_session(*_numbered_flaws(103), batch_delay=0.05)
        mock_bindings.new_session.return_value = session

        # The selection's last flaw is already fresh in the cache.
        _seed_cache(cache_dir, {"CVE-2025-0103": _cached_flaw(cve_id="CVE-2025-0103")})

        page1 = get_osidb_bot_kpi(detail=True, limit=200)
        assert page1.next_cursor == "CVE-2025-0100"
        # 100 flaws refreshed this request + the 1 already-fresh one.
        assert _page_progress(page1).refreshed_flaws == 101
        assert _page_progress(page1).complete is False
        assert {e.cve_id for e in _page_entries(page1)} == {
            f"CVE-2025-{i:04d}" for i in range(1, 101)
        }

        # The already-fresh last flaw is delivered by a later page, exactly
        # once, once the stale gap before it has been refreshed.
        pages = _paginate(detail=True, limit=200, cursor=page1.next_cursor)
        final = pages[-1]
        assert final.next_cursor is None
        assert _page_progress(final).complete is True
        assert final.total_flaws_processed == 103

        accumulated = [e for page in (page1, *pages) for e in _page_entries(page)]
        assert len(accumulated) == 103
        assert {e.cve_id for e in accumulated} == {
            f"CVE-2025-{i:04d}" for i in range(1, 104)
        }

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_flaw_vanishing_after_index_is_tombstoned_not_blocking(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """A flaw present in the index but absent from the batch fetch
        (deleted in OSIDB in between) is cached as a non-bot-processed skip
        marker at the indexed watermark: it contributes no entries, never
        blocks completion, and is not re-fetched on later requests."""
        self._mock_settings(mock_settings, cache_dir)

        real = _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("LOW")]},
            impact="LOW",
            cve_id="CVE-2025-0001",
        )
        session = _make_ghost_session([real], ghost_ids=["CVE-2025-0002"])
        mock_bindings.new_session.return_value = session

        page = get_osidb_bot_kpi(detail=True)
        assert page.total_flaws_processed == 1
        assert page.next_cursor is None
        assert _page_progress(page).selected_flaws == 2
        assert _page_progress(page).refreshed_flaws == 2
        assert _page_progress(page).complete is True
        assert [e.cve_id for e in _page_entries(page)] == ["CVE-2025-0001"]

        cached = BotKPICacheEntry.model_validate_json(cache_dir.read_text())
        ghost = cached.flaws["CVE-2025-0002"]
        assert ghost.bot_processed is False
        assert ghost.updated_dt == _DEFAULT_DT

        # The tombstone is fresh: a repeat request is served warm with no
        # batch fetch, so the vanished flaw cannot stall pagination.
        session.flaws.retrieve_list_iterator.reset_mock()
        warm = get_osidb_bot_kpi(detail=True)
        assert warm.progress is None
        assert warm.total_flaws_processed == 1
        assert session.flaws.retrieve_list_iterator.call_count == 1

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_fully_cached_selection_without_cursor_is_legacy_single_page(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """When every selected flaw is fresh in the cache and no cursor was
        passed, the response is the pre-pagination shape: no progress block,
        no cursor, the full aggregate and every entry in one response."""
        self._mock_settings(mock_settings, cache_dir)

        _seed_cache(
            cache_dir,
            {
                f"CVE-2025-{i:04d}": _cached_flaw(
                    cve_id=f"CVE-2025-{i:04d}", components=("kernel",)
                )
                for i in (1, 2, 3)
            },
        )
        cached_json_before = cache_dir.read_text()
        session = _make_session(*_numbered_flaws(3))
        mock_bindings.new_session.return_value = session

        response = get_osidb_bot_kpi(detail=True)
        assert response.progress is None
        assert response.next_cursor is None
        assert response.total_flaws_processed == 3
        assert response.features["impact"].suggested == 3
        assert response.available_components == ["kernel"]
        assert {e.cve_id for e in _page_entries(response)} == {
            "CVE-2025-0001",
            "CVE-2025-0002",
            "CVE-2025-0003",
        }

        # Index query only: nothing re-fetched, nothing written.
        assert session.flaws.retrieve_list_iterator.call_count == 1
        assert cache_dir.read_text() == cached_json_before

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_fully_cached_selection_with_cursor_still_reports_progress(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """The legacy fast path is gated on the absence of a cursor: a client
        that passes one gets a paginated final page (progress present) whose
        entries cover only the remaining slice."""
        self._mock_settings(mock_settings, cache_dir)

        _seed_cache(
            cache_dir,
            {
                f"CVE-2025-{i:04d}": _cached_flaw(cve_id=f"CVE-2025-{i:04d}")
                for i in (1, 2, 3)
            },
        )
        mock_bindings.new_session.return_value = _make_session(*_numbered_flaws(3))

        response = get_osidb_bot_kpi(detail=True, cursor="CVE-2025-0001")
        assert response.progress is not None
        assert _page_progress(response).complete is True
        assert _page_progress(response).selected_flaws == 3
        assert response.next_cursor is None
        assert response.total_flaws_processed == 3
        assert {e.cve_id for e in _page_entries(response)} == {
            "CVE-2025-0002",
            "CVE-2025-0003",
        }

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_cursor_at_last_flaw_terminates_without_looping(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """A cursor at the last flaw yields the final page directly: the
        aggregate is served, no further cursor is returned, and no entries
        are duplicated for a client that re-sends its last cursor."""
        self._mock_settings(mock_settings, cache_dir)

        _seed_cache(
            cache_dir,
            {
                f"CVE-2025-{i:04d}": _cached_flaw(cve_id=f"CVE-2025-{i:04d}")
                for i in (1, 2, 3)
            },
        )
        mock_bindings.new_session.return_value = _make_session(*_numbered_flaws(3))

        response = get_osidb_bot_kpi(detail=True, cursor="CVE-2025-0003")
        assert response.next_cursor is None
        assert _page_progress(response).complete is True
        assert response.total_flaws_processed == 3
        assert response.entries == []

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_progress_refreshed_counts_whole_selection_not_just_page(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """refreshed_flaws reports freshness across the whole selection at
        response time -- including flaws this request never touched -- and
        only the page's own stale flaws are fetched."""
        self._mock_settings(mock_settings, cache_dir)

        # Flaws 0002 and 0004 are already fresh; 0001 and 0003 are stale.
        _seed_cache(
            cache_dir,
            {
                "CVE-2025-0002": _cached_flaw(cve_id="CVE-2025-0002"),
                "CVE-2025-0004": _cached_flaw(cve_id="CVE-2025-0004"),
            },
        )
        session = _make_session(*_numbered_flaws(4))
        mock_bindings.new_session.return_value = session

        page1 = get_osidb_bot_kpi(detail=True, limit=2)
        assert page1.next_cursor == "CVE-2025-0002"
        assert _page_progress(page1).selected_flaws == 4
        # 0001 refreshed this request plus the pre-cached 0002 and 0004.
        assert _page_progress(page1).refreshed_flaws == 3
        assert _page_progress(page1).complete is False
        assert {e.cve_id for e in _page_entries(page1)} == {
            "CVE-2025-0001",
            "CVE-2025-0002",
        }
        # Only the page's stale flaw was fetched in full.
        assert _batch_fetches(session) == [{"CVE-2025-0001"}]

        page2 = get_osidb_bot_kpi(detail=True, limit=2, cursor="CVE-2025-0002")
        assert _page_progress(page2).complete is True
        assert page2.total_flaws_processed == 4
        assert {e.cve_id for e in _page_entries(page2)} == {
            "CVE-2025-0003",
            "CVE-2025-0004",
        }
        assert _batch_fetches(session) == [
            {"CVE-2025-0001"},
            {"CVE-2025-0003"},
        ]

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_component_filter_composes_with_pagination(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """The component filter scopes the selection that pagination slices:
        pages, progress, and the final aggregate cover only that component's
        flaws."""
        self._mock_settings(mock_settings, cache_dir)

        kernel_1 = _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("LOW")]},
            impact="LOW",
            cve_id="CVE-2025-0001",
            components=["kernel"],
        )
        kernel_2 = _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("LOW")]},
            impact="LOW",
            cve_id="CVE-2025-0002",
            components=["kernel"],
        )
        other = _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("LOW")]},
            impact="LOW",
            cve_id="CVE-2025-0003",
            components=["openssl"],
        )
        session = _make_component_session(
            {"kernel": [kernel_1, kernel_2], "openssl": [other]}
        )
        mock_bindings.new_session.return_value = session

        page1 = get_osidb_bot_kpi(detail=True, component="kernel", limit=1)
        assert _page_progress(page1).selected_flaws == 2
        assert page1.next_cursor == "CVE-2025-0001"
        assert {e.cve_id for e in _page_entries(page1)} == {"CVE-2025-0001"}

        page2 = get_osidb_bot_kpi(
            detail=True, component="kernel", limit=1, cursor="CVE-2025-0001"
        )
        assert page2.next_cursor is None
        assert _page_progress(page2).complete is True
        assert page2.total_flaws_processed == 2
        assert page2.available_components == ["kernel"]

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_changed_after_scoring_applies_to_each_page(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """Date filters keep their pre-pagination meaning: the window selects
        flaws by updated_dt, and each page's scoring drops suggestions whose
        timestamps fall outside it -- a selected flaw can therefore deliver no
        entries while still counting toward selected_flaws."""
        self._mock_settings(mock_settings, cache_dir)

        in_window = _make_flaw_dict(
            {
                "processed": True,
                "impact": [
                    _make_bot_entry("LOW", timestamp="2025-07-01T00:00:00+00:00")
                ],
            },
            impact="LOW",
            cve_id="CVE-2025-0001",
            updated_dt="2025-07-01T00:00:00+00:00",
        )
        out_of_window = _make_flaw_dict(
            {
                "processed": True,
                "impact": [
                    _make_bot_entry("LOW", timestamp="2025-06-01T00:00:00+00:00")
                ],
            },
            impact="LOW",
            cve_id="CVE-2025-0002",
            updated_dt="2025-07-02T00:00:00+00:00",
        )
        session = _make_filtering_session(in_window, out_of_window)
        mock_bindings.new_session.return_value = session

        changed_after = datetime(2025, 6, 15, tzinfo=UTC)

        page1 = get_osidb_bot_kpi(detail=True, changed_after=changed_after, limit=1)
        assert _page_progress(page1).selected_flaws == 2
        assert page1.next_cursor == "CVE-2025-0001"
        assert [e.cve_id for e in _page_entries(page1)] == ["CVE-2025-0001"]

        page2 = get_osidb_bot_kpi(
            detail=True, changed_after=changed_after, limit=1, cursor="CVE-2025-0001"
        )
        assert page2.next_cursor is None
        assert _page_progress(page2).complete is True
        assert _page_progress(page2).selected_flaws == 2
        # Only the flaw with an in-window suggestion contributes.
        assert page2.total_flaws_processed == 1
        assert page2.entries == []

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_concurrent_pagination_runs_converge(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """Two clients paginating the same selection simultaneously both end
        with complete, duplicate-free results; their overlapping refreshes do
        not corrupt the shared cache."""
        self._mock_settings(mock_settings, cache_dir)

        flaws = _numbered_flaws(5)
        mock_bindings.new_session.side_effect = lambda **kwargs: _make_session(
            *flaws, index_delay=0.02
        )

        runs = []

        def run_client():
            runs.append(_paginate(detail=True, limit=2))

        threads = [threading.Thread(target=run_client) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(runs) == 2
        expected = {f"CVE-2025-{i:04d}" for i in range(1, 6)}
        for pages in runs:
            final = pages[-1]
            assert final.next_cursor is None
            assert _page_progress(final).complete is True
            assert final.total_flaws_processed == 5
            entries = [e for page in pages for e in _page_entries(page)]
            assert {e.cve_id for e in entries} == expected
            assert len(entries) == 5

        cached = BotKPICacheEntry.model_validate_json(cache_dir.read_text())
        assert set(cached.flaws) == expected
        assert cached.total_flaws_processed == 5
