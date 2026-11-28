"""Tests for osidb-bot KPI cache orchestration."""

import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aegis_ai_web.src.data_models import BotKPIEntry, BotKPIProgress, BotKPIResponse
from aegis_ai_web.src.endpoints.bot_kpi import (
    OSIDB_BOT_BIRTHDAY,
    BotKPICacheEntry,
    FlawCacheData,
    SelectionStamp,
    _cache_handler,
    _fetch_flaw_index,
    _flaw_cache_data,
    _get_cache_path,
    _merge_fetched,
    _needs_fetch,
    _read_cache,
    get_osidb_bot_kpi,
    selection_signature,
    stale_reason,
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
        "statement": "",
        "mitigation": "",
        "aegis_meta": aegis_meta,
    }
    flaw.update(overrides)
    return flaw


def _make_session(*flaws, index_delay=0.0):
    """Build a mock OSIDB session for the two-phase fetch.

    ``flaws`` are full flaw dicts (each with ``cve_id`` + ``updated_dt``). The
    first-phase index iterator yields ``{cve_id, updated_dt}`` stubs; the
    second-phase batch iterator (called with ``cve_id=[...]``) returns full flaw
    data for the requested IDs. This lets tests assert exactly which flaws were
    fetched in full versus served from the cache via the index alone.
    ``index_delay`` sleeps before each index query so concurrent requests'
    read-modify-write cycles can be forced to overlap.
    ``count`` answers the selection-size query the engine uses to detect
    deletions.
    """
    by_cve = {flaw["cve_id"]: flaw for flaw in flaws}

    def _list_iterator(**kwargs):
        if index_delay:
            time.sleep(index_delay)
        requested = kwargs.get("cve_id")
        if requested is not None:
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
    session.flaws.count.side_effect = lambda **kwargs: len(flaws)
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

    def _count(**kwargs):
        component = kwargs.get("components")
        flaws = by_component.get(component, []) if component else all_flaws
        return len(flaws)

    session = MagicMock()
    session.flaws.retrieve_list_iterator.side_effect = _list_iterator
    session.flaws.count.side_effect = _count
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

    def _matches(flaw, component, gte, lte):
        if component is not None and component not in flaw.get("_components", []):
            return False
        updated = datetime.fromisoformat(flaw["updated_dt"])
        return not (
            (gte is not None and updated < gte) or (lte is not None and updated > lte)
        )

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
            if not _matches(flaw, component, gte, lte):
                continue
            stub = MagicMock()
            stub.to_dict.return_value = {
                "cve_id": flaw["cve_id"],
                "updated_dt": flaw["updated_dt"],
            }
            stubs.append(stub)
        return iter(stubs)

    def _count(**kwargs):
        return sum(
            1
            for flaw in flaws
            if _matches(
                flaw,
                kwargs.get("components"),
                kwargs.get("updated_dt_gte"),
                kwargs.get("updated_dt_lte"),
            )
        )

    session = MagicMock()
    session.flaws.retrieve_list_iterator.side_effect = _list_iterator
    session.flaws.count.side_effect = _count
    return session


def _seed_cache(cache_path: Path, flaws: dict[str, FlawCacheData]) -> None:
    """Write a per-flaw cache directly from ``FlawCacheData`` entries."""
    entry = BotKPICacheEntry(flaws=flaws)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(entry.model_dump_json())


def _seed_stamped_cache(
    cache_path: Path,
    flaws: dict[str, FlawCacheData],
    selections: dict[str, SelectionStamp],
) -> None:
    """Write a cache with pre-stamped selections.

    Stamp-age behavior (LRU eviction) is tested by constructing stamps at
    chosen ``fetched_at`` instants rather than by sleeping.
    """
    entry = BotKPICacheEntry(flaws=flaws, selections=selections)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(entry.model_dump_json())


def _mock_kpi_settings(mock_settings, cache_dir) -> None:
    """Pin the settings the KPI engine reads to real values."""
    mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
    mock_settings.return_value.config_dir = str(cache_dir.parent.parent)


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
    session.flaws.count.side_effect = lambda **kwargs: len(index)
    return session


def _batch_fetches(session):
    """The cve_id sets requested by full-data batch fetches, in call order."""
    return [
        set(call.kwargs["cve_id"])
        for call in session.flaws.retrieve_list_iterator.call_args_list
        if call.kwargs.get("cve_id") is not None
    ]


def _index_calls(session):
    """The flaw-index queries (everything but cve_id batch fetches), in call
    order -- the sequence a test asserts on when distinguishing delta
    validation, full rebuilds, and count queries."""
    return [
        call
        for call in session.flaws.retrieve_list_iterator.call_args_list
        if "cve_id" not in call.kwargs
    ]


def _paginate(**kwargs):
    """Drive get_osidb_bot_kpi as a paginating client would: follow
    last_cve from page to page until the final page. An initial cursor
    may be passed to resume mid-selection."""
    pages = []
    cursor = kwargs.pop("cursor", None)
    for _ in range(100):
        page = get_osidb_bot_kpi(cursor=cursor, **kwargs)
        pages.append(page)
        if page.last_cve is None:
            return pages
        cursor = page.last_cve
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


class TestStaleReason:
    """The staleness semantics for unusable watermarks.

    An unparseable *index* watermark (OSIDB reported no updated_dt) can never
    be satisfied by a fetch, so a flaw with such a watermark is fresh once
    cached -- otherwise a polling refresh would livelock -- while an
    uncached one is still fetched once. A malformed *cached* watermark cannot
    prove freshness, so it stays outdated.
    """

    def test_cached_flaw_with_unparseable_index_watermark_is_fresh(self):
        cached = _cached_flaw()
        assert stale_reason(cached, "") is None

    def test_uncached_flaw_with_unparseable_index_watermark_is_uncached(self):
        assert stale_reason(None, "") == "uncached"

    def test_malformed_cached_watermark_stays_outdated(self):
        cached = _cached_flaw(updated_dt="not-a-timestamp")
        assert stale_reason(cached, _DEFAULT_DT) == "outdated"


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

        # The first request stamps the selection index for these filters.
        get_osidb_bot_kpi(changed_after=datetime(2025, 6, 1, tzinfo=UTC))
        cached_json_stamped = cache_dir.read_text()
        session.flaws.retrieve_list_iterator.reset_mock()

        response = get_osidb_bot_kpi(changed_after=datetime(2025, 6, 1, tzinfo=UTC))
        assert response.total_flaws_processed == 1

        # Only the delta-validation index call; the selected flaw is already
        # cached, so no batch fetch and no write.
        assert session.flaws.retrieve_list_iterator.call_count == 1
        assert cache_dir.read_text() == cached_json_stamped

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

        session = _make_session(
            _make_flaw_dict(
                {"processed": True, "impact": [_make_bot_entry("LOW")]},
                cve_id="CVE-2025-0001",
            )
        )
        mock_bindings.new_session.return_value = session

        # The first request stamps the selection index; snapshot after it.
        get_osidb_bot_kpi()
        cached_json_stamped = cache_dir.read_text()
        session.flaws.retrieve_list_iterator.reset_mock()

        response = get_osidb_bot_kpi()
        assert response.total_flaws_processed == 1
        assert response.features["impact"].suggested == 1
        assert response.features["impact"].kept == 1

        # Only the delta-validation index call; no batch fetch for unchanged
        # flaws, and no change means no write.
        assert session.flaws.retrieve_list_iterator.call_count == 1
        assert cache_dir.read_text() == cached_json_stamped

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

        # A fresh session per request; the filtering session honors
        # updated_dt bounds, so each range selects only its own flaw.
        sessions = [_make_filtering_session(flaw_a, flaw_b) for _ in range(3)]
        mock_bindings.new_session.side_effect = sessions

        # 1. Range A selects and fetches only flaw A, then serves it.
        response_a = get_osidb_bot_kpi(
            changed_after=range_a[0], changed_before=range_a[1]
        )
        assert response_a.total_flaws_processed == 1
        # 2. Range B refreshes only flaw B; it must not evict flaw A.
        get_osidb_bot_kpi(changed_after=range_b[0], changed_before=range_b[1])

        cached = BotKPICacheEntry.model_validate_json(cache_dir.read_text())
        assert set(cached.flaws) == {"CVE-2026-0001", "CVE-2026-0002"}

        # 3. Range A again: flaw A still cached, so only the index is queried --
        # no full re-fetch.
        response = get_osidb_bot_kpi(
            changed_after=range_a[0], changed_before=range_a[1]
        )
        assert response.total_flaws_processed == 1
        assert sessions[2].flaws.retrieve_list_iterator.call_count == 1

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

        # The first request stamps the kernel selection; snapshot after it.
        get_osidb_bot_kpi(component="kernel")
        cached_json_stamped = cache_dir.read_text()

        response = get_osidb_bot_kpi(component="kernel")

        # Only the kernel flaw is counted, even though both are cached...
        assert response.total_flaws_processed == 1
        # ...and the other component's flaw is retained (component filtering only
        # selects which flaws to score, it never prunes the shared cache).
        cached = BotKPICacheEntry.model_validate_json(cache_dir.read_text())
        assert set(cached.flaws) == {"CVE-2025-0001", "CVE-2025-0002"}
        assert cache_dir.read_text() == cached_json_stamped

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

        # The lock serializes the writes; neither request corrupts the cache.
        # Both fetch the same two flaws and merge them, so both threads
        # observe a fully refreshed selection no matter how they interleaved.
        assert len(responses) == 2
        assert [r.total_flaws_processed for r in responses] == [2, 2]
        assert [r.features["impact"].suggested for r in responses] == [2, 2]

        cached = BotKPICacheEntry.model_validate_json(cache_dir.read_text())
        assert cached.total_flaws_processed == 2
        assert set(cached.flaws.keys()) == {"CVE-2025-0001", "CVE-2025-0002"}


class TestGetOsidbBotKpiPagination:
    """The paginated contract of get_osidb_bot_kpi.

    The selection is served in ``limit``-sized pages of sorted CVE IDs: each
    intermediate page refreshes only its own slice, carries placeholder
    aggregates, its own ``entries`` slice, a ``progress`` block over the whole
    selection, and the ``last_cve`` to continue from; the final page adds
    the complete aggregate. A client that follows the cursor and concatenates
    ``entries`` ends with exactly one copy of every selected flaw's records.
    A fully warm page is a pure cache read: it fetches nothing and writes
    nothing.
    """

    def _mock_settings(self, mock_settings, cache_dir):
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_settings.return_value.config_dir = str(cache_dir.parent.parent)

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_pages_slice_sorted_selection_with_placeholder_aggregates(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """Intermediate pages carry placeholders (0 / {}), their own entries
        slice, progress over the whole selection, and last_cve; the final
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

        # Each page refreshes its own slice, so the refreshed count grows
        # page by page and only the final page is complete.
        page1 = get_osidb_bot_kpi(detail=True, limit=2)
        assert page1.total_flaws_processed == 0
        assert page1.features == {}
        assert page1.last_cve == "CVE-2025-0002"
        assert _page_progress(page1).selected_flaws == 5
        assert _page_progress(page1).refreshed_flaws == 2
        assert _page_progress(page1).complete is False
        assert page1.available_components is None
        assert {e.cve_id for e in _page_entries(page1)} == {
            "CVE-2025-0001",
            "CVE-2025-0002",
        }

        page2 = get_osidb_bot_kpi(detail=True, limit=2, cursor="CVE-2025-0002")
        assert page2.last_cve == "CVE-2025-0004"
        assert _page_progress(page2).refreshed_flaws == 4
        assert _page_progress(page2).complete is False
        assert {e.cve_id for e in _page_entries(page2)} == {
            "CVE-2025-0003",
            "CVE-2025-0004",
        }

        page3 = get_osidb_bot_kpi(detail=True, limit=2, cursor="CVE-2025-0004")
        assert page3.last_cve is None
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

        # Each page fetched exactly its own slice's full data.
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
        assert page1.last_cve == "CVE-2025-0400"
        assert _page_progress(page1).selected_flaws == 401
        assert _page_progress(page1).refreshed_flaws == 400
        assert _page_progress(page1).complete is False
        assert page1.total_flaws_processed == 0

        page2 = get_osidb_bot_kpi(cursor="CVE-2025-0400")
        assert page2.last_cve is None
        assert _page_progress(page2).complete is True
        assert page2.total_flaws_processed == 401
        assert page2.features["impact"].suggested == 401

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_unparseable_watermark_refresh_still_terminates(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """Regression test for a refresh livelock: a flaw whose indexed
        updated_dt is missing can never satisfy a watermark comparison, so a
        naive refresh would re-fetch it forever. Such a flaw is fetched once
        and then treated as fresh -- as fresh as OSIDB allows -- so
        pagination terminates and never re-fetches it."""
        self._mock_settings(mock_settings, cache_dir)

        # 100 flaws with valid watermarks, then the unparseable-watermark flaw
        # sorting last.
        unparseable = _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("LOW")]},
            impact="LOW",
            cve_id="CVE-2025-0101",
            updated_dt=None,
        )
        session = _make_session(*_numbered_flaws(100), unparseable)
        mock_bindings.new_session.return_value = session

        # Pagination terminates: the unparseable flaw is fetched once (in the
        # second 100-flaw batch) and delivers every record exactly once,
        # with an honest complete flag over the whole selection.
        pages = _paginate(detail=True, limit=200)
        final = pages[-1]
        assert len(pages) == 1
        assert final.last_cve is None
        assert final.total_flaws_processed == 101
        assert _page_progress(final).selected_flaws == 101
        assert _page_progress(final).refreshed_flaws == 101
        assert _page_progress(final).complete is True
        assert {e.cve_id for e in _page_entries(final)} == {
            f"CVE-2025-{i:04d}" for i in range(1, 102)
        }
        assert _batch_fetches(session) == [
            {f"CVE-2025-{i:04d}" for i in range(1, 101)},
            {"CVE-2025-0101"},
        ]

        # A second run fetches nothing: the unparseable flaw is treated as
        # fresh once cached, so the flaw cannot cause a re-fetch livelock.
        session.flaws.retrieve_list_iterator.reset_mock()
        pages = _paginate(detail=True, limit=200)
        assert len(pages) == 1
        assert _batch_fetches(session) == []

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_flaw_vanishing_after_index_is_tombstoned_not_blocking(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """A flaw present in the index but absent from the batch fetch
        (deleted in OSIDB in between) is cached as a non-bot-processed skip
        marker at the indexed watermark: it contributes no entries, never
        blocks pagination, and is not re-fetched by later requests."""
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
        assert page.last_cve is None
        assert _page_progress(page).selected_flaws == 2
        assert _page_progress(page).refreshed_flaws == 2
        assert _page_progress(page).complete is True
        assert [e.cve_id for e in _page_entries(page)] == ["CVE-2025-0001"]

        cached = BotKPICacheEntry.model_validate_json(cache_dir.read_text())
        ghost = cached.flaws["CVE-2025-0002"]
        assert ghost.bot_processed is False
        assert ghost.updated_dt == _DEFAULT_DT

        # The tombstone is fresh: a repeat request fetches nothing further, so
        # the vanished flaw cannot stall the refresh, and the single warm
        # page reports refresh completion via the progress block.
        session.flaws.retrieve_list_iterator.reset_mock()
        warm = get_osidb_bot_kpi(detail=True)
        assert _page_progress(warm).complete is True
        assert warm.last_cve is None
        assert warm.total_flaws_processed == 1
        assert _batch_fetches(session) == []

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_fully_cached_selection_serves_single_final_page(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """When every selected flaw is fresh in the cache, the whole
        selection is served as one final page: full aggregate and every entry
        in a single response, no cursor to follow. Only the progress block
        differs from the pre-pagination shape -- the paginated path always
        reports refresh completion."""
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
        assert _page_progress(response).complete is True
        assert response.last_cve is None
        assert response.total_flaws_processed == 3
        assert response.features["impact"].suggested == 3
        assert response.available_components == ["kernel"]
        assert {e.cve_id for e in _page_entries(response)} == {
            "CVE-2025-0001",
            "CVE-2025-0002",
            "CVE-2025-0003",
        }

        # Index query only: nothing re-fetched, and the flaw entries are
        # untouched -- only the selection stamp was persisted.
        assert session.flaws.retrieve_list_iterator.call_count == 1
        assert _batch_fetches(session) == []
        cached = BotKPICacheEntry.model_validate_json(cache_dir.read_text())
        assert (
            cached.flaws
            == BotKPICacheEntry.model_validate_json(cached_json_before).flaws
        )

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_fully_cached_selection_with_cursor_still_reports_progress(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """A warm selection sliced by a cursor still paginates: the final
        page carries the progress block and an aggregate over the whole
        selection, while its entries cover only the remaining slice."""
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
        assert response.last_cve is None
        assert response.total_flaws_processed == 3
        assert {e.cve_id for e in _page_entries(response)} == {
            "CVE-2025-0002",
            "CVE-2025-0003",
        }

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_warm_selection_of_exactly_limit_is_single_final_page(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """A warm selection of exactly `limit` flaws fits one page: a single
        final response with the full aggregate, every entry, and no cursor."""
        self._mock_settings(mock_settings, cache_dir)

        _seed_cache(
            cache_dir,
            {
                f"CVE-2025-{i:04d}": _cached_flaw(cve_id=f"CVE-2025-{i:04d}")
                for i in range(1, 1001)
            },
        )
        session = _make_session(*_numbered_flaws(1000))
        mock_bindings.new_session.return_value = session

        response = get_osidb_bot_kpi(detail=True, limit=1000)
        assert response.last_cve is None
        assert _page_progress(response).complete is True
        assert response.total_flaws_processed == 1000
        assert response.features["impact"].suggested == 1000
        assert len(_page_entries(response)) == 1000
        # Index query only: nothing re-fetched.
        assert session.flaws.retrieve_list_iterator.call_count == 1

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_warm_selection_of_limit_plus_one_ends_with_single_entry_page(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """One flaw past the page boundary splits the run into exactly two
        requests: a full limit-entry intermediate page, then a final page
        carrying only the last flaw plus the aggregate over the whole
        selection."""
        self._mock_settings(mock_settings, cache_dir)

        _seed_cache(
            cache_dir,
            {
                f"CVE-2025-{i:04d}": _cached_flaw(cve_id=f"CVE-2025-{i:04d}")
                for i in range(1, 1002)
            },
        )
        session = _make_session(*_numbered_flaws(1001))
        mock_bindings.new_session.return_value = session

        page1 = get_osidb_bot_kpi(detail=True, limit=1000)
        assert page1.last_cve == "CVE-2025-1000"
        assert len(_page_entries(page1)) == 1000
        assert {e.cve_id for e in _page_entries(page1)} == {
            f"CVE-2025-{i:04d}" for i in range(1, 1001)
        }
        assert page1.total_flaws_processed == 0
        assert page1.features == {}
        assert _page_progress(page1).complete is True

        page2 = get_osidb_bot_kpi(detail=True, limit=1000, cursor="CVE-2025-1000")
        assert page2.last_cve is None
        assert _page_progress(page2).complete is True
        assert page2.total_flaws_processed == 1001
        assert [e.cve_id for e in _page_entries(page2)] == ["CVE-2025-1001"]

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_warm_selection_serves_limit_sized_pages(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """A fully-cached selection is served in pages of the client's limit:
        the limit is the honest page size, warm or cold. Intermediate pages
        carry placeholder aggregates, a progress block reporting a complete
        refresh, and the cursor of their last flaw; the final page carries the
        aggregate over the whole selection. A warm run never fetches flaw data
        and never writes the cache: only the run's first request runs the
        flaw-index query (the stamping scan), and its pages trust the stamp."""
        self._mock_settings(mock_settings, cache_dir)

        # 2500 flaws = ceil(2500/1000) = 3 pages: 1000 + 1000 + 500.
        total = 2500
        _seed_cache(
            cache_dir,
            {
                f"CVE-2025-{i:04d}": _cached_flaw(
                    cve_id=f"CVE-2025-{i:04d}", components=("kernel",)
                )
                for i in range(1, total + 1)
            },
        )
        session = _make_session(*_numbered_flaws(total))
        mock_bindings.new_session.return_value = session

        page1 = get_osidb_bot_kpi(detail=True, limit=1000)
        assert page1.last_cve == "CVE-2025-1000"
        assert len(_page_entries(page1)) == 1000
        assert {e.cve_id for e in _page_entries(page1)} == {
            f"CVE-2025-{i:04d}" for i in range(1, 1001)
        }
        assert page1.total_flaws_processed == 0
        assert page1.features == {}
        assert page1.available_components is None
        assert _page_progress(page1).selected_flaws == total
        assert _page_progress(page1).refreshed_flaws == total
        # The cache refresh IS complete while pagination continues: warm
        # pages carry no refresh work, so this combination is served as-is.
        assert _page_progress(page1).complete is True
        # The run's first request stamped the selection; snapshot after it.
        cached_json_stamped = cache_dir.read_text()

        page2 = get_osidb_bot_kpi(detail=True, limit=1000, cursor="CVE-2025-1000")
        assert page2.last_cve == "CVE-2025-2000"
        assert len(_page_entries(page2)) == 1000
        assert {e.cve_id for e in _page_entries(page2)} == {
            f"CVE-2025-{i:04d}" for i in range(1001, 2001)
        }
        assert page2.total_flaws_processed == 0
        assert _page_progress(page2).complete is True

        page3 = get_osidb_bot_kpi(detail=True, limit=1000, cursor="CVE-2025-2000")
        assert page3.last_cve is None
        assert _page_progress(page3).complete is True
        assert page3.total_flaws_processed == total
        assert page3.features["impact"].suggested == total
        assert page3.available_components == ["kernel"]
        assert {e.cve_id for e in _page_entries(page3)} == {
            f"CVE-2025-{i:04d}" for i in range(2001, 2501)
        }

        # ceil(2500/1000) = 3 requests delivered every flaw exactly once.
        accumulated = [e for page in (page1, page2, page3) for e in _page_entries(page)]
        assert len(accumulated) == total
        assert {e.cve_id for e in accumulated} == {
            f"CVE-2025-{i:04d}" for i in range(1, total + 1)
        }

        # Only the run's first request ran the flaw-index query (the stamping
        # full scan); the cursor pages trusted the stamp, and no request made
        # a cve_id batch fetch of full flaw data...
        assert session.flaws.retrieve_list_iterator.call_count == 1
        assert _batch_fetches(session) == []
        # ...and the cache file's bytes are unchanged from the stamp on.
        assert cache_dir.read_text() == cached_json_stamped

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_warm_pagination_without_detail_omits_entries(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """detail=false keeps entries and available_components out of warm
        pages while the pagination metadata and the final aggregate remain."""
        self._mock_settings(mock_settings, cache_dir)

        _seed_cache(
            cache_dir,
            {
                f"CVE-2025-{i:04d}": _cached_flaw(cve_id=f"CVE-2025-{i:04d}")
                for i in range(1, 1201)
            },
        )
        session = _make_session(*_numbered_flaws(1200))
        mock_bindings.new_session.return_value = session

        page1 = get_osidb_bot_kpi(limit=1000)
        assert page1.last_cve == "CVE-2025-1000"
        assert page1.entries is None
        assert page1.available_components is None
        assert page1.total_flaws_processed == 0
        assert page1.features == {}
        assert _page_progress(page1).complete is True

        page2 = get_osidb_bot_kpi(limit=1000, cursor="CVE-2025-1000")
        assert page2.last_cve is None
        assert page2.entries is None
        assert page2.available_components is None
        assert page2.total_flaws_processed == 1200
        assert page2.features["impact"].suggested == 1200

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_mixed_selection_refreshes_its_slice_then_serves_limit_pages(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """A mixed selection (mostly cached, a few stale flaws) serves
        limit-sized pages: the first page refreshes the stale flaws inside
        its own slice, the pages that follow are warm cache reads, and the
        client accumulates exactly one copy of every entry."""
        self._mock_settings(mock_settings, cache_dir)

        # The two stale flaws must sort inside the first page.
        total = 1204
        _seed_cache(
            cache_dir,
            {
                f"CVE-2025-{i:04d}": _cached_flaw(cve_id=f"CVE-2025-{i:04d}")
                for i in range(3, total + 1)
            },
        )
        session = _make_session(*_numbered_flaws(total))
        mock_bindings.new_session.return_value = session

        # Page1 refreshes the two stale flaws of its own slice.
        page1 = get_osidb_bot_kpi(detail=True, limit=1000)
        assert page1.last_cve == "CVE-2025-1000"
        assert len(_page_entries(page1)) == 1000
        assert page1.total_flaws_processed == 0
        assert _page_progress(page1).selected_flaws == total
        assert _page_progress(page1).complete is True
        assert _batch_fetches(session) == [{"CVE-2025-0001", "CVE-2025-0002"}]
        # Page1 wrote the two fetched flaws; snapshot the bytes so the warm
        # page can be proven read-only.
        cache_json_after_refresh = cache_dir.read_text()

        page2 = get_osidb_bot_kpi(detail=True, limit=1000, cursor="CVE-2025-1000")
        assert page2.last_cve is None
        assert page2.total_flaws_processed == total
        assert page2.features["impact"].suggested == total
        assert len(_page_entries(page2)) == 204

        # The only full-data fetch of the run was page1's slice, and the warm
        # page never wrote the cache.
        assert _batch_fetches(session) == [{"CVE-2025-0001", "CVE-2025-0002"}]
        assert cache_dir.read_text() == cache_json_after_refresh

        accumulated = [e for page in (page1, page2) for e in _page_entries(page)]
        assert len(accumulated) == total
        assert {e.cve_id for e in accumulated} == {
            f"CVE-2025-{i:04d}" for i in range(1, total + 1)
        }

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_warm_run_start_page_fetches_nothing_following_page_fetches_its_slice(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """A run interrupted mid-pagination leaves its tail uncached while
        its stamp still covers the whole selection. Resuming, the run's
        first page is a pure cache read -- no flaw fetched, nothing written,
        the delta validation and its count the only OSIDB contact -- while
        the following page fetches exactly its own slice's uncached flaws
        and makes no further index or count contact."""
        self._mock_settings(mock_settings, cache_dir)

        flaws = _numbered_flaws(4)
        # The previous run delivered only page 1 (flaws 0001-0002) before
        # stopping; its stamp still covers the whole four-flaw selection.
        _seed_stamped_cache(
            cache_dir,
            {
                "CVE-2025-0001": _cached_flaw(cve_id="CVE-2025-0001"),
                "CVE-2025-0002": _cached_flaw(cve_id="CVE-2025-0002"),
            },
            {
                selection_signature(None, None, None): SelectionStamp(
                    index={f["cve_id"]: f["updated_dt"] for f in flaws},
                    fetched_at=datetime.now(UTC),
                )
            },
        )
        # The filtering session honors the delta bound, so validation sees
        # no change and the count matches the stamp: nothing to re-stamp.
        session = _make_filtering_session(*flaws)
        mock_bindings.new_session.return_value = session

        cache_json_before = cache_dir.read_text()
        page1 = get_osidb_bot_kpi(detail=True, limit=2)
        assert page1.last_cve == "CVE-2025-0002"
        assert page1.total_flaws_processed == 0
        assert _page_progress(page1).selected_flaws == 4
        # The warm page honestly reports the selection's uncached tail as
        # not yet refreshed, while serving its own slice without work.
        assert _page_progress(page1).refreshed_flaws == 2
        assert _page_progress(page1).complete is False
        assert {e.cve_id for e in _page_entries(page1)} == {
            "CVE-2025-0001",
            "CVE-2025-0002",
        }
        assert _batch_fetches(session) == []
        assert cache_dir.read_text() == cache_json_before
        assert session.flaws.count.call_count == 1

        page2 = get_osidb_bot_kpi(detail=True, limit=2, cursor="CVE-2025-0002")
        assert page2.last_cve is None
        assert _page_progress(page2).complete is True
        assert page2.total_flaws_processed == 4
        assert {e.cve_id for e in _page_entries(page2)} == {
            "CVE-2025-0003",
            "CVE-2025-0004",
        }
        # The trusting cursor page made zero OSIDB contact -- no index
        # query, no count -- and fetched exactly its own slice's flaws.
        assert len(_index_calls(session)) == 1
        assert session.flaws.count.call_count == 1
        assert _batch_fetches(session) == [{"CVE-2025-0003", "CVE-2025-0004"}]

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_cursor_mid_selection_refreshes_only_its_slice(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """A cursor mid-selection serves limit-sized pages, refreshing only
        each page's own slice: cached flaws are served warm without any
        fetch, the uncached tail is fetched when its page arrives, and
        progress reports the cached fraction of the whole selection on
        every page."""
        self._mock_settings(mock_settings, cache_dir)

        # Fresh prefix through #1490, then a stale tail.
        total = 1500
        _seed_cache(
            cache_dir,
            {
                f"CVE-2025-{i:04d}": _cached_flaw(cve_id=f"CVE-2025-{i:04d}")
                for i in range(1, 1491)
            },
        )
        session = _make_session(*_numbered_flaws(total))
        mock_bindings.new_session.return_value = session

        # Resuming mid-selection: the remainder holds 1000 flaws of which the
        # last 10 are uncached; the page is limit-sized (400) and serves its
        # cached records without fetching anything.
        page1 = get_osidb_bot_kpi(detail=True, limit=400, cursor="CVE-2025-0500")
        assert page1.last_cve == "CVE-2025-0900"
        assert len(_page_entries(page1)) == 400
        assert {e.cve_id for e in _page_entries(page1)} == {
            f"CVE-2025-{i:04d}" for i in range(501, 901)
        }
        assert page1.total_flaws_processed == 0
        assert _page_progress(page1).selected_flaws == total
        assert _page_progress(page1).refreshed_flaws == 1490
        assert _page_progress(page1).complete is False
        assert _batch_fetches(session) == []

        page2 = get_osidb_bot_kpi(detail=True, limit=400, cursor="CVE-2025-0900")
        assert page2.last_cve == "CVE-2025-1300"
        assert len(_page_entries(page2)) == 400
        assert _batch_fetches(session) == []

        # The final page reaches the uncached tail: exactly those flaws are
        # fetched -- the cached prefix of its slice is served warm.
        page3 = get_osidb_bot_kpi(detail=True, limit=400, cursor="CVE-2025-1300")
        assert page3.last_cve is None
        assert _page_progress(page3).refreshed_flaws == total
        assert _page_progress(page3).complete is True
        assert len(_page_entries(page3)) == 200
        assert _batch_fetches(session) == [
            {f"CVE-2025-{i:04d}" for i in range(1491, 1501)}
        ]

        accumulated = [e for page in (page1, page2, page3) for e in _page_entries(page)]
        assert len(accumulated) == 1000
        assert {e.cve_id for e in accumulated} == (
            {f"CVE-2025-{i:04d}" for i in range(501, 1501)}
        )

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
        assert response.last_cve is None
        assert _page_progress(response).complete is True
        assert response.total_flaws_processed == 3
        assert response.entries == []

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_progress_refreshed_counts_whole_selection_not_just_page(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """refreshed_flaws reports freshness across the whole selection at
        response time -- including flaws the page never touched -- while
        only each page's own stale flaws are fetched."""
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

        # Page1 refreshes only flaw 0001: the sole stale flaw of its slice.
        page1 = get_osidb_bot_kpi(detail=True, limit=2)
        assert page1.last_cve == "CVE-2025-0002"
        assert _page_progress(page1).selected_flaws == 4
        assert _page_progress(page1).refreshed_flaws == 3
        assert _page_progress(page1).complete is False
        assert {e.cve_id for e in _page_entries(page1)} == {
            "CVE-2025-0001",
            "CVE-2025-0002",
        }
        assert _batch_fetches(session) == [{"CVE-2025-0001"}]

        page2 = get_osidb_bot_kpi(detail=True, limit=2, cursor="CVE-2025-0002")
        assert _page_progress(page2).complete is True
        assert page2.total_flaws_processed == 4
        assert {e.cve_id for e in _page_entries(page2)} == {
            "CVE-2025-0003",
            "CVE-2025-0004",
        }
        # refreshed_flaws counted the whole selection, including flaw 0004,
        # which no page ever fetched.
        assert _batch_fetches(session) == [{"CVE-2025-0001"}, {"CVE-2025-0003"}]

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
        assert page1.last_cve == "CVE-2025-0001"
        assert {e.cve_id for e in _page_entries(page1)} == {"CVE-2025-0001"}

        page2 = get_osidb_bot_kpi(
            detail=True, component="kernel", limit=1, cursor="CVE-2025-0001"
        )
        assert page2.last_cve is None
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
        assert page1.last_cve == "CVE-2025-0001"
        assert [e.cve_id for e in _page_entries(page1)] == ["CVE-2025-0001"]

        page2 = get_osidb_bot_kpi(
            detail=True, changed_after=changed_after, limit=1, cursor="CVE-2025-0001"
        )
        assert page2.last_cve is None
        assert _page_progress(page2).complete is True
        assert _page_progress(page2).selected_flaws == 2
        # Only the flaw with an in-window suggestion contributes.
        assert page2.total_flaws_processed == 1
        assert page2.entries == []

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_concurrent_clients_converge(self, mock_settings, mock_bindings, cache_dir):
        """Two clients paginating the same selection simultaneously both end
        with complete, duplicate-free results; their overlapping refreshes
        do not corrupt the shared cache."""
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
            assert final.last_cve is None
            assert _page_progress(final).complete is True
            assert final.total_flaws_processed == 5
            entries = [e for page in pages for e in _page_entries(page)]
            assert {e.cve_id for e in entries} == expected
            assert len(entries) == 5

        cached = BotKPICacheEntry.model_validate_json(cache_dir.read_text())
        assert set(cached.flaws) == expected
        assert cached.total_flaws_processed == 5


class TestSelectionStampLifecycle:
    """The watermark-stamped selection index kept per filter signature.

    A run's first request (no cursor) validates the selection: a full query
    when no stamp exists, else a delta query bounded near the stamp's
    watermark plus a count that detects deletions and triggers a full
    rebuild. Cursor requests trust the matching stamp with zero OSIDB
    contact, and interleaved filter scopes beyond the LRU limit are
    evicted.
    """

    def _sole_stamp(self, cache_path: Path) -> SelectionStamp:
        """The cache's single selection stamp, asserted to be alone."""
        cached = BotKPICacheEntry.model_validate_json(cache_path.read_text())
        assert len(cached.selections) == 1
        return next(iter(cached.selections.values()))

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_first_request_full_queries_and_stamps(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """A run's first request for a filter signature with no stamp runs
        the full index query -- bounded only by the bot birthday, never by a
        watermark -- refreshes its own slice, and persists the resulting
        stamp."""
        _mock_kpi_settings(mock_settings, cache_dir)
        session = _make_session(*_numbered_flaws(2))
        mock_bindings.new_session.return_value = session

        started = datetime.now(UTC)
        response = get_osidb_bot_kpi(detail=True)

        index_calls = [
            call
            for call in session.flaws.retrieve_list_iterator.call_args_list
            if "cve_id" not in call.kwargs
        ]
        assert len(index_calls) == 1
        kwargs = index_calls[0].kwargs
        assert kwargs["created_dt_gte"] == OSIDB_BOT_BIRTHDAY
        assert "updated_dt_gte" not in kwargs
        # The page refreshed its own slice: both selected flaws.
        assert _batch_fetches(session) == [{"CVE-2025-0001", "CVE-2025-0002"}]

        assert _page_progress(response).selected_flaws == 2
        assert _page_progress(response).refreshed_flaws == 2
        assert _page_progress(response).complete is True
        assert len(_page_entries(response)) == 2

        # The stamp is persisted with the selection's watermarks.
        stamp = self._sole_stamp(cache_dir)
        assert stamp.fetched_at >= started
        assert stamp.index == {
            "CVE-2025-0001": _DEFAULT_DT,
            "CVE-2025-0002": _DEFAULT_DT,
        }
        cached = BotKPICacheEntry.model_validate_json(cache_dir.read_text())
        assert set(cached.flaws) == {"CVE-2025-0001", "CVE-2025-0002"}

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_second_request_delta_validates_near_watermark_without_writing(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """A second no-cursor request validates the stamp with a delta query
        bounded near the stamp's watermark (minus clock-skew slack), not the
        full unbounded scan; an empty delta writes nothing."""
        _mock_kpi_settings(mock_settings, cache_dir)
        # The filtering session honors updated_dt bounds like the real
        # server, so the delta query genuinely returns nothing: every flaw's
        # watermark predates the stamp.
        session = _make_filtering_session(*_numbered_flaws(2))
        mock_bindings.new_session.return_value = session

        get_osidb_bot_kpi()
        stamp = self._sole_stamp(cache_dir)
        cached_json_stamped = cache_dir.read_text()
        session.flaws.retrieve_list_iterator.reset_mock()

        get_osidb_bot_kpi()

        # Exactly one OSIDB contact: the delta validation.
        assert session.flaws.retrieve_list_iterator.call_count == 1
        delta_kwargs = session.flaws.retrieve_list_iterator.call_args.kwargs
        bound = delta_kwargs.get("updated_dt_gte")
        assert bound is not None
        # Bounded near the stamp's watermark (minutes-scale slack at most),
        # i.e. a delta query rather than the full unbounded scan.
        assert bound <= stamp.fetched_at
        assert stamp.fetched_at - bound <= timedelta(minutes=5)
        # Nothing changed, so nothing was fetched and nothing written.
        assert _batch_fetches(session) == []
        assert cache_dir.read_text() == cached_json_stamped

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_delta_reseeing_identical_watermarks_keeps_the_stamp(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """A delta that re-sees flaws at watermarks identical to the stamp's
        (e.g. flaws re-seen through the clock-skew slack window) is not a
        change: the persisted stamp and its watermark stand, and no write
        happens."""
        _mock_kpi_settings(mock_settings, cache_dir)
        # _make_session ignores query bounds, so the delta query re-returns
        # every flaw -- at the very watermarks the stamp already holds.
        session = _make_session(*_numbered_flaws(2))
        mock_bindings.new_session.return_value = session

        get_osidb_bot_kpi()
        stamp_before = self._sole_stamp(cache_dir)
        cached_json_stamped = cache_dir.read_text()
        session.flaws.retrieve_list_iterator.reset_mock()

        get_osidb_bot_kpi()

        assert session.flaws.retrieve_list_iterator.call_count == 1
        assert _batch_fetches(session) == []
        # Not re-stamped: same watermark, same bytes.
        assert self._sole_stamp(cache_dir) == stamp_before
        assert cache_dir.read_text() == cached_json_stamped

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_delta_with_advanced_watermark_merges_and_restamps(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """When the delta re-sees a flaw whose watermark advanced, the
        stamped index is merged and re-stamped at a new watermark, and the
        page fetches the flaw's new state before serving it."""
        _mock_kpi_settings(mock_settings, cache_dir)
        _seed_cache(cache_dir, {"CVE-2025-0001": _cached_flaw()})

        edited = _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("LOW")]},
            impact="LOW",
            cve_id="CVE-2025-0001",
        )
        session = _make_session(edited)
        mock_bindings.new_session.return_value = session

        # The first request stamps the selection at the flaw's old watermark.
        get_osidb_bot_kpi()
        stamp_before = self._sole_stamp(cache_dir)

        # The flaw is edited in OSIDB: watermark advances, impact changes.
        edited["updated_dt"] = "2025-08-01T00:00:00+00:00"
        edited["impact"] = "MODERATE"

        mid = get_osidb_bot_kpi(detail=True)
        # The merged, re-stamped index carries the advanced watermark.
        stamp_after = self._sole_stamp(cache_dir)
        assert stamp_after.index["CVE-2025-0001"] == "2025-08-01T00:00:00+00:00"
        assert stamp_after.fetched_at > stamp_before.fetched_at
        # The page fetched the flaw's new state before serving it.
        assert _page_progress(mid).refreshed_flaws == 1
        assert _page_progress(mid).complete is True
        assert mid.features["impact"].modified == 1
        assert _batch_fetches(session) == [{"CVE-2025-0001"}]

        # A later request serves the new state warm from the cache.
        final = get_osidb_bot_kpi()
        assert _page_progress(final).complete is True
        assert final.features["impact"].modified == 1

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_cursor_pages_trust_the_stamp_with_zero_osidb_contact(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """Cursor requests serve from the run's stamp without contacting
        OSIDB at all, so every page of a run reflects the selection as of
        the run's first request -- even if OSIDB gained flaws in between."""
        _mock_kpi_settings(mock_settings, cache_dir)
        _seed_cache(
            cache_dir,
            {
                "CVE-2025-0001": _cached_flaw(cve_id="CVE-2025-0001"),
                "CVE-2025-0002": _cached_flaw(cve_id="CVE-2025-0002"),
            },
        )
        # A fresh session per request; the second one would list a third
        # flaw that appeared in OSIDB after the run's first request.
        sessions = [
            _make_session(*_numbered_flaws(2)),
            _make_session(*_numbered_flaws(3)),
        ]
        mock_bindings.new_session.side_effect = sessions

        page1 = get_osidb_bot_kpi(detail=True, limit=1)
        assert page1.last_cve == "CVE-2025-0001"
        assert _page_progress(page1).selected_flaws == 2

        page2 = get_osidb_bot_kpi(detail=True, limit=1, cursor="CVE-2025-0001")

        # The trusting page made zero OSIDB index calls...
        assert sessions[1].flaws.retrieve_list_iterator.call_count == 0
        # ...so the run still serves the two-flaw selection it started with,
        # not the three flaws OSIDB now lists.
        assert page2.last_cve is None
        assert _page_progress(page2).selected_flaws == 2
        assert _page_progress(page2).complete is True
        assert [e.cve_id for e in _page_entries(page2)] == ["CVE-2025-0002"]

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_cursor_request_without_stamp_self_heals_via_full_query(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """A cursor request whose signature has no stamp (cold cache, evicted
        stamp, or a filter first paginated mid-run) neither fails nor serves
        an empty page: it falls back to the validating full query, stamps,
        refreshes its own slice, and serves; the run's following pages then
        trust that stamp."""
        _mock_kpi_settings(mock_settings, cache_dir)
        session = _make_session(*_numbered_flaws(3))
        mock_bindings.new_session.return_value = session

        page = get_osidb_bot_kpi(detail=True, cursor="CVE-2025-0002")

        # Self-healing: one full query (no watermark-derived bound), and the
        # slice's single uncached flaw is fetched and served.
        index_calls = [
            call
            for call in session.flaws.retrieve_list_iterator.call_args_list
            if "cve_id" not in call.kwargs
        ]
        assert len(index_calls) == 1
        assert "updated_dt_gte" not in index_calls[0].kwargs
        assert _batch_fetches(session) == [{"CVE-2025-0003"}]
        assert page.last_cve is None
        assert _page_progress(page).selected_flaws == 3
        assert _page_progress(page).refreshed_flaws == 1
        assert _page_progress(page).complete is False
        assert {e.cve_id for e in _page_entries(page)} == {"CVE-2025-0003"}

        # The self-heal stamped the selection, so the next cursor page
        # trusts it with zero OSIDB contact.
        session.flaws.retrieve_list_iterator.reset_mock()
        resumed = get_osidb_bot_kpi(detail=True, cursor="CVE-2025-0002")
        assert session.flaws.retrieve_list_iterator.call_count == 0
        assert _page_progress(resumed).selected_flaws == 3

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_each_filter_signature_gets_its_own_stamp(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """Two filter scopes stamp independently: the component-scoped
        selection and the unfiltered selection each keep their own index,
        and each scope's cursor pages trust their own stamp."""
        _mock_kpi_settings(mock_settings, cache_dir)
        kernel = _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("LOW")]},
            impact="LOW",
            cve_id="CVE-2025-0001",
        )
        openssl = _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("LOW")]},
            impact="LOW",
            cve_id="CVE-2025-0002",
        )
        session = _make_component_session({"kernel": [kernel], "openssl": [openssl]})
        mock_bindings.new_session.return_value = session

        _seed_cache(
            cache_dir,
            {
                "CVE-2025-0001": _cached_flaw(cve_id="CVE-2025-0001"),
                "CVE-2025-0002": _cached_flaw(cve_id="CVE-2025-0002"),
            },
        )

        get_osidb_bot_kpi(component="kernel")
        get_osidb_bot_kpi()

        cached = BotKPICacheEntry.model_validate_json(cache_dir.read_text())
        assert len(cached.selections) == 2
        # One stamp holds exactly the kernel selection, the other the whole
        # two-flaw selection: each scope validated its own index.
        indices = {frozenset(stamp.index) for stamp in cached.selections.values()}
        assert indices == {
            frozenset({"CVE-2025-0001"}),
            frozenset({"CVE-2025-0001", "CVE-2025-0002"}),
        }

        # Each scope's cursor pages trust their own stamp: no OSIDB contact.
        session.flaws.retrieve_list_iterator.reset_mock()
        get_osidb_bot_kpi(component="kernel", cursor="CVE-2025-0001")
        get_osidb_bot_kpi(cursor="CVE-2025-0001")
        assert session.flaws.retrieve_list_iterator.call_count == 0

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_fifth_distinct_signature_evicts_the_least_recently_stamped(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """At most four filter signatures keep stamps; a fifth distinct
        signature evicts the least recently stamped one, not the newest."""
        _mock_kpi_settings(mock_settings, cache_dir)
        flaws = _numbered_flaws(2)
        now = datetime.now(UTC)
        dates = [datetime(2025, 1, day, tzinfo=UTC) for day in (1, 2, 3, 4)]
        ages = (
            timedelta(hours=4),
            timedelta(hours=3),
            timedelta(hours=2),
            timedelta(hours=1),
        )

        def _sig(changed_after):
            return selection_signature(changed_after, None, None)

        _seed_stamped_cache(
            cache_dir,
            {f["cve_id"]: _cached_flaw(cve_id=f["cve_id"]) for f in flaws},
            {
                _sig(date): SelectionStamp(
                    index={f["cve_id"]: f["updated_dt"] for f in flaws},
                    fetched_at=now - age,
                )
                for date, age in zip(dates, ages, strict=True)
            },
        )
        session = _make_session(*flaws)
        mock_bindings.new_session.return_value = session

        fifth = datetime(2025, 2, 1, tzinfo=UTC)
        response = get_osidb_bot_kpi(changed_after=fifth)
        assert response.total_flaws_processed == 2

        cached = BotKPICacheEntry.model_validate_json(cache_dir.read_text())
        # The oldest stamp (Jan 1) was evicted; the newer three and the
        # freshly stamped fifth signature remain.
        assert set(cached.selections) == {_sig(date) for date in dates[1:]} | {
            _sig(fifth)
        }

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_nothing_stale_request_persists_new_stamp(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """Regression test: a request that finds nothing stale must still
        persist a newly resolved selection stamp. Without it, a client on an
        already-fresh selection with no stamp for its signature (a second
        filter scope, an evicted stamp) re-ran the full index scan on every
        request -- the stamp was built and then dropped by the nothing-stale
        early return."""
        _mock_kpi_settings(mock_settings, cache_dir)
        # Everything cached and fresh, but no stamp for this signature yet.
        seeded = {"CVE-2025-0001": _cached_flaw()}
        _seed_cache(cache_dir, seeded)
        session = _make_session(*_numbered_flaws(1))
        mock_bindings.new_session.return_value = session

        first = get_osidb_bot_kpi()
        assert first.total_flaws_processed == 1
        # The first request paid the full, unbounded index query...
        index_calls = [
            call
            for call in session.flaws.retrieve_list_iterator.call_args_list
            if "cve_id" not in call.kwargs
        ]
        assert len(index_calls) == 1
        assert "updated_dt_gte" not in index_calls[0].kwargs
        # ...and fetched nothing (its slice was already fresh), so the write
        # carried only the stamp and left the flaw entries untouched.
        assert _batch_fetches(session) == []
        stamp = self._sole_stamp(cache_dir)
        cached = BotKPICacheEntry.model_validate_json(cache_dir.read_text())
        assert cached.flaws == seeded
        cache_json_after_first = cache_dir.read_text()

        session.flaws.retrieve_list_iterator.reset_mock()
        second = get_osidb_bot_kpi()
        assert second.total_flaws_processed == 1

        # The second request is only a delta query bounded near the stamp's
        # watermark (minutes-scale clock-skew slack at most)...
        assert session.flaws.retrieve_list_iterator.call_count == 1
        bound = session.flaws.retrieve_list_iterator.call_args.kwargs.get(
            "updated_dt_gte"
        )
        assert bound is not None
        assert bound <= stamp.fetched_at
        assert stamp.fetched_at - bound <= timedelta(minutes=5)
        # ...that fetches nothing and, the delta being unchanged, writes
        # nothing either.
        assert _batch_fetches(session) == []
        assert cache_dir.read_text() == cache_json_after_first


class TestDeletionDetection:
    """Deletions, which delta queries cannot see, are caught by a cheap
    OSIDB count at run start.

    The count runs over the same selection filters as the index (bounded
    by the bot birthday, never carrying the delta's watermark bound), so
    it counts exactly the set the stamp's index selected. When OSIDB holds
    fewer flaws than the stamp indexed -- flaws were deleted, or left the
    DONE state -- the selection is rebuilt with the full unbounded query;
    a count at or above the index size means delta extension only.
    """

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_lower_count_rebuilds_selection_in_full_and_restamps(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """A flaw that left the selection stays in the stamped index -- the
        delta query only adds and updates -- but the count catches it: OSIDB
        holds two of the stamp's three flaws, so the run start re-runs the
        full unbounded index query and re-stamps the shrunken selection.
        The survivors were already fresh, so the rebuild fetches no flaw
        data, and the deleted flaw's cache entry is retained: selection
        never evicts."""
        _mock_kpi_settings(mock_settings, cache_dir)
        flaws = _numbered_flaws(3)
        seeded_flaws = {f["cve_id"]: _cached_flaw(cve_id=f["cve_id"]) for f in flaws}
        _seed_stamped_cache(
            cache_dir,
            seeded_flaws,
            {
                selection_signature(None, None, None): SelectionStamp(
                    index={f["cve_id"]: f["updated_dt"] for f in flaws},
                    fetched_at=datetime.now(UTC),
                )
            },
        )
        # OSIDB now lists only the first two flaws; the third was deleted.
        session = _make_session(*flaws[:2])
        # The count agrees with the listing: two of the stamp's three.
        session.flaws.count.side_effect = lambda **kwargs: 2
        mock_bindings.new_session.return_value = session

        started = datetime.now(UTC)
        response = get_osidb_bot_kpi(detail=True)

        # The count query carries the selection filters -- bounded by the
        # bot birthday like the index, and without the delta's watermark
        # bound, so it counts the same set the index selects.
        assert session.flaws.count.call_count == 1
        count_kwargs = session.flaws.count.call_args.kwargs
        assert count_kwargs["workflow_state"] == "DONE"
        assert count_kwargs["created_dt_gte"] == OSIDB_BOT_BIRTHDAY
        assert count_kwargs["cve_id__isempty"] is False
        assert "updated_dt_gte" not in count_kwargs

        # Delta validation first, then the full rebuild the deficit
        # triggered -- unbounded by any watermark, still birthday-bounded.
        index_calls = _index_calls(session)
        assert len(index_calls) == 2
        assert index_calls[0].kwargs["updated_dt_gte"] is not None
        assert "updated_dt_gte" not in index_calls[1].kwargs
        assert index_calls[1].kwargs["created_dt_gte"] == OSIDB_BOT_BIRTHDAY

        # The shrunken selection is served and re-stamped...
        assert _page_progress(response).selected_flaws == 2
        assert _page_progress(response).complete is True
        assert response.total_flaws_processed == 2
        assert {e.cve_id for e in _page_entries(response)} == {
            "CVE-2025-0001",
            "CVE-2025-0002",
        }
        cached = BotKPICacheEntry.model_validate_json(cache_dir.read_text())
        assert len(cached.selections) == 1
        stamp = next(iter(cached.selections.values()))
        assert stamp.index == {
            "CVE-2025-0001": _DEFAULT_DT,
            "CVE-2025-0002": _DEFAULT_DT,
        }
        assert stamp.fetched_at >= started
        # ...the rebuild is index-only (the survivors were already fresh)...
        assert _batch_fetches(session) == []
        # ...and the deleted flaw's cache entry is retained, not pruned.
        assert set(cached.flaws) == set(seeded_flaws)

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_count_at_or_above_index_size_never_rebuilds_in_full(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """Only a deficit rebuilds. Run starts whose count equals the
        stamp's index size (nothing deleted) or exceeds it (OSIDB holds
        flaws the delta window has yet to merge) stay delta-extension only:
        the full unbounded scan never re-runs, nothing is fetched, and
        nothing is written. A cold run start (no stamp) never runs the
        count at all -- the full query is its validation."""
        _mock_kpi_settings(mock_settings, cache_dir)
        session = _make_filtering_session(*_numbered_flaws(2))
        # Two validating run starts follow the cold one: count == index
        # size, then a count above it (a surplus is not a deletion signal).
        session.flaws.count.side_effect = [2, 5]
        mock_bindings.new_session.return_value = session

        # Cold run start: the stamp is built by the full query alone.
        first = get_osidb_bot_kpi()
        assert first.total_flaws_processed == 2
        assert session.flaws.count.call_count == 0
        assert len(_index_calls(session)) == 1
        assert "updated_dt_gte" not in _index_calls(session)[0].kwargs
        cache_json_stamped = cache_dir.read_text()

        # Second run start: the count equals the index size. Delta only.
        assert get_osidb_bot_kpi().total_flaws_processed == 2
        # Third run start: the count exceeds it. Still delta only.
        assert get_osidb_bot_kpi().total_flaws_processed == 2

        assert session.flaws.count.call_count == 2
        # One full query (the cold start) plus two bounded deltas; the only
        # flaw fetch was the cold start's own slice, and nothing was
        # written since.
        index_calls = _index_calls(session)
        assert len(index_calls) == 3
        assert "updated_dt_gte" not in index_calls[0].kwargs
        assert all(
            call.kwargs["updated_dt_gte"] is not None for call in index_calls[1:]
        )
        assert _batch_fetches(session) == [{"CVE-2025-0001", "CVE-2025-0002"}]
        assert cache_dir.read_text() == cache_json_stamped


class TestDeliveredFlawsProgress:
    """delivered_flaws reports the cumulative count of selected flaws a
    paginating client has received once it appends the page's entries."""

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_counts_cumulative_position_per_page(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """Page N of a limit-L pagination reports L*N flaws delivered, except
        the final page, which reports the whole selection's size."""
        _mock_kpi_settings(mock_settings, cache_dir)
        session = _make_session(*_numbered_flaws(7))
        mock_bindings.new_session.return_value = session

        pages = _paginate(detail=True, limit=3)

        assert len(pages) == 3
        assert [_page_progress(page).delivered_flaws for page in pages] == [3, 6, 7]
        # The count is consistent with the cursor chain: each page delivers
        # through the flaw the next request resumes from.
        assert [page.last_cve for page in pages[:2]] == [
            "CVE-2025-0003",
            "CVE-2025-0006",
        ]
        assert pages[-1].last_cve is None

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_counts_position_without_detail(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """delivered_flaws is a property of the pagination, not the entries:
        detail=false pages report it identically."""
        _mock_kpi_settings(mock_settings, cache_dir)
        session = _make_session(*_numbered_flaws(5))
        mock_bindings.new_session.return_value = session

        pages = _paginate(limit=2)

        assert [_page_progress(page).delivered_flaws for page in pages] == [2, 4, 5]
        assert all(page.entries is None for page in pages)

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_zero_for_empty_selection(self, mock_settings, mock_bindings, cache_dir):
        """An empty selection delivers a single final page reporting zero
        selected, refreshed, and delivered flaws."""
        _mock_kpi_settings(mock_settings, cache_dir)
        session = _make_session()
        mock_bindings.new_session.return_value = session

        response = get_osidb_bot_kpi(detail=True)

        progress = _page_progress(response)
        assert progress.selected_flaws == 0
        assert progress.delivered_flaws == 0
        assert progress.refreshed_flaws == 0
        assert progress.complete is True
        assert response.last_cve is None
        assert _page_entries(response) == []
