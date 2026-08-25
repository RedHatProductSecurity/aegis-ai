"""Tests for osidb-bot KPI cache orchestration."""

import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aegis_ai_web.src.endpoints.bot_kpi import (
    OSIDB_BOT_BIRTHDAY,
    BotKPICacheEntry,
    FlawCacheData,
    _cache_handler,
    _fetch_flaw_index,
    _flaw_cache_data,
    _get_cache_path,
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


def _make_session(*flaws, index_delay=0.0):
    """Build a mock OSIDB session for the two-phase fetch.

    ``flaws`` are full flaw dicts (each with ``cve_id`` + ``updated_dt``). The
    first-phase index iterator yields ``{cve_id, updated_dt}`` stubs; the
    second-phase batch iterator (called with ``cve_id=[...]``) returns full flaw
    data for the requested IDs. This lets tests assert exactly which flaws were
    fetched in full versus served from the cache via the index alone.
    """
    by_cve = {flaw["cve_id"]: flaw for flaw in flaws}

    def _list_iterator(**kwargs):
        if index_delay:
            time.sleep(index_delay)
        requested = kwargs.get("cve_id")
        if requested is not None:
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


def _seed_cache(cache_path: Path, flaws: dict[str, FlawCacheData]) -> None:
    """Write a per-flaw cache directly from ``FlawCacheData`` entries."""
    entry = BotKPICacheEntry(flaws=flaws)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(entry.model_dump_json())


def _cached_flaw(
    applied=1, *, updated_dt=_DEFAULT_DT, suggestion_dt=None, current_impact="LOW"
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
        updated_dt=updated_dt,
    )
    return _flaw_cache_data(flaw, updated_dt)


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
        # no update-date filter given, so none is pushed down
        assert "updated_dt_gte" not in kwargs
        assert "updated_dt_lte" not in kwargs

    def test_pushes_changed_after_as_update_lower_bound(self):
        after = datetime(2026, 6, 1, tzinfo=UTC)
        kwargs = self._captured_kwargs(changed_after=after)
        # creation bound stays; changed_after applies to updated_dt
        assert kwargs["created_dt_gte"] == OSIDB_BOT_BIRTHDAY
        assert kwargs["updated_dt_gte"] == after

    def test_pushes_changed_before_as_update_upper_bound(self):
        before = datetime(2026, 6, 1, tzinfo=UTC)
        kwargs = self._captured_kwargs(changed_before=before)
        assert kwargs["created_dt_gte"] == OSIDB_BOT_BIRTHDAY
        assert kwargs["updated_dt_lte"] == before
        assert "updated_dt_gte" not in kwargs


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
        assert loaded.to_kpi_result().features["impact"].suggested == 3

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
    def test_date_filter_returns_subset_without_altering_cache(
        self, mock_settings, mock_bindings, cache_dir
    ):
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

        # Index returns the same two flaws with identical watermarks: nothing to
        # re-fetch, and the set is unchanged, so the cache is served as-is.
        session = _make_session(
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

        from datetime import UTC, datetime

        response = get_osidb_bot_kpi(changed_after=datetime(2025, 6, 1, tzinfo=UTC))
        assert response.total_flaws_processed == 1

        # Only the index call; no batch fetch for unchanged flaws.
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
    def test_unfiltered_query_prunes_departed_flaw(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """An unfiltered request sees a complete index (every DONE flaw), so a
        cached flaw absent from it has left DONE and is pruned -- and no longer
        counted."""
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_settings.return_value.config_dir = str(cache_dir.parent.parent)

        _seed_cache(
            cache_dir,
            {
                "CVE-2025-0001": _cached_flaw(),
                "CVE-2025-0002": _cached_flaw(),
            },
        )

        # Complete (unfiltered) index now lists only CVE-2025-0001; the other has
        # left DONE.
        session = _make_session(
            _make_flaw_dict(
                {"processed": True, "impact": [_make_bot_entry("LOW")]},
                cve_id="CVE-2025-0001",
            )
        )
        mock_bindings.new_session.return_value = session

        response = get_osidb_bot_kpi()

        # The departed flaw is pruned and no longer counted.
        assert response.total_flaws_processed == 1
        cached = BotKPICacheEntry.model_validate_json(cache_dir.read_text())
        assert set(cached.flaws) == {"CVE-2025-0001"}

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_date_bounded_query_retains_out_of_window_flaw(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """A date-bounded index is only a window, so a cached flaw absent from it
        is retained (it may simply be outside the window), not pruned -- pruning
        would evict flaws from other windows and force a full re-fetch on every
        alternation (see ``_reconcile_flaws``)."""
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_settings.return_value.config_dir = str(cache_dir.parent.parent)

        _seed_cache(
            cache_dir,
            {
                "CVE-2025-0001": _cached_flaw(),
                "CVE-2025-0002": _cached_flaw(),
            },
        )

        # Date-bounded index lists only CVE-2025-0001.
        session = _make_session(
            _make_flaw_dict(
                {"processed": True, "impact": [_make_bot_entry("LOW")]},
                cve_id="CVE-2025-0001",
            )
        )
        mock_bindings.new_session.return_value = session

        get_osidb_bot_kpi(changed_after=datetime(2025, 1, 1, tzinfo=UTC))

        # Both flaws survive; the absent one is kept, not deleted, and not
        # re-fetched (index call only, no batch fetch).
        assert session.flaws.retrieve_list_iterator.call_count == 1
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
        """Regression test: querying two non-overlapping date ranges in turn must
        not flush each other's flaws from the shared cache.

        A flaw's single ``updated_dt`` cannot fall in two disjoint windows, so
        each window's index is a disjoint set. Rebuilding the cache to the current
        index (the old behavior) evicted the other window entirely, forcing a full
        re-fetch on every alternation. Merging retains both.
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

        # A fresh session per request; each window's index lists only its own
        # flaw, because a flaw's updated_dt cannot fall in both windows.
        session_a1 = _make_session(flaw_a)
        session_b = _make_session(flaw_b)
        session_a2 = _make_session(flaw_a)
        mock_bindings.new_session.side_effect = [session_a1, session_b, session_a2]

        # 1. Range A fetches flaw A in full.
        get_osidb_bot_kpi(changed_after=range_a[0], changed_before=range_a[1])
        # 2. Range B fetches flaw B; it must not evict flaw A.
        get_osidb_bot_kpi(changed_after=range_b[0], changed_before=range_b[1])

        cached = BotKPICacheEntry.model_validate_json(cache_dir.read_text())
        assert set(cached.flaws) == {"CVE-2026-0001", "CVE-2026-0002"}

        # 3. Range A again: flaw A is still cached, so only the index is queried --
        # no full re-fetch. The date filter still scopes the result to range A.
        response = get_osidb_bot_kpi(
            changed_after=range_a[0], changed_before=range_a[1]
        )
        assert response.total_flaws_processed == 1
        assert session_a2.flaws.retrieve_list_iterator.call_count == 1

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
