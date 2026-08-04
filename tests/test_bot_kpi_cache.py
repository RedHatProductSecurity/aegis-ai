"""Tests for osidb-bot KPI cache orchestration."""

import threading
import time
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aegis_ai_web.src.endpoints.bot_kpi import (
    BotKPICacheEntry,
    BotKPIResult,
    FeatureStats,
    _get_cache_path,
    _load_cache,
    _save_cache,
    get_osidb_bot_kpi,
)

_BOT_KPI_MODULE = "aegis_ai_web.src.endpoints.bot_kpi"


def _make_bot_entry(value, *, dq=0.9, conf=0.85):
    return {
        "type": "AI-Bot",
        "value": value,
        "explanation": "test",
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
        "aegis_meta": aegis_meta,
    }
    flaw.update(overrides)
    return flaw


class _RecordingClock:
    """Stand-in for the `datetime` name used by bot_kpi's `datetime.now(...)` calls.

    Records that `now()` was invoked (in `events`) and returns a real timestamp,
    so call order relative to other recorded events (e.g. a mocked fetch) can be
    asserted without needing to freeze or fake the actual time value.
    """

    def __init__(self, events: list[str]):
        self._events = events

    def now(self, tz=None):
        self._events.append("cutoff")
        return datetime.now(tz)


def _seed_cache(cache_path: Path, result: BotKPIResult, cutoff: datetime) -> None:
    """Seed a per-flaw cache whose resummed aggregate matches `result`.

    Synthesizes one flaw carrying all of `result`'s feature stats, padded
    with empty-stats flaw entries so `total_flaws_processed` (now `len(flaws)`)
    matches exactly -- these tests only care about the resulting aggregate
    and count, not realistic per-flaw data.
    """
    flaws: dict[str, dict[str, dict[str, float]]] = {}
    remaining = result.total_flaws_processed
    if result.features:
        flaws["CVE-SEED-0000"] = {
            name: asdict(stats) for name, stats in result.features.items()
        }
        remaining -= 1
    for i in range(max(remaining, 0)):
        flaws[f"CVE-SEED-PAD-{i:04d}"] = {}
    entry = BotKPICacheEntry.build(flaws, cutoff)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(entry.model_dump_json())


@pytest.fixture()
def cache_dir(tmp_path, monkeypatch):
    cache_path = tmp_path / "osidb_bot_kpi" / "kpi_cache.json"
    monkeypatch.setattr(
        "aegis_ai_web.src.endpoints.bot_kpi._get_cache_path",
        lambda: cache_path,
    )
    return cache_path


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
        assert _load_cache() is None

    def test_save_and_load_round_trip(self, cache_dir):
        cutoff = datetime(2025, 7, 1, tzinfo=UTC)
        entry = BotKPICacheEntry.build(
            {"CVE-2025-0001": {"impact": asdict(FeatureStats(applied=3, kept=2))}},
            cutoff,
        )
        _save_cache(entry)
        loaded = _load_cache()
        assert loaded is not None
        assert loaded.cutoff == cutoff
        assert loaded.total_flaws_processed == 1
        assert loaded.to_kpi_result().features["impact"].applied == 3

    def test_corrupt_cache_returns_none(self, cache_dir):
        cache_dir.parent.mkdir(parents=True, exist_ok=True)
        cache_dir.write_text("not valid json {{{")
        assert _load_cache() is None

    def test_old_schema_cache_returns_none(self, cache_dir):
        """A cache file from before the per-flaw schema (flat aggregate sums
        + a seen-IDs list, no `flaws`/`aggregate` keys) must be treated as
        absent, triggering one full refresh rather than a crash or a
        silently-empty cache."""
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
        assert _load_cache() is None

    def test_save_failure_does_not_raise(self, cache_dir, monkeypatch):
        monkeypatch.setattr(
            "aegis_ai_web.src.endpoints.bot_kpi._get_cache_path",
            lambda: Path("/nonexistent/dir/cache.json"),
        )
        cutoff = datetime(2025, 7, 1, tzinfo=UTC)
        entry = BotKPICacheEntry.build({}, cutoff)
        _save_cache(entry)


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
        mock_flaw = MagicMock()
        mock_flaw.to_dict.return_value = flaw_data
        mock_session = MagicMock()
        mock_session.flaws.retrieve_list_iterator.return_value = iter([mock_flaw])
        mock_bindings.new_session.return_value = mock_session

        response = get_osidb_bot_kpi()
        assert response.total_flaws_processed == 1
        assert response.features["impact"].kept == 1

        assert cache_dir.is_file()
        cached = BotKPICacheEntry.model_validate_json(cache_dir.read_text())
        assert cached.total_flaws_processed == 1

    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_incremental_with_cache(self, mock_settings, mock_bindings, cache_dir):
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_settings.return_value.config_dir = str(cache_dir.parent.parent)

        cached_result = BotKPIResult(
            total_flaws_processed=10,
            features={"impact": FeatureStats(applied=8, kept=6, modified=2)},
        )
        cutoff = datetime(2025, 6, 1, tzinfo=UTC)
        _seed_cache(cache_dir, cached_result, cutoff)

        new_flaw = _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("MODERATE")]},
            impact="MODERATE",
        )
        mock_flaw = MagicMock()
        mock_flaw.to_dict.return_value = new_flaw
        mock_session = MagicMock()
        mock_session.flaws.retrieve_list_iterator.return_value = iter([mock_flaw])
        mock_bindings.new_session.return_value = mock_session

        response = get_osidb_bot_kpi()
        assert response.total_flaws_processed == 11
        assert response.features["impact"].applied == 9
        assert response.features["impact"].kept == 7

        call_kwargs = mock_session.flaws.retrieve_list_iterator.call_args[1]
        assert call_kwargs["updated_dt__gte"] == cutoff

    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_full_refresh_overwrites_cache(
        self, mock_settings, mock_bindings, cache_dir
    ):
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_settings.return_value.config_dir = str(cache_dir.parent.parent)

        old_result = BotKPIResult(
            total_flaws_processed=100,
            features={"impact": FeatureStats(applied=80)},
        )
        _seed_cache(cache_dir, old_result, datetime(2025, 1, 1, tzinfo=UTC))

        flaw_data = _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("LOW")]},
            impact="LOW",
        )
        mock_flaw = MagicMock()
        mock_flaw.to_dict.return_value = flaw_data
        mock_session = MagicMock()
        mock_session.flaws.retrieve_list_iterator.return_value = iter([mock_flaw])
        mock_bindings.new_session.return_value = mock_session

        response = get_osidb_bot_kpi(full_refresh=True)
        assert response.total_flaws_processed == 1

        cached = BotKPICacheEntry.model_validate_json(cache_dir.read_text())
        assert cached.total_flaws_processed == 1

        call_kwargs = mock_session.flaws.retrieve_list_iterator.call_args[1]
        assert "updated_dt__gte" not in call_kwargs

    @patch("aegis_ai_web.src.endpoints.bot_kpi.osidb_bindings")
    @patch("aegis_ai_web.src.endpoints.bot_kpi.get_settings")
    def test_date_filter_skips_cache(self, mock_settings, mock_bindings, cache_dir):
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_settings.return_value.config_dir = str(cache_dir.parent.parent)

        old_result = BotKPIResult(total_flaws_processed=50)
        _seed_cache(cache_dir, old_result, datetime(2025, 6, 1, tzinfo=UTC))

        mock_session = MagicMock()
        mock_session.flaws.retrieve_list_iterator.return_value = iter([])
        mock_bindings.new_session.return_value = mock_session

        after = datetime(2025, 5, 1, tzinfo=UTC)
        response = get_osidb_bot_kpi(changed_after=after)
        assert response.total_flaws_processed == 0

        cached = BotKPICacheEntry.model_validate_json(cache_dir.read_text())
        assert cached.total_flaws_processed == 50

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_full_refresh_with_date_filter_does_not_corrupt_cache(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """full_refresh + date filters must not save a partial result as cache."""
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"

        old_result = BotKPIResult(total_flaws_processed=50)
        _seed_cache(cache_dir, old_result, datetime(2025, 6, 1, tzinfo=UTC))

        flaw_data = _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("LOW")]},
            impact="LOW",
        )
        mock_flaw = MagicMock()
        mock_flaw.to_dict.return_value = flaw_data
        mock_session = MagicMock()
        mock_session.flaws.retrieve_list_iterator.return_value = iter([mock_flaw])
        mock_bindings.new_session.return_value = mock_session

        after = datetime(2025, 7, 1, tzinfo=UTC)
        response = get_osidb_bot_kpi(full_refresh=True, changed_after=after)
        assert response.total_flaws_processed == 1

        cached = BotKPICacheEntry.model_validate_json(cache_dir.read_text())
        assert cached.total_flaws_processed == 50

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
        mock_flaw = MagicMock()
        mock_flaw.to_dict.return_value = flaw_data
        mock_session = MagicMock()
        mock_session.flaws.retrieve_list_iterator.return_value = iter([mock_flaw])
        mock_bindings.new_session.return_value = mock_session

        response = get_osidb_bot_kpi()
        assert response.total_flaws_processed == 1
        assert response.features["impact"].kept == 1

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_reseeing_unchanged_flaw_does_not_double_count(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """Re-fetching an unchanged, already-cached flaw overwrites its
        entry with identical data, so it must not be double-counted."""
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"

        cutoff = datetime(2025, 6, 1, tzinfo=UTC)
        entry = BotKPICacheEntry.build(
            {"CVE-2025-0001": {"impact": asdict(FeatureStats(applied=1, kept=1))}},
            cutoff,
        )
        cache_dir.parent.mkdir(parents=True, exist_ok=True)
        cache_dir.write_text(entry.model_dump_json())

        re_seen_flaw = _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("LOW")]},
            impact="LOW",
            cve_id="CVE-2025-0001",
        )
        mock_flaw = MagicMock()
        mock_flaw.to_dict.return_value = re_seen_flaw
        mock_session = MagicMock()
        mock_session.flaws.retrieve_list_iterator.return_value = iter([mock_flaw])
        mock_bindings.new_session.return_value = mock_session

        response = get_osidb_bot_kpi()
        assert response.total_flaws_processed == 1
        assert response.features["impact"].applied == 1
        assert response.features["impact"].kept == 1

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_incremental_counts_new_flaw_and_updates_reseen(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """A genuinely new flaw is added; a re-seen unchanged flaw is not
        double-counted (its entry is overwritten with the same data)."""
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"

        cutoff = datetime(2025, 6, 1, tzinfo=UTC)
        entry = BotKPICacheEntry.build(
            {"CVE-2025-0001": {"impact": asdict(FeatureStats(applied=1, kept=1))}},
            cutoff,
        )
        cache_dir.parent.mkdir(parents=True, exist_ok=True)
        cache_dir.write_text(entry.model_dump_json())

        re_seen = _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("LOW")]},
            impact="LOW",
            cve_id="CVE-2025-0001",
        )
        new_flaw = _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("MODERATE")]},
            impact="MODERATE",
            cve_id="CVE-2025-0002",
        )
        mock_flaws = [MagicMock(), MagicMock()]
        mock_flaws[0].to_dict.return_value = re_seen
        mock_flaws[1].to_dict.return_value = new_flaw
        mock_session = MagicMock()
        mock_session.flaws.retrieve_list_iterator.return_value = iter(mock_flaws)
        mock_bindings.new_session.return_value = mock_session

        response = get_osidb_bot_kpi()
        assert response.total_flaws_processed == 2
        assert response.features["impact"].applied == 2
        assert response.features["impact"].kept == 2

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_reseen_flaw_with_changed_value_is_rescored_not_frozen(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """Regression test for the staleness bug: a flaw whose current value
        changed since it was first cached (e.g. an analyst edited it after
        the bot's initial pass) must be re-scored using the new value, not
        permanently frozen at its first-seen classification."""
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"

        cutoff = datetime(2025, 6, 1, tzinfo=UTC)
        entry = BotKPICacheEntry.build(
            {"CVE-2025-0001": {"impact": asdict(FeatureStats(applied=1, kept=1))}},
            cutoff,
        )
        cache_dir.parent.mkdir(parents=True, exist_ok=True)
        cache_dir.write_text(entry.model_dump_json())

        # Bot suggested LOW and it was initially kept; an analyst has since
        # changed the flaw's impact to MODERATE.
        edited_flaw = _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("LOW")]},
            impact="MODERATE",
            cve_id="CVE-2025-0001",
        )
        mock_flaw = MagicMock()
        mock_flaw.to_dict.return_value = edited_flaw
        mock_session = MagicMock()
        mock_session.flaws.retrieve_list_iterator.return_value = iter([mock_flaw])
        mock_bindings.new_session.return_value = mock_session

        response = get_osidb_bot_kpi()
        assert response.total_flaws_processed == 1
        assert response.features["impact"].applied == 1
        assert response.features["impact"].kept == 0
        assert response.features["impact"].modified == 1

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_no_changes_returns_cached_aggregate_without_resum(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """A fetch that finds nothing new must serve the cached aggregate
        as-is -- no lock, no resum -- so cost scales with how often data
        actually changes, not with how often the endpoint is polled."""
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"

        cutoff = datetime(2025, 6, 1, tzinfo=UTC)
        entry = BotKPICacheEntry.build(
            {"CVE-2025-0001": {"impact": asdict(FeatureStats(applied=1, kept=1))}},
            cutoff,
        )
        cache_dir.parent.mkdir(parents=True, exist_ok=True)
        cache_dir.write_text(entry.model_dump_json())
        cached_json_before = cache_dir.read_text()

        mock_session = MagicMock()
        mock_session.flaws.retrieve_list_iterator.return_value = iter([])
        mock_bindings.new_session.return_value = mock_session

        with patch(f"{_BOT_KPI_MODULE}._save_cache") as mock_save_cache:
            response = get_osidb_bot_kpi()
            mock_save_cache.assert_not_called()

        assert response.total_flaws_processed == 1
        assert response.features["impact"].applied == 1
        assert response.features["impact"].kept == 1
        assert cache_dir.read_text() == cached_json_before

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_full_refresh_populates_per_flaw_entries(
        self, mock_settings, mock_bindings, cache_dir
    ):
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"

        flaw_data = _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("LOW")]},
            impact="LOW",
        )
        mock_flaw = MagicMock()
        mock_flaw.to_dict.return_value = flaw_data
        mock_session = MagicMock()
        mock_session.flaws.retrieve_list_iterator.return_value = iter([mock_flaw])
        mock_bindings.new_session.return_value = mock_session

        get_osidb_bot_kpi(full_refresh=True)

        cached = BotKPICacheEntry.model_validate_json(cache_dir.read_text())
        assert list(cached.flaws.keys()) == ["CVE-2025-0001"]

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_cutoff_captured_before_fetch_runs(
        self, mock_settings, mock_bindings, cache_dir, monkeypatch
    ):
        """Regression test: cutoff must be stamped before the OSIDB query runs,
        not after, or flaws updated mid-fetch are permanently skipped by the
        next incremental fetch's `changed_after=cutoff` filter."""
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_settings.return_value.config_dir = str(cache_dir.parent.parent)
        mock_bindings.new_session.return_value = MagicMock()

        events: list[str] = []
        monkeypatch.setattr(f"{_BOT_KPI_MODULE}.datetime", _RecordingClock(events))

        def fake_fetch(osidb, *, changed_after=None, changed_before=None):
            events.append("fetch")
            return []

        monkeypatch.setattr(f"{_BOT_KPI_MODULE}.fetch_bot_processed_flaws", fake_fetch)

        get_osidb_bot_kpi()

        assert events == ["cutoff", "fetch"]

    @patch(f"{_BOT_KPI_MODULE}.osidb_bindings")
    @patch(f"{_BOT_KPI_MODULE}.get_settings")
    def test_concurrent_requests_do_not_corrupt_cache(
        self, mock_settings, mock_bindings, cache_dir
    ):
        """Regression test: concurrent requests must not race on the cache's
        read-modify-write cycle and clobber each other's results."""
        mock_settings.return_value.osidb_server_url = "https://osidb.example.com"
        mock_settings.return_value.config_dir = str(cache_dir.parent.parent)

        def make_session(cve_id):
            flaw_data = _make_flaw_dict(
                {"processed": True, "impact": [_make_bot_entry("LOW")]},
                impact="LOW",
                cve_id=cve_id,
            )
            mock_flaw = MagicMock()
            mock_flaw.to_dict.return_value = flaw_data
            session = MagicMock()

            def iterator(**kwargs):
                # Sleep while the cache lock is held so the two requests'
                # read-modify-write cycles are forced to overlap without it.
                time.sleep(0.05)
                return iter([mock_flaw])

            session.flaws.retrieve_list_iterator.side_effect = iterator
            return session

        sessions = [make_session("CVE-2025-0001"), make_session("CVE-2025-0002")]
        mock_bindings.new_session.side_effect = lambda **kwargs: sessions.pop(0)

        responses = []

        def run_and_collect():
            responses.append(get_osidb_bot_kpi())

        threads = [threading.Thread(target=run_and_collect) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        # The lock serializes the two requests, so whichever acquires it first
        # only sees the single flaw that existed at that instant (total=1);
        # the second sees the fully-merged result (total=2) after loading the
        # first request's cached entry and fetching the newly-added flaw.
        # Neither response should ever be corrupted (e.g. 0, or a mismatch
        # between total_flaws_processed and the per-field applied count).
        assert len(responses) == 2
        assert sorted(r.total_flaws_processed for r in responses) == [1, 2]
        for response in responses:
            assert response.features["impact"].applied == response.total_flaws_processed

        cached = BotKPICacheEntry.model_validate_json(cache_dir.read_text())
        assert cached.total_flaws_processed == 2
        assert set(cached.flaws.keys()) == {"CVE-2025-0001", "CVE-2025-0002"}
