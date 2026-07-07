"""Tests for osidb-bot KPI cache orchestration."""

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aegis_ai.osidb_bot.kpi import BotKPICacheEntry, BotKPIResult, FeatureStats
from aegis_ai_web.src.endpoints.bot_kpi import (
    _get_cache_path,
    _load_cache,
    _save_cache,
    get_osidb_bot_kpi,
)


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


def _seed_cache(cache_path: Path, result: BotKPIResult, cutoff: datetime) -> None:
    entry = BotKPICacheEntry.from_kpi_result(result, cutoff)
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
    def test_defaults_to_config_dir(self, monkeypatch):
        monkeypatch.delenv("AEGIS_BOT_KPI_CACHE_DIR", raising=False)
        path = _get_cache_path()
        assert path.name == "kpi_cache.json"
        assert "osidb_bot_kpi" in path.parts

    def test_uses_env_var_when_set(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AEGIS_BOT_KPI_CACHE_DIR", str(tmp_path / "custom"))
        path = _get_cache_path()
        assert path == tmp_path / "custom" / "kpi_cache.json"


class TestCacheIO:
    def test_load_nonexistent_returns_none(self, cache_dir):
        assert _load_cache() is None

    def test_save_and_load_round_trip(self, cache_dir):
        result = BotKPIResult(
            total_flaws_processed=5,
            features={"impact": FeatureStats(applied=3, kept=2)},
        )
        cutoff = datetime(2025, 7, 1, tzinfo=timezone.utc)
        entry = BotKPICacheEntry.from_kpi_result(result, cutoff)
        _save_cache(entry)
        loaded = _load_cache()
        assert loaded is not None
        assert loaded.cutoff == cutoff
        assert loaded.total_flaws_processed == 5

    def test_corrupt_cache_returns_none(self, cache_dir):
        cache_dir.parent.mkdir(parents=True, exist_ok=True)
        cache_dir.write_text("not valid json {{{")
        assert _load_cache() is None

    def test_save_failure_does_not_raise(self, cache_dir, monkeypatch):
        monkeypatch.setattr(
            "aegis_ai_web.src.endpoints.bot_kpi._get_cache_path",
            lambda: Path("/nonexistent/dir/cache.json"),
        )
        result = BotKPIResult(total_flaws_processed=1)
        cutoff = datetime(2025, 7, 1, tzinfo=timezone.utc)
        entry = BotKPICacheEntry.from_kpi_result(result, cutoff)
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
        cutoff = datetime(2025, 6, 1, tzinfo=timezone.utc)
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
        _seed_cache(cache_dir, old_result, datetime(2025, 1, 1, tzinfo=timezone.utc))

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
        _seed_cache(cache_dir, old_result, datetime(2025, 6, 1, tzinfo=timezone.utc))

        mock_session = MagicMock()
        mock_session.flaws.retrieve_list_iterator.return_value = iter([])
        mock_bindings.new_session.return_value = mock_session

        after = datetime(2025, 5, 1, tzinfo=timezone.utc)
        response = get_osidb_bot_kpi(changed_after=after)
        assert response.total_flaws_processed == 0

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
