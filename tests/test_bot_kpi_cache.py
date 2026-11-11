"""Tests for osidb-bot KPI cache orchestration."""

from datetime import UTC, datetime
from unittest.mock import patch

from aegis_ai_web.src.endpoints.bot_kpi import (
    OSIDB_BOT_BIRTHDAY,
    FlawCacheData,
    _flaw_cache_data,
    _get_cache_path,
    _index_query,
    _merge_fetched,
    _needs_fetch,
)

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


class TestFlawIndexQuery:
    """The index search must be bounded so it never scrapes all OSIDB history."""

    @staticmethod
    def _captured_kwargs(**call_kwargs) -> dict:
        return _index_query(**call_kwargs)

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

    def test_no_fetch_when_osidb_watermark_unparseable(self):
        """An unparseable OSIDB watermark is treated as current: the cache
        entry was fetched at full fidelity at exactly this watermark, and
        re-fetching on every request would livelock refresh progress (e.g.
        the tombstone of a flaw that vanished after the index query)."""
        cached = _cached_flaw(updated_dt="")
        assert not _needs_fetch(cached, "")
        assert not _needs_fetch(cached, "not-a-date")

    def test_fetches_when_cached_watermark_unparseable_against_parseable_osidb(self):
        """An unparseable cached watermark cannot be ordered against a
        parseable OSIDB one, so the flaw is re-fetched -- this is what picks
        up a flaw that reappears with a real watermark."""
        cached = _cached_flaw(updated_dt="")
        assert _needs_fetch(cached, "2025-07-01T00:00:00+00:00")

    def test_fetches_when_cache_entry_is_absent(self):
        assert _needs_fetch(None, "2025-07-01T00:00:00+00:00")

    def test_fetches_when_cache_entry_lacks_component_provenance(self):
        """An old-schema cache entry with components=None (missing component
        provenance) is re-fetched so it is rewritten with components."""
        cached = FlawCacheData(updated_dt="2025-07-01T00:00:00+00:00")
        assert _needs_fetch(cached, "2025-07-01T00:00:00+00:00")


class TestFlawCacheData:
    """The cache entry's watermark prefers the flaw's own updated_dt."""

    def test_prefers_flaw_own_updated_dt_over_indexed_watermark(self):
        """The flaw's own updated_dt from the full fetch is authoritative --
        the index projection may lag or be malformed -- so it becomes the
        cache entry's watermark even when the indexed one differs."""
        flaw = _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("LOW")]},
            impact="LOW",
            updated_dt="2025-08-01T00:00:00+00:00",
        )
        entry = _flaw_cache_data(flaw, "2025-07-01T00:00:00+00:00")
        assert entry.updated_dt == "2025-08-01T00:00:00+00:00"

    def test_falls_back_to_indexed_watermark_when_flaw_own_is_empty(self):
        flaw = _make_flaw_dict(
            {"processed": True, "impact": [_make_bot_entry("LOW")]},
            impact="LOW",
            updated_dt=None,
        )
        entry = _flaw_cache_data(flaw, "2025-07-01T00:00:00+00:00")
        assert entry.updated_dt == "2025-07-01T00:00:00+00:00"

    def test_skip_marker_also_prefers_flaw_own_updated_dt(self):
        flaw = _make_flaw_dict(
            {"processed": False}, updated_dt="2025-08-01T00:00:00+00:00"
        )
        entry = _flaw_cache_data(flaw, "2025-07-01T00:00:00+00:00")
        assert entry.updated_dt == "2025-08-01T00:00:00+00:00"
        assert entry.bot_processed is False
        assert entry.components == []
