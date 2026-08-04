"""KPI metrics computation and endpoint handler for osidb-bot auto-processed flaws.

Compares bot suggestions (stored in aegis_meta) against current flaw field
values to measure how often analysts keep, modify, or skip bot suggestions.
"""

import fcntl
import logging
import os
import tempfile
from collections.abc import Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import osidb_bindings
from fastapi import HTTPException
from pydantic import BaseModel

from aegis_ai import get_settings
from aegis_ai.features.cve.impact_mappings import score_cvss3_diff, score_impact_diff
from aegis_ai_web.src.data_models import BotFeatureKPI, BotKPIResponse

logger = logging.getLogger(__name__)

# Flaw fields that the bot writes suggestions for and that we can compare
# against current values.  Underscore-prefixed keys (_ecosystems, _cvss3_vector)
# are metadata-only and have no direct flaw-field counterpart.
BOT_KPI_FIELDS = ("components", "title", "cve_description", "cwe_id", "impact")

_META_ONLY_FIELDS = ("_cvss3_vector",)
_ALL_KPI_FIELDS = BOT_KPI_FIELDS + _META_ONLY_FIELDS

_INCLUDE_FIELDS = ",".join(
    ["cve_id", "updated_dt", "aegis_meta", "cvss_scores", *BOT_KPI_FIELDS]
)

_DISPLAY_NAMES: dict[str, str] = {"_cvss3_vector": "cvss3_vector"}


def _display_name(field_name: str) -> str:
    return _DISPLAY_NAMES.get(field_name, field_name)


def _get_current_value(field_name: str, flaw_data: dict[str, Any]) -> Any:
    if field_name == "_cvss3_vector":
        # `or []` also covers cvss_scores explicitly serialized as null, not just absent.
        for cvss_entry in flaw_data.get("cvss_scores") or []:
            if cvss_entry.get("issuer") == "RH":
                return cvss_entry.get("vector")
        return None
    return flaw_data.get(field_name)


def _safe_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _compute_distance(field_name: str, suggested: Any, current: Any) -> float | None:
    if field_name == "impact":
        try:
            return round(1.0 - score_impact_diff(str(suggested), str(current)), 4)
        except KeyError:
            return None
    if field_name == "_cvss3_vector":
        score, _reason = score_cvss3_diff(str(suggested), str(current))
        return round(1.0 - score, 4)
    return None


@dataclass
class FeatureStats:
    applied: int = 0
    skipped: int = 0
    kept: int = 0
    modified: int = 0
    data_quality_sum: float = 0.0
    data_quality_count: int = 0
    confidence_sum: float = 0.0
    confidence_count: int = 0
    total_entries: int = 0
    distance_sum: float = 0.0
    distance_count: int = 0

    @property
    def acceptance_rate(self) -> float:
        if self.applied == 0:
            return 0.0
        return round((self.kept / self.applied) * 100, 1)

    @property
    def avg_data_quality(self) -> float | None:
        if self.data_quality_count == 0:
            return None
        return round(self.data_quality_sum / self.data_quality_count, 2)

    @property
    def avg_confidence(self) -> float | None:
        if self.confidence_count == 0:
            return None
        return round(self.confidence_sum / self.confidence_count, 2)

    @property
    def avg_distance(self) -> float | None:
        if self.distance_count == 0:
            return None
        return round(self.distance_sum / self.distance_count, 2)


@dataclass
class BotKPIResult:
    total_flaws_processed: int = 0
    features: dict[str, FeatureStats] = field(default_factory=dict)


def _values_equal(suggested: Any, current: Any) -> bool:
    """Compare a bot-suggested value with the current flaw field value."""
    if suggested is None or current is None:
        return suggested is current
    if isinstance(suggested, list) and isinstance(current, list):
        return sorted(str(x) for x in suggested) == sorted(str(x) for x in current)
    if type(suggested) is type(current):
        return suggested == current
    return str(suggested) == str(current)


def _score_bot_entries(
    entries: list[dict[str, Any]],
) -> tuple[FeatureStats, dict[str, Any] | None]:
    """Accumulate per-entry stats and return the latest AI-Bot entry, if any."""
    stats = FeatureStats()
    bot_entry: dict[str, Any] | None = None

    for entry in entries:
        # Older entries recorded before data_quality/confidence tracking was
        # added have no such keys; treat them as unknown rather than 0.0, so
        # they don't drag the average down.
        if entry.get("data_quality") is not None:
            stats.data_quality_sum += _safe_float(entry.get("data_quality"))
            stats.data_quality_count += 1
        if entry.get("confidence") is not None:
            stats.confidence_sum += _safe_float(entry.get("confidence"))
            stats.confidence_count += 1
        stats.total_entries += 1

        entry_type = entry.get("type", "")
        if entry_type == "AI-Bot":
            stats.applied += 1
            # Keep overwriting so we compare against the latest suggestion;
            # entries are appended chronologically by record_aegis_meta().
            bot_entry = entry
        elif entry_type == "AI-Bot-Skipped":
            stats.skipped += 1

    return stats, bot_entry


def _score_against_current(
    field_name: str,
    bot_entry: dict[str, Any],
    flaw_data: dict[str, Any],
    stats: FeatureStats,
) -> None:
    """Compare the bot's suggested value with the current flaw value, updating stats."""
    current_value = _get_current_value(field_name, flaw_data)
    if _values_equal(bot_entry["value"], current_value):
        stats.kept += 1
        return

    stats.modified += 1
    dist = _compute_distance(field_name, bot_entry["value"], current_value)
    if dist is not None:
        stats.distance_sum += dist
        stats.distance_count += 1


def extract_flaw_kpi(
    aegis_meta: dict[str, Any],
    flaw_data: dict[str, Any],
) -> dict[str, FeatureStats]:
    """Extract per-feature stats from a single flaw's aegis_meta."""
    result: dict[str, FeatureStats] = {}

    for field_name in _ALL_KPI_FIELDS:
        entries = aegis_meta.get(field_name)
        if not entries or not isinstance(entries, list):
            continue

        stats, bot_entry = _score_bot_entries(entries)
        if bot_entry is not None and "value" in bot_entry:
            _score_against_current(field_name, bot_entry, flaw_data, stats)

        result[_display_name(field_name)] = stats

    return result


def _merge_feature_stats(target: FeatureStats, source: FeatureStats) -> None:
    """Add source stats into target (mutating target)."""
    target.applied += source.applied
    target.skipped += source.skipped
    target.kept += source.kept
    target.modified += source.modified
    target.data_quality_sum += source.data_quality_sum
    target.data_quality_count += source.data_quality_count
    target.confidence_sum += source.confidence_sum
    target.confidence_count += source.confidence_count
    target.total_entries += source.total_entries
    target.distance_sum += source.distance_sum
    target.distance_count += source.distance_count


def _is_bot_processed(flaw_data: dict[str, Any]) -> bool:
    """Shared bot-processed filter used by aggregate_kpi and _extract_flaw_ids."""
    aegis_meta = flaw_data.get("aegis_meta")
    return isinstance(aegis_meta, dict) and bool(aegis_meta.get("processed"))


def _extract_per_flaw_stats(
    flaws: Sequence[dict[str, Any]],
) -> tuple[dict[str, dict[str, FeatureStats]], dict[str, str]]:
    """Compute per-field KPI stats for each bot-processed flaw, keyed by CVE ID.

    Returns (stats_by_cve, timestamps_by_cve).

    A flaw with no CVE ID has no stable identity to key a per-flaw cache
    entry on (and can never be re-scored later if it's edited again), so
    it's excluded -- this doesn't occur for real OSIDB flaws in practice.
    """
    result: dict[str, dict[str, FeatureStats]] = {}
    timestamps: dict[str, str] = {}
    for flaw_data in flaws:
        if not _is_bot_processed(flaw_data):
            continue
        cve_id = flaw_data.get("cve_id")
        if not cve_id:
            continue
        result[cve_id] = extract_flaw_kpi(flaw_data["aegis_meta"], flaw_data)
        updated_dt = flaw_data.get("updated_dt")
        if updated_dt is not None:
            timestamps[cve_id] = str(updated_dt)
    return result, timestamps


def _resum(per_flaw: dict[str, dict[str, FeatureStats]]) -> BotKPIResult:
    """Recompute the aggregate from scratch by summing every flaw's per-field stats.

    Always a complete, from-scratch sum -- never an incremental add/subtract
    -- so there's no floating-point drift no matter how many times a flaw
    gets re-scored over time.
    """
    merged: dict[str, FeatureStats] = {}
    for stats_by_field in per_flaw.values():
        for field_name, stats in stats_by_field.items():
            if field_name not in merged:
                merged[field_name] = FeatureStats()
            _merge_feature_stats(merged[field_name], stats)
    return BotKPIResult(total_flaws_processed=len(per_flaw), features=merged)


def _aggregate_kpi_and_ids(
    flaws: Sequence[dict[str, Any]],
) -> tuple[BotKPIResult, list[str]]:
    """Aggregate KPI stats and collect processed CVE IDs in a single pass."""
    per_flaw, _ = _extract_per_flaw_stats(flaws)
    return _resum(per_flaw), list(per_flaw.keys())


def aggregate_kpi(flaws: Sequence[dict[str, Any]]) -> BotKPIResult:
    """Aggregate KPI stats across multiple flaws."""
    result, _ = _aggregate_kpi_and_ids(flaws)
    return result


def _extract_flaw_ids(flaws: Sequence[dict[str, Any]]) -> list[str]:
    """Extract CVE IDs from processed flaws (same filter as aggregate_kpi)."""
    _, flaw_ids = _aggregate_kpi_and_ids(flaws)
    return flaw_ids


def fetch_bot_processed_flaws(
    osidb: Any,
    *,
    changed_after: datetime | None = None,
    changed_before: datetime | None = None,
) -> list[dict[str, Any]]:
    """Query OSIDB for bot-processed flaws in DONE workflow state."""
    kwargs: dict[str, Any] = {
        "include_fields": _INCLUDE_FIELDS,
        "workflow_state": "DONE",
        "limit": 200,
    }

    if changed_after is not None:
        kwargs["updated_dt__gte"] = changed_after
    if changed_before is not None:
        kwargs["updated_dt__lte"] = changed_before

    logger.info("querying OSIDB for bot-processed flaws: %s", kwargs)

    flaws: list[dict[str, Any]] = []
    for flaw in osidb.flaws.retrieve_list_iterator(**kwargs):
        flaw_dict = flaw.to_dict()
        if _is_bot_processed(flaw_dict):
            flaws.append(flaw_dict)

    logger.info("found %d bot-processed flaws", len(flaws))
    return flaws


def _feature_stats_from_dict(d: dict[str, float]) -> FeatureStats:
    """Reconstruct FeatureStats from its serialized form, tolerating missing keys.

    Guards against a truncated or corrupt on-disk entry raising KeyError and
    turning into a 500 that repeats on every request until someone manually
    deletes the cache file.
    """
    return FeatureStats(
        applied=int(d.get("applied", 0)),
        skipped=int(d.get("skipped", 0)),
        kept=int(d.get("kept", 0)),
        modified=int(d.get("modified", 0)),
        data_quality_sum=d.get("data_quality_sum", 0.0),
        data_quality_count=int(d.get("data_quality_count", 0)),
        confidence_sum=d.get("confidence_sum", 0.0),
        confidence_count=int(d.get("confidence_count", 0)),
        total_entries=int(d.get("total_entries", 0)),
        distance_sum=d.get("distance_sum", 0.0),
        distance_count=int(d.get("distance_count", 0)),
    )


def _serialize_per_flaw(
    per_flaw: dict[str, dict[str, FeatureStats]],
) -> dict[str, dict[str, dict[str, float]]]:
    return {
        cve_id: {field_name: asdict(stats) for field_name, stats in by_field.items()}
        for cve_id, by_field in per_flaw.items()
    }


class BotKPICacheEntry(BaseModel):
    """On-disk cache of each flaw's own KPI contribution, plus a memoized
    aggregate over all of them.

    Storing each flaw's contribution individually (rather than only a
    running total) is what lets a flaw be correctly re-scored if it's
    edited again after the bot's initial pass: its entry is simply
    overwritten and the aggregate is resummed from scratch, instead of the
    flaw being permanently frozen at its first-seen state.
    """

    cutoff: datetime
    # No defaults: a cache file from before this schema (flat aggregate
    # sums + a seen-IDs list, no `flaws`/`aggregate` keys) must fail
    # validation here so `_load_cache` treats it as absent and triggers a
    # full refresh, rather than silently defaulting to an empty cache.
    flaws: dict[str, dict[str, dict[str, float]]]
    aggregate: dict[str, dict[str, float]]
    timestamps: dict[str, str] = {}

    @property
    def total_flaws_processed(self) -> int:
        return len(self.flaws)

    def to_kpi_result(self) -> BotKPIResult:
        return BotKPIResult(
            total_flaws_processed=self.total_flaws_processed,
            features={
                name: _feature_stats_from_dict(d) for name, d in self.aggregate.items()
            },
        )

    def filter_by_date(
        self,
        *,
        changed_after: datetime | None = None,
        changed_before: datetime | None = None,
    ) -> "BotKPIResult":
        """Resum only flaws whose updated_dt falls within the given range."""
        filtered: dict[str, dict[str, FeatureStats]] = {}
        for cve_id, by_field in self.flaws.items():
            ts_str = self.timestamps.get(cve_id)
            if ts_str is None:
                continue
            updated_dt = datetime.fromisoformat(ts_str)
            if updated_dt.tzinfo is None:
                updated_dt = updated_dt.replace(tzinfo=UTC)
            if changed_after is not None:
                ca = changed_after if changed_after.tzinfo else changed_after.replace(tzinfo=UTC)
                if updated_dt < ca:
                    continue
            if changed_before is not None:
                cb = changed_before if changed_before.tzinfo else changed_before.replace(tzinfo=UTC)
                if updated_dt > cb:
                    continue
            filtered[cve_id] = {
                field_name: _feature_stats_from_dict(d)
                for field_name, d in by_field.items()
            }
        return _resum(filtered)

    @classmethod
    def build(
        cls,
        flaws: dict[str, dict[str, dict[str, float]]],
        cutoff: datetime,
        timestamps: dict[str, str] | None = None,
    ) -> "BotKPICacheEntry":
        """Build a cache entry from a serialized per-flaw stats map, resumming
        the aggregate from scratch."""
        per_flaw_stats = {
            cve_id: {
                field_name: _feature_stats_from_dict(d)
                for field_name, d in by_field.items()
            }
            for cve_id, by_field in flaws.items()
        }
        aggregate_result = _resum(per_flaw_stats)
        return cls(
            cutoff=cutoff,
            flaws=flaws,
            aggregate={
                name: asdict(stats) for name, stats in aggregate_result.features.items()
            },
            timestamps=timestamps or {},
        )


# -- Response helpers ----------------------------------------------------------


def _stats_to_response(stats: FeatureStats) -> BotFeatureKPI:
    return BotFeatureKPI(
        applied=stats.applied,
        skipped=stats.skipped,
        kept=stats.kept,
        modified=stats.modified,
        acceptance_rate=stats.acceptance_rate,
        avg_data_quality=stats.avg_data_quality,
        avg_confidence=stats.avg_confidence,
        avg_distance=stats.avg_distance,
    )


def _result_to_response(result: BotKPIResult) -> BotKPIResponse:
    return BotKPIResponse(
        total_flaws_processed=result.total_flaws_processed,
        features={
            name: _stats_to_response(stats) for name, stats in result.features.items()
        },
    )


# -- Cache helpers -------------------------------------------------------------


def _get_cache_path() -> Path:
    settings = get_settings()
    if settings.bot_kpi_cache_dir:
        return Path(settings.bot_kpi_cache_dir) / "kpi_cache.json"
    return Path(settings.config_dir) / "osidb_bot_kpi" / "kpi_cache.json"


@contextmanager
def _cache_lock():
    """Serialize cache read-modify-write cycles across concurrent requests."""
    lock_path = _get_cache_path().with_suffix(".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "w") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _load_cache() -> BotKPICacheEntry | None:
    cache_path = _get_cache_path()
    if not cache_path.is_file():
        return None
    try:
        return BotKPICacheEntry.model_validate_json(cache_path.read_text())
    except Exception:
        logger.warning("Failed to load bot KPI cache, will do full query")
        logger.debug("Cache load error details", exc_info=True)
        return None


def _save_cache(entry: BotKPICacheEntry) -> None:
    cache_path = _get_cache_path()
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            dir=cache_path.parent, suffix=".tmp", prefix="kpi_cache_"
        )
        try:
            with os.fdopen(fd, "w") as f:
                f.write(entry.model_dump_json(indent=2))
            os.replace(tmp_path, cache_path)
        except BaseException:
            os.unlink(tmp_path)
            raise
    except Exception:
        logger.warning("Failed to write bot KPI cache")
        logger.debug("Cache write error details", exc_info=True)


# -- Endpoint handler ----------------------------------------------------------


def _fetch_with_cache(
    osidb: Any,
    *,
    changed_after: datetime | None = None,
    changed_before: datetime | None = None,
) -> BotKPIResult:
    """Fetch flaws using the incremental cache, falling back to a full query.

    The OSIDB fetch runs outside the cache lock so a slow or hung query can't
    block every other concurrent request. If nothing changed since the cache
    was built, the stored aggregate is returned as-is -- no lock, no resum.
    Only a fetch that actually finds changed/new flaws pays for a lock and a
    full resum, so the expensive work scales with how often the underlying
    data changes, not with how often this endpoint is polled. Every fetched
    flaw overwrites its own entry (whether new or previously seen), which is
    what allows a flaw to be correctly re-scored if it's edited again after
    the bot's initial pass, instead of being frozen at its first-seen state.

    When date filters are provided, the cache is still refreshed incrementally
    (and saved in full) but the returned result is filtered to only include
    flaws whose updated_dt falls within the requested range.
    """
    has_date_filters = changed_after is not None or changed_before is not None
    # Captured before the OSIDB query runs so flaws updated mid-fetch are
    # still >= cutoff and get picked up by the next incremental fetch.
    cutoff = datetime.now(UTC)
    cached = _load_cache()
    if cached is not None:
        flaws = fetch_bot_processed_flaws(osidb, changed_after=cached.cutoff)
    else:
        flaws = fetch_bot_processed_flaws(osidb)

    new_per_flaw, new_timestamps = _extract_per_flaw_stats(flaws)
    if not new_per_flaw:
        if cached is None:
            return BotKPIResult()
        if has_date_filters:
            return cached.filter_by_date(
                changed_after=changed_after, changed_before=changed_before
            )
        return cached.to_kpi_result()

    new_serialized = _serialize_per_flaw(new_per_flaw)
    with _cache_lock():
        latest_cached = _load_cache()
        if latest_cached is not None:
            merged_flaws = {**latest_cached.flaws, **new_serialized}
            merged_timestamps = {**latest_cached.timestamps, **new_timestamps}
            saved_cutoff = max(cutoff, latest_cached.cutoff)
        else:
            merged_flaws = new_serialized
            merged_timestamps = new_timestamps
            saved_cutoff = cutoff

        entry = BotKPICacheEntry.build(merged_flaws, saved_cutoff, merged_timestamps)
        _save_cache(entry)
        if has_date_filters:
            return entry.filter_by_date(
                changed_after=changed_after, changed_before=changed_before
            )
        return entry.to_kpi_result()


def _fetch_direct(osidb: Any) -> BotKPIResult:
    """Full refresh: fetch all flaws from OSIDB and replace the cache."""
    with _cache_lock():
        cutoff = datetime.now(UTC)
        flaws = fetch_bot_processed_flaws(osidb)
        per_flaw, timestamps = _extract_per_flaw_stats(flaws)
        entry = BotKPICacheEntry.build(
            _serialize_per_flaw(per_flaw), cutoff, timestamps
        )
        _save_cache(entry)
        return entry.to_kpi_result()


def get_osidb_bot_kpi(
    *,
    changed_after: datetime | None = None,
    changed_before: datetime | None = None,
    full_refresh: bool = False,
) -> BotKPIResponse:
    """Fetch bot-processed flaws from OSIDB and compute KPI metrics."""
    try:
        osidb_server = get_settings().osidb_server_url
        osidb = osidb_bindings.new_session(osidb_server_uri=osidb_server)
        if full_refresh:
            result = _fetch_direct(osidb)
        else:
            result = _fetch_with_cache(
                osidb,
                changed_after=changed_after,
                changed_before=changed_before,
            )
        return _result_to_response(result)
    except OSError:
        # OSError also covers requests.exceptions.RequestException (it subclasses
        # OSError), so this catches real connectivity failures without masking
        # programming bugs (AttributeError, TypeError, etc.) as a 503 outage.
        logger.error("Failed to connect to OSIDB")
        logger.debug("OSIDB connection error details", exc_info=True)
        raise HTTPException(
            status_code=503,
            detail="Unable to connect to OSIDB.",
        ) from None
    except HTTPException:
        raise
    except Exception:
        logger.error("Error computing osidb-bot KPI")
        logger.debug("osidb-bot KPI error details", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while computing osidb-bot KPI metrics.",
        ) from None
