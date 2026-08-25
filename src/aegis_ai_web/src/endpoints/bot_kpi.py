"""KPI metrics computation and endpoint handler for osidb-bot auto-processed flaws.

Compares bot suggestions (stored in aegis_meta) against current flaw field
values to measure how often analysts keep, modify, or skip bot suggestions.
"""

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import osidb_bindings
from fastapi import HTTPException
from pydantic import BaseModel

from aegis_ai import get_settings
from aegis_ai.features.cve.impact_mappings import score_cvss3_diff, score_impact_diff
from aegis_ai.state_file import StateFileHandler
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


def _compute_deviation(field_name: str, suggested: Any, current: Any) -> float:
    """Compute how far the current value deviates from the bot's suggestion.

    Returns 0.0 for an exact match.  For fields with a graded metric (impact,
    CVSS) returns a normalized 0-1 score.  For all other fields returns 1.0
    (binary mismatch) since no finer-grained comparison is available.
    """
    if field_name == "impact":
        try:
            return round(1.0 - score_impact_diff(str(suggested), str(current)), 4)
        except KeyError:
            return 1.0
    if field_name == "_cvss3_vector":
        score, _reason = score_cvss3_diff(str(suggested), str(current))
        return round(1.0 - score, 4)
    return 1.0


@dataclass
class FeatureStats:
    applied: int = 0
    skipped: int = 0
    data_quality_sum: float = 0.0
    data_quality_count: int = 0
    confidence_sum: float = 0.0
    confidence_count: int = 0
    total_entries: int = 0
    suggestion_deviation_sum: float = 0.0
    # Number of the bot's *latest* per-field suggestions that were compared
    # against the flaw's current value -- i.e. the accept/modify decisions
    # (kept + modified), one per field. Skipped suggestions are not compared,
    # and re-suggestions of the same field count once (only the latest is
    # compared), so this is <= `applied`. It is the denominator for both
    # `avg_suggestion_deviation` and the acceptance rate.
    suggestions_compared: int = 0

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
    def avg_suggestion_deviation(self) -> float | None:
        if self.suggestions_compared == 0:
            return None
        return round(self.suggestion_deviation_sum / self.suggestions_compared, 2)


@dataclass
class BotKPIResult:
    total_flaws_processed: int = 0
    features: dict[str, FeatureStats] = field(default_factory=dict)
    modified_counts: dict[str, int] = field(default_factory=dict)


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
        stats.suggestions_compared += 1
        return

    deviation = _compute_deviation(field_name, bot_entry["value"], current_value)
    stats.suggestion_deviation_sum += deviation
    stats.suggestions_compared += 1


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
    target.data_quality_sum += source.data_quality_sum
    target.data_quality_count += source.data_quality_count
    target.confidence_sum += source.confidence_sum
    target.confidence_count += source.confidence_count
    target.total_entries += source.total_entries
    target.suggestion_deviation_sum += source.suggestion_deviation_sum
    target.suggestions_compared += source.suggestions_compared


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
    modified_counts: dict[str, int] = {}
    for stats_by_field in per_flaw.values():
        for field_name, stats in stats_by_field.items():
            if field_name not in merged:
                merged[field_name] = FeatureStats()
                modified_counts[field_name] = 0
            _merge_feature_stats(merged[field_name], stats)
            if stats.suggestion_deviation_sum > 0.0:
                modified_counts[field_name] += 1
    return BotKPIResult(
        total_flaws_processed=len(per_flaw),
        features=merged,
        modified_counts=modified_counts,
    )


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
    """Reconstruct FeatureStats from its compact serialized form.

    Guards against a truncated or corrupt on-disk entry raising KeyError and
    turning into a 500 that repeats on every request until someone manually
    deletes the cache file.
    """
    applied = int(d.get("applied", 0))
    skipped = int(d.get("skipped", 0))
    has_deviation = "deviation" in d
    dq = d.get("data_quality")
    conf = d.get("confidence")
    return FeatureStats(
        applied=applied,
        skipped=skipped,
        total_entries=applied + skipped,
        suggestion_deviation_sum=d.get("deviation", 0.0),
        suggestions_compared=1 if has_deviation else 0,
        data_quality_sum=dq if dq is not None else 0.0,
        data_quality_count=int(d.get("dq_n", 1)) if dq is not None else 0,
        confidence_sum=conf if conf is not None else 0.0,
        confidence_count=int(d.get("conf_n", 1)) if conf is not None else 0,
    )


def _serialize_flaw_feature(stats: FeatureStats) -> dict[str, float]:
    """Serialize a single flaw's per-feature stats for the cache.

    Omits zero/default fields and derives counts from presence, so a typical
    entry is just ``{"applied": 1, "deviation": 0.0, "data_quality": 0.9,
    "confidence": 0.85}`` instead of nine sum/count pairs.
    """
    d: dict[str, float] = {"applied": stats.applied}
    if stats.skipped:
        d["skipped"] = stats.skipped
    if stats.suggestions_compared:
        d["deviation"] = stats.suggestion_deviation_sum
    if stats.data_quality_count:
        d["data_quality"] = stats.data_quality_sum
        if stats.data_quality_count != 1:
            d["dq_n"] = stats.data_quality_count
    if stats.confidence_count:
        d["confidence"] = stats.confidence_sum
        if stats.confidence_count != 1:
            d["conf_n"] = stats.confidence_count
    return d


def _serialize_per_flaw(
    per_flaw: dict[str, dict[str, FeatureStats]],
    timestamps: dict[str, str] | None = None,
) -> dict[str, "FlawCacheData"]:
    ts = timestamps or {}
    return {
        cve_id: FlawCacheData(
            fields={
                field_name: _serialize_flaw_feature(stats)
                for field_name, stats in by_field.items()
            },
            updated_dt=ts.get(cve_id),
        )
        for cve_id, by_field in per_flaw.items()
    }


class FlawCacheData(BaseModel):
    """Per-flaw cache entry: the feature stats and the flaw's last-updated timestamp."""

    fields: dict[str, dict[str, float]]
    updated_dt: str | None = None


class BotKPICacheEntry(BaseModel):
    """On-disk cache of each bot-processed flaw's own KPI contribution.

    Only per-flaw data is cached, never an aggregate: the aggregate depends on
    the request's date filters and on whatever changed in OSIDB between
    requests, and resumming it from the cached per-flaw stats is far cheaper
    than the JSON (de)serialization the cache already pays for. The cache
    exists solely to avoid re-fetching unchanged flaws from OSIDB.

    Storing each flaw's contribution individually (rather than only a running
    total) is what lets a flaw be correctly re-scored if it's edited again
    after the bot's initial pass: its entry is simply overwritten and the
    aggregate is resummed from scratch.
    """

    cutoff: datetime
    flaws: dict[str, FlawCacheData]

    @property
    def total_flaws_processed(self) -> int:
        return len(self.flaws)

    def to_kpi_result(self) -> BotKPIResult:
        per_flaw = {
            cve_id: {
                field_name: _feature_stats_from_dict(d)
                for field_name, d in flaw.fields.items()
            }
            for cve_id, flaw in self.flaws.items()
        }
        return _resum(per_flaw)

    def filter_by_date(
        self,
        *,
        changed_after: datetime | None = None,
        changed_before: datetime | None = None,
    ) -> "BotKPIResult":
        """Resum only flaws whose updated_dt falls within the given range."""
        filtered: dict[str, dict[str, FeatureStats]] = {}
        for cve_id, flaw in self.flaws.items():
            if flaw.updated_dt is None:
                continue
            updated_dt = datetime.fromisoformat(flaw.updated_dt)
            if updated_dt.tzinfo is None:
                updated_dt = updated_dt.replace(tzinfo=UTC)
            if changed_after is not None:
                ca = (
                    changed_after
                    if changed_after.tzinfo
                    else changed_after.replace(tzinfo=UTC)
                )
                if updated_dt < ca:
                    continue
            if changed_before is not None:
                cb = (
                    changed_before
                    if changed_before.tzinfo
                    else changed_before.replace(tzinfo=UTC)
                )
                if updated_dt > cb:
                    continue
            filtered[cve_id] = {
                field_name: _feature_stats_from_dict(d)
                for field_name, d in flaw.fields.items()
            }
        return _resum(filtered)

    @classmethod
    def build(
        cls,
        flaws: dict[str, FlawCacheData],
        cutoff: datetime,
    ) -> "BotKPICacheEntry":
        """Build a cache entry from per-flaw data."""
        return cls(cutoff=cutoff, flaws=flaws)


# -- Response helpers ----------------------------------------------------------


def _stats_to_response(stats: FeatureStats, modified_count: int) -> BotFeatureKPI:
    # Acceptance is a per-flaw-field decision (kept vs. modified), so the rate
    # is measured against suggestions_compared, not `applied` (a per-entry count
    # that a re-suggested flaw inflates past the number of accept/modify
    # decisions).
    kept = stats.suggestions_compared - modified_count
    compared = stats.suggestions_compared
    acceptance_rate = round((kept / compared) * 100, 1) if compared > 0 else 0.0
    return BotFeatureKPI(
        applied=stats.applied,
        skipped=stats.skipped,
        kept=kept,
        modified=modified_count,
        acceptance_rate=acceptance_rate,
        avg_data_quality=stats.avg_data_quality,
        avg_confidence=stats.avg_confidence,
        avg_suggestion_deviation=stats.avg_suggestion_deviation,
    )


def _result_to_response(result: BotKPIResult) -> BotKPIResponse:
    return BotKPIResponse(
        total_flaws_processed=result.total_flaws_processed,
        features={
            name: _stats_to_response(stats, result.modified_counts.get(name, 0))
            for name, stats in result.features.items()
        },
    )


# -- Cache helpers -------------------------------------------------------------


def _get_cache_path() -> Path:
    settings = get_settings()
    if settings.bot_kpi_cache_dir:
        return Path(settings.bot_kpi_cache_dir) / "kpi_cache.json"
    return Path(settings.config_dir) / "osidb_bot_kpi" / "kpi_cache.json"


def _cache_handler() -> StateFileHandler[BotKPICacheEntry]:
    """A blocking, file-locked handler over the KPI cache file itself.

    Locking the cache file directly (no separate ``.lock`` sidecar) means
    there is only ever one file to reason about. The blocking lock serializes
    the read-modify-write cycles of concurrent requests so they can't clobber
    each other's results.
    """
    cache_path = _get_cache_path()
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    return StateFileHandler(str(cache_path), BotKPICacheEntry, blocking=True)


def _read_cache() -> BotKPICacheEntry | None:
    """Read the cache under a brief lock; None if absent, empty, or corrupt."""
    with _cache_handler() as handler:
        return handler.read()


# -- Endpoint handler ----------------------------------------------------------


def _fetch_with_cache(
    osidb: Any,
    *,
    changed_after: datetime | None = None,
    changed_before: datetime | None = None,
) -> BotKPIResult:
    """Fetch flaws using the incremental cache, then aggregate on demand.

    The OSIDB fetch runs outside the cache lock so a slow or hung query can't
    block every other concurrent request. If nothing changed since the cache
    was built, the cached per-flaw data is aggregated and returned without a
    write. Only a fetch that finds changed/new flaws pays for a lock and a
    save, so the expensive work scales with how often the underlying data
    changes, not with how often this endpoint is polled. Every fetched flaw
    overwrites its own entry (whether new or previously seen), which is what
    allows a flaw to be correctly re-scored if it's edited again after the
    bot's initial pass, instead of being frozen at its first-seen state.

    The aggregate is always computed fresh from per-flaw stats (never cached),
    so date filters simply restrict which cached flaws are summed for the
    response; the cache always holds the complete set fetched from OSIDB.
    """
    has_date_filters = changed_after is not None or changed_before is not None
    # Stamped before the OSIDB query runs so flaws updated mid-fetch are still
    # >= cutoff and get picked up by the next incremental fetch.
    cutoff = datetime.now(UTC)

    cached = _read_cache()
    flaws = fetch_bot_processed_flaws(
        osidb, changed_after=cached.cutoff if cached is not None else None
    )
    new_per_flaw, new_timestamps = _extract_per_flaw_stats(flaws)

    if not new_per_flaw:
        # Nothing changed since the cache was built; serve it as-is.
        entry = cached or BotKPICacheEntry(cutoff=cutoff, flaws={})
    else:
        new_serialized = _serialize_per_flaw(new_per_flaw, new_timestamps)
        with _cache_handler() as handler:
            latest = handler.read()
            merged_flaws = dict(latest.flaws) if latest is not None else {}
            merged_flaws.update(new_serialized)
            saved_cutoff = max(cutoff, latest.cutoff) if latest is not None else cutoff
            entry = BotKPICacheEntry(cutoff=saved_cutoff, flaws=merged_flaws)
            handler.write(entry)

    if has_date_filters:
        return entry.filter_by_date(
            changed_after=changed_after, changed_before=changed_before
        )
    return entry.to_kpi_result()


def get_osidb_bot_kpi(
    *,
    changed_after: datetime | None = None,
    changed_before: datetime | None = None,
) -> BotKPIResponse:
    """Fetch bot-processed flaws from OSIDB and compute KPI metrics."""
    try:
        osidb_server = get_settings().osidb_server_url
        osidb = osidb_bindings.new_session(osidb_server_uri=osidb_server)
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
