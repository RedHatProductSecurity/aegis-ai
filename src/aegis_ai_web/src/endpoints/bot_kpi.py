"""KPI metrics computation and endpoint handler for osidb-bot auto-processed flaws.

Compares bot suggestions (stored in aegis_meta) against current flaw field
values to measure how often analysts keep, modify, or skip bot suggestions.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import osidb_bindings
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict

from aegis_ai import get_settings
from aegis_ai.features.cve.impact_mappings import (
    score_components_diff,
    score_cvss3_diff,
    score_impact_diff,
)
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

# osidb-bot's "birthday": the date the bot feature was introduced (first commit
# 2026-02-10).  Applied unconditionally as a ``created_dt_gte`` lower bound on
# the flaw-index search so the query can never scrape unrelated OSIDB history --
# either by mistake or as a DoS attempt.  The request's ``changed_after`` filter
# is applied separately as ``updated_dt_gte``.
OSIDB_BOT_BIRTHDAY = datetime(2026, 2, 10, tzinfo=UTC)


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


def _compute_deviation(field_name: str, suggested: Any, current: Any) -> float:
    """Compute how far the current value deviates from the bot's suggestion.

    Returns 0.0 for an exact match.  For fields with a graded metric (impact,
    CVSS, components) returns a normalized 0-1 score.  For the remaining fields
    (title, cve_description, cwe_id) returns 1.0 (binary mismatch) since no
    finer-grained comparison is available.
    """
    if field_name == "impact":
        try:
            return round(1.0 - score_impact_diff(str(suggested), str(current)), 4)
        except KeyError:
            return 1.0
    if field_name == "_cvss3_vector":
        score, _reason = score_cvss3_diff(str(suggested), str(current))
        return round(1.0 - score, 4)
    if field_name == "components":
        # Graded set distance: a case-only change scores 0.0 and a single
        # component added/removed from a list of N scores 1/(N+1), rather than
        # a flat 1.0 for any difference.
        suggested_list = suggested if isinstance(suggested, list) else [suggested]
        current_list = current if isinstance(current, list) else [current]
        return round(1.0 - score_components_diff(suggested_list, current_list), 4)
    return 1.0


@dataclass
class FeatureStats:
    suggested: int = 0
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
    # compared), so this is <= `suggested`. It is the denominator for both
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


def _opt_float(value: Any) -> float | None:
    """Coerce an optional metric to float, preserving None.

    A missing metric (None) must not count toward an average, whereas a present
    but non-numeric one degrades to 0.0 rather than raising.
    """
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _suggestion_record(
    field_name: str, entry: dict[str, Any], current_value: Any
) -> SuggestionRecord:
    """Distill one raw aegis_meta entry into the compact record KPI scoring needs.

    The deviation of an AI-Bot suggestion from the flaw's current value is
    computed here, once, at fetch time -- it stays valid until the flaw's
    ``updated_dt`` advances, which itself forces a re-fetch and recompute.
    Skipped entries have no value to compare, so their deviation is None.
    """
    entry_type = entry.get("type", "")
    deviation: float | None = None
    if entry_type == "AI-Bot" and "value" in entry:
        if _values_equal(entry["value"], current_value):
            deviation = 0.0
        else:
            deviation = _compute_deviation(field_name, entry["value"], current_value)
    return SuggestionRecord(
        timestamp=entry.get("timestamp"),
        type=entry_type,
        data_quality=_opt_float(entry.get("data_quality")),
        confidence=_opt_float(entry.get("confidence")),
        deviation=deviation,
    )


def _compact_fields(
    aegis_meta: dict[str, Any], flaw_data: dict[str, Any]
) -> dict[str, list[SuggestionRecord]]:
    """Reduce a raw flaw's suggestion history to the compact records KPI reads.

    Only the KPI-relevant fields are kept, and each suggestion is reduced to its
    timestamp, type, data_quality/confidence and (for AI-Bot entries) its
    pre-computed deviation. The bulky raw fields never read by KPI -- explanation,
    tools_used, skip_description, the full ``cvss_scores`` array, the raw
    suggested value -- are dropped.
    """
    fields: dict[str, list[SuggestionRecord]] = {}
    for field_name in _ALL_KPI_FIELDS:
        entries = aegis_meta.get(field_name)
        if not entries or not isinstance(entries, list):
            continue
        current_value = _get_current_value(field_name, flaw_data)
        fields[field_name] = [
            _suggestion_record(field_name, entry, current_value) for entry in entries
        ]
    return fields


def _score_records(
    records: list[SuggestionRecord],
    *,
    changed_after: datetime | None = None,
    changed_before: datetime | None = None,
) -> FeatureStats | None:
    """Aggregate one field's suggestion records, filtered to the date window.

    Each suggestion is filtered by its own recorded ``timestamp`` -- *not* the
    flaw's ``updated_dt`` -- so a field whose suggestions all fall outside the
    window drops out entirely (returns None). Only the latest in-window AI-Bot
    suggestion is compared against the current value (via its pre-computed
    deviation), matching the single accept/modify decision an analyst made.
    """
    in_window = [
        record
        for record in records
        if _in_date_range(record.timestamp, changed_after, changed_before)
    ]
    if not in_window:
        return None

    stats = FeatureStats()
    latest_bot: SuggestionRecord | None = None
    for record in in_window:
        # Entries recorded before data_quality/confidence tracking existed have
        # None for those metrics; they must not drag the average toward 0.
        if record.data_quality is not None:
            stats.data_quality_sum += record.data_quality
            stats.data_quality_count += 1
        if record.confidence is not None:
            stats.confidence_sum += record.confidence
            stats.confidence_count += 1
        stats.total_entries += 1

        if record.type == "AI-Bot":
            stats.suggested += 1
            # Keep overwriting so we compare against the latest suggestion;
            # records are stored chronologically by record_aegis_meta().
            latest_bot = record
        elif record.type == "AI-Bot-Skipped":
            stats.skipped += 1

    if latest_bot is not None and latest_bot.deviation is not None:
        stats.suggestion_deviation_sum += latest_bot.deviation
        stats.suggestions_compared += 1

    return stats


def _score_fields(
    fields: dict[str, list[SuggestionRecord]],
    *,
    changed_after: datetime | None = None,
    changed_before: datetime | None = None,
) -> dict[str, FeatureStats]:
    """Score every field's records, keyed by display name; skip empty windows."""
    result: dict[str, FeatureStats] = {}
    for field_name, records in fields.items():
        stats = _score_records(
            records, changed_after=changed_after, changed_before=changed_before
        )
        if stats is not None:
            result[_display_name(field_name)] = stats
    return result


def extract_flaw_kpi(
    aegis_meta: dict[str, Any],
    flaw_data: dict[str, Any],
    *,
    changed_after: datetime | None = None,
    changed_before: datetime | None = None,
) -> dict[str, FeatureStats]:
    """Extract per-feature stats from a single flaw's raw aegis_meta.

    Compacts the raw suggestion history (see :func:`_compact_fields`) and scores
    it (see :func:`_score_records`). Date filters apply per suggestion against
    its own ``timestamp`` -- *not* the flaw's ``updated_dt`` -- so a flaw edited
    last week whose ``components`` suggestion was made months ago does not
    distort a "last N days" query. A field with no in-window suggestion
    contributes nothing.
    """
    fields = _compact_fields(aegis_meta, flaw_data)
    return _score_fields(
        fields, changed_after=changed_after, changed_before=changed_before
    )


def _merge_feature_stats(target: FeatureStats, source: FeatureStats) -> None:
    """Add source stats into target (mutating target)."""
    target.suggested += source.suggested
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
) -> dict[str, dict[str, FeatureStats]]:
    """Compute per-field KPI stats for each bot-processed flaw, keyed by CVE ID.

    A flaw with no CVE ID has no stable identity to key a per-flaw cache
    entry on (and can never be re-scored later if it's edited again), so
    it's excluded -- this doesn't occur for real OSIDB flaws in practice.
    """
    result: dict[str, dict[str, FeatureStats]] = {}
    for flaw_data in flaws:
        if not _is_bot_processed(flaw_data):
            continue
        cve_id = flaw_data.get("cve_id")
        if not cve_id:
            continue
        result[cve_id] = extract_flaw_kpi(flaw_data["aegis_meta"], flaw_data)
    return result


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
    per_flaw = _extract_per_flaw_stats(flaws)
    return _resum(per_flaw), list(per_flaw.keys())


def aggregate_kpi(flaws: Sequence[dict[str, Any]]) -> BotKPIResult:
    """Aggregate KPI stats across multiple flaws."""
    result, _ = _aggregate_kpi_and_ids(flaws)
    return result


def _extract_flaw_ids(flaws: Sequence[dict[str, Any]]) -> list[str]:
    """Extract CVE IDs from processed flaws (same filter as aggregate_kpi)."""
    _, flaw_ids = _aggregate_kpi_and_ids(flaws)
    return flaw_ids


def _fetch_flaw_index(
    osidb: Any,
    *,
    changed_after: datetime | None = None,
    changed_before: datetime | None = None,
) -> dict[str, str]:
    """Fetch a cheap ``{cve_id: updated_dt}`` index of DONE flaws in range.

    This is the first phase of the two-phase fetch: it pulls only the two
    fields needed to decide whether each flaw's cached full data is still
    current (bot-processed status can't be filtered server-side, so every DONE
    flaw in range is indexed). Full per-flaw data is fetched separately, and
    only for flaws whose watermark has advanced -- see :func:`_fetch_flaws_batch`.

    The search is always bounded by ``created_dt_gte=OSIDB_BOT_BIRTHDAY`` so it
    can never scrape unrelated OSIDB history. The request's ``changed_after`` and
    ``changed_before`` filters are pushed down separately as ``updated_dt`` bounds
    so a narrow query (e.g. the last few days) fetches only that window.
    ``cve_id__isempty=False`` drops flaws without a CVE ID server-side instead of
    fetching them only to discard them here.
    """
    kwargs: dict[str, Any] = {
        "include_fields": "cve_id,updated_dt",
        "workflow_state": "DONE",
        "created_dt_gte": OSIDB_BOT_BIRTHDAY,
        "cve_id__isempty": False,
        "limit": 1000,
    }
    if changed_after is not None:
        kwargs["updated_dt_gte"] = changed_after
    if changed_before is not None:
        kwargs["updated_dt_lte"] = changed_before
    logger.info("querying OSIDB flaw index: %s", kwargs)

    index: dict[str, str] = {}
    for flaw in osidb.flaws.retrieve_list_iterator(**kwargs):
        flaw_dict = flaw.to_dict()
        cve_id = flaw_dict.get("cve_id")
        if not cve_id:
            continue
        index[cve_id] = str(flaw_dict.get("updated_dt") or "")

    logger.info("flaw index: %d DONE flaws", len(index))
    return index


_BATCH_SIZE = 100


def _fetch_flaws_batch(osidb: Any, cve_ids: list[str]) -> dict[str, dict[str, Any]]:
    """Fetch full KPI-relevant fields for multiple flaws in batched queries.

    CVE IDs are chunked to avoid exceeding the HTTP URL length limit.
    """
    if not cve_ids:
        return {}
    logger.info("fetching %d flaws from OSIDB in batch", len(cve_ids))
    result: dict[str, dict[str, Any]] = {}
    for offset in range(0, len(cve_ids), _BATCH_SIZE):
        chunk = cve_ids[offset : offset + _BATCH_SIZE]
        for flaw in osidb.flaws.retrieve_list_iterator(
            cve_id=chunk, include_fields=_INCLUDE_FIELDS, limit=200
        ):
            flaw_dict = flaw.to_dict()
            cve_id = flaw_dict.get("cve_id")
            if cve_id:
                result[cve_id] = flaw_dict
    logger.info("fetched %d/%d flaws", len(result), len(cve_ids))
    return result


def _flaw_cache_data(flaw_data: dict[str, Any], updated_dt: str) -> FlawCacheData:
    """Build a cache entry from a fully-fetched flaw.

    A bot-processed flaw stores its compact per-field suggestion records (see
    :func:`_compact_fields`) so it can be re-scored per request with any date
    filter -- the per-suggestion timestamps and deviations survive to disk,
    without the bulky raw fields KPI never reads. A non-bot-processed flaw is
    stored as a skip marker (no fields) so its full data isn't re-fetched until
    its watermark advances.
    """
    if not _is_bot_processed(flaw_data):
        return FlawCacheData(updated_dt=updated_dt, bot_processed=False)
    aegis_meta = flaw_data.get("aegis_meta") or {}
    return FlawCacheData(
        updated_dt=updated_dt,
        bot_processed=True,
        fields=_compact_fields(aegis_meta, flaw_data),
    )


def _needs_fetch(cached: FlawCacheData | None, updated_dt: str) -> bool:
    """A flaw needs a full fetch when it's uncached or its watermark advanced."""
    return cached is None or cached.updated_dt != updated_dt


def _in_date_range(
    dt_str: str | None,
    changed_after: datetime | None,
    changed_before: datetime | None,
) -> bool:
    """Whether an ISO timestamp falls within the (optional) request filters.

    Used both for a suggestion's own ``timestamp`` and, historically, a flaw's
    ``updated_dt``.
    """
    if changed_after is None and changed_before is None:
        return True
    if not dt_str:
        # A value with no timestamp can't be placed on the timeline, so it can't
        # satisfy an explicit date filter.
        return False
    updated_dt = datetime.fromisoformat(dt_str)
    if updated_dt.tzinfo is None:
        updated_dt = updated_dt.replace(tzinfo=UTC)
    if changed_after is not None:
        ca = (
            changed_after if changed_after.tzinfo else changed_after.replace(tzinfo=UTC)
        )
        if updated_dt < ca:
            return False
    if changed_before is not None:
        cb = (
            changed_before
            if changed_before.tzinfo
            else changed_before.replace(tzinfo=UTC)
        )
        if updated_dt > cb:
            return False
    return True


class SuggestionRecord(BaseModel):
    """One bot suggestion's KPI-relevant facts, distilled from an aegis_meta entry.

    Only what scoring reads is kept: the ``timestamp`` (for per-suggestion date
    filtering), the entry ``type``, ``data_quality``/``confidence``, and -- for
    AI-Bot entries -- the ``deviation`` of the suggested value from the flaw's
    current value, pre-computed at fetch time. The bulky raw fields never read by
    KPI (explanation, tools_used, skip_description, the full ``cvss_scores``
    array, the raw suggested value) are not stored.
    """

    timestamp: str | None = None
    type: str = ""
    data_quality: float | None = None
    confidence: float | None = None
    deviation: float | None = None


class FlawCacheData(BaseModel):
    """Per-flaw cache entry keyed by the flaw's own ``updated_dt`` watermark.

    ``updated_dt`` is the per-CVE watermark: there is no globally valid cutoff
    across requests, so each flaw is re-fetched only when *its own* timestamp
    advances past the cached one.

    ``bot_processed`` records whether the flaw carried bot suggestions when it
    was last fetched. Non-bot-processed DONE flaws are cached too -- as a skip
    marker with empty ``fields`` -- so their full data isn't re-fetched on every
    request; only a change to their ``updated_dt`` triggers a re-fetch.

    ``fields`` maps each KPI-relevant field to its compact suggestion records.
    Records are stored -- rather than a pre-aggregated per-flaw stat -- so each
    request can re-score with its own date filter against the per-suggestion
    timestamps, which a pre-aggregated stat would have discarded.

    ``extra="forbid"`` makes a cache file written in an earlier schema (e.g. the
    prior ``flaw``-keyed raw-flaw format) fail validation rather than parse as an
    empty entry, so the whole cache is treated as absent and cleanly re-fetched
    instead of silently undercounting.
    """

    model_config = ConfigDict(extra="forbid")

    updated_dt: str
    bot_processed: bool = True
    fields: dict[str, list[SuggestionRecord]] = {}


class BotKPICacheEntry(BaseModel):
    """On-disk cache of each DONE flaw's compact KPI-relevant records.

    Only per-flaw data is cached, never an aggregate: the aggregate depends on
    the request's date filters, and re-scoring the cached records is far cheaper
    than the OSIDB round-trip the cache exists to avoid. The cache exists solely
    to avoid re-fetching unchanged flaws from OSIDB.

    Storing each flaw's records individually (rather than a running total) is
    what lets a flaw be correctly re-scored if it's edited again after the bot's
    initial pass, and lets each request apply its own date filter to the
    per-suggestion timestamps: its entry is simply overwritten and the aggregate
    is recomputed from scratch.
    """

    flaws: dict[str, FlawCacheData]

    @property
    def total_flaws_processed(self) -> int:
        return sum(1 for flaw in self.flaws.values() if flaw.bot_processed)

    def to_kpi_result(
        self,
        *,
        changed_after: datetime | None = None,
        changed_before: datetime | None = None,
    ) -> BotKPIResult:
        """Re-score the bot-processed flaws, filtering suggestions by the range.

        Non-bot-processed skip markers never contribute. Date filters (if any)
        are applied per suggestion against its own ``timestamp`` (see
        :func:`_score_records`), so a flaw contributes only the fields it was
        actually given a suggestion for within the window -- and drops out
        entirely if none of its suggestions fall in range.
        """
        per_flaw: dict[str, dict[str, FeatureStats]] = {}
        for cve_id, flaw in self.flaws.items():
            if not flaw.bot_processed:
                continue
            stats_by_field = _score_fields(
                flaw.fields,
                changed_after=changed_after,
                changed_before=changed_before,
            )
            if stats_by_field:
                per_flaw[cve_id] = stats_by_field
        return _resum(per_flaw)


# -- Response helpers ----------------------------------------------------------


def _stats_to_response(stats: FeatureStats, modified_count: int) -> BotFeatureKPI:
    # Acceptance is a per-flaw-field decision (kept vs. modified), so the rate
    # is measured against suggestions_compared, not `suggested` (a per-entry
    # count that a re-suggested flaw inflates past the number of accept/modify
    # decisions).
    kept = stats.suggestions_compared - modified_count
    compared = stats.suggestions_compared
    acceptance_rate = round((kept / compared) * 100, 1) if compared > 0 else 0.0
    return BotFeatureKPI(
        suggested=stats.suggested,
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


def _reconcile_flaws(
    existing: dict[str, FlawCacheData],
    fetched: dict[str, FlawCacheData],
    index: dict[str, str],
    *,
    index_is_complete: bool,
) -> dict[str, FlawCacheData]:
    """Merge freshly fetched flaws into the cache, pruning departures if it's safe.

    Freshly fetched entries always win. Pruning of cached flaws absent from the
    index depends on whether the index is *complete*:

    - Complete index (an unfiltered request, whose index lists every DONE flaw
      since the bot birthday): a cached flaw absent from it has left DONE (or was
      deleted), so it is pruned and stops counting.
    - Date-bounded index (a windowed request): the index is only that window, so
      an absent flaw may simply be outside it -- pruning would evict flaws from
      other windows (two disjoint ranges would flush each other completely) and
      permanently drop a flaw edited past a fixed report's window. Nothing is
      pruned; such departures are reconciled by the next unfiltered request. A
      KPI query only counts flaws whose suggestions fall in its window (see
      :func:`_score_records`), so retained out-of-window entries never distort a
      windowed result.
    """
    if index_is_complete:
        merged = {cve_id: flaw for cve_id, flaw in existing.items() if cve_id in index}
    else:
        merged = dict(existing)
    merged.update(fetched)
    return merged


def _fetch_with_cache(
    osidb: Any,
    *,
    changed_after: datetime | None = None,
    changed_before: datetime | None = None,
) -> BotKPIResult:
    """Fetch flaws via the two-phase incremental cache, then aggregate on demand.

    A cheap ``{cve_id: updated_dt}`` index of the DONE flaws in range is fetched
    first (see :func:`_fetch_flaw_index` for how the range is bounded); full
    per-flaw data is fetched only for flaws that are new or whose own
    ``updated_dt`` watermark advanced past the cached one. Both fetches run
    outside the cache lock so a slow query can't block other requests. When
    nothing new is fetched, the cache is served as-is without a write; otherwise
    the freshly fetched flaws are merged into it under the lock (see
    :func:`_merge_flaws`). Re-fetching a flaw overwrites its own entry, so a flaw
    edited again after the bot's pass is correctly re-scored rather than frozen.

    Departed flaws are pruned only against a *complete* index -- i.e. on an
    unfiltered request, whose index lists every DONE flaw since the bot birthday.
    A date-bounded index is only a window, so the cache is never pruned to it
    (that would evict flaws from other windows and defeat the cache whenever the
    window changes); such departures are reconciled by the next unfiltered
    request. The aggregate is always computed fresh by re-scoring the cached
    records (never cached itself). ``to_kpi_result`` applies the request's date
    range to each flaw's per-suggestion timestamps, so the response is correct
    even when the cache holds flaws outside the requested window.
    """
    index = _fetch_flaw_index(
        osidb, changed_after=changed_after, changed_before=changed_before
    )

    cached = _read_cache()
    cached_flaws = cached.flaws if cached is not None else {}

    stale_ids = [
        cve_id
        for cve_id, updated_dt in index.items()
        if _needs_fetch(cached_flaws.get(cve_id), updated_dt)
    ]
    batch = _fetch_flaws_batch(osidb, stale_ids)
    fetched: dict[str, FlawCacheData] = {}
    for cve_id, flaw_data in batch.items():
        updated_dt = index.get(cve_id, "")
        fetched[cve_id] = _flaw_cache_data(flaw_data, updated_dt)

    # Only an unfiltered request sees a complete index (every DONE flaw since the
    # bot birthday); only then can a cached flaw's absence be read as a departure
    # and pruned. A date-bounded index is just a window, so absence there is
    # ambiguous and nothing is pruned (see _reconcile_flaws).
    index_is_complete = changed_after is None and changed_before is None
    has_departures = index_is_complete and not set(cached_flaws).issubset(index)

    if not fetched and not has_departures:
        # Nothing new to fetch and nothing to prune, so nothing to write; serve
        # the cache as-is.
        entry = cached if cached is not None else BotKPICacheEntry(flaws={})
    else:
        with _cache_handler() as handler:
            latest = handler.read()
            existing = latest.flaws if latest is not None else cached_flaws
            entry = BotKPICacheEntry(
                flaws=_reconcile_flaws(
                    existing, fetched, index, index_is_complete=index_is_complete
                )
            )
            handler.write(entry)

    return entry.to_kpi_result(
        changed_after=changed_after, changed_before=changed_before
    )


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
