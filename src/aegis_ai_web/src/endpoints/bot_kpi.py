"""KPI metrics computation and endpoint handler for osidb-bot auto-processed flaws.

Compares bot suggestions (stored in aegis_meta) against current flaw field
values to measure how often analysts keep, modify, or skip bot suggestions.
"""

from __future__ import annotations

import logging
import time
from bisect import bisect_right
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

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
from aegis_ai.toolsets.tools.osidb.osidb_bearer import BearerOSIDBSession
from aegis_ai_web.src.data_models import (
    BotFeatureKPI,
    BotKPICacheStatusResponse,
    BotKPIEntry,
    BotKPIProgress,
    BotKPIResponse,
)
from aegis_ai_web.src.endpoints.kpi_filters import (
    NO_RECORD_FILTERS,
    KPIRecordFilters,
)
from aegis_ai_web.src.endpoints.kpi_filters import (
    timestamp_in_range as _timestamp_in_range,
)

logger = logging.getLogger(__name__)

# Flaw fields that the bot writes suggestions for and that we can compare
# against current values.  Underscore-prefixed keys (_ecosystems, _cvss3_vector)
# are metadata-only and have no direct flaw-field counterpart.
BOT_KPI_FIELDS = (
    "components",
    "title",
    "cve_description",
    "cwe_id",
    "impact",
    "statement",
    "mitigation",
)

_META_ONLY_FIELDS = ("_cvss3_vector",)
_ALL_KPI_FIELDS = BOT_KPI_FIELDS + _META_ONLY_FIELDS

_INCLUDE_FIELDS = ",".join(
    ["cve_id", "updated_dt", "aegis_meta", "cvss_scores", *BOT_KPI_FIELDS]
)

_DISPLAY_NAMES: dict[str, str] = {"_cvss3_vector": "cvss3_vector"}

# osidb-bot's "birthday": the date the bot feature was introduced (first commit
# 2026-02-10).  Applied unconditionally as a ``created_dt_gte`` lower bound on
# the flaw-index search so the query can never scrape unrelated OSIDB history --
# either by mistake or as a DoS attempt.  The request's ``changed_after`` /
# ``changed_before`` filters are pushed down as ``updated_dt`` bounds on top of
# this floor, so the index is the set of flaws the request actually selects.
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
        # Graded set distance via a normalized Jaccard index, so a single
        # component added/removed from a list of N scores 1/(N+1) rather than a
        # flat 1.0 for any difference.  The 0.9 factor keeps a case-only change
        # (which normalizes to an exact Jaccard match) from scoring 0.0: since
        # this branch is only reached for values that are not already equal, it
        # registers a small 0.1 deviation instead of reading as "kept".
        suggested_list = suggested if isinstance(suggested, list) else [suggested]
        current_list = current if isinstance(current, list) else [current]
        return round(1.0 - 0.9 * score_components_diff(suggested_list, current_list), 4)
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
    # and a re-suggested field is compared once (only the latest), so this is
    # <= `suggested` (itself per-field, at most 1 here). It is the denominator
    # for both `avg_suggestion_deviation` and the acceptance rate.
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
    entries: list[BotKPIEntry] | None = None
    available_components: list[str] | None = None
    # Pagination metadata (see _fetch_with_cache): ``final_page`` marks the
    # response that carries the aggregate over the whole selection;
    # ``last_cve`` is set on intermediate pages only.
    final_page: bool = True
    last_cve: str | None = None
    progress: BotKPIProgress | None = None


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
        aegis_version=entry.get("aegis_version") or "",
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
    """Aggregate one field's suggestion records into a ``FeatureStats``.

    The OSIDB selection query (see :func:`_fetch_flaw_index`) selects flaws by
    their ``updated_dt``. The request bounds are also applied here so a
    selected flaw contributes only suggestions recorded in the KPI interval.
    A field with no records drops out entirely (returns None). Only the latest
    AI-Bot suggestion is compared against the current value (via its
    pre-computed deviation), matching the single accept/modify decision an
    analyst made.
    """
    records = [
        record
        for record in records
        if _timestamp_in_range(record.timestamp, changed_after, changed_before)
    ]
    if not records:
        return None

    stats = FeatureStats()
    latest_bot: SuggestionRecord | None = None
    for record in records:
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
            # A field re-suggested multiple times (only possible via
            # `osidb-bot --force`) counts as one suggestion, so `suggested` is
            # per-field, not per-entry. This keeps it a checkable invariant --
            # suggestions_compared <= suggested <= 1 per field -- so a corrupted
            # server-side cache can be detected. Keep overwriting `latest_bot`
            # so we compare against the latest suggestion; records are stored
            # chronologically by record_aegis_meta().
            stats.suggested = 1
            latest_bot = record
        elif record.type == "AI-Bot-Skipped":
            # Skips are per-field too (at most 1), for the same integrity reason.
            stats.skipped = 1

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
    """Score every field's records, keyed by display name; skip empty fields."""
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
    it (see :func:`_score_records`). Flaw selection is applied server-side on
    the flaw's ``updated_dt``; suggestion timestamps are scoped here to the
    request interval. A field with no in-range suggestion contributes nothing.
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
    component: str | None = None,
    updated_since: datetime | None = None,
) -> dict[str, str]:
    """Fetch a cheap ``{cve_id: updated_dt}`` index of the selected DONE flaws.

    This is the selection query: it applies the request's filters server-side
    and returns exactly the flaws the response covers. It pulls only the two
    fields needed to decide whether each flaw's cached full data is still
    current (bot-processed status can't be filtered server-side, so every
    matching DONE flaw is indexed). Full per-flaw data is fetched separately,
    and only for flaws whose watermark has advanced -- see
    :func:`_fetch_flaws_batch`.

    The search is always bounded by ``created_dt_gte=OSIDB_BOT_BIRTHDAY`` so it
    can never scrape unrelated OSIDB history. ``cve_id__isempty=False`` drops
    flaws without a CVE ID server-side instead of fetching them only to discard
    them here.

    ``changed_after`` / ``changed_before`` are pushed down as ``updated_dt``
    bounds and ``component`` as the flaw-level ``components`` filter (the field
    the KPI scores against). These drive *selection* only: they never invalidate
    a cache entry, which is refreshed solely when its own ``updated_dt`` advances
    (see :func:`_fetch_with_cache``).

    ``updated_since`` bounds the query to flaws updated since a watermark,
    turning it into a delta query for stamp validation (see
    :func:`resolve_selection`); when both bounds apply, the later one wins.
    """
    kwargs: dict[str, Any] = {
        "include_fields": "cve_id,updated_dt",
        "workflow_state": "DONE",
        "created_dt_gte": OSIDB_BOT_BIRTHDAY,
        "cve_id__isempty": False,
        "limit": 1000,
    }
    lower_bounds = [
        as_utc(bound) for bound in (changed_after, updated_since) if bound is not None
    ]
    if lower_bounds:
        kwargs["updated_dt_gte"] = max(lower_bounds)
    if changed_before is not None:
        kwargs["updated_dt_lte"] = changed_before
    if component is not None:
        kwargs["components"] = component
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

# Default number of selected flaws served (and at most refreshed) per request.
_DEFAULT_PAGE_SIZE = 400


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


def refresh_stale_slice(
    osidb: Any, index: dict[str, str], stale_ids: list[str]
) -> dict[str, FlawCacheData]:
    """Fetch one bounded slice of the stale flaws under the refresh budget.

    Flaws are fetched in ``_BATCH_SIZE`` batches in order. When the time
    budget (``AEGIS_BOT_KPI_MAX_REFRESH_SECS``) is exhausted, the remaining
    flaws are left for the next call; at least one batch always runs so every
    call makes progress. A flaw that vanished between the index query and the
    fetch (e.g. deleted) is tombstoned as a non-bot-processed skip marker at
    its indexed watermark, so the refresh still completes. Called by the
    cache-refresh endpoint, whose polling clients drive the pacing.
    """
    fetched: dict[str, FlawCacheData] = {}
    deadline = time.monotonic() + get_settings().bot_kpi_max_refresh_seconds
    for offset in range(0, len(stale_ids), _BATCH_SIZE):
        if fetched and time.monotonic() > deadline:
            logger.info(
                "KPI refresh time budget exhausted after %d flaws; "
                "deferring %d flaws to the next refresh call",
                len(fetched),
                len(stale_ids) - offset,
            )
            break
        chunk = stale_ids[offset : offset + _BATCH_SIZE]
        batch = _fetch_flaws_batch(osidb, chunk)
        for cve_id in chunk:
            flaw_data = batch.get(cve_id)
            if flaw_data is None:
                fetched[cve_id] = FlawCacheData(
                    updated_dt=index.get(cve_id, ""),
                    bot_processed=False,
                    components=[],
                )
            else:
                fetched[cve_id] = _flaw_cache_data(flaw_data, index.get(cve_id, ""))
    return fetched


def _flaw_cache_data(flaw_data: dict[str, Any], updated_dt: str) -> FlawCacheData:
    """Build a cache entry from a fully-fetched flaw.

    A bot-processed flaw stores its compact per-field suggestion records (see
    :func:`_compact_fields`) -- the pre-computed deviations and per-field
    suggestion history -- so it can be re-scored from the cache without the bulky
    raw fields KPI never reads. A non-bot-processed flaw is stored as a skip
    marker (no fields) so its full data isn't re-fetched until its watermark
    advances.
    """
    if not _is_bot_processed(flaw_data):
        return FlawCacheData(updated_dt=updated_dt, bot_processed=False, components=[])
    aegis_meta = flaw_data.get("aegis_meta") or {}
    return FlawCacheData(
        updated_dt=updated_dt,
        bot_processed=True,
        components=flaw_data.get("components") or [],
        fields=_compact_fields(aegis_meta, flaw_data),
    )


def stale_reason(
    cached: FlawCacheData | None, updated_dt: str
) -> Literal["uncached", "outdated"] | None:
    """Why a flaw's cached data is stale; None when it is still current.

    ``uncached`` -- the flaw has no cache entry at all. ``outdated`` -- an
    entry exists but cannot be trusted to be current: OSIDB's watermark
    advanced past it, it predates component provenance (``components is
    None``), or its own watermark is malformed. The latter two share the
    bucket because the remedy is identical: a full re-fetch.

    A flaw whose *OSIDB* watermark is unusable (the index stores ``""`` when
    OSIDB reports none) is treated as fresh once cached: OSIDB provides no
    ordering to compare against, so re-fetching it could never converge and
    a polling refresh drain would never terminate. It is fetched once, as
    fresh as OSIDB allows.
    """
    if cached is None:
        return "uncached"
    if cached.components is None:
        return "outdated"
    try:
        osidb_dt = datetime.fromisoformat(updated_dt)
    except ValueError:
        return None
    try:
        cached_dt = datetime.fromisoformat(cached.updated_dt)
    except ValueError:
        # A malformed cached watermark cannot establish freshness safely.
        return "outdated"
    if cached_dt.tzinfo is None:
        cached_dt = cached_dt.replace(tzinfo=UTC)
    if osidb_dt.tzinfo is None:
        osidb_dt = osidb_dt.replace(tzinfo=UTC)
    if cached_dt < osidb_dt:
        return "outdated"
    return None


def _needs_fetch(cached: FlawCacheData | None, updated_dt: str) -> bool:
    """A flaw needs a full fetch when its cached data is stale."""
    return stale_reason(cached, updated_dt) is not None


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
    aegis_version: str = ""
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
    # None identifies old caches missing component AND version provenance.
    # Keep the marker across cache rewrites until this flaw has been fetched.
    components: list[str] | None = None
    fields: dict[str, list[SuggestionRecord]] = {}


class SelectionStamp(BaseModel):
    """The OSIDB flaw index for one selection, watermark-stamped.

    ``index`` maps cve_id to the flaw's OSIDB ``updated_dt`` watermark at the
    time the selection was last validated. ``fetched_at`` is recorded *before*
    the validating query is issued, so anything updated during a long query is
    re-seen by the next delta (monotone-safe). Cursor-carrying page requests
    trust the matching stamp: all pages of one run reflect the selection as
    of the run's first request.
    """

    index: dict[str, str]
    fetched_at: datetime


class BotKPICacheEntry(BaseModel):
    """On-disk cache of each DONE flaw's compact KPI-relevant records.

    Only per-flaw data is cached, never an aggregate: the aggregate depends on
    which CVE IDs a request selects, and re-scoring the cached records is far
    cheaper than the OSIDB round-trip the cache exists to avoid. The cache exists
    solely to avoid re-fetching unchanged flaws from OSIDB.

    Storing each flaw's records individually (rather than a running total) is
    what lets a flaw be correctly re-scored if it's edited again after the bot's
    initial pass: its entry is simply overwritten and the aggregate is recomputed
    from scratch over the selected CVE IDs.

    ``selections`` holds the watermark-stamped selection indexes (see
    :class:`SelectionStamp`) keyed by filter signature, so a run's first request
    validates the selection with a cheap delta query instead of a full scan and
    the run's page requests reuse it without OSIDB contact.
    """

    flaws: dict[str, FlawCacheData]
    selections: dict[str, SelectionStamp] = {}

    @property
    def total_flaws_processed(self) -> int:
        return sum(1 for flaw in self.flaws.values() if flaw.bot_processed)

    def to_kpi_result(
        self,
        *,
        only_cve_ids: set[str] | None = None,
        changed_after: datetime | None = None,
        changed_before: datetime | None = None,
        record_filters: KPIRecordFilters = NO_RECORD_FILTERS,
        detail: bool = False,
    ) -> BotKPIResult:
        """Re-score the bot-processed flaws restricted to the selected CVE IDs.

        Non-bot-processed skip markers never contribute. Flaw-level date and
        component scoping are applied server-side by the selection query (see
        :func:`_fetch_flaw_index`), while suggestion-level date scoping is
        applied during scoring. The cache may hold flaws from other windows or
        components, which are simply not scored. ``None`` (used only in tests)
        scores every cached flaw.
        """
        per_flaw: dict[str, dict[str, FeatureStats]] = {}
        entries: list[BotKPIEntry] = []
        components: set[str] = set()
        for cve_id, flaw in self.flaws.items():
            if only_cve_ids is not None and cve_id not in only_cve_ids:
                continue
            if not flaw.bot_processed:
                continue
            components.update(flaw.components or [])
            fields = {
                name: [
                    record
                    for record in records
                    if record_filters.matches(record.timestamp, record.aegis_version)
                    and _timestamp_in_range(
                        record.timestamp, changed_after, changed_before
                    )
                ]
                for name, records in flaw.fields.items()
            }
            stats_by_field = _score_fields(
                fields,
            )
            if stats_by_field:
                per_flaw[cve_id] = stats_by_field
            if detail:
                entries.extend(_detail_entries(cve_id, fields))
        result = _resum(per_flaw)
        if detail:
            result.entries = entries
            result.available_components = sorted(components)
        return result


def _detail_entries(
    cve_id: str, fields: dict[str, list[SuggestionRecord]]
) -> list[BotKPIEntry]:
    return [
        BotKPIEntry(
            cve_id=cve_id,
            feature=_display_name(name),
            datetime=record.timestamp,
            aegis_version=record.aegis_version,
            type=record.type,
            deviation=record.deviation,
            data_quality=record.data_quality,
            confidence=record.confidence,
        )
        for name, records in fields.items()
        for record in records
    ]


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
    """Map an internal result to the API response.

    Intermediate pages of a paginated response carry placeholder aggregates
    (``total_flaws_processed`` 0, empty ``features``) plus their slice's
    ``entries``, the refresh ``progress``, and the ``last_cve`` to
    continue from; the final page carries the complete aggregate.
    """
    if result.final_page:
        features = {
            name: _stats_to_response(stats, result.modified_counts.get(name, 0))
            for name, stats in result.features.items()
        }
        total_flaws_processed = result.total_flaws_processed
    else:
        features = {}
        total_flaws_processed = 0
    response = BotKPIResponse(
        total_flaws_processed=total_flaws_processed,
        features=features,
    )
    if result.entries is not None:
        response.entries = result.entries
    if result.final_page and result.available_components is not None:
        response.available_components = result.available_components
    if not result.final_page:
        response.last_cve = result.last_cve
    if result.progress is not None:
        response.progress = result.progress
    return response


# -- Cache helpers -------------------------------------------------------------


def _get_cache_path() -> Path:
    settings = get_settings()
    if settings.bot_kpi_cache_dir:
        return Path(settings.bot_kpi_cache_dir) / "kpi_cache.json"
    return Path(settings.config_dir) / "osidb_bot_kpi" / "kpi_cache.json"


def _cache_handler(*, create: bool = True) -> StateFileHandler[BotKPICacheEntry]:
    """A blocking, file-locked handler over the KPI cache file itself.

    Locking the cache file directly (no separate ``.lock`` sidecar) means
    there is only ever one file to reason about. The blocking lock serializes
    the read-modify-write cycles of concurrent requests so they can't clobber
    each other's results. ``create=False`` is the read-only discipline: the
    cache file (and its directory) is never materialized by a read.
    """
    cache_path = _get_cache_path()
    if create:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
    return StateFileHandler(
        str(cache_path), BotKPICacheEntry, blocking=True, create=create
    )


def _read_cache() -> BotKPICacheEntry | None:
    """Read the cache under a brief lock; None if absent, empty, or corrupt.

    Read-only: an absent or corrupt cache must not be created or repaired by
    a reader -- the write path materializes it on first refresh.
    """
    with _cache_handler(create=False) as handler:
        return handler.read()


def as_utc(value: datetime) -> datetime:
    """Read a possibly naive datetime as UTC (query params may be naive)."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def selection_signature(
    changed_after: datetime | None,
    changed_before: datetime | None,
    component: str | None,
) -> str:
    """Identify the selection a stamp belongs to, from its filter triple."""
    return "|".join(
        (
            changed_after.isoformat() if changed_after is not None else "",
            changed_before.isoformat() if changed_before is not None else "",
            component or "",
        )
    )


# A stamp is re-validated by a delta query bounded to flaws updated since its
# watermark; one minute of slack absorbs clock skew between OSIDB and this
# host (re-seeing a flaw is harmless -- the merge is idempotent).
_SELECTION_DELTA_SLACK = timedelta(minutes=1)

# A stamp older than a day is rebuilt from a full query so deletions --
# which delta queries cannot see -- cannot drift the selection forever.
_SELECTION_FULL_REFRESH_AFTER = timedelta(hours=24)

# Filter signatures whose stamped indexes are kept in the cache file;
# interleaved filter scopes beyond this evict the least recently stamped.
_SELECTION_STAMP_LIMIT = 4


def evict_old_stamps(stamps: dict[str, SelectionStamp]) -> None:
    """Keep the most recently stamped ``_SELECTION_STAMP_LIMIT`` signatures."""
    if len(stamps) <= _SELECTION_STAMP_LIMIT:
        return
    by_recency = sorted(stamps, key=lambda sig: as_utc(stamps[sig].fetched_at))
    for signature in by_recency[: len(stamps) - _SELECTION_STAMP_LIMIT]:
        del stamps[signature]


def merge_stamps(
    existing: dict[str, SelectionStamp], updated: dict[str, SelectionStamp] | None
) -> dict[str, SelectionStamp]:
    """Merge updated stamps onto the live set, keeping the newer stamp per
    signature so a concurrent writer's fresher validation is never regressed."""
    if updated is None:
        return existing
    merged = dict(existing)
    for signature, stamp in updated.items():
        current = merged.get(signature)
        if current is None or as_utc(stamp.fetched_at) >= as_utc(current.fetched_at):
            merged[signature] = stamp
    evict_old_stamps(merged)
    return merged


def resolve_selection(
    osidb: Any,
    cached: BotKPICacheEntry | None,
    *,
    changed_after: datetime | None,
    changed_before: datetime | None,
    component: str | None,
    validate: bool,
) -> tuple[dict[str, str], dict[str, SelectionStamp] | None]:
    """Resolve the selection index, reusing the matching watermark stamp.

    A validating request (a run's first request, or the status endpoints)
    extends the stamped index with a delta query over flaws updated since the
    stamp watermark -- measured at ~0.25s for an hour of updates versus the
    ~150s full scan for 72k flaws -- or rebuilds it with a full query when no
    stamp exists or it is older than the full-refresh horizon. A trusting
    request (a cursor-carrying page) serves from the matching stamp with no
    OSIDB contact, so all pages of one run reflect the selection as of the
    run's first request. A missing or mismatched stamp always falls back to
    validation: requests are self-healing and never depend on prior state.

    Returns the resolved index and, when it changed, the stamps to persist.
    An unchanged index (empty delta, identical watermarks) keeps the existing
    stamp so the common warm run-start stays write-free.
    """
    signature = selection_signature(changed_after, changed_before, component)
    stamps = dict(cached.selections) if cached is not None else {}
    stamp = stamps.get(signature)

    if not validate and stamp is not None:
        return stamp.index, None

    fetched_at = datetime.now(UTC)
    if (
        stamp is not None
        and fetched_at - as_utc(stamp.fetched_at) <= _SELECTION_FULL_REFRESH_AFTER
    ):
        delta = _fetch_flaw_index(
            osidb,
            changed_after=changed_after,
            changed_before=changed_before,
            component=component,
            updated_since=as_utc(stamp.fetched_at) - _SELECTION_DELTA_SLACK,
        )
        if any(
            stamp.index.get(cve_id) != updated_dt
            for cve_id, updated_dt in delta.items()
        ):
            index = dict(stamp.index)
            index.update(delta)
            stamps[signature] = SelectionStamp(index=index, fetched_at=fetched_at)
            return index, stamps
        # Nothing changed; the persisted stamp (and its watermark) stands.
        return stamp.index, None

    index = _fetch_flaw_index(
        osidb,
        changed_after=changed_after,
        changed_before=changed_before,
        component=component,
    )
    stamps[signature] = SelectionStamp(index=index, fetched_at=fetched_at)
    evict_old_stamps(stamps)
    return index, stamps


@dataclass
class CacheCheck:
    """The selection index diffed against the on-disk cache.

    Shared by the KPI refresh path (which fetches ``stale_ids`` and merges
    them into the cache) and the cache-status endpoint (which only reports
    the counts). ``cached`` is the cache snapshot taken *before* any fetch,
    which the merge logic relies on to detect concurrent writes. ``stamps``
    carries updated selection stamps to persist when the resolution changed
    the index (None means unchanged).
    """

    index: dict[str, str]
    cached: BotKPICacheEntry | None
    stale_ids: list[str]
    uncached_count: int
    outdated_count: int
    stamps: dict[str, SelectionStamp] | None = None


def classify_stale(
    index: dict[str, str], cached_flaws: dict[str, FlawCacheData]
) -> tuple[list[str], int, int]:
    """Classify every selected flaw as fresh, uncached, or outdated.

    Returns the stale CVE IDs in selection order plus the uncached and
    outdated counts; fresh flaws are simply absent from the stale list.
    """
    stale_ids: list[str] = []
    uncached_count = 0
    outdated_count = 0
    for cve_id, updated_dt in index.items():
        reason = stale_reason(cached_flaws.get(cve_id), updated_dt)
        if reason is None:
            continue
        stale_ids.append(cve_id)
        if reason == "uncached":
            uncached_count += 1
        else:
            outdated_count += 1
    return stale_ids, uncached_count, outdated_count


def check_cache(
    osidb: Any,
    *,
    changed_after: datetime | None = None,
    changed_before: datetime | None = None,
    component: str | None = None,
    validate: bool = True,
) -> CacheCheck:
    """Select the requested flaws and diff their watermarks against the cache.

    Runs the selection resolution (see :func:`resolve_selection`; a trusting
    check reuses the matching stamp without OSIDB contact) and classifies
    every selected flaw as fresh, uncached, or outdated (see
    :func:`stale_reason`). Read-only: full flaw data is never fetched and the
    cache is never written here -- the caller persists ``stamps`` if it
    chooses to write at all.
    """
    cached = _read_cache()
    index, stamps = resolve_selection(
        osidb,
        cached,
        changed_after=changed_after,
        changed_before=changed_before,
        component=component,
        validate=validate,
    )
    cached_flaws = cached.flaws if cached is not None else {}
    stale_ids, uncached_count, outdated_count = classify_stale(index, cached_flaws)
    return CacheCheck(
        index=index,
        cached=cached,
        stale_ids=stale_ids,
        uncached_count=uncached_count,
        outdated_count=outdated_count,
        stamps=stamps,
    )


# -- Endpoint handler ----------------------------------------------------------


def _merge_fetched(
    existing: dict[str, FlawCacheData],
    fetched: dict[str, FlawCacheData],
    snapshot: dict[str, FlawCacheData],
) -> dict[str, FlawCacheData]:
    """Apply freshly fetched entries onto the live cache, per CVE.

    ``fetched`` is captured from OSIDB *before* the cache lock, so ``existing``
    (re-read under the lock) may already carry work from a concurrent request. A
    fetched entry is skipped when the live ``existing`` watermark differs from
    ``snapshot`` and is at least as new as the fetched watermark; if the fetched
    entry is newer, it is applied.

    Entries outside ``fetched`` are left untouched: selection never evicts, so a
    narrow request never drops another window's or component's cached flaws.
    """
    merged = dict(existing)
    for cve_id, flaw in fetched.items():
        prior = snapshot.get(cve_id)
        live = merged.get(cve_id)
        prior_dt = prior.updated_dt if prior is not None else None
        live_dt = live.updated_dt if live is not None else None
        if live_dt != prior_dt and not _needs_fetch(live, flaw.updated_dt):
            # Keep a concurrent entry when it is at least as new as our fetch.
            continue
        merged[cve_id] = flaw
    return merged


def _fetch_with_cache(
    osidb: Any,
    *,
    changed_after: datetime | None = None,
    changed_before: datetime | None = None,
    component: str | None = None,
    record_filters: KPIRecordFilters = NO_RECORD_FILTERS,
    detail: bool = False,
    cursor: str | None = None,
    limit: int = _DEFAULT_PAGE_SIZE,
) -> BotKPIResult:
    """Serve one limit-sized page of the selection from the cache.

    The request's filters drive a single *selection* query and nothing else:

    *Select* -- the request's ``changed_after`` / ``changed_before`` (as
    ``updated_dt`` bounds) and ``component`` define a selection whose index
    is resolved once per run and then reused: the run's first request (no
    cursor) validates the watermark-stamped index with a cheap delta query,
    and the run's page requests (cursor present) trust that stamp without
    OSIDB contact (see :func:`resolve_selection`). Its CVE IDs, sorted, are
    exactly the flaws the response covers.

    *Serve* -- the selection is served in ``limit``-sized pages as pure cache
    reads: a page never fetches from OSIDB and never writes the cache, so it
    can never block or time out. A stale flaw serves its last-known cached
    records and a never-cached flaw simply contributes no entries; the
    ``progress`` block honestly reports how much of the selection is
    currently cached. Refreshing is the cache-refresh endpoint's job, driven
    by polling clients (see :func:`refresh_osidb_bot_kpi_cache`). A selection
    that fits one page is served as a single final page.

    The aggregate is recomputed fresh from the cached records, never cached
    itself. Intermediate pages carry only their own slice's ``entries`` plus
    pagination metadata; the final page adds the aggregate over the whole
    selection, so a client that accumulates pages ends with exactly one copy
    of every entry.
    """
    check = check_cache(
        osidb,
        changed_after=changed_after,
        changed_before=changed_before,
        component=component,
        # A run's first request validates the selection; its page requests
        # trust the stamp so pagination costs no further index queries.
        validate=cursor is None,
    )
    index = check.index
    cached = check.cached

    selected = sorted(index)
    page_ids = [cve_id for cve_id in selected if cursor is None or cve_id > cursor][
        :limit
    ]

    if check.stamps is not None:
        # The selection resolution changed the index; persist the stamp so
        # the run's page requests can trust it.
        entry = persist_stamps(check.stamps, check.cached)
    else:
        entry = cached if cached is not None else BotKPICacheEntry(flaws={})

    live = entry.flaws

    # Pure serving: every flaw of the page is delivered at its last-known
    # cached state; freshness is reported, not enforced.
    final_page = not page_ids or page_ids[-1] == selected[-1]

    page_result = entry.to_kpi_result(
        only_cve_ids=set(page_ids),
        changed_after=changed_after,
        changed_before=changed_before,
        record_filters=record_filters,
        detail=detail,
    )
    if final_page:
        # The final page's aggregate covers the whole selection; its entries
        # stay scoped to the page so accumulating clients don't double-count.
        result = entry.to_kpi_result(
            only_cve_ids=set(index),
            changed_after=changed_after,
            changed_before=changed_before,
            record_filters=record_filters,
            detail=detail,
        )
        if detail:
            result.entries = page_result.entries
    else:
        result = page_result

    refreshed = sum(
        1 for cve_id in selected if not _needs_fetch(live.get(cve_id), index[cve_id])
    )
    # Delivered counts every selected flaw up to and including this page's
    # last flaw, so a client appending this page's entries reaches exactly
    # this total -- an honest delivery bar without any run state.
    delivered_through = page_ids[-1] if page_ids else cursor
    delivered = bisect_right(selected, delivered_through) if delivered_through else 0
    result.final_page = final_page
    result.last_cve = None if final_page else (page_ids[-1] if page_ids else cursor)
    result.progress = BotKPIProgress(
        selected_flaws=len(selected),
        refreshed_flaws=refreshed,
        delivered_flaws=delivered,
        complete=refreshed == len(selected),
    )
    return result


def new_osidb_session(osidb_token: str | None) -> Any:
    """An OSIDB session for the configured server, authenticated per token."""
    osidb_server = get_settings().osidb_server_url
    if osidb_token:
        return BearerOSIDBSession(osidb_server, osidb_token)
    return osidb_bindings.new_session(osidb_server_uri=osidb_server)


def guarded_osidb_call[T](operation: str, call: Callable[[], T]) -> T:
    """Run an OSIDB-backed handler body, mapping failures to HTTP errors.

    OSError also covers requests.exceptions.RequestException (it subclasses
    OSError), so this catches real connectivity failures without masking
    programming bugs (AttributeError, TypeError, etc.) as a 503 outage.
    """
    try:
        return call()
    except OSError:
        logger.error("Failed to connect to OSIDB")
        logger.debug("OSIDB connection error details", exc_info=True)
        raise HTTPException(
            status_code=503,
            detail="Unable to connect to OSIDB.",
        ) from None
    except HTTPException:
        raise
    except Exception:
        logger.error("Error computing %s", operation)
        logger.debug("%s error details", operation, exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"An internal error occurred while computing {operation}.",
        ) from None


def persist_stamps(
    stamps: dict[str, SelectionStamp], cached: BotKPICacheEntry | None
) -> BotKPICacheEntry:
    """Persist newly resolved selection stamps under the cache lock.

    A stamps-only write: flaw entries are never touched, and an unchanged
    stamp set writes nothing. Without this, a selection resolution that
    built its stamp via a full query would be re-run in full on every
    subsequent request. ``cached`` is the pre-resolution snapshot the merge
    diffs against; returns the post-write cache entry.
    """
    with _cache_handler() as handler:
        latest = handler.read()
        base = latest if latest is not None else cached
        if base is None:
            entry = BotKPICacheEntry(flaws={}, selections=stamps)
            handler.write(entry)
            return entry
        merged = merge_stamps(base.selections, stamps)
        if merged == base.selections:
            return base
        entry = BotKPICacheEntry(flaws=base.flaws, selections=merged)
        handler.write(entry)
        return entry


def refresh_cache_slice(
    osidb: Any,
    *,
    changed_after: datetime | None = None,
    changed_before: datetime | None = None,
    component: str | None = None,
) -> CacheCheck:
    """Advance the refresh of the selected flaws by one bounded slice.

    Validates the selection (delta or full query, see :func:`check_cache`),
    refreshes a time-budgeted slice of the whole stale list (see
    :func:`refresh_stale_slice`), merges the fetched entries and updated
    stamps into the cache under the lock, and re-classifies so the returned
    counts describe the post-slice state. A call with nothing stale refreshes
    no flaws but still persists a newly resolved selection stamp, so polling
    an already-fresh selection stops paying the full index scan.
    """
    check = check_cache(
        osidb,
        changed_after=changed_after,
        changed_before=changed_before,
        component=component,
    )
    if not check.stale_ids:
        if check.stamps is not None:
            persist_stamps(check.stamps, check.cached)
        return check

    cached = check.cached
    cached_flaws = cached.flaws if cached is not None else {}
    fetched = refresh_stale_slice(osidb, check.index, check.stale_ids)

    with _cache_handler() as handler:
        latest = handler.read()
        existing = latest.flaws if latest is not None else cached_flaws
        existing_stamps = (
            latest.selections
            if latest is not None
            else (cached.selections if cached is not None else {})
        )
        entry = BotKPICacheEntry(
            flaws=_merge_fetched(existing, fetched, cached_flaws),
            selections=merge_stamps(existing_stamps, check.stamps),
        )
        handler.write(entry)

    stale_ids, uncached_count, outdated_count = classify_stale(check.index, entry.flaws)
    return CacheCheck(
        index=check.index,
        cached=entry,
        stale_ids=stale_ids,
        uncached_count=uncached_count,
        outdated_count=outdated_count,
        stamps=None,
    )


def get_osidb_bot_kpi(
    *,
    changed_after: datetime | None = None,
    changed_before: datetime | None = None,
    component: str | None = None,
    record_filters: KPIRecordFilters = NO_RECORD_FILTERS,
    detail: bool = False,
    osidb_token: str | None = None,
    cursor: str | None = None,
    limit: int = _DEFAULT_PAGE_SIZE,
) -> BotKPIResponse:
    """Fetch bot-processed flaws from OSIDB and compute KPI metrics.

    The response is paginated over the selected flaws: follow ``last_cve``
    (passing it back as ``cursor``) until it is absent, accumulating each
    page's ``entries``; the final page carries the aggregate metrics. Pages
    are pure cache reads -- poll the cache-refresh endpoint first to bring
    the cache up to date (see :func:`refresh_osidb_bot_kpi_cache`).
    """

    def fetch() -> BotKPIResponse:
        result = _fetch_with_cache(
            new_osidb_session(osidb_token),
            changed_after=changed_after,
            changed_before=changed_before,
            component=component,
            record_filters=record_filters,
            detail=detail,
            cursor=cursor,
            limit=limit,
        )
        return _result_to_response(result)

    return guarded_osidb_call("osidb-bot KPI metrics", fetch)


def refresh_osidb_bot_kpi_cache(
    *,
    changed_after: datetime | None = None,
    changed_before: datetime | None = None,
    component: str | None = None,
    osidb_token: str | None = None,
) -> BotKPICacheStatusResponse:
    """Advance the osidb-bot KPI cache refresh by one bounded slice.

    Each call refreshes a time-budgeted batch of the selected flaws' stale
    entries (at least one batch, so every call makes progress) and returns
    the post-slice counts. A polling client drains the backlog at its own
    pace: the poll rate bounds the OSIDB load and no server-side job state
    exists -- requests stay stateless.
    """

    def fetch() -> BotKPICacheStatusResponse:
        check = refresh_cache_slice(
            new_osidb_session(osidb_token),
            changed_after=changed_after,
            changed_before=changed_before,
            component=component,
        )
        return BotKPICacheStatusResponse(
            total_flaws_selected=len(check.index),
            fresh_count=len(check.index) - len(check.stale_ids),
            stale_count=len(check.stale_ids),
            uncached_count=check.uncached_count,
            outdated_count=check.outdated_count,
        )

    return guarded_osidb_call("osidb-bot cache refresh", fetch)


def get_osidb_bot_cache_status(
    *,
    changed_after: datetime | None = None,
    changed_before: datetime | None = None,
    component: str | None = None,
    osidb_token: str | None = None,
) -> BotKPICacheStatusResponse:
    """Report how many selected flaws need a cache refresh, without refreshing.

    Read-only: the cheap OSIDB flaw-index query runs (it *is* the freshness
    check -- see :func:`check_cache`), but no full flaw data is fetched and
    the cache file is never written.
    """

    def fetch() -> BotKPICacheStatusResponse:
        check = check_cache(
            new_osidb_session(osidb_token),
            changed_after=changed_after,
            changed_before=changed_before,
            component=component,
        )
        return BotKPICacheStatusResponse(
            total_flaws_selected=len(check.index),
            fresh_count=len(check.index) - len(check.stale_ids),
            stale_count=len(check.stale_ids),
            uncached_count=check.uncached_count,
            outdated_count=check.outdated_count,
        )

    return guarded_osidb_call("osidb-bot cache status", fetch)
