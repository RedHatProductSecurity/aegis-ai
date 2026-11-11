"""KPI metrics computation and endpoint handler for osidb-bot auto-processed flaws.

Compares bot suggestions (stored in aegis_meta) against current flaw field
values to measure how often analysts keep, modify, or skip bot suggestions.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import osidb_bindings
import requests
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict

from aegis_ai import get_settings
from aegis_ai.features.cve.impact_mappings import (
    score_components_diff,
    score_cvss3_diff,
    score_impact_diff,
)
from aegis_ai.toolsets.tools.osidb.osidb_bearer import BearerOSIDBSession
from aegis_ai_web.src.data_models import (
    BotFeatureKPI,
    BotKPIDelivery,
    BotKPIEntry,
    BotKPIResponse,
)
from aegis_ai_web.src.endpoints.kpi_filters import (
    NO_RECORD_FILTERS,
    KPIRecordFilters,
)
from aegis_ai_web.src.endpoints.kpi_filters import (
    timestamp_in_range as _timestamp_in_range,
)
from aegis_ai_web.src.endpoints.kpi_retry import KPIFailure, _retimeout_session

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

    The OSIDB selection query selects flaws by their ``updated_dt``. The
    request bounds are also applied here so a selected flaw contributes only
    suggestions recorded in the KPI interval. A field with no records drops
    out entirely (returns None). Only the latest AI-Bot suggestion is compared
    against the current value (via its pre-computed deviation), matching the
    single accept/modify decision an analyst made.
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


def _index_query(
    changed_after: datetime | None = None,
    changed_before: datetime | None = None,
    component: str | None = None,
) -> dict[str, Any]:
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
    if component is not None:
        kwargs["components"] = component
    return kwargs


_BATCH_SIZE = 100

# Default number of selected flaws served (and at most refreshed) per request.
_DEFAULT_PAGE_SIZE = 400


def _fetch_flaws_batch(
    osidb: Any, cve_ids: list[str], *, strict: bool = False
) -> dict[str, dict[str, Any]]:
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
                if strict and cve_id in result:
                    raise KPIFailure(
                        409,
                        "Conflicting OSIDB detail identities.",
                        code="kpi_run_invalidated",
                    )
                result[cve_id] = flaw_dict
    logger.info("fetched %d/%d flaws", len(result), len(cve_ids))
    return result


def _flaw_cache_data(flaw_data: dict[str, Any], updated_dt: str) -> FlawCacheData:
    """Build a cache entry from a fully-fetched flaw.

    The flaw's own ``updated_dt`` from the full fetch is the authoritative
    watermark (the index projection may be missing or malformed); the indexed
    watermark is only a fallback. A bot-processed flaw stores its compact
    per-field suggestion records (see :func:`_compact_fields`) -- the
    pre-computed deviations and per-field suggestion history -- so it can be
    re-scored from the cache without the bulky raw fields KPI never reads. A
    non-bot-processed flaw is stored as a skip marker (no fields) so its full
    data isn't re-fetched until its watermark advances.
    """
    watermark = str(flaw_data.get("updated_dt") or "") or updated_dt
    if not _is_bot_processed(flaw_data):
        return FlawCacheData(updated_dt=watermark, bot_processed=False, components=[])
    aegis_meta = flaw_data.get("aegis_meta") or {}
    return FlawCacheData(
        updated_dt=watermark,
        bot_processed=True,
        components=flaw_data.get("components") or [],
        fields=_compact_fields(aegis_meta, flaw_data),
    )


def _needs_fetch(cached: FlawCacheData | None, updated_dt: str) -> bool:
    """A flaw needs a full fetch when OSIDB's watermark is newer.

    A watermark that cannot be parsed cannot be ordered against the cache.
    An unparseable *OSIDB* watermark is treated as current: the cache entry
    was fetched at full fidelity at exactly this watermark, and re-fetching
    on every request would livelock pagination (e.g. a tombstone for a flaw
    that vanished after the index query). An unparseable *cached* watermark
    against a parseable OSIDB one means the flaw moved past a watermark we
    cannot compare, so it is re-fetched.
    """
    if cached is None or cached.components is None:
        return True
    try:
        osidb_dt = datetime.fromisoformat(updated_dt)
    except ValueError:
        return False
    try:
        cached_dt = datetime.fromisoformat(cached.updated_dt)
    except ValueError:
        return True
    if cached_dt.tzinfo is None:
        cached_dt = cached_dt.replace(tzinfo=UTC)
    if osidb_dt.tzinfo is None:
        osidb_dt = osidb_dt.replace(tzinfo=UTC)
    return cached_dt < osidb_dt


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
    """

    flaws: dict[str, FlawCacheData]

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
        component scoping are applied server-side by the selection query,
        while suggestion-level date scoping is applied during scoring. The
        cache may hold flaws from other windows or components, which are
        simply not scored. ``None`` (used only in tests) scores every cached
        flaw.
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


def _result_to_response(
    result: BotKPIResult, delivery: BotKPIDelivery
) -> BotKPIResponse:
    """Map an internal result and delivery metadata to the API response."""
    features = {
        name: _stats_to_response(stats, result.modified_counts.get(name, 0))
        for name, stats in result.features.items()
    }
    response = BotKPIResponse(
        total_flaws_processed=result.total_flaws_processed,
        features=features,
        delivery=delivery,
    )
    if result.entries is not None:
        response.entries = result.entries
    if result.available_components is not None:
        response.available_components = result.available_components
    return response


# -- Cache helpers -------------------------------------------------------------


def _get_cache_path() -> Path:
    settings = get_settings()
    if settings.bot_kpi_cache_dir:
        return Path(settings.bot_kpi_cache_dir) / "kpi_cache.json"
    return Path(settings.config_dir) / "osidb_bot_kpi" / "kpi_cache.json"


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


def _osidb_session(server_url: str, token: str | None, timeout: float) -> Any:
    """Create the request's OSIDB session with per-call HTTP timeouts.

    The retry adapter retimes iterator HTTP calls against the remaining refresh
    budget. Requests timeouts bound connection/read inactivity, not total
    elapsed response time. Bindings authenticate eagerly before exposing their
    client, so initial Kerberos authentication cannot be retimed here. Neither
    this helper nor the refresh budget guarantees a hard end-to-end deadline.
    """
    if token:
        return BearerOSIDBSession(server_url, token, timeout=timeout)
    session = osidb_bindings.new_session(osidb_server_uri=server_url)
    _retimeout_session(session, timeout)
    return session


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
    max_refresh_secs: int | None = None,
    run_id: str | None = None,
    authorization_identity: str | None = None,
) -> BotKPIResponse:
    """Fetch bot-processed flaws from OSIDB and compute KPI metrics.

    Responses are served through stable delivery runs: follow
    ``delivery.continue_token`` (passing it back as ``cursor`` together with
    ``delivery.run_id``) until it is absent, accumulating each page's
    ``entries``; aggregates are cumulative on every page. HTTP 503 operations
    receive at most three retries. The refresh budget is shared by calls and
    retry delays; bindings' eager Kerberos session authentication has no
    injectable timeout and is excluded from any hard wall-clock guarantee.
    """
    try:
        budget = (
            max_refresh_secs
            if max_refresh_secs is not None
            else get_settings().bot_kpi_max_refresh_seconds
        )
        deadline = time.monotonic() + budget
        from .kpi_delivery import get_delivery

        return get_delivery(
            osidb_token=osidb_token,
            run_id=run_id,
            changed_after=changed_after,
            changed_before=changed_before,
            component=component,
            record_filters=record_filters,
            detail=detail,
            cursor=cursor,
            limit=limit,
            deadline=deadline,
            authorization_identity=authorization_identity,
        )
    except requests.exceptions.SSLError:
        logger.debug("Non-transient OSIDB TLS error", exc_info=True)
        raise HTTPException(
            502, "Unable to establish a secure OSIDB connection."
        ) from None
    except requests.HTTPError:
        logger.debug("OSIDB returned a non-retryable HTTP error", exc_info=True)
        raise HTTPException(502, "OSIDB rejected the KPI query.") from None
    except (requests.ConnectionError, requests.Timeout, ConnectionError):
        logger.error("Failed to connect to OSIDB")
        logger.debug("OSIDB connection error details", exc_info=True)
        raise HTTPException(
            status_code=503,
            detail="Unable to connect to OSIDB.",
        ) from None
    except requests.RequestException:
        logger.debug("Non-transient OSIDB request error", exc_info=True)
        raise HTTPException(502, "Unable to issue the OSIDB query.") from None
    except HTTPException:
        raise
    except Exception:
        logger.error("Error computing osidb-bot KPI")
        logger.debug("osidb-bot KPI error details", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while computing osidb-bot KPI metrics.",
        ) from None
