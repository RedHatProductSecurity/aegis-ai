"""KPI metrics computation and endpoint handler for osidb-bot auto-processed flaws.

Compares bot suggestions (stored in aegis_meta) against current flaw field
values to measure how often analysts keep, modify, or skip bot suggestions.
"""

import logging
import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Sequence

import osidb_bindings
from fastapi import HTTPException
from pydantic import BaseModel

from aegis_ai import get_settings
from aegis_ai_web.src.data_models import BotFeatureKPI, BotKPIResponse

logger = logging.getLogger(__name__)

# Flaw fields that the bot writes suggestions for and that we can compare
# against current values.  Underscore-prefixed keys (_ecosystems, _cvss3_vector)
# are metadata-only and have no direct flaw-field counterpart.
BOT_KPI_FIELDS = ("components", "title", "cve_description", "cwe_id", "impact")

_INCLUDE_FIELDS = ",".join(["cve_id", "aegis_meta", *BOT_KPI_FIELDS])


@dataclass
class FeatureStats:
    applied: int = 0
    skipped: int = 0
    kept: int = 0
    modified: int = 0
    data_quality_sum: float = 0.0
    confidence_sum: float = 0.0
    total_entries: int = 0

    @property
    def acceptance_rate(self) -> float:
        if self.applied == 0:
            return 0.0
        return round((self.kept / self.applied) * 100, 1)

    @property
    def avg_data_quality(self) -> float:
        if self.total_entries == 0:
            return 0.0
        return round(self.data_quality_sum / self.total_entries, 2)

    @property
    def avg_confidence(self) -> float:
        if self.total_entries == 0:
            return 0.0
        return round(self.confidence_sum / self.total_entries, 2)


@dataclass
class BotKPIResult:
    total_flaws_processed: int = 0
    features: dict[str, FeatureStats] = field(default_factory=dict)


def _values_equal(suggested: Any, current: Any) -> bool:
    """Compare a bot-suggested value with the current flaw field value."""
    if type(suggested) is type(current):
        return suggested == current
    return str(suggested) == str(current)


def extract_flaw_kpi(
    aegis_meta: dict[str, Any],
    flaw_data: dict[str, Any],
) -> dict[str, FeatureStats]:
    """Extract per-feature stats from a single flaw's aegis_meta."""
    result: dict[str, FeatureStats] = {}

    for field_name in BOT_KPI_FIELDS:
        entries = aegis_meta.get(field_name)
        if not entries or not isinstance(entries, list):
            continue

        stats = FeatureStats()
        bot_entry: Optional[dict[str, Any]] = None

        for entry in entries:
            entry_type = entry.get("type", "")
            dq = float(entry.get("data_quality", 0))
            conf = float(entry.get("confidence", 0))
            stats.data_quality_sum += dq
            stats.confidence_sum += conf
            stats.total_entries += 1

            if entry_type == "AI-Bot":
                stats.applied += 1
                if bot_entry is None:
                    bot_entry = entry
            elif entry_type == "AI-Bot-Skipped":
                stats.skipped += 1

        if bot_entry is not None and "value" in bot_entry:
            current_value = flaw_data.get(field_name)
            if _values_equal(bot_entry["value"], current_value):
                stats.kept += 1
            else:
                stats.modified += 1

        result[field_name] = stats

    return result


def _merge_feature_stats(target: FeatureStats, source: FeatureStats) -> None:
    """Add source stats into target (mutating target)."""
    target.applied += source.applied
    target.skipped += source.skipped
    target.kept += source.kept
    target.modified += source.modified
    target.data_quality_sum += source.data_quality_sum
    target.confidence_sum += source.confidence_sum
    target.total_entries += source.total_entries


def aggregate_kpi(flaws: Sequence[dict[str, Any]]) -> BotKPIResult:
    """Aggregate KPI stats across multiple flaws."""
    result = BotKPIResult()
    merged: dict[str, FeatureStats] = {}

    for flaw_data in flaws:
        aegis_meta = flaw_data.get("aegis_meta")
        if not isinstance(aegis_meta, dict):
            continue
        if not aegis_meta.get("processed"):
            continue

        result.total_flaws_processed += 1
        flaw_stats = extract_flaw_kpi(aegis_meta, flaw_data)

        for field_name, stats in flaw_stats.items():
            if field_name not in merged:
                merged[field_name] = FeatureStats()
            _merge_feature_stats(merged[field_name], stats)

    result.features = merged
    return result


def merge_kpi_results(base: BotKPIResult, incremental: BotKPIResult) -> BotKPIResult:
    """Combine two KPI results by summing all counters."""
    merged = BotKPIResult(
        total_flaws_processed=base.total_flaws_processed
        + incremental.total_flaws_processed,
    )
    for name, stats in base.features.items():
        merged.features[name] = FeatureStats(**asdict(stats))
    for name, stats in incremental.features.items():
        if name not in merged.features:
            merged.features[name] = FeatureStats()
        _merge_feature_stats(merged.features[name], stats)
    return merged


def fetch_bot_processed_flaws(
    osidb: Any,
    *,
    changed_after: Optional[datetime] = None,
    changed_before: Optional[datetime] = None,
) -> list[dict[str, Any]]:
    """Query OSIDB for bot-processed flaws in DONE workflow state."""
    kwargs: dict[str, Any] = {
        "include_fields": _INCLUDE_FIELDS,
        "workflow_state": "DONE",
        "aegis_meta__has_key": "processed",
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
        if isinstance(flaw_dict.get("aegis_meta"), dict):
            flaws.append(flaw_dict)

    logger.info("found %d bot-processed flaws", len(flaws))
    return flaws


class BotKPICacheEntry(BaseModel):
    """On-disk cache for precomputed bot KPI aggregates."""

    cutoff: datetime
    total_flaws_processed: int
    features: dict[str, dict[str, float]]

    def to_kpi_result(self) -> BotKPIResult:
        return BotKPIResult(
            total_flaws_processed=self.total_flaws_processed,
            features={
                name: FeatureStats(
                    applied=int(d["applied"]),
                    skipped=int(d["skipped"]),
                    kept=int(d["kept"]),
                    modified=int(d["modified"]),
                    data_quality_sum=d["data_quality_sum"],
                    confidence_sum=d["confidence_sum"],
                    total_entries=int(d["total_entries"]),
                )
                for name, d in self.features.items()
            },
        )

    @classmethod
    def from_kpi_result(
        cls, result: BotKPIResult, cutoff: datetime
    ) -> "BotKPICacheEntry":
        return cls(
            cutoff=cutoff,
            total_flaws_processed=result.total_flaws_processed,
            features={name: asdict(stats) for name, stats in result.features.items()},
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
    cache_dir = os.environ.get("AEGIS_BOT_KPI_CACHE_DIR")
    if cache_dir:
        return Path(cache_dir) / "kpi_cache.json"
    return Path(get_settings().config_dir) / "osidb_bot_kpi" / "kpi_cache.json"


def _load_cache() -> Optional[BotKPICacheEntry]:
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


def get_osidb_bot_kpi(
    *,
    changed_after: Optional[datetime] = None,
    changed_before: Optional[datetime] = None,
    full_refresh: bool = False,
) -> BotKPIResponse:
    """Fetch bot-processed flaws from OSIDB and compute KPI metrics."""
    try:
        osidb_server = get_settings().osidb_server_url
        osidb = osidb_bindings.new_session(osidb_server_uri=osidb_server)
    except Exception:
        logger.error("Failed to connect to OSIDB")
        logger.debug("OSIDB connection error details", exc_info=True)
        raise HTTPException(
            status_code=503,
            detail="Unable to connect to OSIDB.",
        )

    has_date_filters = changed_after is not None or changed_before is not None

    try:
        if full_refresh or has_date_filters:
            flaws = fetch_bot_processed_flaws(
                osidb,
                changed_after=changed_after,
                changed_before=changed_before,
            )
            result = aggregate_kpi(flaws)
            if full_refresh:
                cutoff = datetime.now(timezone.utc)
                _save_cache(BotKPICacheEntry.from_kpi_result(result, cutoff))
            return _result_to_response(result)

        cached = _load_cache()
        if cached is not None:
            cached_result = cached.to_kpi_result()
            incremental_flaws = fetch_bot_processed_flaws(
                osidb, changed_after=cached.cutoff
            )
            incremental_result = aggregate_kpi(incremental_flaws)
            result = merge_kpi_results(cached_result, incremental_result)
        else:
            flaws = fetch_bot_processed_flaws(osidb)
            result = aggregate_kpi(flaws)

        cutoff = datetime.now(timezone.utc)
        _save_cache(BotKPICacheEntry.from_kpi_result(result, cutoff))
        return _result_to_response(result)
    except HTTPException:
        raise
    except Exception:
        logger.error("Error computing osidb-bot KPI")
        logger.debug("osidb-bot KPI error details", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while computing osidb-bot KPI metrics.",
        )
