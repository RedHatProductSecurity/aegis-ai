"""KPI metrics extraction for osidb-bot auto-processed flaws.

Compares bot suggestions (stored in aegis_meta) against current flaw field
values to measure how often analysts keep, modify, or skip bot suggestions.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional, Sequence

from osidb_bindings.session import Session

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
    # Handle type mismatches (e.g. str vs None, list vs str)
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

        # Compare the first applied suggestion against the current value
        if bot_entry is not None and "value" in bot_entry:
            current_value = flaw_data.get(field_name)
            if _values_equal(bot_entry["value"], current_value):
                stats.kept += 1
            else:
                stats.modified += 1

        result[field_name] = stats

    return result


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
            m = merged[field_name]
            m.applied += stats.applied
            m.skipped += stats.skipped
            m.kept += stats.kept
            m.modified += stats.modified
            m.data_quality_sum += stats.data_quality_sum
            m.confidence_sum += stats.confidence_sum
            m.total_entries += stats.total_entries

    result.features = merged
    return result


def fetch_bot_processed_flaws(
    osidb: Session,
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
