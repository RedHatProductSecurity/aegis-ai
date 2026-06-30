"""
KPI endpoint module for CVE analysis feedback.
"""

import logging
from datetime import datetime
from enum import Enum
from typing import Any

from fastapi import HTTPException

from aegis_ai_web.src.data_models import FeatureKPI, KPIEntry
from aegis_ai_web.src.feedback_logger import (
    feedback_logger,
    programmatic_feedback_logger,
)
from aegis_ai_web.src.semantic_scoring import _parse_json_list


class SortOrder(str, Enum):
    """Sort order for datetime field."""

    ASC = "asc"
    DESC = "desc"


COMPONENT_FEATURE_KEYS = frozenset({"source_component", "suggest-affected-components"})


def resolve_feature_aliases(query_feature: str) -> set[str]:
    """Expand ``source_component`` to cover both component feedback log keys.

    Aliasing is intentionally one-way: querying ``source_component`` returns
    entries logged under both ``source_component`` and
    ``suggest-affected-components``, but ``suggest-affected-components`` resolves
    to itself only so existing callers keep their original KPI scope.
    """
    if query_feature == "source_component":
        return set(COMPONENT_FEATURE_KEYS)
    return {query_feature}


def _parse_datetime_str(dt_str: str) -> datetime:
    """Parse datetime string to datetime object for sorting."""
    try:
        return datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S.%f")  # noqa: DTZ007
    except ValueError:
        try:
            return datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")  # noqa: DTZ007
        except ValueError:
            return datetime.fromtimestamp(0)  # noqa: DTZ006


def parse_components(value: str) -> list[str]:
    """Parse a JSON component list from feedback CSV values."""
    parsed = _parse_json_list(value or "")
    return parsed or []


def clean_components(components: list[str]) -> list[str]:
    """Trim entries, drop empty/whitespace values, and de-duplicate.

    Order is preserved (first-seen wins) so component sequences from the
    feedback logs are not reshuffled.
    """
    seen: set[str] = set()
    cleaned: list[str] = []
    for component in components:
        value = component.strip()
        if not value or value in seen:
            continue
        seen.add(value)
        cleaned.append(value)
    return cleaned


def component_diff(
    suggested: list[str], submitted: list[str]
) -> tuple[list[str], list[str], list[str]]:
    """Return accepted, rejected, and added component lists.

    Comparison is case-sensitive (``Glib`` and ``glib`` are distinct components)
    and each list preserves the original feedback-log ordering.
    """
    suggested_clean = clean_components(suggested)
    submitted_clean = clean_components(submitted)
    suggested_set = set(suggested_clean)
    submitted_set = set(submitted_clean)
    accepted = [c for c in suggested_clean if c in submitted_set]
    rejected = [c for c in suggested_clean if c not in submitted_set]
    added = [c for c in submitted_clean if c not in suggested_set]
    return accepted, rejected, added


def _deduplicate_programmatic_feedback(
    entries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Deduplicate programmatic feedback entries by (cve_id, feature), keeping the most recent.

    Args:
        entries: List of programmatic feedback entry dictionaries

    Returns:
        List of deduplicated entries, keeping only the most recent entry per (cve_id, feature)
    """
    deduped: dict[tuple[str, str], dict[str, Any]] = {}

    for entry in entries:
        cve_id = entry.get("cve_id", "")
        feature = entry.get("feature", "")
        key = (cve_id, feature)
        deduped[key] = entry

    return list(deduped.values())


def matches_entry_filters(
    entry: dict[str, Any],
    *,
    cve_id: str | None,
    source_component: str | None,
    multiple_source_components: bool,
) -> bool:
    """Apply optional CVE and component filters to a normalized feedback entry."""
    if cve_id and entry.get("cve_id") != cve_id:
        return False

    # Component filters only make sense for component features. Under
    # feature="all" this excludes non-component features rather than filtering
    # them on scalar values parsed as empty component lists.
    if (source_component or multiple_source_components) and entry.get(
        "feature"
    ) not in COMPONENT_FEATURE_KEYS:
        return False

    suggested = clean_components(parse_components(entry.get("suggested_raw", "")))
    if source_component:
        needle = source_component.strip()
        if needle and needle not in suggested:
            return False

    return not (multiple_source_components and len(suggested) < 2)


def normalize_manual_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Normalize a manual feedback CSV row for KPI processing."""
    return {
        "datetime": entry.get("datetime", ""),
        "accepted": entry.get("accept", "") == "true",
        "aegis_version": entry.get("version", ""),
        "cve_id": entry.get("cve_id", ""),
        "feedback_source": "manual",
        "suggested_raw": entry.get("actual", ""),
        "submitted_raw": entry.get("expected", ""),
        "feature": entry.get("feature", ""),
    }


def normalize_programmatic_entry(entry: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize a programmatic feedback CSV row, or None if unscored."""
    score_str = entry.get("acceptance_score", "")
    if not score_str:
        return None
    try:
        score = float(score_str)
    except ValueError:
        return None

    return {
        "datetime": entry.get("datetime", ""),
        "accepted": score == 1.0,
        "aegis_version": entry.get("version", ""),
        "cve_id": entry.get("cve_id", ""),
        "feedback_source": "programmatic",
        "suggested_raw": entry.get("suggested_value", ""),
        "submitted_raw": entry.get("submitted_value", ""),
        "feature": entry.get("feature", ""),
    }


def collect_normalized_entries(
    feature: str,
    *,
    cve_id: str | None = None,
    source_component: str | None = None,
    multiple_source_components: bool = False,
) -> list[dict[str, Any]]:
    """Read and filter feedback log entries for a feature query."""
    if feature == "all":
        feature_aliases = None
    else:
        feature_aliases = resolve_feature_aliases(feature)

    entries: list[dict[str, Any]] = []

    for raw in feedback_logger.read():
        raw_feature = raw.get("feature")
        if not raw_feature:
            continue
        if feature_aliases is not None and raw_feature not in feature_aliases:
            continue
        normalized = normalize_manual_entry(raw)
        if matches_entry_filters(
            normalized,
            cve_id=cve_id,
            source_component=source_component,
            multiple_source_components=multiple_source_components,
        ):
            entries.append(normalized)

    deduped_programmatic = _deduplicate_programmatic_feedback(
        programmatic_feedback_logger.read()
    )
    for raw in deduped_programmatic:
        raw_feature = raw.get("feature")
        if not raw_feature:
            continue
        if feature_aliases is not None and raw_feature not in feature_aliases:
            continue
        normalized = normalize_programmatic_entry(raw)
        if normalized is None:
            continue
        if matches_entry_filters(
            normalized,
            cve_id=cve_id,
            source_component=source_component,
            multiple_source_components=multiple_source_components,
        ):
            entries.append(normalized)

    return entries


def to_kpi_entry(entry: dict[str, Any], detail: bool) -> KPIEntry:
    """Convert a normalized feedback entry to a KPIEntry response object."""
    if not detail:
        return KPIEntry(
            datetime=entry["datetime"],
            accepted=entry["accepted"],
            aegis_version=entry["aegis_version"],
        )

    suggested = parse_components(entry.get("suggested_raw", ""))
    submitted = parse_components(entry.get("submitted_raw", ""))
    accepted_components, rejected, added = component_diff(suggested, submitted)

    return KPIEntry(
        datetime=entry["datetime"],
        accepted=entry["accepted"],
        aegis_version=entry["aegis_version"],
        cve_id=entry.get("cve_id") or None,
        feedback_source=entry.get("feedback_source"),
        suggested_components=suggested or None,
        submitted_components=submitted or None,
        accepted_components=accepted_components or None,
        rejected_suggestions=rejected or None,
        added_components=added or None,
    )


def _compute_kpi(
    normalized_entries: list[dict[str, Any]],
    order: SortOrder,
    detail: bool,
) -> FeatureKPI:
    """Compute KPI metrics from normalized feedback entries."""
    kpi_entries = [to_kpi_entry(entry, detail) for entry in normalized_entries]
    if not kpi_entries:
        return FeatureKPI(acceptance_percentage=0.0, entries=[])

    kpi_entries.sort(
        key=lambda e: _parse_datetime_str(e.datetime),
        reverse=(order == SortOrder.DESC),
    )

    accepted_count = sum(1 for e in kpi_entries if e.accepted)
    acceptance_percentage = round((accepted_count / len(kpi_entries)) * 100, 1)

    return FeatureKPI(
        acceptance_percentage=acceptance_percentage,
        entries=kpi_entries,
    )


def _get_all_features_kpi(
    order: SortOrder = SortOrder.ASC,
    *,
    cve_id: str | None = None,
    source_component: str | None = None,
    multiple_source_components: bool = False,
    detail: bool = False,
) -> dict[str, FeatureKPI]:
    """Get KPI metrics for all features in a single pass over log data."""
    entries_by_feature: dict[str, list[dict[str, Any]]] = {}

    for entry in collect_normalized_entries(
        "all",
        cve_id=cve_id,
        source_component=source_component,
        multiple_source_components=multiple_source_components,
    ):
        feature_key = entry.get("feature", "")
        if feature_key:
            entries_by_feature.setdefault(feature_key, []).append(entry)

    return {
        feature: _compute_kpi(entries, order, detail)
        for feature, entries in entries_by_feature.items()
    }


def get_cve_kpi(
    feature: str,
    order: SortOrder = SortOrder.ASC,
    *,
    cve_id: str | None = None,
    source_component: str | None = None,
    multiple_source_components: bool = False,
    detail: bool = False,
) -> dict[str, FeatureKPI]:
    """
    Get KPI metrics for CVE analysis feedback filtered by feature.

    Args:
        feature: Feature name to filter entries by, or "all" to get all features
        order: Sort order for datetime field (default: ASC)
        cve_id: Optional exact CVE identifier filter
        source_component: Optional filter for entries suggesting this component
        multiple_source_components: When True, only entries with 2+ suggested components
        detail: When True, include CVE and component fields on each entry

    Returns:
        Dict[str, FeatureKPI] mapping feature names to their KPI responses.
    """
    if feature == "all":
        try:
            return _get_all_features_kpi(
                order,
                cve_id=cve_id,
                source_component=source_component,
                multiple_source_components=multiple_source_components,
                detail=detail,
            )
        except Exception:
            logging.error(  # noqa: G201
                "Error retrieving KPI data for all features",
                exc_info=True,
            )
            raise HTTPException(
                status_code=500,
                detail="An internal error occurred while retrieving KPI data for all features.",
            )

    try:
        normalized_entries = collect_normalized_entries(
            feature,
            cve_id=cve_id,
            source_component=source_component,
            multiple_source_components=multiple_source_components,
        )
        return {feature: _compute_kpi(normalized_entries, order, detail)}

    except Exception:
        logging.error(  # noqa: G201
            f"Error retrieving KPI data for feature '{feature}'",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500,
            detail=f"An internal error occurred while retrieving KPI data for feature '{feature}'.",
        )
