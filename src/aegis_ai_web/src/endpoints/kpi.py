"""
KPI endpoint module for CVE analysis feedback.
"""

import logging
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional

from enum import Enum

from fastapi import HTTPException

from aegis_ai_web.src.data_models import KPIEntry, FeatureKPI
from aegis_ai_web.src.feedback_logger import (
    feedback_logger,
    programmatic_feedback_logger,
)
from aegis_ai_web.src.semantic_scoring import _parse_json_list


class SortOrder(str, Enum):
    """Sort order for datetime field."""

    ASC = "asc"
    DESC = "desc"


COMPONENT_FEATURE_KEYS = frozenset(
    {"source_component", "suggest-affected-components"}
)


def _resolve_feature_aliases(query_feature: str) -> set[str]:
    """Map component feature aliases to the same CSV feature keys."""
    if query_feature in COMPONENT_FEATURE_KEYS:
        return set(COMPONENT_FEATURE_KEYS)
    return {query_feature}


def _parse_datetime_str(dt_str: str) -> datetime:
    """Parse datetime string to datetime object for sorting."""
    try:
        return datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S.%f")
    except ValueError:
        try:
            return datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return datetime.fromtimestamp(0)


def _parse_components(value: str) -> list[str]:
    """Parse a JSON component list from feedback CSV values."""
    parsed = _parse_json_list(value or "")
    return parsed or []


def _component_diff(
    suggested: list[str], submitted: list[str]
) -> tuple[list[str], list[str], list[str]]:
    """Return accepted, rejected, and added component lists (case-insensitive)."""
    suggested_map = {c.lower().strip(): c for c in suggested if c.strip()}
    submitted_map = {c.lower().strip(): c for c in submitted if c.strip()}
    suggested_keys = set(suggested_map)
    submitted_keys = set(submitted_map)
    accepted = sorted(suggested_map[k] for k in suggested_keys & submitted_keys)
    rejected = sorted(suggested_map[k] for k in suggested_keys - submitted_keys)
    added = sorted(submitted_map[k] for k in submitted_keys - suggested_keys)
    return accepted, rejected, added


def _deduplicate_programmatic_feedback(
    entries: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Deduplicate programmatic feedback entries by (cve_id, feature), keeping the most recent.

    Args:
        entries: List of programmatic feedback entry dictionaries

    Returns:
        List of deduplicated entries, keeping only the most recent entry per (cve_id, feature)
    """
    deduped: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for entry in entries:
        cve_id = entry.get("cve_id", "")
        feature = entry.get("feature", "")
        key = (cve_id, feature)
        deduped[key] = entry

    return list(deduped.values())


def _matches_entry_filters(
    entry: Dict[str, Any],
    *,
    cve_id: Optional[str],
    source_component: Optional[str],
    multiple_source_components: bool,
) -> bool:
    """Apply optional CVE and component filters to a normalized feedback entry."""
    if cve_id and entry.get("cve_id") != cve_id:
        return False

    suggested = _parse_components(entry.get("suggested_raw", ""))
    if source_component:
        needle = source_component.lower().strip()
        if needle not in {c.lower().strip() for c in suggested}:
            return False

    if multiple_source_components and len(suggested) < 2:
        return False

    return True


def _normalize_manual_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a manual feedback CSV row for KPI processing."""
    return {
        "datetime": entry.get("datetime", ""),
        "accepted": entry.get("accept", "") == "true",
        "aegis_version": entry.get("version", ""),
        "cve_id": entry.get("cve_id", ""),
        "email": entry.get("email", ""),
        "feedback_source": "manual",
        "suggested_raw": entry.get("actual", ""),
        "submitted_raw": entry.get("expected", ""),
        "feature": entry.get("feature", ""),
    }


def _normalize_programmatic_entry(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
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
        "email": entry.get("email", ""),
        "feedback_source": "programmatic",
        "suggested_raw": entry.get("suggested_value", ""),
        "submitted_raw": entry.get("submitted_value", ""),
        "feature": entry.get("feature", ""),
    }


def _collect_normalized_entries(
    feature: str,
    *,
    cve_id: Optional[str] = None,
    source_component: Optional[str] = None,
    multiple_source_components: bool = False,
) -> List[Dict[str, Any]]:
    """Read and filter feedback log entries for a feature query."""
    if feature == "all":
        feature_aliases = None
    else:
        feature_aliases = _resolve_feature_aliases(feature)

    entries: List[Dict[str, Any]] = []

    for raw in feedback_logger.read():
        raw_feature = raw.get("feature")
        if not raw_feature:
            continue
        if feature_aliases is not None and raw_feature not in feature_aliases:
            continue
        normalized = _normalize_manual_entry(raw)
        if _matches_entry_filters(
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
        normalized = _normalize_programmatic_entry(raw)
        if normalized is None:
            continue
        if _matches_entry_filters(
            normalized,
            cve_id=cve_id,
            source_component=source_component,
            multiple_source_components=multiple_source_components,
        ):
            entries.append(normalized)

    return entries


def _to_kpi_entry(entry: Dict[str, Any], detail: bool) -> KPIEntry:
    """Convert a normalized feedback entry to a KPIEntry response object."""
    if not detail:
        return KPIEntry(
            datetime=entry["datetime"],
            accepted=entry["accepted"],
            aegis_version=entry["aegis_version"],
        )

    suggested = _parse_components(entry.get("suggested_raw", ""))
    submitted = _parse_components(entry.get("submitted_raw", ""))
    accepted_components, rejected, added = _component_diff(suggested, submitted)

    return KPIEntry(
        datetime=entry["datetime"],
        accepted=entry["accepted"],
        aegis_version=entry["aegis_version"],
        cve_id=entry.get("cve_id") or None,
        email=entry.get("email") or None,
        feedback_source=entry.get("feedback_source"),
        suggested_components=suggested or None,
        submitted_components=submitted or None,
        accepted_components=accepted_components or None,
        rejected_suggestions=rejected or None,
        added_components=added or None,
    )


def _compute_kpi(
    normalized_entries: List[Dict[str, Any]],
    order: SortOrder,
    detail: bool,
) -> FeatureKPI:
    """Compute KPI metrics from normalized feedback entries."""
    kpi_entries = [_to_kpi_entry(entry, detail) for entry in normalized_entries]
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
    cve_id: Optional[str] = None,
    source_component: Optional[str] = None,
    multiple_source_components: bool = False,
    detail: bool = False,
) -> Dict[str, FeatureKPI]:
    """Get KPI metrics for all features in a single pass over log data."""
    entries_by_feature: Dict[str, List[Dict[str, Any]]] = {}

    for entry in _collect_normalized_entries(
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
    cve_id: Optional[str] = None,
    source_component: Optional[str] = None,
    multiple_source_components: bool = False,
    detail: bool = False,
) -> Dict[str, FeatureKPI]:
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
            logging.error(
                "Error retrieving KPI data for all features",
                exc_info=True,
            )
            raise HTTPException(
                status_code=500,
                detail="An internal error occurred while retrieving KPI data for all features.",
            )

    try:
        normalized_entries = _collect_normalized_entries(
            feature,
            cve_id=cve_id,
            source_component=source_component,
            multiple_source_components=multiple_source_components,
        )
        return {feature: _compute_kpi(normalized_entries, order, detail)}

    except Exception:
        logging.error(
            f"Error retrieving KPI data for feature '{feature}'",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500,
            detail=f"An internal error occurred while retrieving KPI data for feature '{feature}'.",
        )
