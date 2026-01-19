"""
KPI endpoint module for CVE analysis feedback.
"""

import logging
from datetime import datetime
from typing import List, Dict, Any, Tuple

from enum import Enum

from fastapi import HTTPException

from aegis_ai_web.src.data_models import KPIEntry, FeatureKPI
from aegis_ai_web.src.feedback_logger import (
    feedback_logger,
    programmatic_feedback_logger,
)


class SortOrder(str, Enum):
    """Sort order for datetime field."""

    ASC = "asc"
    DESC = "desc"


def _parse_datetime_str(dt_str: str) -> datetime:
    """Parse datetime string to datetime object for sorting."""
    try:
        return datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S.%f")
    except ValueError:
        try:
            return datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return datetime.fromtimestamp(0)


def _standard_entry_to_kpi(entry: Dict[str, Any]) -> KPIEntry:
    """Convert standard feedback log entry to KPIEntry."""
    accept_value = entry.get("accept", "")
    return KPIEntry(
        datetime=entry.get("datetime", ""),
        accepted=accept_value == "true",
        aegis_version=entry.get("version", ""),
    )


def _programmatic_entry_to_kpi(entry: Dict[str, Any]) -> KPIEntry | None:
    """Convert programmatic feedback entry to KPIEntry, or None if no valid score."""
    score_str = entry.get("acceptance_score", "")
    if not score_str:
        return None
    try:
        score = float(score_str)
    except ValueError:
        return None
    return KPIEntry(
        datetime=entry.get("datetime", ""),
        accepted=score == 1.0,
        aegis_version=entry.get("version", ""),
    )


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
        # Always overwrite the entry with the most recent one
        cve_id = entry.get("cve_id", "")
        feature = entry.get("feature", "")
        key = (cve_id, feature)
        deduped[key] = entry

    return list(deduped.values())


def _compute_kpi(entries: List[KPIEntry], order: SortOrder) -> FeatureKPI:
    """Compute KPI metrics from a list of KPIEntry objects."""
    if not entries:
        return FeatureKPI(acceptance_percentage=0.0, entries=[])

    entries.sort(
        key=lambda e: _parse_datetime_str(e.datetime),
        reverse=(order == SortOrder.DESC),
    )

    accepted_count = sum(1 for e in entries if e.accepted)
    acceptance_percentage = round((accepted_count / len(entries)) * 100, 1)

    return FeatureKPI(acceptance_percentage=acceptance_percentage, entries=entries)


def _get_all_features_kpi(order: SortOrder = SortOrder.ASC) -> Dict[str, FeatureKPI]:
    """Get KPI metrics for all features in a single pass over log data."""
    entries_by_feature: Dict[str, List[KPIEntry]] = {}

    # Process standard feedback
    for entry in feedback_logger.read():
        feature = entry.get("feature")
        if feature:
            entries_by_feature.setdefault(feature, []).append(
                _standard_entry_to_kpi(entry)
            )

    # Process programmatic feedback with deduplication
    programmatic_entries = programmatic_feedback_logger.read()
    deduped_programmatic = _deduplicate_programmatic_feedback(programmatic_entries)
    for entry in deduped_programmatic:
        feature = entry.get("feature")
        if feature:
            kpi_entry = _programmatic_entry_to_kpi(entry)
            if kpi_entry:
                entries_by_feature.setdefault(feature, []).append(kpi_entry)

    return {
        feature: _compute_kpi(entries, order)
        for feature, entries in entries_by_feature.items()
    }


def get_cve_kpi(
    feature: str, order: SortOrder = SortOrder.ASC
) -> Dict[str, FeatureKPI]:
    """
    Get KPI metrics for CVE analysis feedback filtered by feature.

    Args:
        feature: Feature name to filter entries by, or "all" to get all features
        order: Sort order for datetime field (default: ASC)

    Returns:
        Dict[str, FeatureKPI] mapping feature names to their KPI responses.
    """
    if feature == "all":
        try:
            return _get_all_features_kpi(order)
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
        entries: List[KPIEntry] = []

        # Standard feedback
        for entry in feedback_logger.read():
            if entry.get("feature") == feature:
                entries.append(_standard_entry_to_kpi(entry))

        # Programmatic feedback with deduplication
        programmatic_entries = programmatic_feedback_logger.read()
        deduped_programmatic = _deduplicate_programmatic_feedback(programmatic_entries)
        for entry in deduped_programmatic:
            if entry.get("feature") == feature:
                kpi_entry = _programmatic_entry_to_kpi(entry)
                if kpi_entry:
                    entries.append(kpi_entry)

        return {feature: _compute_kpi(entries, order)}

    except Exception:
        logging.error(
            f"Error retrieving KPI data for feature '{feature}'",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500,
            detail=f"An internal error occurred while retrieving KPI data for feature '{feature}'.",
        )
