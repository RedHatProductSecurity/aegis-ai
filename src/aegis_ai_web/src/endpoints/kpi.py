"""
KPI endpoint module for CVE analysis feedback.
"""

import logging
from datetime import datetime
from typing import List, Dict, Any

from enum import Enum

from fastapi import HTTPException

from aegis_ai_web.src.data_models import KPIEntry, FeatureKPI
from aegis_ai_web.src.feedback_logger import AegisLogger


class SortOrder(str, Enum):
    """Sort order for datetime field."""

    ASC = "asc"
    DESC = "desc"


def _parse_datetime(entry: Dict[str, Any]) -> datetime:
    """
    Parse datetime string to datetime object for sorting.

    Args:
        entry: Log entry dictionary

    Returns:
        Parsed datetime object
    """
    dt_str = entry.get("datetime", "")
    try:
        # Format: "YYYY-MM-DD HH:MM:SS.mmm"
        return datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S.%f")
    except ValueError:
        # Fallback for entries without milliseconds
        try:
            return datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            # Return epoch if parsing fails
            return datetime.fromtimestamp(0)


def _compute_kpi_for_entries(
    filtered_entries: List[Dict[str, Any]], order: SortOrder
) -> FeatureKPI:
    """
    Compute KPI metrics for a list of filtered entries.

    Args:
        filtered_entries: List of log entries filtered by feature
        order: Sort order for datetime field

    Returns:
        FeatureKPI with score and entries
    """
    if not filtered_entries:
        return FeatureKPI(
            acceptance_percentage=0.0,
            entries=[],
        )

    # Sort entries by datetime
    filtered_entries.sort(
        key=_parse_datetime,
        reverse=(order == SortOrder.DESC),
    )

    # Convert accept field from normalized lowercase string to boolean and calculate acceptance score
    # Create KPIEntry models with datetime, accepted, and aegis_version
    accepted_count = 0
    filtered_response_entries: List[KPIEntry] = []
    for entry in filtered_entries:
        accept_value = entry.get("accept", "")
        # Convert normalized lowercase string to boolean
        # accept_value is already normalized to lowercase during parsing, so it's always a string
        accept_bool = accept_value == "true"
        if accept_bool:
            accepted_count += 1

        # Create KPIEntry with datetime, accepted, and aegis_version
        filtered_response_entries.append(
            KPIEntry(
                datetime=entry.get("datetime", ""),
                accepted=accept_bool,
                aegis_version=entry.get("version", ""),
            )
        )

    total_count = len(filtered_entries)
    acceptance_percentage = (
        round((accepted_count / total_count) * 100, 1) if total_count > 0 else 0.0
    )

    return FeatureKPI(
        acceptance_percentage=acceptance_percentage,
        entries=filtered_response_entries,
    )


def _get_all_features_kpi(order: SortOrder = SortOrder.ASC) -> Dict[str, FeatureKPI]:
    """
    Get KPI metrics for all features in a single pass over log data.

    Args:
        order: Sort order for datetime field (default: ASC)

    Returns:
        Dict[str, FeatureKPI] mapping feature names to their KPI responses
    """
    # Read all log entries once
    all_entries = AegisLogger.read()

    # Group entries by feature
    entries_by_feature: Dict[str, List[Dict[str, Any]]] = {}
    for entry in all_entries:
        feature = entry.get("feature")
        if feature:
            if feature not in entries_by_feature:
                entries_by_feature[feature] = []
            entries_by_feature[feature].append(entry.copy())

    # Compute KPIs for each feature
    result: Dict[str, FeatureKPI] = {}
    for feature, feature_entries in entries_by_feature.items():
        result[feature] = _compute_kpi_for_entries(feature_entries, order)

    return result


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
        For a single feature query, the dict contains one key-value pair.
        For feature="all", the dict contains all features.
    """
    # Handle "all" case
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

    # Handle single feature case - wrap in dict for consistent return type
    kpi_response = _get_single_feature_kpi(feature, order)
    return {feature: kpi_response}


def _get_single_feature_kpi(
    feature: str, order: SortOrder = SortOrder.ASC
) -> FeatureKPI:
    """
    Get KPI metrics for a single CVE analysis feedback feature.

    Args:
        feature: Feature name to filter entries by
        order: Sort order for datetime field (default: ASC)

    Returns:
        FeatureKPI with score and entries
    """
    try:
        # Read all log entries
        all_entries = AegisLogger.read()

        # Filter entries by feature
        filtered_entries: List[Dict[str, Any]] = [
            entry.copy() for entry in all_entries if entry.get("feature") == feature
        ]

        return _compute_kpi_for_entries(filtered_entries, order)

    except Exception:
        logging.error(
            f"Error retrieving KPI data for feature '{feature}'",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500,
            detail=f"An internal error occurred while retrieving KPI data for feature '{feature}'.",
        )
