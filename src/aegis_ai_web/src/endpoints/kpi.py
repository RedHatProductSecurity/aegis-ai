"""
KPI endpoint module for CVE analysis feedback.
"""

from datetime import datetime
from typing import List, Dict, Any

from enum import Enum

from fastapi import HTTPException

from aegis_ai_web.src.data_models import KPIEntry, KPIScoreResponse
from aegis_ai_web.src.feedback_logger import AegisLogger


class SortOrder(str, Enum):
    """Sort order for datetime field."""

    ASC = "asc"
    DESC = "desc"


def get_cve_kpi(feature: str, order: SortOrder = SortOrder.ASC) -> KPIScoreResponse:
    """
    Get KPI metrics for CVE analysis feedback filtered by feature.

    Args:
        feature: Feature name to filter entries by
        order: Sort order for datetime field (default: ASC)

    Returns:
        KPIScoreResponse with score and entries
    """
    try:
        # Read all log entries
        all_entries = AegisLogger().read()

        # Filter entries by feature
        filtered_entries: List[Dict[str, Any]] = [
            entry.copy() for entry in all_entries if entry.get("feature") == feature
        ]

        if not filtered_entries:
            return KPIScoreResponse(
                acceptance_percentage=0.0,
                entries=[],
            )

        # Sort entries by datetime
        def parse_datetime(entry: Dict[str, Any]) -> datetime:
            """Parse datetime string to datetime object for sorting."""
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

        filtered_entries.sort(
            key=parse_datetime,
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

        return KPIScoreResponse(
            acceptance_percentage=acceptance_percentage,
            entries=filtered_response_entries,
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving KPI data for feature '{feature}': {str(e)}",
        )
