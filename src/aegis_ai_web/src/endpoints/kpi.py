"""
KPI endpoint module for CVE analysis feedback.
"""

import csv
import fcntl
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from enum import Enum

from fastapi import HTTPException

from aegis_ai import get_settings
from aegis_ai_web.src.data_models import FEEDBACK_SCHEMA, KPIEntry, KPIScoreResponse


def read_feedback_logs() -> List[Dict[str, str]]:
    """
    Read and parse feedback log entries from CSV file.

    Returns:
        List of Dict entries where all values are strings from CSV.
        Returns empty list if file doesn't exist or has no valid entries.
    """
    # Read env var dynamically to support test fixtures that set it
    log_file = os.getenv(
        "AEGIS_WEB_FEEDBACK_LOG", f"{get_settings().config_dir}/feedback.csv"
    )
    log_path = Path(log_file)

    # Return empty list if file doesn't exist
    if not log_path.exists():
        return []

    entries = []

    # Open file with read lock for thread-safe reads
    with open(log_path, "r", newline="", encoding="utf-8") as csvfile:
        # Acquire shared lock for thread-safe reads
        fcntl.flock(csvfile.fileno(), fcntl.LOCK_SH)
        try:
            reader = csv.DictReader(csvfile)
            for row in reader:
                # Validate entry matches schema
                if FEEDBACK_SCHEMA.validate_parsed_log(row):
                    # Normalize accept field to lowercase
                    if "accept" in row and row["accept"]:
                        row["accept"] = row["accept"].lower()
                    entries.append(row)
        finally:
            # Release lock
            fcntl.flock(csvfile.fileno(), fcntl.LOCK_UN)

    return entries


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
        all_entries = read_feedback_logs()

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

        # TODO: Add version information to entries based on git history

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
