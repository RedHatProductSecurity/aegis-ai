"""
Failed scoring entries tracking system.

This module provides functions to track and manage programmatic feedback entries
that failed semantic similarity scoring, allowing them to be retried later.
"""

import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Path to the failed entries JSON file
FAILED_ENTRIES_FILE = Path(
    os.getenv("AEGIS_FAILED_SCORING_ENTRIES_FILE", "tmp/failed_scoring_entries.json")
)


def _ensure_file_exists() -> None:
    """Ensure the failed entries file and directory exist."""
    FAILED_ENTRIES_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not FAILED_ENTRIES_FILE.exists():
        with open(FAILED_ENTRIES_FILE, "w", encoding="utf-8") as f:
            json.dump([], f)


def _load_entries() -> List[Dict[str, str]]:
    """
    Load failed entries from the JSON file.

    Returns:
        List of failed entry dictionaries
    """
    _ensure_file_exists()
    try:
        with open(FAILED_ENTRIES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        logger.warning(f"Error loading failed entries file: {e}, starting with empty list")
        return []


def _save_entries(entries: List[Dict[str, str]]) -> None:
    """
    Save failed entries to the JSON file.

    Args:
        entries: List of failed entry dictionaries to save
    """
    _ensure_file_exists()
    try:
        with open(FAILED_ENTRIES_FILE, "w", encoding="utf-8") as f:
            json.dump(entries, f, indent=2, ensure_ascii=False)
    except OSError as e:
        logger.error(f"Error saving failed entries file: {e}")


def add_failed_entry(
    datetime: str,
    cve_id: str,
    feature: str,
    suggested_value: str,
    submitted_value: str,
    email: Optional[str] = None,
) -> None:
    """
    Add a failed scoring entry to the tracking system.

    Args:
        datetime: Timestamp of the feedback entry
        cve_id: CVE identifier
        feature: Feature name (e.g., 'suggest-title')
        suggested_value: The AI-suggested value
        submitted_value: The value actually submitted by the user
        email: Optional user email address
    """
    entries = _load_entries()

    # Create entry dictionary
    entry = {
        "datetime": datetime,
        "cve_id": cve_id,
        "feature": feature,
        "suggested_value": suggested_value,
        "submitted_value": submitted_value,
        "email": email or "",
    }

    # Check if entry already exists (by datetime, cve_id, feature)
    existing = [
        e
        for e in entries
        if e["datetime"] == datetime
        and e["cve_id"] == cve_id
        and e["feature"] == feature
    ]

    if not existing:
        entries.append(entry)
        _save_entries(entries)
        logger.info(
            f"Added failed scoring entry: feature={feature}, "
            f"cve_id={cve_id}, datetime={datetime}"
        )
    else:
        logger.debug(
            f"Failed scoring entry already exists: feature={feature}, "
            f"cve_id={cve_id}, datetime={datetime}"
        )


def get_failed_entries(
    feature: Optional[str] = None, cve_id: Optional[str] = None
) -> List[Dict[str, str]]:
    """
    Get failed entries, optionally filtered by feature and/or cve_id.

    Args:
        feature: Optional feature name to filter by
        cve_id: Optional CVE ID to filter by

    Returns:
        List of failed entry dictionaries matching the filters
    """
    entries = _load_entries()

    if feature:
        entries = [e for e in entries if e["feature"] == feature]
    if cve_id:
        entries = [e for e in entries if e["cve_id"] == cve_id]

    return entries


def remove_failed_entry(datetime: str, cve_id: str, feature: str) -> bool:
    """
    Remove a failed entry from the tracking system.

    Args:
        datetime: Timestamp of the feedback entry
        cve_id: CVE identifier
        feature: Feature name

    Returns:
        True if entry was found and removed, False otherwise
    """
    entries = _load_entries()
    initial_count = len(entries)

    entries = [
        e
        for e in entries
        if not (
            e["datetime"] == datetime
            and e["cve_id"] == cve_id
            and e["feature"] == feature
        )
    ]

    if len(entries) < initial_count:
        _save_entries(entries)
        logger.info(
            f"Removed failed scoring entry: feature={feature}, "
            f"cve_id={cve_id}, datetime={datetime}"
        )
        return True
    else:
        logger.debug(
            f"Failed scoring entry not found: feature={feature}, "
            f"cve_id={cve_id}, datetime={datetime}"
        )
        return False


def clear_all_failed_entries() -> int:
    """
    Clear all failed entries from the tracking system.

    Returns:
        Number of entries that were cleared
    """
    entries = _load_entries()
    count = len(entries)
    if count > 0:
        _save_entries([])
        logger.info(f"Cleared {count} failed scoring entries")
    return count
