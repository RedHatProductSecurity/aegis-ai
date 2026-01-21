#!/usr/bin/env python3
"""
Retry script for unscored semantic scoring entries.

This script reads the programmatic feedback CSV, finds entries with empty
acceptance_score for features that support semantic scoring, and attempts
to score them. This script can be run periodically (e.g., hourly via cron)
to retry scoring for entries that initially failed.
"""

import argparse
import asyncio
import logging
from typing import List, Dict

from aegis_ai_web.src.feedback_logger import programmatic_feedback_logger
from aegis_ai_web.src.semantic_scoring import (
    calculate_semantic_proximity_score,
    get_semantic_scored_features,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


def get_unscored_entries(
    feature_filter: str | None = None,
    cve_id_filter: str | None = None,
) -> List[Dict[str, str]]:
    """
    Get entries from the CSV that have empty acceptance_score and are
    for features that support semantic scoring.

    Args:
        feature_filter: Optional feature name to filter by
        cve_id_filter: Optional CVE ID to filter by

    Returns:
        List of entry dictionaries that need scoring
    """
    semantic_features = get_semantic_scored_features()
    all_entries = programmatic_feedback_logger.read()

    unscored = []
    for entry in all_entries:
        # Check if entry has empty acceptance_score
        if entry.get("acceptance_score", "") != "":
            continue

        # Check if feature supports semantic scoring
        feature = entry.get("feature", "")
        if feature not in semantic_features:
            continue

        # Apply optional filters
        if feature_filter and feature != feature_filter:
            continue
        if cve_id_filter and entry.get("cve_id", "") != cve_id_filter:
            continue

        unscored.append(entry)

    return unscored


async def retry_entry(entry: Dict[str, str], dry_run: bool = False) -> bool:
    """
    Retry semantic scoring for a single entry.

    Args:
        entry: Dictionary containing entry data from CSV
        dry_run: If True, don't actually update anything, just log

    Returns:
        True if scoring succeeded, False otherwise
    """
    datetime_str = entry["datetime"]
    cve_id = entry.get("cve_id", "")
    feature = entry["feature"]
    suggested = entry.get("suggested_value", "")
    submitted = entry.get("submitted_value", "")

    logger.info(
        f"Retrying semantic scoring: feature={feature}, "
        f"cve_id={cve_id}, datetime={datetime_str}"
    )

    try:
        score = await calculate_semantic_proximity_score(
            suggested=suggested,
            submitted=submitted,
            feature=feature,
            cve_id=cve_id,
        )
    except Exception:
        logger.debug(
            f"Error retrying semantic scoring: feature={feature}, cve_id={cve_id}",
            exc_info=True,
        )
        return False

    if score is None:
        logger.warning(
            f"Semantic scoring still failed: feature={feature}, "
            f"cve_id={cve_id}, datetime={datetime_str}"
        )
        return False

    logger.info(
        f"Semantic scoring succeeded: feature={feature}, "
        f"cve_id={cve_id}, score={score}"
    )

    if dry_run:
        logger.info(
            f"[DRY RUN] Would update CSV entry: "
            f"feature={feature}, cve_id={cve_id}, score={score}"
        )
        return True

    updated = programmatic_feedback_logger.update_entry(
        datetime_str=datetime_str,
        cve_id=cve_id,
        feature=feature,
        updates={"acceptance_score": str(score)},
    )
    if updated:
        logger.info(f"Updated CSV entry: feature={feature}, cve_id={cve_id}")
    else:
        logger.warning(
            f"Could not find CSV entry to update: "
            f"datetime={datetime_str}, cve_id={cve_id}, feature={feature}"
        )

    return True


async def main() -> None:
    """Main entry point for the retry script."""
    parser = argparse.ArgumentParser(
        description="Retry semantic scoring for entries with empty acceptance_score"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be retried without making changes",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=None,
        help="Maximum number of entries to retry (default: all)",
    )
    parser.add_argument(
        "--feature",
        type=str,
        default=None,
        help="Filter by specific feature name",
    )
    parser.add_argument(
        "--cve-id",
        type=str,
        default=None,
        help="Filter by specific CVE ID",
    )

    args = parser.parse_args()

    # Get unscored entries directly from CSV
    unscored_entries = get_unscored_entries(
        feature_filter=args.feature,
        cve_id_filter=args.cve_id,
    )

    if not unscored_entries:
        logger.info("No unscored entries found to retry")
        return

    logger.info(f"Found {len(unscored_entries)} unscored entries to retry")

    if args.max_retries:
        unscored_entries = unscored_entries[: args.max_retries]
        logger.info(f"Limiting to {args.max_retries} entries")

    if args.dry_run:
        logger.info("DRY RUN MODE - No changes will be made")

    # Retry each entry
    succeeded = 0
    failed = 0

    for entry in unscored_entries:
        success = await retry_entry(entry, dry_run=args.dry_run)
        if success:
            succeeded += 1
        else:
            failed += 1

    logger.info(
        f"Retry summary: {succeeded} succeeded, {failed} still failed, "
        f"{len(unscored_entries)} total"
    )


if __name__ == "__main__":
    asyncio.run(main())
