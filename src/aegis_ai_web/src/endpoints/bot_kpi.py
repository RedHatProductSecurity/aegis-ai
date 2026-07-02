"""Endpoint handler for osidb-bot KPI metrics."""

import logging
from datetime import datetime
from typing import Optional

import osidb_bindings
from fastapi import HTTPException

from aegis_ai import get_settings
from aegis_ai.osidb_bot.kpi import (
    BotKPIResult,
    FeatureStats,
    aggregate_kpi,
    fetch_bot_processed_flaws,
)
from aegis_ai_web.src.data_models import BotFeatureKPI, BotKPIResponse

logger = logging.getLogger(__name__)


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


def get_osidb_bot_kpi(
    *,
    changed_after: Optional[datetime] = None,
    changed_before: Optional[datetime] = None,
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

    try:
        flaws = fetch_bot_processed_flaws(
            osidb,
            changed_after=changed_after,
            changed_before=changed_before,
        )
        result = aggregate_kpi(flaws)
        return _result_to_response(result)
    except Exception:
        logger.error("Error computing osidb-bot KPI")
        logger.debug("osidb-bot KPI error details", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while computing osidb-bot KPI metrics.",
        )
