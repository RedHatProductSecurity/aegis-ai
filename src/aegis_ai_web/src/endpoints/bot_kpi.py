"""Endpoint handler for osidb-bot KPI metrics."""

import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import osidb_bindings
from fastapi import HTTPException

from aegis_ai import get_settings
from aegis_ai.osidb_bot.kpi import (
    BotKPICacheEntry,
    BotKPIResult,
    FeatureStats,
    aggregate_kpi,
    fetch_bot_processed_flaws,
    merge_kpi_results,
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


def _get_cache_path() -> Path:
    cache_dir = os.environ.get("AEGIS_BOT_KPI_CACHE_DIR")
    if cache_dir:
        return Path(cache_dir) / "kpi_cache.json"
    return Path(get_settings().config_dir) / "osidb_bot_kpi" / "kpi_cache.json"


def _load_cache() -> Optional[BotKPICacheEntry]:
    cache_path = _get_cache_path()
    if not cache_path.is_file():
        return None
    try:
        return BotKPICacheEntry.model_validate_json(cache_path.read_text())
    except Exception:
        logger.warning("Failed to load bot KPI cache, will do full query")
        logger.debug("Cache load error details", exc_info=True)
        return None


def _save_cache(entry: BotKPICacheEntry) -> None:
    cache_path = _get_cache_path()
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            dir=cache_path.parent, suffix=".tmp", prefix="kpi_cache_"
        )
        try:
            with os.fdopen(fd, "w") as f:
                f.write(entry.model_dump_json(indent=2))
            os.replace(tmp_path, cache_path)
        except BaseException:
            os.unlink(tmp_path)
            raise
    except Exception:
        logger.warning("Failed to write bot KPI cache")
        logger.debug("Cache write error details", exc_info=True)


def get_osidb_bot_kpi(
    *,
    changed_after: Optional[datetime] = None,
    changed_before: Optional[datetime] = None,
    full_refresh: bool = False,
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

    has_date_filters = changed_after is not None or changed_before is not None

    try:
        if full_refresh or has_date_filters:
            flaws = fetch_bot_processed_flaws(
                osidb,
                changed_after=changed_after,
                changed_before=changed_before,
            )
            result = aggregate_kpi(flaws)
            if full_refresh:
                cutoff = datetime.now(timezone.utc)
                _save_cache(BotKPICacheEntry.from_kpi_result(result, cutoff))
            return _result_to_response(result)

        cached = _load_cache()
        if cached is not None:
            cached_result = cached.to_kpi_result()
            incremental_flaws = fetch_bot_processed_flaws(
                osidb, changed_after=cached.cutoff
            )
            incremental_result = aggregate_kpi(incremental_flaws)
            result = merge_kpi_results(cached_result, incremental_result)
        else:
            flaws = fetch_bot_processed_flaws(osidb)
            result = aggregate_kpi(flaws)

        cutoff = datetime.now(timezone.utc)
        _save_cache(BotKPICacheEntry.from_kpi_result(result, cutoff))
        return _result_to_response(result)
    except HTTPException:
        raise
    except Exception:
        logger.error("Error computing osidb-bot KPI")
        logger.debug("osidb-bot KPI error details", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred while computing osidb-bot KPI metrics.",
        )
