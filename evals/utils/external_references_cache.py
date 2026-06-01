import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any

from aegis_ai.toolsets.tools.external_references import (
    ExternalReferenceResult,
    cache_key_for_url,
    fetch_reference as live_fetch_reference,
)

logger = logging.getLogger(__name__)

CACHE_DIR = os.getenv(
    "EXTERNAL_REFERENCES_CACHE_DIR", "evals/external_references_cache"
)

cache_lock = asyncio.Lock()

cache_misses: list[str] = []


def write_cache_entry(url: str, result: ExternalReferenceResult) -> Path:
    """Serialize an ExternalReferenceResult to the cache."""
    cache_file = Path(CACHE_DIR) / f"{cache_key_for_url(url)}.json"
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    data = {"url": url, "result": result.model_dump()}
    cache_file.write_text(json.dumps(data, indent=4) + "\n", encoding="utf-8")
    return cache_file


async def extref_cache_retrieve(url: str) -> ExternalReferenceResult:
    """Return cached external reference data if available.

    On cache miss, fetch live and store for subsequent runs.
    """
    cache_file = Path(CACHE_DIR) / f"{cache_key_for_url(url)}.json"

    async with cache_lock:
        try:
            with open(cache_file) as f:
                data: dict[str, Any] = json.load(f)
            logger.debug('read external reference cache from "%s"', cache_file)
            return ExternalReferenceResult(**data["result"])

        except OSError:
            result = await live_fetch_reference(url)
            write_cache_entry(url, result)
            logger.info('writing external reference cache to "%s"', cache_file)
            cache_misses.append(url)
            return result


def write_misses_report() -> Path | None:
    """Write cache-miss URLs to a file so the user knows what was fetched live."""
    if not cache_misses:
        return None
    report = Path(CACHE_DIR) / "MISSES.txt"
    report.write_text("\n".join(sorted(cache_misses)) + "\n", encoding="utf-8")
    return report
