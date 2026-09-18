import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any

from aegis_ai.toolsets.tools.osv_dev_cve import OSVClient

logger = logging.getLogger(__name__)

GHSA_CACHE_DIR = os.getenv("GHSA_CACHE_DIR", "evals/ghsa_cache")

cache_lock = asyncio.Lock()

cache_misses: list[str] = []

# per-vuln in-flight tasks so concurrent misses for the same ID fetch only once
_inflight: dict[str, asyncio.Task[dict[str, Any]]] = {}


def _strip_versions(data: dict[str, Any]) -> dict[str, Any]:
    """Remove ``affected[].versions`` to keep cache files small."""
    if not data or "affected" not in data:
        return data
    stripped = dict(data)
    stripped["affected"] = [
        {k: v for k, v in entry.items() if k != "versions"}
        for entry in data["affected"]
    ]
    return stripped


def write_ghsa_cache_entry(vuln_id: str, data: dict[str, Any]) -> Path:
    """Serialize a raw OSV.dev response to the GHSA cache."""
    cache_file = Path(GHSA_CACHE_DIR) / f"{vuln_id}.json"
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(
        json.dumps(_strip_versions(data), indent=4) + "\n", encoding="utf-8"
    )
    return cache_file


async def _do_fetch(vuln_id: str) -> dict[str, Any]:
    """Fetch a single vulnerability from OSV.dev and write the result to cache."""
    data = await asyncio.to_thread(OSVClient().get_vuln_by_id, vuln_id)

    async with cache_lock:
        path = write_ghsa_cache_entry(vuln_id, data)
        logger.info('writing GHSA data cache to "%s"', path)
        cache_misses.append(vuln_id)

    return data


async def ghsa_cache_retrieve(vuln_id: str) -> dict[str, Any]:
    """Return cached OSV.dev data if available.  If not, fetch from
    OSV.dev and store to cache for subsequent runs."""
    cache_file = Path(GHSA_CACHE_DIR, f"{vuln_id}.json")

    async with cache_lock:
        try:
            with open(cache_file, "r") as f:  # noqa: ASYNC230
                data: dict[str, Any] = json.load(f)
            logger.debug('read GHSA data from "%s"', cache_file)
            return data
        except OSError:
            pass

        # coalesce concurrent misses for the same vuln into a single fetch
        task = _inflight.get(vuln_id)
        if task is None:
            task = asyncio.create_task(_do_fetch(vuln_id))
            _inflight[vuln_id] = task

    try:
        return await task
    finally:
        _inflight.pop(vuln_id, None)


def write_misses_report() -> Path | None:
    """Write cache-miss IDs to a file so the user knows what was fetched live."""
    if not cache_misses:
        return None
    report = Path(GHSA_CACHE_DIR) / "MISSES.txt"
    report.write_text("\n".join(sorted(cache_misses)) + "\n", encoding="utf-8")
    return report


def get_miss_files() -> list[Path]:
    """Return paths to cache files written during this session (misses)."""
    return [Path(GHSA_CACHE_DIR) / f"{vuln_id}.json" for vuln_id in cache_misses]
