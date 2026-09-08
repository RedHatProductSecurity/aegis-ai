import json
import logging
import os
import threading
from pathlib import Path

from aegis_ai.toolsets.tools.build_system import ListBinaryRPMsOutput
from aegis_ai.toolsets.tools.build_system import (
    _lookup_binary_rpms as live_lookup_binary_rpms,
)

logger = logging.getLogger(__name__)

CACHE_DIR = os.getenv("BUILD_SYSTEM_CACHE_DIR", "evals/build_system_cache")

cache_lock = threading.Lock()

cache_misses: list[str] = []


def _cache_filename(package: str, ps_update_stream: str) -> str:
    return f"{package}__{ps_update_stream}.json"


def write_cache_entry(
    package: str, ps_update_stream: str, result: ListBinaryRPMsOutput
) -> Path:
    """Serialize a ListBinaryRPMsOutput to the cache."""
    cache_file = Path(CACHE_DIR) / _cache_filename(package, ps_update_stream)
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(
        json.dumps(result.model_dump(), indent=4) + "\n", encoding="utf-8"
    )
    return cache_file


def build_system_cache_retrieve(
    package: str, ps_update_stream: str
) -> ListBinaryRPMsOutput:
    """Return cached build system data if available.

    On cache miss, fetch live and store for subsequent runs.
    Synchronous because _lookup_binary_rpms is sync (called via asyncio.to_thread).
    """
    cache_file = Path(CACHE_DIR) / _cache_filename(package, ps_update_stream)

    with cache_lock:
        try:
            with open(cache_file) as f:
                data = json.load(f)
            logger.debug('read build system cache from "%s"', cache_file)
            return ListBinaryRPMsOutput(**data)

        except OSError:
            result = live_lookup_binary_rpms(package, ps_update_stream)
            write_cache_entry(package, ps_update_stream, result)
            logger.info('writing build system cache to "%s"', cache_file)
            miss_key = f"{package}/{ps_update_stream}"
            cache_misses.append(miss_key)
            return result


def write_misses_report() -> Path | None:
    """Write cache-miss keys to a file so the user knows what was fetched live."""
    if not cache_misses:
        return None
    report = Path(CACHE_DIR) / "MISSES.txt"
    report.write_text("\n".join(sorted(cache_misses)) + "\n", encoding="utf-8")
    return report


def get_miss_files() -> list[Path]:
    """Return paths to cache files written during this session (misses)."""
    return [
        Path(CACHE_DIR) / _cache_filename(*key.split("/", 1)) for key in cache_misses
    ]
