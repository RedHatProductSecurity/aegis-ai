import json
import logging
import os
import threading
from pathlib import Path

from pydantic import ValidationError

from aegis_ai.toolsets.tools.build_system import ListBinaryRPMsOutput
from aegis_ai.toolsets.tools.build_system import (
    _lookup_binary_rpms as live_lookup_binary_rpms,
)

logger = logging.getLogger(__name__)

CACHE_DIR = os.getenv("BUILD_SYSTEM_CACHE_DIR", "evals/build_system_cache")

_cache_lock = threading.Lock()
_inflight: dict[str, threading.Event] = {}

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
    cache_key = f"{package}/{ps_update_stream}"

    # Fast path: read from cache under a short lock.
    with _cache_lock:
        try:
            with open(cache_file) as f:
                data = json.load(f)
            logger.debug('read build system cache from "%s"', cache_file)
            return ListBinaryRPMsOutput(**data)
        except (OSError, json.JSONDecodeError, ValidationError):
            pass

        # Per-key dedup: if another thread is already fetching this key, wait.
        event = _inflight.get(cache_key)
        if event is not None:
            wait = True
        else:
            event = threading.Event()
            _inflight[cache_key] = event
            wait = False

    if wait:
        event.wait()
        # The other thread wrote the cache file — read it.
        with _cache_lock:
            with open(cache_file) as f:
                data = json.load(f)
            return ListBinaryRPMsOutput(**data)

    # Live lookup runs outside the lock so other keys proceed concurrently.
    try:
        result = live_lookup_binary_rpms(package, ps_update_stream)
        write_cache_entry(package, ps_update_stream, result)
        logger.info('writing build system cache to "%s"', cache_file)
        cache_misses.append(cache_key)
        return result
    finally:
        with _cache_lock:
            _inflight.pop(cache_key, None)
        event.set()


def build_system_cache_retrieve_batch(
    package: str, streams: list[str]
) -> list[ListBinaryRPMsOutput]:
    """Batch wrapper: resolve each stream through the per-key cache."""
    return [build_system_cache_retrieve(package, s) for s in streams]


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
