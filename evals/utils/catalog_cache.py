"""Checked-in HTTP cache for bomq and Anitya catalog lookups during evals.

Wraps ``http_get_json`` so the manifest-component eval reads committed JSON
instead of calling live catalogs. Miss policy:

- Public Anitya (``release-monitoring.org``) is fetched and written even when
  ``AEGIS_EVALS_CATALOG_LIVE`` is unset, so CI can fill and dump those files.
- With ``AEGIS_EVALS_CATALOG_LIVE=1``, non-localhost hosts are recorded (how
  ``scripts/populate_catalog_cache.py`` fills bomq).
- Prefetch misses (``deadline`` set) for private catalogs raise
  ``CatalogCacheMiss``.
- Other private misses (agent tool / confirm URLs) log and return ``None`` so
  invented localhost bomq queries do not fail the eval.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from aegis_ai.features.cve.downstream import http_get_json as _live_http_get_json

logger = logging.getLogger(__name__)

CACHE_DIR = os.getenv("CATALOG_CACHE_DIR", "evals/catalog_cache")

# Keep in sync with AppSettings defaults in aegis_ai.__init__.
_DEFAULT_BOMQ_URL = "https://localhost:8080"
_DEFAULT_BOMQ_COMMUNITY_URL = "https://localhost:8081"
_DEFAULT_ANITYA_URL = "https://release-monitoring.org"
_PUBLIC_ANITYA_HOST = "release-monitoring.org"

_cache_lock = threading.Lock()
_inflight: dict[str, threading.Event] = {}

cache_misses: list[str] = []


class CatalogCacheMiss(Exception):
    """Raised when a catalog URL is absent from the checked-in cache."""

    def __init__(self, url: str) -> None:
        self.url = url
        super().__init__(
            f"catalog cache miss for {url}; "
            "run scripts/populate_catalog_cache.py with AEGIS_EVALS_CATALOG_LIVE=1 "
            "and commit the new evals/catalog_cache/*.json files"
        )


def _live_enabled() -> bool:
    return os.getenv("AEGIS_EVALS_CATALOG_LIVE", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _configured_catalog_hosts() -> list[tuple[str, str]]:
    """Return (role_token, base_url) pairs from the current process env."""
    hosts = [
        (
            "{bomq_primary}",
            os.getenv("AEGIS_BOMQ_URL", _DEFAULT_BOMQ_URL),
        ),
        (
            "{bomq_community}",
            os.getenv("AEGIS_BOMQ_COMMUNITY_URL", _DEFAULT_BOMQ_COMMUNITY_URL),
        ),
        (
            "{anitya}",
            os.getenv("AEGIS_ANITYA_URL", _DEFAULT_ANITYA_URL),
        ),
    ]
    return [(token, base.rstrip("/")) for token, base in hosts if (base or "").strip()]


def normalize_cache_url(url: str) -> str:
    """Map configured catalog hosts to stable role tokens for cache keys.

    CI defaults to localhost bomq hosts while fixtures are recorded against
    prod/community URLs. Role tokens keep path+query keys aligned across both.
    Reads ``AEGIS_BOMQ_*`` / ``AEGIS_ANITYA_URL`` from the environment so
    populate and CI agree without relying on cached AppSettings.
    """
    candidates = _configured_catalog_hosts()
    candidates.sort(key=lambda item: len(item[1]), reverse=True)
    for token, base in candidates:
        if url == base or url.startswith((f"{base}/", f"{base}?")):
            return f"{token}{url[len(base) :]}"
    return url


def _cache_filename(url: str) -> str:
    digest = hashlib.sha256(normalize_cache_url(url).encode("utf-8")).hexdigest()
    return f"{digest}.json"


def _is_localhost_url(url: str) -> bool:
    host = (urlparse(url).hostname or "").casefold()
    return host in {"localhost", "127.0.0.1", "::1"}


def _is_public_anitya_url(url: str) -> bool:
    """True for the default public Anitya host (safe to fetch in CI)."""
    host = (urlparse(url).hostname or "").casefold()
    return host == _PUBLIC_ANITYA_HOST


def write_cache_entry(url: str, body: Any) -> Path:
    """Serialize a successful JSON response to the cache.

    The stored ``url`` field uses role tokens (``{bomq_primary}``,
    ``{bomq_community}``, ``{anitya}``) so committed fixtures do not embed
    deployment-specific catalog hosts. Filenames already hash the normalized
    form; concrete hosts come from ``AEGIS_BOMQ_*`` / ``AEGIS_ANITYA_URL`` at
    request time.
    """
    cache_file = Path(CACHE_DIR) / _cache_filename(url)
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(
        json.dumps(
            {"url": normalize_cache_url(url), "body": body},
            indent=4,
        )
        + "\n",
        encoding="utf-8",
    )
    return cache_file


def _try_read_cache(url: str) -> Any | None:
    """Return cached body, or None on miss / corruption."""
    cache_file = Path(CACHE_DIR) / _cache_filename(url)
    try:
        with open(cache_file) as handle:
            data = json.load(handle)
        if not isinstance(data, dict) or "body" not in data:
            return None
        logger.debug('read catalog cache from "%s"', cache_file)
        return data["body"]
    except (OSError, json.JSONDecodeError, TypeError):
        return None


def _record_live_fetch(
    url: str,
    *,
    timeout: float,
    deadline: float | None,
    live_fetch: Callable[..., Any] | None,
    cache_file: Path,
) -> Any:
    """Fetch, write cache on success, and record the miss URL."""
    if _is_localhost_url(url):
        raise ValueError(f"refusing to record localhost catalog response for {url}")

    fetch = live_fetch or _live_http_get_json
    result = fetch(url, timeout=timeout, deadline=deadline)
    if result is None:
        # Match http_get_json failure semantics so prefetch can continue.
        logger.warning(
            "catalog live fetch returned None for %s; not writing cache", url
        )
        return None

    write_cache_entry(url, result)
    logger.info('writing catalog cache to "%s"', cache_file)
    cache_misses.append(normalize_cache_url(url))
    return result


def _handle_miss(
    url: str,
    *,
    timeout: float,
    deadline: float | None,
    live_fetch: Callable[..., Any] | None,
    cache_file: Path,
) -> Any:
    """Apply miss policy: fetch Anitya / live mode, raise prefetch, or block."""
    if _is_public_anitya_url(url):
        return _record_live_fetch(
            url,
            timeout=timeout,
            deadline=deadline,
            live_fetch=live_fetch,
            cache_file=cache_file,
        )

    if _live_enabled():
        return _record_live_fetch(
            url,
            timeout=timeout,
            deadline=deadline,
            live_fetch=live_fetch,
            cache_file=cache_file,
        )

    if deadline is not None:
        raise CatalogCacheMiss(url)

    logger.warning(
        "catalog cache miss for %s; blocking uncached private catalog lookup",
        url,
    )
    return None


def catalog_cache_retrieve(
    url: str,
    *,
    timeout: float = 30.0,
    deadline: float | None = None,
    live_fetch: Callable[..., Any] | None = None,
) -> Any:
    """Return cached JSON for *url*, or fetch/raise/block depending on miss policy.

    Signature matches ``downstream.http_get_json`` so evals can monkeypatch
    that name with this function.
    """
    cache_file = Path(CACHE_DIR) / _cache_filename(url)

    with _cache_lock:
        cached = _try_read_cache(url)
        if cached is not None:
            return cached

        event = _inflight.get(url)
        if event is not None:
            wait = True
        else:
            event = threading.Event()
            _inflight[url] = event
            wait = False

    if wait:
        event.wait()
        cached = _try_read_cache(url)
        if cached is not None:
            return cached
        # First request finished without writing (block, live None, or raise).
        # Re-apply miss policy so waiters match the primary outcome.
        return _handle_miss(
            url,
            timeout=timeout,
            deadline=deadline,
            live_fetch=live_fetch,
            cache_file=cache_file,
        )

    try:
        return _handle_miss(
            url,
            timeout=timeout,
            deadline=deadline,
            live_fetch=live_fetch,
            cache_file=cache_file,
        )
    finally:
        with _cache_lock:
            _inflight.pop(url, None)
        event.set()


def write_misses_report() -> Path | None:
    """Write cache-miss URLs recorded during a live session.

    Entries are role-token URLs (same form as committed fixture ``url``
    fields) so ``MISSES.txt`` does not embed deployment-specific hosts.
    """
    if not cache_misses:
        return None
    report = Path(CACHE_DIR) / "MISSES.txt"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(
        "\n".join(sorted(normalize_cache_url(u) for u in cache_misses)) + "\n",
        encoding="utf-8",
    )
    return report


def get_miss_files() -> list[Path]:
    """Return paths to cache files written during this session (misses)."""
    return [Path(CACHE_DIR) / _cache_filename(url) for url in cache_misses]


def get_public_miss_files() -> list[Path]:
    """Return miss files whose stored ``url`` is an Anitya role-token fixture.

    Used by eval session teardown to dump only public Anitya bodies into CI
    logs. Bomq miss files are omitted: CI cannot fetch them, and some slimmed
    search bodies are still too large for a single log line.
    """
    paths: list[Path] = []
    for url in cache_misses:
        path = Path(CACHE_DIR) / _cache_filename(url)
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError):
            continue
        stored = data.get("url") if isinstance(data, dict) else None
        if isinstance(stored, str) and stored.startswith("{anitya}"):
            paths.append(path)
    return paths
