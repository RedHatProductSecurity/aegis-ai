"""Disk cache for kernel git patches and commit HTML pages.

Provides cached replacements for ``KernelImpactClassifier._fetch_patches``
and ``_fetch_commit_html`` that read from ``evals/kernel_patch_cache/``
instead of making live HTTP requests to git.kernel.org and GitHub.

Cache layout::

    evals/kernel_patch_cache/patches/{40-char-hash}.patch
    evals/kernel_patch_cache/html/{40-char-hash}.html

The cache is **read-only** during eval runs.  Use
``populate_kernel_cve_cache.py`` (phase 2) to fill it from live sources
before running evals.
"""

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

KERNEL_PATCH_CACHE_DIR = Path(
    os.getenv("KERNEL_PATCH_CACHE_DIR", "evals/kernel_patch_cache")
)

patch_cache_misses: set[str] = set()
html_cache_misses: set[str] = set()


async def cached_fetch_patches(
    self,  # noqa: ARG001 — matches KernelImpactClassifier method signature
    commit_hashes: list[str],
) -> list[tuple[str, str]]:
    """Cache-only replacement for ``KernelImpactClassifier._fetch_patches``.

    Reads patch text from ``KERNEL_PATCH_CACHE_DIR/patches/{hash}.patch``.
    Missing hashes are recorded in :data:`patch_cache_misses` and skipped.
    """
    patches_dir = KERNEL_PATCH_CACHE_DIR / "patches"
    results: list[tuple[str, str]] = []
    for h in commit_hashes:
        cache_file = patches_dir / f"{h}.patch"
        try:
            content = cache_file.read_text()
            if len(content) > 100:
                results.append((h, content))
                logger.debug("patch cache hit: %s", h[:12])
            else:
                logger.warning("patch cache file too small: %s", cache_file)
                patch_cache_misses.add(h)
        except OSError:
            logger.warning("patch cache miss: %s", h[:12])
            patch_cache_misses.add(h)
    return results


async def cached_fetch_commit_html(
    self,  # noqa: ARG001 — matches KernelImpactClassifier method signature
    commit_hashes: list[str],
) -> list[tuple[str, str]]:
    """Cache-only replacement for ``KernelImpactClassifier._fetch_commit_html``.

    Reads HTML from ``KERNEL_PATCH_CACHE_DIR/html/{hash}.html``.
    Missing hashes are recorded in :data:`html_cache_misses` and skipped.
    """
    html_dir = KERNEL_PATCH_CACHE_DIR / "html"
    results: list[tuple[str, str]] = []
    for h in commit_hashes:
        cache_file = html_dir / f"{h}.html"
        try:
            content = cache_file.read_text()
            if len(content) > 200:
                results.append((h, content))
                logger.debug("HTML cache hit: %s", h[:12])
            else:
                logger.warning("HTML cache file too small: %s", cache_file)
                html_cache_misses.add(h)
        except OSError:
            logger.warning("HTML cache miss: %s", h[:12])
            html_cache_misses.add(h)
    return results


def write_patch_cache_misses_report() -> Path | None:
    """Write patch/HTML cache misses to a report file.

    Returns the path written, or ``None`` if there were no misses.
    The populate script reads this file to know which hashes to fetch.
    """
    all_misses = patch_cache_misses | html_cache_misses
    misses_file = KERNEL_PATCH_CACHE_DIR / "cache_misses.txt"

    if not all_misses:
        if misses_file.exists():
            misses_file.unlink()
        return None

    misses_file.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for h in sorted(patch_cache_misses):
        lines.append(f"patch:{h}")
    for h in sorted(html_cache_misses):
        lines.append(f"html:{h}")
    misses_file.write_text("\n".join(lines) + "\n")
    logger.info(
        "wrote %d patch/HTML cache miss(es) to %s", len(all_misses), misses_file
    )
    return misses_file
