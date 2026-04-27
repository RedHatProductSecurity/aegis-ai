#!/usr/bin/env python3
"""Populate all kernel eval caches: CVE context, patches, and commit HTML.

Phase 1 — CVE context cache (``evals/kernel_cve_context_cache/``)
    Performs live ``kernel_cve_lookup`` calls against the upstream linux-vulns
    git repo and writes the results.  Only responses that contain actual
    metadata are persisted.

Phase 2 — Patch / HTML cache (``evals/kernel_patch_cache/``)
    Extracts commit hashes from the Phase 1 output and fetches raw git
    patches from git.kernel.org and rendered commit HTML from GitHub.

At the start of every run, any CVE IDs listed in
``kernel_cve_context_cache/cache_misses.txt`` (written by the eval session)
are automatically retried before processing the rest of the work list.
Likewise, hashes in ``kernel_patch_cache/cache_misses.txt`` are retried.

Usage::

    # Retry previous misses only
    uv run python evals/utils/populate_kernel_cve_cache.py

    # Populate specific CVEs
    uv run python evals/utils/populate_kernel_cve_cache.py CVE-2024-53147 CVE-2025-39792

    # Populate all CVEs from the eval CSV
    uv run python evals/utils/populate_kernel_cve_cache.py --from-eval-csv
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import logging
import re
import sys
from pathlib import Path

import httpx

from aegis_ai.kernel_classifier import HTML_COMMIT_URL_TEMPLATES, PATCH_URL_TEMPLATES
from aegis_ai.toolsets.tools.kernel_cves import LINUXCVEToolResponse, kernel_cve_lookup

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s  %(levelname)-7s  %(message)s"
)
log = logging.getLogger(__name__)

SCRIPT_DIR = Path(__file__).resolve().parent
CACHE_DIR = SCRIPT_DIR.parent / "kernel_cve_context_cache"
CACHE_MISSES_FILE = CACHE_DIR / "cache_misses.txt"
PATCH_CACHE_DIR = SCRIPT_DIR.parent / "kernel_patch_cache"
PATCH_MISSES_FILE = PATCH_CACHE_DIR / "cache_misses.txt"
EVAL_CSV = SCRIPT_DIR.parent / "features" / "cve" / "eval-kernel-cves.csv"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_misses_file() -> list[str]:
    """Read CVE IDs from the misses file left by the last eval run."""
    if not CACHE_MISSES_FILE.exists():
        return []
    lines = CACHE_MISSES_FILE.read_text().splitlines()
    return [line.strip() for line in lines if line.strip().startswith("CVE-")]


def _read_eval_csv() -> list[str]:
    """Read CVE IDs from the eval ground-truth CSV."""
    if not EVAL_CSV.exists():
        log.error("eval CSV not found: %s", EVAL_CSV)
        sys.exit(1)
    cves: list[str] = []
    with open(EVAL_CSV, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            cve_id = row["CVE"].strip()
            if cve_id.startswith("CVE-"):
                cves.append(cve_id)
    return cves


def _is_cached(cve_id: str) -> bool:
    """Return True if a cache file with non-null metadata exists."""
    cache_file = CACHE_DIR / f"{cve_id}.json"
    if not cache_file.exists():
        return False
    try:
        response = LINUXCVEToolResponse.model_validate_json(cache_file.read_text())
        return response.metadata is not None
    except Exception:
        return False


def _read_patch_misses_file() -> tuple[set[str], set[str]]:
    """Read hashes from the patch cache misses file.

    Returns (patch_hashes, html_hashes).
    """
    patch_misses: set[str] = set()
    html_misses: set[str] = set()
    if not PATCH_MISSES_FILE.exists():
        return patch_misses, html_misses
    for line in PATCH_MISSES_FILE.read_text().splitlines():
        line = line.strip()
        if line.startswith("patch:"):
            patch_misses.add(line.removeprefix("patch:"))
        elif line.startswith("html:"):
            html_misses.add(line.removeprefix("html:"))
    return patch_misses, html_misses


def _collect_commit_hashes(cve_ids: list[str]) -> set[str]:
    """Extract 40-char commit hashes from kernel CVE context cache files."""
    hashes: set[str] = set()
    for cve_id in cve_ids:
        cache_file = CACHE_DIR / f"{cve_id}.json"
        if not cache_file.exists():
            continue
        try:
            data = json.loads(cache_file.read_text())
            metadata = data.get("metadata")
            raw_hashes = metadata.get("commit_hashes", []) if metadata else []
            for href in raw_hashes:
                m = re.search(r"([0-9a-fA-F]{40})", href)
                if m:
                    hashes.add(m.group(1))
        except Exception:
            log.exception("failed to read context cache for %s", cve_id)
    return hashes


# ---------------------------------------------------------------------------
# Phase 1: CVE context cache
# ---------------------------------------------------------------------------


async def _populate_cve_context(cve_ids: list[str]) -> None:
    """Perform live lookups and write results to the cache directory."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    to_fetch = [cve for cve in cve_ids if not _is_cached(cve)]
    if not to_fetch:
        log.info("[context] all %d CVE(s) already cached — nothing to do", len(cve_ids))
        return

    log.info("[context] %d of %d CVE(s) need fetching", len(to_fetch), len(cve_ids))

    succeeded = 0
    still_missing: list[str] = []

    for i, cve_id in enumerate(to_fetch, 1):
        log.info("[context] [%d/%d] %s", i, len(to_fetch), cve_id)
        try:
            response = await kernel_cve_lookup(cve_id)
        except Exception:
            log.exception("lookup failed for %s", cve_id)
            still_missing.append(cve_id)
            continue

        if response.metadata is None:
            log.warning("%s: no metadata returned, skipping cache write", cve_id)
            still_missing.append(cve_id)
            continue

        cache_file = CACHE_DIR / f"{cve_id}.json"
        data = response.model_dump(mode="json")
        if data.get("metadata") and data["metadata"].get("source_files"):
            home = str(Path.home())
            data["metadata"]["source_files"] = [
                p.replace(home, "~", 1) if p.startswith(home) else p
                for p in data["metadata"]["source_files"]
            ]
        cache_file.write_text(json.dumps(data, indent=4) + "\n")
        succeeded += 1
        log.info("%s: cached", cve_id)

    if still_missing:
        CACHE_MISSES_FILE.write_text("\n".join(sorted(still_missing)) + "\n")
        log.warning(
            "%d CVE(s) still missing (updated %s): %s",
            len(still_missing),
            CACHE_MISSES_FILE,
            ", ".join(sorted(still_missing)),
        )
    elif CACHE_MISSES_FILE.exists():
        CACHE_MISSES_FILE.unlink()

    log.info(
        "[context] done: %d fetched, %d still missing, %d already cached",
        succeeded,
        len(still_missing),
        len(cve_ids) - len(to_fetch),
    )


# ---------------------------------------------------------------------------
# Phase 2: patch / HTML cache
# ---------------------------------------------------------------------------


async def _fetch_patches(hashes: set[str]) -> None:
    """Fetch raw patches and write to the cache directory."""
    patches_dir = PATCH_CACHE_DIR / "patches"
    patches_dir.mkdir(parents=True, exist_ok=True)

    to_fetch = [
        h
        for h in sorted(hashes)
        if not (patches_dir / f"{h}.patch").exists()
        or (patches_dir / f"{h}.patch").stat().st_size <= 100
    ]
    if not to_fetch:
        log.info("[patches] all %d patch(es) already cached", len(hashes))
        return

    log.info("[patches] %d of %d patch(es) need fetching", len(to_fetch), len(hashes))
    failed: list[str] = []

    async with httpx.AsyncClient(timeout=30.0) as client:
        for i, h in enumerate(to_fetch, 1):
            log.info("[patches] [%d/%d] %s", i, len(to_fetch), h[:12])
            fetched = False
            for tmpl in PATCH_URL_TEMPLATES:
                url = tmpl.format(hash=h)
                try:
                    resp = await client.get(url, follow_redirects=True)
                    if resp.status_code == 200 and len(resp.text) > 100:
                        (patches_dir / f"{h}.patch").write_text(resp.text)
                        log.info("  cached from %s", url.split("/")[2])
                        fetched = True
                        break
                except Exception as e:
                    log.debug("  failed %s: %s", url, e)
            if not fetched:
                log.warning("  could not fetch patch for %s", h[:12])
                failed.append(h)

    log.info(
        "[patches] %d fetched, %d failed, %d already cached",
        len(to_fetch) - len(failed),
        len(failed),
        len(hashes) - len(to_fetch),
    )


async def _fetch_html(hashes: set[str]) -> None:
    """Fetch commit HTML pages and write to the cache directory."""
    html_dir = PATCH_CACHE_DIR / "html"
    html_dir.mkdir(parents=True, exist_ok=True)

    to_fetch = [
        h
        for h in sorted(hashes)
        if not (html_dir / f"{h}.html").exists()
        or (html_dir / f"{h}.html").stat().st_size <= 200
    ]
    if not to_fetch:
        log.info("[html] all %d HTML page(s) already cached", len(hashes))
        return

    log.info("[html] %d of %d HTML page(s) need fetching", len(to_fetch), len(hashes))
    failed: list[str] = []

    async with httpx.AsyncClient(timeout=30.0) as client:
        for i, h in enumerate(to_fetch, 1):
            log.info("[html] [%d/%d] %s", i, len(to_fetch), h[:12])
            fetched = False
            for tmpl in HTML_COMMIT_URL_TEMPLATES:
                url = tmpl.format(hash=h)
                try:
                    resp = await client.get(url, follow_redirects=True)
                    if resp.status_code == 200 and len(resp.text) > 200:
                        (html_dir / f"{h}.html").write_text(resp.text)
                        log.info("  cached from %s", url.split("/")[2])
                        fetched = True
                        break
                except Exception as e:
                    log.debug("  failed %s: %s", url, e)
            if not fetched:
                log.warning("  could not fetch HTML for %s", h[:12])
                failed.append(h)

    log.info(
        "[html] %d fetched, %d failed, %d already cached",
        len(to_fetch) - len(failed),
        len(failed),
        len(hashes) - len(to_fetch),
    )


async def _populate_patches(
    cve_ids: list[str], extra_hashes: set[str] | None = None
) -> None:
    """Extract commit hashes from CVE context cache and fetch patches + HTML."""
    hashes = _collect_commit_hashes(cve_ids)
    if extra_hashes:
        hashes |= extra_hashes

    if not hashes:
        log.info("[patches] no commit hashes found — nothing to do")
        return

    log.info(
        "[patches] %d unique commit hashes across %d CVE(s)",
        len(hashes),
        len(cve_ids),
    )

    await _fetch_patches(hashes)
    await _fetch_html(hashes)

    if PATCH_MISSES_FILE.exists():
        PATCH_MISSES_FILE.unlink()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


async def _populate(cve_ids: list[str], extra_hashes: set[str] | None = None) -> None:
    """Run both phases: CVE context, then patches/HTML."""
    await _populate_cve_context(cve_ids)
    await _populate_patches(cve_ids, extra_hashes=extra_hashes)
    log.info("all caches populated")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Populate kernel eval caches (CVE context + patches + HTML)"
    )
    parser.add_argument(
        "cves",
        nargs="*",
        metavar="CVE-ID",
        help="CVE IDs to populate (in addition to any retries from cache_misses.txt)",
    )
    parser.add_argument(
        "--from-eval-csv",
        action="store_true",
        help="Also include all CVEs from eval-kernel-cves.csv",
    )
    args = parser.parse_args()

    cve_ids: list[str] = []
    seen: set[str] = set()

    retries = _read_misses_file()
    if retries:
        log.info("retrying %d CVE context miss(es) from previous run", len(retries))
    for cve in retries:
        if cve not in seen:
            cve_ids.append(cve)
            seen.add(cve)

    for cve in args.cves:
        if cve not in seen:
            cve_ids.append(cve)
            seen.add(cve)

    if args.from_eval_csv:
        for cve in _read_eval_csv():
            if cve not in seen:
                cve_ids.append(cve)
                seen.add(cve)

    patch_retries, html_retries = _read_patch_misses_file()
    extra_hashes = patch_retries | html_retries
    if extra_hashes:
        log.info(
            "retrying %d patch/HTML hash miss(es) from previous run", len(extra_hashes)
        )

    if not cve_ids and not extra_hashes:
        log.info("nothing to do (no CVEs specified and no cache_misses.txt)")
        return

    asyncio.run(_populate(cve_ids, extra_hashes=extra_hashes or None))


if __name__ == "__main__":
    main()
