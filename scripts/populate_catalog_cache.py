#!/usr/bin/env python3
"""Pre-populate evals/catalog_cache for suggest-manifest-component evals.

Loads each CVE from the manifest-component golden sample (OSIDB cache),
routes ``http_get_json`` through the catalog cache with live recording, and
runs ``collect_downstream_candidates`` so bomq/Anitya prefetch responses are
committed.

Requires real ``AEGIS_BOMQ_URL`` / ``AEGIS_BOMQ_COMMUNITY_URL`` (not localhost).
CI fetches public Anitya misses and dumps them for import; uncached bomq tool
URLs are blocked at eval time, so a follow-up live eval is not required to
record invented agent queries.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

# Enable live recording before catalog_cache reads the env flag.
os.environ["AEGIS_EVALS_CATALOG_LIVE"] = "1"

from aegis_ai import config_logging, get_settings
from aegis_ai.features.cve import downstream as downstream_mod
from aegis_ai.features.cve.downstream import (
    collect_downstream_candidates,
)
from evals.features.cve.test_suggest_manifest_component_and_state import (
    DEFAULT_CVE_IDS,
)
from evals.utils.catalog_cache import (
    cache_misses,
    catalog_cache_retrieve,
    write_misses_report,
)
from evals.utils.osidb_cache import read_cache_json


def _is_localhost_host(url: str) -> bool:
    host = (urlparse(url).hostname or "").casefold()
    return host in {"localhost", "127.0.0.1", "::1"}


def _require_real_bomq_hosts() -> None:
    settings = get_settings()
    for label, url in (
        ("AEGIS_BOMQ_URL", settings.bomq_url),
        ("AEGIS_BOMQ_COMMUNITY_URL", settings.bomq_community_url),
    ):
        if not (url or "").strip():
            if label == "AEGIS_BOMQ_COMMUNITY_URL":
                continue
            print(f"error: {label} is empty", file=sys.stderr)
            sys.exit(1)
        if _is_localhost_host(url):
            print(
                f"error: {label}={url!r} is localhost; "
                "set real bomq hosts before populating the catalog cache",
                file=sys.stderr,
            )
            sys.exit(1)


def main() -> None:
    config_logging(level="INFO")
    _require_real_bomq_hosts()

    # Route all prefetch HTTP through the cache writer.
    # catalog_cache_retrieve accepts an extra optional live_fetch kwarg.
    downstream_mod.http_get_json = catalog_cache_retrieve  # type:ignore

    ok = 0
    failed: list[str] = []
    for cve_id in DEFAULT_CVE_IDS:
        flaw = read_cache_json(cve_id)
        if not flaw:
            print(f"  skip {cve_id}: missing OSIDB cache entry", file=sys.stderr)
            failed.append(cve_id)
            continue
        try:
            gathered = collect_downstream_candidates(flaw)
            print(
                f"  {cve_id}: seeds={len(gathered.seeds)} "
                f"candidates={len(gathered.candidates)} "
                f"tools={gathered.tools_used} "
                f"unavailable={gathered.catalog_unavailable}",
                file=sys.stderr,
            )
            if gathered.catalog_unavailable:
                failed.append(cve_id)
            else:
                ok += 1
        except Exception as exc:
            print(f"  FAILED {cve_id}: {exc}", file=sys.stderr)
            failed.append(cve_id)

    report = write_misses_report()
    print(
        f"\ndone: {ok} ok, {len(failed)} failed, "
        f"{len(cache_misses)} new cache entries"
        + (f" (see {report})" if report else ""),
        file=sys.stderr,
    )
    if failed:
        print("failed CVEs:", ", ".join(failed), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
