#!/usr/bin/env python3
"""Generate eval-kernel-cves.csv from the canonical CVE list and OSIDB.

Reads CVE IDs from kernel_eval_cves.txt, looks up each CVE's impact and
CVSS data from the local OSIDB cache (evals/osidb_cache/) first, falling
back to a live OSIDB query when the cache misses.

Usage:
    uv run python evals/features/cve/generate_kernel_eval_csv.py
    uv run python evals/features/cve/generate_kernel_eval_csv.py --cves CVE-2025-38590 CVE-2024-53104
    uv run python evals/features/cve/generate_kernel_eval_csv.py --no-cache
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import subprocess
import sys
import time
from pathlib import Path

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s  %(levelname)-7s  %(message)s"
)
log = logging.getLogger(__name__)

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent.parent
CVE_LIST_PATH = SCRIPT_DIR / "kernel_eval_cves.txt"
CSV_OUTPUT_PATH = SCRIPT_DIR / "eval-kernel-cves.csv"

# Make evals package importable when running as a standalone script
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from evals.utils.osidb_cache import read_cache_json  # noqa: E402

OSIDB_BASE = "https://osidb.prodsec.redhat.com/osidb/api/v2/flaws"

CVSS_ISSUER_PRIORITY = ["RH", "NIST", "CVEORG", "OSV", "CISA"]

CVE_RE = re.compile(r"^(CVE-\d{4}-\d{4,7})")


def load_cve_list(path: Path) -> list[str]:
    """Parse a plain-text CVE list, ignoring comments and blank lines."""
    cves: list[str] = []
    seen: set[str] = set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            stripped = line.split("#", 1)[0].strip()
            if not stripped:
                continue
            m = CVE_RE.match(stripped)
            if m and m.group(1) not in seen:
                cves.append(m.group(1))
                seen.add(m.group(1))
    return cves


def _query_osidb(cve_id: str) -> dict | None:
    """Query OSIDB for a single flaw. Returns the JSON dict or None."""
    url = f"{OSIDB_BASE}/{cve_id}?include_fields=cve_id,impact,cvss_scores"
    try:
        result = subprocess.run(
            ["curl", "-s", "--negotiate", "-u", ":", url],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            log.warning("curl failed for %s (exit %d)", cve_id, result.returncode)
            return None
        data = json.loads(result.stdout)
        if "detail" in data and "not found" in str(data["detail"]).lower():
            log.warning("%s not found in OSIDB", cve_id)
            return None
        return data
    except json.JSONDecodeError:
        log.warning("Invalid JSON response for %s", cve_id)
        return None
    except Exception as exc:
        log.warning("Query failed for %s: %s", cve_id, exc)
        return None


def _fetch_flaw(cve_id: str, *, use_cache: bool = True) -> dict | None:
    """Fetch flaw data: cache first, then live OSIDB."""
    if use_cache:
        cached = read_cache_json(cve_id)
        if cached is not None:
            log.info("  (cache hit)")
            return cached
    return _query_osidb(cve_id)


def _pick_best_cvss3(cvss_scores: list[dict]) -> tuple[float | None, str]:
    """Select the best CVSS 3.x score and vector, preferring RH's assessment.

    Returns (score, vector) where score is None and vector "" if unavailable.
    """
    best_score: float | None = None
    best_vector = ""
    best_priority = len(CVSS_ISSUER_PRIORITY) + 1

    for entry in cvss_scores:
        vector = entry.get("vector", "")
        issuer = entry.get("issuer", "")
        if not vector or "CVSS:3" not in vector:
            continue

        try:
            priority = CVSS_ISSUER_PRIORITY.index(issuer)
        except ValueError:
            priority = len(CVSS_ISSUER_PRIORITY)

        if priority >= best_priority:
            continue

        score = entry.get("score")
        if score is not None:
            best_score = float(score)
            best_vector = vector
            best_priority = priority
            continue

        try:
            import cvss as cvss_lib

            best_score = cvss_lib.CVSS3(vector).scores()[0]
            best_vector = vector
            best_priority = priority
        except Exception:
            pass

    return best_score, best_vector


def _normalize_impact(raw: str) -> str:
    """Normalize OSIDB impact: 'IMPORTANT' -> 'Important'."""
    mapping = {
        "CRITICAL": "Critical",
        "IMPORTANT": "Important",
        "MODERATE": "Moderate",
        "LOW": "Low",
        "NONE": "None",
    }
    return mapping.get(raw.upper(), raw.title()) if raw else ""


def generate(cve_ids: list[str], output: Path, *, use_cache: bool = True) -> None:
    """Look up OSIDB data for each CVE and write the ground-truth CSV."""
    rows: list[dict[str, str]] = []
    errors = 0

    for i, cve_id in enumerate(cve_ids, 1):
        log.info("[%d/%d] %s", i, len(cve_ids), cve_id)

        data = _fetch_flaw(cve_id, use_cache=use_cache)
        if data is None:
            errors += 1
            log.warning("No data for %s: not in cache and live query failed", cve_id)
            rows.append(
                {
                    "CVE": cve_id,
                    "OSIDB Impact": "ERROR",
                    "OSIDB CVSS": "",
                    "OSIDB CVSS Vector": "",
                }
            )
            continue

        impact = _normalize_impact(data.get("impact", ""))
        cvss_score, cvss_vector = _pick_best_cvss3(data.get("cvss_scores", []))

        rows.append(
            {
                "CVE": cve_id,
                "OSIDB Impact": impact,
                "OSIDB CVSS": str(round(cvss_score, 1))
                if cvss_score is not None
                else "",
                "OSIDB CVSS Vector": cvss_vector,
            }
        )

        if i % 10 == 0:
            time.sleep(0.1)

    fieldnames = ["CVE", "OSIDB Impact", "OSIDB CVSS", "OSIDB CVSS Vector"]
    ok = len(cve_ids) - errors

    if ok == 0 and output.exists():
        log.error(
            "All %d lookups failed — refusing to overwrite %s with error-only data. "
            "Are the CVEs in evals/osidb_cache/? For live queries: VPN + kinit.",
            errors,
            output,
        )
        sys.exit(1)

    with open(output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    log.info(
        "Wrote %s: %d/%d CVEs populated (%d errors)", output, ok, len(cve_ids), errors
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate eval-kernel-cves.csv from OSIDB ground truth"
    )
    parser.add_argument(
        "--cves",
        nargs="+",
        metavar="CVE-ID",
        help="Process specific CVEs instead of reading kernel_eval_cves.txt",
    )
    parser.add_argument(
        "--cve-list",
        type=Path,
        default=CVE_LIST_PATH,
        help=f"Path to CVE list file (default: {CVE_LIST_PATH.name})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=CSV_OUTPUT_PATH,
        help=f"Output CSV path (default: {CSV_OUTPUT_PATH.name})",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Skip local OSIDB cache, always query OSIDB live (requires Kerberos)",
    )
    args = parser.parse_args()

    if args.cves:
        cve_ids = args.cves
    else:
        if not args.cve_list.exists():
            print(f"ERROR: CVE list not found: {args.cve_list}", file=sys.stderr)
            sys.exit(1)
        cve_ids = load_cve_list(args.cve_list)

    if not cve_ids:
        print("ERROR: No CVEs to process", file=sys.stderr)
        sys.exit(1)

    log.info("Processing %d CVEs -> %s", len(cve_ids), args.output)
    generate(cve_ids, args.output, use_cache=not args.no_cache)


if __name__ == "__main__":
    main()
