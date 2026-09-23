#!/usr/bin/env python3
"""Update OSIDB columns in eval-kernel-cves.csv from live OSIDB data.

Reads the existing CSV, queries OSIDB for each CVE's current impact and CVSS
data, and overwrites the three OSIDB columns in place.  Requires Kerberos
credentials (kinit) and VPN access to OSIDB.

The OSIDB endpoint is derived from ``$AEGIS_OSIDB_SERVER_URL``.

Usage:
    uv run python scripts/update_kernel_eval_csv.py
    uv run python scripts/update_kernel_eval_csv.py --dry-run
"""

from __future__ import annotations

import argparse
import csv
import logging
import os
import sys
from pathlib import Path
from typing import Any

import osidb_bindings

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s  %(levelname)-7s  %(message)s"
)
log = logging.getLogger(__name__)

CSV_PATH = (
    Path(__file__).resolve().parent.parent / "evals/features/cve/eval-kernel-cves.csv"
)

CVSS_ISSUER_PRIORITY = ["RH", "NIST", "CVEORG", "OSV", "CISA"]

_INCLUDE_FIELDS = "cve_id,impact,cvss_scores"


def _query_osidb(session: Any, cve_id: str) -> dict | None:
    try:
        flaw = session.flaws.retrieve(id=cve_id, include_fields=_INCLUDE_FIELDS)
    except Exception as exc:
        text = str(exc).lower()
        if "404" in text or "not found" in text:
            log.warning("%s not found in OSIDB", cve_id)
        else:
            log.warning("Query failed for %s: %s", cve_id, exc)
        return None

    cvss_scores = [
        {
            "issuer": score.issuer,
            "vector": score.vector,
            "score": getattr(score, "score", None),
        }
        for score in (flaw.cvss_scores or [])
    ]
    return {"impact": flaw.impact or "", "cvss_scores": cvss_scores}


def _pick_best_cvss3(cvss_scores: list[dict]) -> tuple[float | None, str]:
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
        except Exception:  # noqa: S110
            pass

    return best_score, best_vector


def _normalize_impact(raw: str) -> str:
    mapping = {
        "CRITICAL": "Critical",
        "IMPORTANT": "Important",
        "MODERATE": "Moderate",
        "LOW": "Low",
        "NONE": "None",
    }
    return mapping.get(raw.upper(), raw.title()) if raw else ""


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Update OSIDB columns in eval-kernel-cves.csv from live OSIDB"
    )
    parser.add_argument(
        "--csv",
        type=Path,
        default=CSV_PATH,
        help=f"Path to the eval CSV (default: {CSV_PATH})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print changes without writing the CSV",
    )
    args = parser.parse_args()

    osidb_url = os.environ.get("AEGIS_OSIDB_SERVER_URL")
    if not osidb_url:
        print("ERROR: AEGIS_OSIDB_SERVER_URL is not set", file=sys.stderr)
        sys.exit(1)

    csv_path: Path = args.csv
    if not csv_path.exists():
        print(f"ERROR: CSV not found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    log.info("Connecting to OSIDB at %s", osidb_url)
    session = osidb_bindings.new_session(osidb_server_uri=osidb_url)

    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    total = len(rows)
    updated = 0
    failed = 0

    for i, row in enumerate(rows, 1):
        cve_id = row["CVE"]
        log.info("[%d/%d] %s", i, total, cve_id)

        data = _query_osidb(session, cve_id)
        if data is None:
            failed += 1
            continue

        new_impact = _normalize_impact(data.get("impact", ""))
        new_score, new_vector = _pick_best_cvss3(data.get("cvss_scores", []))
        new_cvss = str(round(new_score, 1)) if new_score is not None else ""

        old = (row["OSIDB Impact"], row["OSIDB CVSS"], row["OSIDB CVSS Vector"])
        new = (new_impact, new_cvss, new_vector)

        if old != new:
            log.info("  %s: %s -> %s", cve_id, old, new)
            row["OSIDB Impact"] = new_impact
            row["OSIDB CVSS"] = new_cvss
            row["OSIDB CVSS Vector"] = new_vector
            updated += 1

    log.info("Done: %d/%d updated, %d failed", updated, total, failed)

    if args.dry_run:
        log.info("Dry run — not writing changes")
        return

    if updated == 0:
        log.info("No changes to write")
        return

    fieldnames = ["CVE", "OSIDB Impact", "OSIDB CVSS", "OSIDB CVSS Vector"]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    log.info("Wrote %s", csv_path)


if __name__ == "__main__":
    main()
