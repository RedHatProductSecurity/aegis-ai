#!/usr/bin/env python3
"""Analyze Aegis suggest-impact accuracy on kernel CVEs from OSIDB prod data.

Reads CVE IDs from a gold.tsv file, fetches aegis_meta and ground truth
from OSIDB, and computes accuracy metrics.

Usage:
    uv run python scripts/analyze_kernel_accuracy.py
    uv run python scripts/analyze_kernel_accuracy.py --gold path/to/gold.tsv
    uv run python scripts/analyze_kernel_accuracy.py --fresh --jobs 4

Requires: VPN + Kerberos ticket (kinit), AEGIS_OSIDB_SERVER_URL env var.
With --fresh: also requires AEGIS_LLM_HOST, AEGIS_LLM_MODEL, and an LLM API key.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import logging
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import osidb_bindings

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s  %(levelname)-7s  %(message)s"
)
log = logging.getLogger(__name__)

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_GOLD = SCRIPT_DIR / "gold.tsv"

SEVERITY_RANK = {"CRITICAL": 0, "IMPORTANT": 1, "MODERATE": 2, "LOW": 3}

INCLUDE_FIELDS = "cve_id,impact,cvss_scores,aegis_meta,classification"
INCLUDE_FIELDS_FRESH = "cve_id,impact,cvss_scores,classification"


def load_cve_ids(gold_path: Path) -> list[str]:
    """Read CVE IDs from the first column of a TSV file."""
    cves: list[str] = []
    with open(gold_path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f, delimiter="\t")
        next(reader, None)
        for row in reader:
            if row and row[0].strip().startswith("CVE-"):
                cves.append(row[0].strip())
    return cves


def get_latest_suggestion(aegis_meta: dict, field: str) -> str | None:
    """Get the value from the latest AI-Bot entry for a field."""
    entries = aegis_meta.get(field, [])
    for entry in reversed(entries):
        if entry.get("type") == "AI-Bot":
            return entry.get("value")
    return None


def get_rh_cvss(cvss_scores: list[dict]) -> tuple[float | None, str]:
    """Extract the RH CVSS3 score and vector."""
    for entry in cvss_scores:
        if entry.get("issuer") != "RH":
            continue
        vector = entry.get("vector", "")
        if not vector or "CVSS:3" not in vector:
            continue
        score = entry.get("score")
        if score is not None:
            return float(score), vector
        return _score_from_vector(vector), vector
    return None, ""


def _score_from_vector(vector: str) -> float | None:
    """Compute CVSS 3.x base score from a vector string."""
    if not vector or "CVSS:3" not in vector:
        return None
    try:
        import cvss as cvss_lib

        return cvss_lib.CVSS3(vector).scores()[0]
    except Exception:
        return None


def classify_diff(suggested: str, actual: str) -> str:
    """Classify the difference: match, underestimation, or overestimation."""
    s_rank = SEVERITY_RANK.get(suggested.upper(), 4)
    a_rank = SEVERITY_RANK.get(actual.upper(), 4)
    if s_rank == a_rank:
        return "match"
    elif s_rank > a_rank:
        return "underestimation"
    else:
        return "overestimation"


async def _fetch_one(
    session: Any,
    cve_id: str,
    index: int,
    total: int,
    sem: asyncio.Semaphore,
) -> dict:
    """Fetch a single flaw from OSIDB and extract comparison fields."""
    async with sem:
        log.info("[%d/%d] %s", index, total, cve_id)
        try:
            flaw = await asyncio.to_thread(
                session.flaws.retrieve, id=cve_id, include_fields=INCLUDE_FIELDS
            )
            data = flaw.to_dict()
        except Exception as exc:
            log.warning("Failed to fetch %s: %s", cve_id, exc)
            return {"cve_id": cve_id, "error": str(exc)}

    osidb_impact = (data.get("impact") or "").upper()
    rh_score, rh_vector = get_rh_cvss(data.get("cvss_scores") or [])
    classification = data.get("classification") or {}

    meta = data.get("aegis_meta") or {}
    processed = meta.get("processed", False)

    suggested_impact = get_latest_suggestion(meta, "impact")
    suggested_vector = get_latest_suggestion(meta, "_cvss3_vector")
    suggested_score = _score_from_vector(suggested_vector) if suggested_vector else None

    diff = None
    if suggested_impact and osidb_impact:
        diff = classify_diff(suggested_impact, osidb_impact)

    return {
        "cve_id": cve_id,
        "processed": processed,
        "classification": (
            f"{classification.get('workflow', '?')}/{classification.get('state', '?')}"
        ),
        "osidb_impact": osidb_impact,
        "suggested_impact": (suggested_impact or "").upper(),
        "diff": diff or "",
        "rh_cvss_score": rh_score,
        "suggested_cvss_score": suggested_score,
        "cvss_diff": round(suggested_score - rh_score, 1)
        if rh_score is not None and suggested_score is not None
        else None,
        "rh_cvss_vector": rh_vector,
        "suggested_cvss_vector": suggested_vector or "",
    }


async def _fetch_and_suggest_one(
    session: Any,
    cve_id: str,
    index: int,
    total: int,
    sem: asyncio.Semaphore,
    output_dir: Path | None = None,
) -> dict:
    """Fetch ground truth from OSIDB, then run SuggestImpact live."""
    from aegis_ai.agents import rh_feature_agent
    from aegis_ai.features.cve import SuggestImpact

    async with sem:
        log.info("[%d/%d] %s (fresh)", index, total, cve_id)
        try:
            flaw = await asyncio.to_thread(
                session.flaws.retrieve,
                id=cve_id,
                include_fields=INCLUDE_FIELDS_FRESH,
            )
            data = flaw.to_dict()
        except Exception as exc:
            log.warning("Failed to fetch %s: %s", cve_id, exc)
            return {"cve_id": cve_id, "error": str(exc)}

    osidb_impact = (data.get("impact") or "").upper()
    rh_score, rh_vector = get_rh_cvss(data.get("cvss_scores") or [])
    classification = data.get("classification") or {}

    try:
        feature = SuggestImpact(rh_feature_agent)
        result = await feature.exec(cve_id)
        output = result.output
        suggested_impact = (output.impact or "").upper()
        suggested_vector = output.cvss3_vector
        suggested_score = (
            _score_from_vector(suggested_vector) if suggested_vector else None
        )
    except Exception as exc:
        log.warning("SuggestImpact failed for %s: %s", cve_id, exc)
        return {"cve_id": cve_id, "error": f"suggest-impact: {exc}"}

    if output_dir is not None:
        dump_path = output_dir / f"{cve_id}-suggest-impact.json"
        dump_path.write_text(output.model_dump_json(indent=2) + "\n", encoding="utf-8")
        log.info("  -> %s", dump_path)

    diff = None
    if suggested_impact and osidb_impact:
        diff = classify_diff(suggested_impact, osidb_impact)

    return {
        "cve_id": cve_id,
        "processed": None,
        "classification": (
            f"{classification.get('workflow', '?')}/{classification.get('state', '?')}"
        ),
        "osidb_impact": osidb_impact,
        "suggested_impact": suggested_impact,
        "diff": diff or "",
        "rh_cvss_score": rh_score,
        "suggested_cvss_score": suggested_score,
        "cvss_diff": round(suggested_score - rh_score, 1)
        if rh_score is not None and suggested_score is not None
        else None,
        "rh_cvss_vector": rh_vector,
        "suggested_cvss_vector": suggested_vector or "",
    }


async def fetch_all(
    session: Any,
    cve_ids: list[str],
    jobs: int,
    *,
    fresh: bool = False,
    output_dir: Path | None = None,
) -> list[dict]:
    """Fetch flaw data from OSIDB for all CVEs, up to *jobs* in parallel."""
    sem = asyncio.Semaphore(jobs)
    if fresh:
        tasks = [
            _fetch_and_suggest_one(session, cve_id, i, len(cve_ids), sem, output_dir)
            for i, cve_id in enumerate(cve_ids, 1)
        ]
    else:
        tasks = [
            _fetch_one(session, cve_id, i, len(cve_ids), sem)
            for i, cve_id in enumerate(cve_ids, 1)
        ]
    results = await asyncio.gather(*tasks)
    errors = sum(1 for r in results if "error" in r)
    if errors:
        log.warning("%d/%d CVEs failed to fetch", errors, len(cve_ids))
    return list(results)


def print_report(results: list[dict]) -> None:
    """Print the accuracy report to stdout."""
    valid = [r for r in results if "error" not in r]
    errored = [r for r in results if "error" in r]
    show_proc = any(r.get("processed") is not None for r in valid)

    print("\n" + "=" * 130)
    print("AEGIS SUGGEST-IMPACT ACCURACY REPORT — Kernel CVEs")
    print("=" * 130)

    # Per-CVE table
    if show_proc:
        header = (
            f"{'CVE':<20} {'Proc':<5} {'Classification':<35} "
            f"{'OSIDB':<12} {'Aegis':<12} {'Diff':<16} "
            f"{'RH CVSS':<8} {'Aegis CVSS':<11} {'CVSS Diff':<10}"
        )
    else:
        header = (
            f"{'CVE':<20} {'Classification':<35} "
            f"{'OSIDB':<12} {'Aegis':<12} {'Diff':<16} "
            f"{'RH CVSS':<8} {'Aegis CVSS':<11} {'CVSS Diff':<10}"
        )
    print(f"\n{header}")
    print("-" * 140)

    for r in valid:
        rh_s = f"{r['rh_cvss_score']:.1f}" if r["rh_cvss_score"] is not None else "—"
        ae_s = (
            f"{r['suggested_cvss_score']:.1f}"
            if r["suggested_cvss_score"] is not None
            else "—"
        )
        cd = f"{r['cvss_diff']:+.1f}" if r["cvss_diff"] is not None else "—"
        if show_proc:
            proc = "Y" if r["processed"] else "N"
            print(
                f"{r['cve_id']:<20} {proc:<5} {r['classification']:<35} "
                f"{r['osidb_impact']:<12} {r['suggested_impact']:<12} "
                f"{r['diff']:<16} {rh_s:<8} {ae_s:<11} {cd:<10}"
            )
        else:
            print(
                f"{r['cve_id']:<20} {r['classification']:<35} "
                f"{r['osidb_impact']:<12} {r['suggested_impact']:<12} "
                f"{r['diff']:<16} {rh_s:<8} {ae_s:<11} {cd:<10}"
            )

    for r in errored:
        print(f"{r['cve_id']:<20} {'ERR':<5} {r['error']}")

    # Aggregate metrics
    unprocessed = [r for r in valid if r.get("processed") is False]
    comparable = [r for r in valid if r["diff"]]
    matches = [r for r in comparable if r["diff"] == "match"]
    underest = [r for r in comparable if r["diff"] == "underestimation"]
    overest = [r for r in comparable if r["diff"] == "overestimation"]

    print(f"\n{'=' * 60}")
    print("AGGREGATE METRICS")
    print(f"{'=' * 60}")
    print(f"Total CVEs:              {len(results)}")
    print(f"Fetch errors:            {len(errored)}")
    print(f"Unprocessed:             {len(unprocessed)}")
    print(f"Comparable:              {len(comparable)}")
    if comparable:
        print(
            f"Impact exact match:      {len(matches)}/{len(comparable)}"
            f" ({100 * len(matches) / len(comparable):.1f}%)"
        )
        print(
            f"Underestimations:        {len(underest)}/{len(comparable)}"
            f" ({100 * len(underest) / len(comparable):.1f}%)"
        )
        print(
            f"Overestimations:         {len(overest)}/{len(comparable)}"
            f" ({100 * len(overest) / len(comparable):.1f}%)"
        )

    # Per-severity breakdown
    if comparable:
        print("\nPer-severity accuracy:")
        for severity in ("CRITICAL", "IMPORTANT", "MODERATE", "LOW"):
            sev_cases = [r for r in comparable if r["osidb_impact"] == severity]
            if not sev_cases:
                continue
            sev_matches = [r for r in sev_cases if r["diff"] == "match"]
            print(
                f"  {severity:<12}: {len(sev_matches)}/{len(sev_cases)}"
                f" ({100 * len(sev_matches) / len(sev_cases):.1f}%)"
            )

    # Confusion matrix
    if comparable:
        print("\nConfusion matrix (rows=OSIDB ground truth, cols=Aegis suggestion):")
        severities = ["CRITICAL", "IMPORTANT", "MODERATE", "LOW"]
        confusion: Counter[tuple[str, str]] = Counter(
            (r["osidb_impact"], r["suggested_impact"]) for r in comparable
        )
        print(f"{'':>12}", end="")
        for s in severities:
            print(f"  {s[:4]:>6}", end="")
        print()
        for actual in severities:
            row_cases = [r for r in comparable if r["osidb_impact"] == actual]
            if not row_cases:
                continue
            print(f"{actual:>12}", end="")
            for predicted in severities:
                count = confusion.get((actual, predicted), 0)
                print(f"  {count:>6}", end="")
            print()

    # CVSS score MAE
    cvss_diffs: list[float] = []
    for r in valid:
        if r["rh_cvss_score"] is not None and r["suggested_cvss_score"] is not None:
            cvss_diffs.append(abs(r["rh_cvss_score"] - r["suggested_cvss_score"]))
    if cvss_diffs:
        mae = sum(cvss_diffs) / len(cvss_diffs)
        print(f"\nCVSS score MAE:          {mae:.2f} (over {len(cvss_diffs)} CVEs)")
        print(f"CVSS score max error:    {max(cvss_diffs):.1f}")


async def async_main(args: argparse.Namespace) -> None:
    cve_ids = load_cve_ids(args.gold)
    if not cve_ids:
        print("ERROR: No CVE IDs found in gold file", file=sys.stderr)
        sys.exit(1)

    if args.fresh:
        from aegis_ai import config_logging

        config_logging()

    log.info("Loaded %d CVE IDs from %s", len(cve_ids), args.gold)
    log.info(
        "Connecting to OSIDB at %s (jobs=%d, fresh=%s)",
        args.osidb_url,
        args.jobs,
        args.fresh,
    )

    session = osidb_bindings.new_session(osidb_server_uri=args.osidb_url)
    output_dir = args.gold.resolve().parent if args.fresh else None
    results = await fetch_all(
        session, cve_ids, args.jobs, fresh=args.fresh, output_dir=output_dir
    )
    print_report(results)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze Aegis suggest-impact accuracy on kernel CVEs from OSIDB prod data"
        )
    )
    parser.add_argument(
        "--gold",
        type=Path,
        default=DEFAULT_GOLD,
        help=f"Path to gold.tsv file with CVE IDs (default: {DEFAULT_GOLD})",
    )
    parser.add_argument(
        "--osidb-url",
        type=str,
        default=os.environ.get(
            "AEGIS_OSIDB_SERVER_URL", "https://osidb.prodsec.redhat.com"
        ),
        help="OSIDB server URL (default: $AEGIS_OSIDB_SERVER_URL)",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=8,
        help="Number of parallel OSIDB fetches (default: 8)",
    )
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="Run suggest-impact live instead of reading aegis_meta from OSIDB",
    )
    args = parser.parse_args()

    if not args.gold.exists():
        print(f"ERROR: Gold file not found: {args.gold}", file=sys.stderr)
        sys.exit(1)

    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
