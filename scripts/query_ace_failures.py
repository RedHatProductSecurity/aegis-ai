#!/usr/bin/env python3
"""
Query OSIDB API for ACE failures to find CVEs with low-confidence component matches.

Based on the OSIDB schema: https://osidb.prodsec.redhat.com/osidb/api/v1/schema/?format=json

Usage:
    python query_ace_failures.py --limit 50 --output ace_failures.json
"""

import argparse
import json
import sys
from datetime import datetime, timedelta

import requests


def query_osidb_flaws(
    server_url: str = "https://osidb.prodsec.redhat.com",
    workflow_labels: list[str] | None = None,
    created_after: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """
    Query OSIDB for flaws matching criteria.

    Args:
        server_url: OSIDB server URL
        workflow_labels: Filter by workflow labels (e.g., ['manual-triage'])
        created_after: ISO date string (e.g., '2026-09-01')
        limit: Max number of results

    Returns:
        List of flaw dictionaries
    """
    endpoint = f"{server_url}/osidb/api/v1/flaws"

    params = {
        "limit": limit,
        "include_fields": [
            "cve_id",
            "title",
            "components",
            "workflow_name",
            "workflow_state",
            "labels",
            "aegis_meta",
            "affects",
            "created_dt",
            "updated_dt",
        ],
    }

    if workflow_labels:
        # Query for flaws with specific workflow labels
        params["labels__name__in"] = workflow_labels

    if created_after:
        params["created_dt__gte"] = created_after

    # Add ordering
    params["order"] = ["-updated_dt"]

    print(f"Querying {endpoint}...", file=sys.stderr)
    print(f"Params: {json.dumps(params, indent=2)}", file=sys.stderr)

    response = requests.get(endpoint, params=params)
    response.raise_for_status()

    data = response.json()
    return data.get("results", [])


def analyze_ace_failures(flaws: list[dict]) -> dict:
    """
    Analyze flaws to categorize ACE failure reasons.

    Returns:
        Dictionary with failure statistics and examples
    """
    stats = {
        "total": len(flaws),
        "manual_triage": 0,
        "low_confidence_components": 0,
        "firefox_thunderbird_chromium": 0,
        "no_aegis_meta": 0,
        "examples": [],
    }

    for flaw in flaws:
        cve_id = flaw.get("cve_id", "?")
        components = flaw.get("components", [])
        aegis_meta = flaw.get("aegis_meta", {})
        labels = [lbl.get("name", "") for lbl in flaw.get("labels", [])]

        if "manual-triage" in labels:
            stats["manual_triage"] += 1

        # Check if it's a browser CVE
        browser_components = {"firefox", "thunderbird", "chromium-browser", "chromium"}
        if any(comp in browser_components for comp in components):
            stats["firefox_thunderbird_chromium"] += 1

        # Check aegis_meta for low confidence
        if aegis_meta:
            component_meta = aegis_meta.get("components", [])
            if component_meta:
                latest = component_meta[-1]  # Most recent suggestion
                confidence = latest.get("confidence", 1.0)
                if confidence < 0.7:
                    stats["low_confidence_components"] += 1

                    stats["examples"].append({
                        "cve_id": cve_id,
                        "components": components,
                        "confidence": confidence,
                        "data_quality": latest.get("data_quality", 0),
                        "skip_reason": latest.get("skip_reason"),
                    })
        else:
            stats["no_aegis_meta"] += 1

    return stats


def main():
    parser = argparse.ArgumentParser(
        description="Query OSIDB for ACE failures"
    )
    parser.add_argument(
        "--server",
        default="https://osidb.prodsec.redhat.com",
        help="OSIDB server URL",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=90,
        help="Look back N days (default: 90)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Max results to fetch (default: 100)",
    )
    parser.add_argument(
        "--output",
        default="ace_failures.json",
        help="Output JSON file",
    )

    args = parser.parse_args()

    # Calculate date range
    cutoff = (datetime.now() - timedelta(days=args.days)).date().isoformat()

    # Query for manual-triage flaws
    print(f"Fetching flaws from last {args.days} days...", file=sys.stderr)
    flaws = query_osidb_flaws(
        server_url=args.server,
        workflow_labels=["manual-triage"],
        created_after=cutoff,
        limit=args.limit,
    )

    print(f"Found {len(flaws)} flaws with manual-triage label", file=sys.stderr)

    # Analyze
    stats = analyze_ace_failures(flaws)

    print("\n=== ACE Failure Analysis ===", file=sys.stderr)
    print(f"Total flaws: {stats['total']}", file=sys.stderr)
    print(f"Manual triage: {stats['manual_triage']}", file=sys.stderr)
    print(f"Low confidence components: {stats['low_confidence_components']}", file=sys.stderr)
    print(f"Firefox/Thunderbird/Chromium: {stats['firefox_thunderbird_chromium']}", file=sys.stderr)
    print(f"No aegis_meta: {stats['no_aegis_meta']}", file=sys.stderr)

    # Save results
    output_data = {
        "query_date": datetime.now().isoformat(),
        "days_back": args.days,
        "statistics": stats,
        "flaws": flaws,
    }

    with open(args.output, "w") as f:
        json.dump(output_data, f, indent=2)

    print(f"\nResults saved to {args.output}", file=sys.stderr)
    print(f"\nTop 10 low-confidence examples:", file=sys.stderr)
    for ex in stats["examples"][:10]:
        print(f"  {ex['cve_id']}: {ex['components']} (conf={ex['confidence']:.2f})", file=sys.stderr)


if __name__ == "__main__":
    main()
