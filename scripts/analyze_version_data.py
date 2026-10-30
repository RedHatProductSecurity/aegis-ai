#!/usr/bin/env python3
"""
Analyze version information availability in OSIDB and OSV.dev data.

Checks whether we're missing vulnerable version ranges that ACE needs to filter affects.
"""

import asyncio
import json
import sys
from datetime import datetime

from osidb_bindings import new_session


async def analyze_cve_version_data(cve_id: str):
    """
    Analyze what version information is available for a CVE from:
    1. OSIDB affects data
    2. OSV.dev/GHSA data
    3. CVE references
    """
    print(f"=== Analyzing {cve_id} ===\n")

    session = new_session(osidb_server_uri="https://osidb.prodsec.redhat.com")

    # Get flaw data
    try:
        flaw = session.flaws.retrieve(id=cve_id)
    except Exception as e:
        print(f"Error fetching {cve_id}: {e}")
        return

    print(f"Title: {flaw.title}")
    print(f"Components: {flaw.components}\n")

    # Check affects data
    print("--- OSIDB Affects Data ---")
    if not flaw.affects:
        print("No affects data in OSIDB")
    else:
        print(f"Found {len(flaw.affects)} affects:")
        for i, affect in enumerate(flaw.affects[:5]):  # Show first 5
            purl = getattr(affect, "purl", None)
            ps_module = getattr(affect, "ps_module", None)
            ps_component = getattr(affect, "ps_component", None)
            affectedness = getattr(affect, "affectedness", None)
            resolution = getattr(affect, "resolution", None)

            print(f"\n  Affect {i+1}:")
            print(f"    ps_module: {ps_module}")
            print(f"    ps_component: {ps_component}")
            print(f"    affectedness: {affectedness}")
            print(f"    resolution: {resolution}")
            print(f"    purl: {purl}")

            # Check if PURL has version
            if purl:
                has_version = "@" in purl
                print(f"    ✅ PURL has version" if has_version else "    ❌ PURL missing version")

        if len(flaw.affects) > 5:
            print(f"\n  ... and {len(flaw.affects) - 5} more affects")

    # Check references for OSV.dev/GHSA links
    print("\n--- CVE References ---")
    osv_refs = []
    ghsa_refs = []
    if flaw.references:
        for ref in flaw.references:
            url = getattr(ref, "url", "")
            if "osv.dev" in url or "github.com/advisories/GHSA-" in url:
                if "GHSA-" in url:
                    ghsa_id = url.split("/")[-1] if "/" in url else None
                    ghsa_refs.append(ghsa_id)
                    print(f"  Found GHSA: {ghsa_id}")
                if "osv.dev" in url:
                    osv_refs.append(url)
                    print(f"  Found OSV: {url}")

    if not osv_refs and not ghsa_refs:
        print("  No OSV.dev or GHSA references found")

    # Simulate what OSV.dev would return
    print("\n--- OSV.dev Data (if we query it) ---")
    if ghsa_refs:
        print(f"GHSA IDs found: {ghsa_refs}")
        print("OSV.dev would provide:")
        print("  - affected[].package.ecosystem")
        print("  - affected[].package.name")
        print("  - affected[].ranges[].events (version ranges)")
        print("  - Example: {'introduced': '0', 'fixed': '1.75.1'}")
    else:
        print("No GHSA references - OSV.dev query may not find version data")

    # Summary
    print("\n--- VERSION DATA SUMMARY ---")

    affects_with_versions = 0
    affects_without_versions = 0
    if flaw.affects:
        for affect in flaw.affects:
            purl = getattr(affect, "purl", None)
            if purl and "@" in purl:
                affects_with_versions += 1
            else:
                affects_without_versions += 1

    print(f"Affects with version in PURL: {affects_with_versions}")
    print(f"Affects WITHOUT version in PURL: {affects_without_versions}")
    print(f"Has GHSA references for version ranges: {len(ghsa_refs) > 0}")

    print("\n--- WHAT ACE NEEDS BUT ISN'T GETTING ---")
    print("ACE needs: Vulnerable version range (e.g., '< 1.75.1', '>= 1.0.0, < 2.5.0')")
    print("Currently available from:")
    print(f"  - OSIDB affects PURLs: {affects_with_versions}/{len(flaw.affects) if flaw.affects else 0} have versions")
    print(f"  - OSV.dev/GHSA: {'✅ Available' if ghsa_refs else '❌ No GHSA references'}")
    print("\n⚠️  If Aegis doesn't extract and provide version ranges,")
    print("    ACE will create affects for ALL versions of the component!")


async def main():
    if len(sys.argv) > 1:
        cve_ids = sys.argv[1:]
    else:
        # Test with known CVEs
        cve_ids = [
            "CVE-2026-88015",  # rclone - has GHSA
            "CVE-2026-6298",   # chromium - browser CVE
        ]

    for cve_id in cve_ids:
        await analyze_cve_version_data(cve_id)
        print("\n" + "=" * 80 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
