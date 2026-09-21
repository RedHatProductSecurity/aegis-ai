#!/usr/bin/env python3
"""Filter a list of CVE IDs, printing only those that are embargoed in OSIDB.

A CVE is considered embargoed if the authenticated user cannot see it (i.e.,
OSIDB does not return it when queried in a batch retrieve_list call).
"""

import os
import sys

import osidb_bindings

_BATCH_SIZE = 100


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <cve_ids_file>", file=sys.stderr)
        print("  Each line should contain one CVE ID.", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1]) as f:
        cve_ids = [line.strip() for line in f if line.strip()]

    osidb_url = os.environ.get("AEGIS_OSIDB_SERVER_URL", "")
    if not osidb_url:
        print("Error: AEGIS_OSIDB_SERVER_URL is not set", file=sys.stderr)
        sys.exit(1)

    session = osidb_bindings.new_session(osidb_server_uri=osidb_url)

    not_embargoed: set[str] = set()
    total = len(cve_ids)

    for offset in range(0, total, _BATCH_SIZE):
        chunk = cve_ids[offset : offset + _BATCH_SIZE]
        batch_num = offset // _BATCH_SIZE + 1
        total_batches = (total + _BATCH_SIZE - 1) // _BATCH_SIZE
        print(
            f"[{batch_num}/{total_batches}] querying {len(chunk)} CVEs...",
            file=sys.stderr,
        )
        for flaw in session.flaws.retrieve_list_iterator(
            cve_id=chunk, include_fields="cve_id,embargoed", limit=200
        ):
            flaw_dict = flaw.to_dict()
            cve_id = flaw_dict.get("cve_id")
            if cve_id and not flaw_dict.get("embargoed"):
                not_embargoed.add(cve_id)

    embargoed = [cve for cve in cve_ids if cve not in not_embargoed]

    print(
        f"\nTotal: {total}  |  Not embargoed: {len(not_embargoed)}"
        f"  |  Embargoed: {len(embargoed)}",
        file=sys.stderr,
    )
    for cve in embargoed:
        print(cve)


if __name__ == "__main__":
    main()
