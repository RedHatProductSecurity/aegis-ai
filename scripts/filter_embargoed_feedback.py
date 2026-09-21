#!/usr/bin/env python3
"""Filter out embargoed CVE records from a programmatic feedback CSV."""

import csv
import sys


def main():
    if len(sys.argv) < 3:
        print(
            f"Usage: {sys.argv[0]} <feedback.csv> <embargoed_cves.txt>",
            file=sys.stderr,
        )
        sys.exit(1)

    feedback_csv = sys.argv[1]
    embargoed_file = sys.argv[2]

    with open(embargoed_file) as f:
        embargoed = {line.strip() for line in f if line.strip()}

    with open(feedback_csv, newline="") as infile:
        reader = csv.DictReader(infile)
        assert reader.fieldnames is not None
        writer = csv.DictWriter(sys.stdout, fieldnames=reader.fieldnames)
        writer.writeheader()

        total = 0
        filtered = 0
        skipped = 0
        for row in reader:
            total += 1
            cve_id = row.get("cve_id", "").strip()
            if not cve_id:
                skipped += 1
                continue
            if cve_id in embargoed:
                filtered += 1
                continue
            writer.writerow(row)

    print(
        f"Total: {total}  |  Kept: {total - filtered - skipped}"
        f"  |  Filtered: {filtered}  |  Skipped: {skipped}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
