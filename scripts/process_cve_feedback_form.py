#!/usr/bin/env python3

import csv
import re
import sys

from aegis_ai.tools.cwe import retrieve_cwe_definitions


def _cve_sort_key(cve_id):
    """Sort key for CVE IDs of the form CVE-YYYY-NNNN..., by (year, number).

    Falls back to case-insensitive lexicographic ordering if not matching.
    """
    text = "" if cve_id is None else str(cve_id).strip()
    match = re.match(r"^CVE-(\d{4})-(\d+)$", text, flags=re.IGNORECASE)
    if match:
        year = int(match.group(1))
        sequence = int(match.group(2))
        return (0, year, sequence)
    return (1, text.lower())


def process_cwe_feedback(file_path):
    """Read CSV, sort rows by the 2nd column (index 1), and write to stdout."""
    with open(file_path, "r", newline="", encoding="utf-8") as input_file:
        csv_reader = csv.reader(input_file)
        rows = list(csv_reader)

    # sort the list by CVE ID
    rows.sort(key=lambda r: _cve_sort_key(r[1]))

    # Try to load CWE-699 view to flag CWEs not present there
    cwe_defs = retrieve_cwe_definitions()

    for row in rows:
        cve = row[1]
        exp_cwe = row[3]
        if cve == "CVE-ID" and exp_cwe == "Expected CWE value":
            # skip table header
            continue

        if not exp_cwe.strip():
            # skip a row with no expected CWE
            continue

        # create a well formatted list out of the full-text field
        cwe_list = [item.strip() for item in re.split(r" *, *| *or *", exp_cwe)]

        # Optionally warn about CWEs not in the CWE-699 view (MITRE)
        for cwe in cwe_list:
            if not re.match(r"^CWE-\d+$", cwe):
                continue

            cwe_data = cwe_defs.get(cwe)
            if cwe_data and cwe_data.get("disallowed", True):
                print(f"{' ' * 4}# FIXME: {cwe} is not included in the CWE-699 view!")

        # print single instantiation of SuggestCweCase
        cwe_list = ", ".join(f'"{cwe}"' for cwe in cwe_list)
        print(f'{" " * 4}SuggestCweCase("{row[1]}", [{cwe_list}]),')


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <cwe_feedback.csv>", file=sys.stderr)
        sys.exit(1)

    input_path = sys.argv[1]

    try:
        process_cwe_feedback(input_path)
    except FileNotFoundError as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
    except csv.Error as error:
        print(f"CSV parse error: {error}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
