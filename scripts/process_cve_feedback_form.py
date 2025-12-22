#!/usr/bin/env python3

import asyncio
import csv
import json
import re
import sys
from typing import no_type_check

from aegis_ai import config_logging
from aegis_ai.toolsets.tools.cwe import cwe_manager
from evals.utils.osidb_cache import osidb_cache_retrieve


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


def osidb_cache_cve(cve):
    # populate OSIDB cache for this CVE (best-effort)
    try:
        asyncio.run(osidb_cache_retrieve(cve))
    except Exception as e:
        # Non-fatal: report and continue
        print(f"{' ' * 4}# NOTE: failed to cache {cve} from OSIDB: {e}")


@no_type_check
def process_cwe_feedback(rows):
    """processor of suggest-cwe feedback"""
    # Try to load CWE-699 view to flag CWEs not present there
    asyncio.run(cwe_manager.initialize())
    cwe_defs = cwe_manager._definitions

    # column headers vary in time
    header_cve = {"Column 1", "CVE-ID"}
    header_exp_cwe = {"Column 3", "Expected CWE value"}

    # there can be multiple rows for a single CVE, for which we merge the CWE lists
    data = []
    for row in rows:
        feature = row[8]
        if feature and feature != "suggest-cwe":
            # skip feedback for other features
            continue

        cve = row[1]
        exp_cwe = row[3]
        if cve in header_cve and exp_cwe in header_exp_cwe:
            # skip table header
            continue

        if not exp_cwe.strip():
            # skip a row with no expected CWE
            continue

        # remove parentheses in case we get "(CWE-119|CWE-122)"
        exp_cwe = exp_cwe.strip("()")

        # create a well formatted list out of the full-text field
        cwe_list = [item.strip() for item in re.split(r" *(?:[,/|]|or) *", exp_cwe)]

        # replace NNN or NNNN by CWE-NNN or CWE-NNNN, respectively
        cwe_list = [re.sub(r"^([0-9]{3,4})$", r"CWE-\1", cwe) for cwe in cwe_list]

        # the rows are sorted by CVE -> check for subsequent rows with identical CVE
        if data and data[-1][0] == cve:
            # merge the CWE list with the last item
            data[-1][1].extend(cwe_list)
        else:
            # create a new item (for a previously unseen CVE)
            data.append((cve, cwe_list))

    for cve, cwe_list in data:
        # Optionally warn about CWEs not in the CWE-699 view (MITRE)
        for cwe in cwe_list:
            cwe_data = cwe_defs.get(cwe)
            if not cwe_data or cwe_data.get("disallowed", True):
                print(f"{' ' * 4}# FIXME: {cwe} is not included in the CWE-699 view!")

        osidb_cache_cve(cve)

        # print single instantiation of SuggestCweCase
        cwe_list = ", ".join(f'"{cwe}"' for cwe in cwe_list)
        print(f"{' ' * 4}SuggestCweCase(")
        print(f'{" " * 8}cve_id="{cve}",')
        print(f"{' ' * 8}cwe_list=[{cwe_list}],")
        print(f"{' ' * 4}),")


def is_title(value):
    """guess whether the provided expected value is a title"""
    return not value.endswith(".") and len(value) < 128


def process_generic_feedback(rows, current_evaluator):
    for row in rows:
        value = row[3]
        feature = row[8]
        match feature:
            case "suggest-cvss":
                evaluator = "Impact"
                field = "cvss3_vector"

            case "suggest-description":
                evaluator = "Description"
                field = "title" if is_title(value) else "description"

            case "suggest-impact":
                evaluator = "Impact"
                field = "impact"

            case "suggest-mitigation":
                evaluator = "Statement"
                field = "mitigation"

            case "suggest-statement":
                evaluator = "Statement"
                field = "statement"

            case "suggest-title":
                evaluator = "Description"
                field = "title"

            case _:
                # skip feedback for other features
                continue

        if evaluator != current_evaluator:
            # skip feedback for other evaluators
            continue

        # get CVE ID
        cve = row[1]
        osidb_cache_cve(cve)

        # get expected output
        print(f"{' ' * 4}Suggest{evaluator}Case(")
        print(f"{' ' * 8}cve_id={json.dumps(cve)},")
        print(f"{' ' * 8}expected_{field}={json.dumps(value)},")
        print(f"{' ' * 4}),")


def process_feedback(file_path):
    """Read CSV, sort rows by the 2nd column (index 1), and run specific processors."""
    with open(file_path, "r", newline="", encoding="utf-8") as input_file:
        csv_reader = csv.reader(input_file)
        rows = list(csv_reader)

    # sort the list by CVE ID
    rows.sort(key=lambda r: _cve_sort_key(r[1]))

    # run specific processors
    process_cwe_feedback(rows)
    for evaluator in ("Description", "Impact", "Statement"):
        process_generic_feedback(rows, evaluator)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <cwe_feedback.csv>", file=sys.stderr)
        sys.exit(1)

    input_path = sys.argv[1]

    try:
        config_logging(level="INFO")
        process_feedback(input_path)
    except FileNotFoundError as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
    except csv.Error as error:
        print(f"CSV parse error: {error}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
