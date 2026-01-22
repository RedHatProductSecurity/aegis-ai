#!/usr/bin/env python3

import asyncio
import csv
import json
import re
import sys

from aegis_ai import config_logging
from aegis_ai.toolsets.tools.cwe import cwe_manager
from evals.utils.osidb_cache import osidb_cache_retrieve

FEEDBACK_CSV_HEADER = [
    "datetime",
    "feature",
    "cve_id",
    "email",
    "actual",
    "expected",
    "request_time",
    "accept",
    "rejection_comment",
    "version",
]

# load CWE-699 view so that we can annotate CWEs not present in the view
asyncio.run(cwe_manager.initialize())
cwe_defs = cwe_manager._definitions


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


def describe_feature(feature) -> tuple[str, str]:
    match feature:
        case "suggest-cvss":
            evaluator = "Impact"
            field = "expected_cvss3_vector"

        case "suggest-cwe":
            evaluator = "Cwe"
            field = "cwe_list"

        case "suggest-description":
            evaluator = "Description"
            field = "expected_description"

        case "suggest-impact":
            evaluator = "Impact"
            field = "expected_impact"

        case "suggest-mitigation":
            evaluator = "Statement"
            field = "expected_mitigation"

        case "suggest-statement":
            evaluator = "Statement"
            field = "expected_statement"

        case "suggest-title":
            evaluator = "Description"
            field = "expected_title"

        case _:
            assert False, f"unknown feature: {feature}"

    return (evaluator, field)


def process_generic_feedback(rows, current_evaluator):
    for row in rows:
        feature = row[1]
        evaluator, field = describe_feature(feature)
        if evaluator != current_evaluator:
            # skip feedback for other evaluators
            continue

        # get CVE ID and fetch the corresponding fixture from OSIDB
        cve = row[2]
        osidb_cache_cve(cve)

        # value suggested by Aegis
        suggested = row[5]

        # check whether we got positie or negative feedback
        accept = row[7]
        match accept:
            case "true":
                value = suggested

            case "false":
                suggested_quoted = json.dumps(suggested)
                rejection_comment = json.dumps(row[8])
                value = f"FIXME: suggested={suggested_quoted}, rejection_comment={rejection_comment}"

            case _:
                assert False, f"unknown 'accept' value: {accept}"

        if field == "cwe_list":
            # FIXME: uncomment and adapt for the new feedback format
            # replace NNN or NNNN by CWE-NNN or CWE-NNNN, respectively
            # cwe_list = [re.sub(r"^([0-9]{3,4})$", r"CWE-\1", cwe) for cwe in cwe_list]

            # annotate CWEs not present in the CWE-699 view
            for m in re.finditer(r"CWE-[0-9]{1,4}", value):
                cwe_id = m.group()
                assert isinstance(cwe_defs, dict)
                cwe_data = cwe_defs.get(cwe_id)
                if cwe_data and not cwe_data.get("disallowed", True):
                    continue

                print(
                    f"{' ' * 4}# FIXME: {cwe_id} is not included in the CWE-699 view!"
                )

            # although we have a single value (in 99% cases), the evaluator takes a list
            value = [value]

        # get expected output
        print(f"{' ' * 4}Suggest{evaluator}Case(")
        print(f"{' ' * 8}cve_id={json.dumps(cve)},")
        print(f"{' ' * 8}{field}={json.dumps(value)},")
        print(f"{' ' * 4}),")


def process_feedback(file_path):
    """Read CSV, sort rows by the 2nd column (index 1), and run specific processors."""
    with open(file_path, "r", newline="", encoding="utf-8") as input_file:
        csv_reader = csv.reader(input_file)
        rows = list(csv_reader)

    # check CSV header end remove the row
    assert rows[0] == FEEDBACK_CSV_HEADER
    rows.pop(0)

    # sort the list by CVE ID
    rows.sort(key=lambda r: _cve_sort_key(r[2]))

    # run specific processors
    for evaluator in ("Cwe", "Description", "Impact", "Statement"):
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
