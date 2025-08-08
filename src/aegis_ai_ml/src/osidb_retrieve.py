#!/usr/bin/env python3

"""This script retrieves impact classification training data from OSIDB"""

import json
import logging
import os
import sys
from pathlib import Path

import osidb_bindings

FLAWS_WITH_IMPACT = [
    "CRITICAL",
    "IMPORTANT",
    "MODERATE",
    "LOW",
]

FLAWS_WITH_STATES = [
    "DONE",
]

FLAWS_FIELDS = [
    "cve_id",
    "uuid",
    "title",
    "cve_description",
    "created_dt",
    "impact",
    "cvss_scores",
]

# retrieve the most recently created flaws
FLAWS_ORDER = [
    "-created_dt",
]

# do not retrieve too many MODERATE/LOW flaws to avoid imbalanced data set
FLAWS_MAX_CNT_PER_IMP = 500

# Configure the logging
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# OSIDB Server URL
OSIDB_URL = os.getenv("AEGIS_OSIDB_SERVER_URL", "https://localhost:8000")

# directory where we store the downloaded CVEs
CVE_DATA_DIR = os.getenv("AEGIS_ML_CVE_DATA_DIR", "./cve_data")
os.makedirs(CVE_DATA_DIR, exist_ok=True)

# create an OSIDB session
logging.info(f"connecting OSIDB at {OSIDB_URL}")
osidb_session = osidb_bindings.new_session(osidb_server_uri=OSIDB_URL)

# retrieve flaws from OSIDB
for impact in FLAWS_WITH_IMPACT:
    logging.info(
        f"retrieving up to {FLAWS_MAX_CNT_PER_IMP} {impact} flaws in states {FLAWS_WITH_STATES}"
    )
    # FIXME: This is not an asynchronous API really.  It will not return
    # anything until the whole server response is read in memory.
    flaw_iter = osidb_session.flaws.retrieve_list_iterator_async(
        impact=impact,
        workflow_state=FLAWS_WITH_STATES,
        max_results=FLAWS_MAX_CNT_PER_IMP,
        include_fields=FLAWS_FIELDS,
        order=FLAWS_ORDER,
    )

    # go through the retrieved flaws
    for flaw in flaw_iter:
        cve_id = flaw.cve_id
        if not cve_id:
            logging.info(f"skipping flaw without cve_id: {flaw.uuid}")
            continue

        # create an output file with JSON-encoded data
        cve_file = Path(CVE_DATA_DIR, f"{cve_id}.json")
        logging.info(f'writing CVE data to "{cve_file}"')
        with open(cve_file, "w") as f:
            # dump JSON
            flaw_dict = flaw.to_dict()
            flaw_json = json.dumps(flaw_dict, indent=2)
            f.write(flaw_json)
            f.write("\n")
