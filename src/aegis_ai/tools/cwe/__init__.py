# https://cwe.mitre.org/data/downloads.html
import csv
import io
import json
import logging
import os
from typing import List, Dict, Any

from zipfile import ZipFile

import requests
from pydantic import Field
from pydantic_ai import Tool, RunContext
from pydantic_ai.toolsets import FunctionToolset

from aegis_ai import config_dir
from aegis_ai.data_models import CWEID, cweid_validator
from aegis_ai.tools import BaseToolOutput, default_tool_http_headers, BaseToolInput

logger = logging.getLogger(__name__)

JsonBlob = Dict[str, Any]

# retrieve allowed cwes from cwe.mitre.org
CWE_URLS = [
    "https://cwe.mitre.org/data/csv/699.csv.zip",  # development - the only view supported by OSIM auto-completions
    "https://cwe.mitre.org/data/csv/1000.csv.zip",  # research
    "https://cwe.mitre.org/data/csv/1008.csv.zip",  # architectural
    "https://cwe.mitre.org/data/csv/1081.csv.zip",  # entries with maintenance notes
]

# lazy load CWE
CACHE_DIR = f"{config_dir}/mitre_cwe"
CACHE_FILE = "cwe_full_defs.json"
os.makedirs(CACHE_DIR, exist_ok=True)


class CWEToolInput(BaseToolInput):
    """CWE tool input"""

    cwe_ids: List[CWEID] = Field(
        ...,
        description="Array of unique CWE identifiers.",
    )


class CWE(BaseToolOutput):
    """Canonical CWE definition returned by the `cwe_tool`."""

    cwe_id: CWEID = Field(
        ...,
        description="The unique CWE identifier for the security CWE.",
    )

    name: str = Field(
        ...,
        description="CWE name.",
    )

    description: str = Field(
        ...,
        description="CWE description.",
    )

    extended_description: str = Field(
        ...,
        description="CWE extended_description.",
    )
    disallowed: bool = Field(
        ...,
        description="True if the CWE is not available in the CWE-699 view.",
    )


def retrieve_cwe_definitions():
    """Retrieve CWE definitions from MITRE."""
    defs = {}
    for idx, url in enumerate(CWE_URLS):
        cwe_699_view = not idx

        try:
            response = requests.get(url, timeout=5, headers=default_tool_http_headers)
            response.raise_for_status()
        except Exception as e:
            logger.error(f"Failed to retrieve CWE definitions from {url}: {e}")
            continue

        zip_file = ZipFile(io.BytesIO(response.content))

        for file_name in zip_file.namelist():
            contents = zip_file.read(file_name).decode("utf-8")
            reader = csv.reader(io.StringIO(contents))

            next(reader)  # Skip header
            for line in reader:
                cwe = f"CWE-{line[0]}"
                if cwe in defs:
                    assert not cwe_699_view, "CWE redifinition in CWE-699 view"
                    continue

                defs[cwe] = {
                    "name": line[1],
                    "description": line[4],
                    "extended_description": line[5],
                    "related_weaknesses": line[6],
                    "disallowed": not cwe_699_view,
                }

    return defs


async def cwe_lookup(cwe_id: CWEID) -> CWE | None:
    """
    Get cwe-id name, description from mitre.

    :param cwe_id:
    :return CWE:
    """
    logger.info(f"retrieving {cwe_id} from cve.mitre.org cwe tool.")
    validated_cwe_id = cweid_validator.validate_python(cwe_id)

    file_path = os.path.join(CACHE_DIR, CACHE_FILE)

    try:
        if os.path.exists(file_path):
            logger.debug(f"Loading data from cwe cached file: {file_path}")
            with open(file_path, "r") as f:
                data = json.load(f)
        else:
            logger.info(f"No cwe cache found. Fetching and writing to: {file_path}")
            data = retrieve_cwe_definitions()
            with open(file_path, "w") as f:
                json.dump(data, f)

        try:
            cwe = data[validated_cwe_id]
            return CWE(
                cwe_id=validated_cwe_id,
                name=cwe["name"],
                description=cwe["description"],
                extended_description=cwe["extended_description"],
                disallowed=cwe["disallowed"],
            )
        except KeyError:
            # if the CWE is not in our table, mark it as disallowed
            return CWE(
                cwe_id=validated_cwe_id,
                name="UNKNOWN",
                description="UNKNOWN",
                extended_description="UNKNOWN",
                disallowed=True,  # disallow CWEs that this tool knows nothing about
                status="not_found",
                error_message="Could not find CWE-ID.",
            )

    except Exception as e:
        logger.error(f"An error occurred: {e}")


@Tool
async def retrieve_all_cwes(ctx: RunContext) -> JsonBlob | None:
    """Retrieve all allowed cwe definitions."""
    logger.info("retrieving allowed cwe definitions.")

    file_path = os.path.join(CACHE_DIR, CACHE_FILE)

    try:
        if os.path.exists(file_path):
            logger.debug(f"Loading data from cwe cached file: {file_path}")
            with open(file_path, "r") as f:
                data = json.load(f)
        else:
            logger.info(f"No cwe cache found. Fetching and writing to: {file_path}")
            data = retrieve_cwe_definitions()
            with open(file_path, "w") as f:
                json.dump(data, f, indent=2)

        return data
    except Exception as e:
        logger.error(f"An error occurred: {e}")


@Tool
async def retrieve_cwes(ctx: RunContext, inputs: CWEToolInput) -> List[CWE]:
    """Lookup specific CWE definitions by CWE ID and return an array of structured `CWE` model."""
    logger.info(f"retrieving {inputs.cwe_ids} cwe definitions.")
    results = []
    for input in inputs.cwe_ids:
        results.append(await cwe_lookup(input))
    return results


toolset = FunctionToolset(
    tools=[retrieve_cwes, retrieve_all_cwes],
)

cwe_toolset = toolset.prefixed("cwe")
