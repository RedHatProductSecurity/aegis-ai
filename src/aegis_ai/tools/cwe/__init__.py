# https://cwe.mitre.org/data/downloads.html
import csv
import io
import json
import logging
import os
from dataclasses import dataclass
from zipfile import ZipFile

import requests
from pydantic import Field
from pydantic_ai import Tool, RunContext

from aegis_ai import config_dir
from aegis_ai.data_models import CWEID, cweid_validator
from aegis_ai.tools import BaseToolOutput

logger = logging.getLogger(__name__)

# retrieve from cwe.mitre.org
CWE_URLS = [
    "https://cwe.mitre.org/data/csv/1000.csv.zip",  # research
    "https://cwe.mitre.org/data/csv/699.csv.zip",  # development
    "https://cwe.mitre.org/data/csv/1008.csv.zip",  # architectural
]


@dataclass
class CWEDependencies:
    test = 1


class CWE(BaseToolOutput):
    """ """

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


def retrieve_cwe_definitions():
    """Retrieve CWE definitions from MITRE."""
    defs = {}
    for url in CWE_URLS:
        response = requests.get(url)
        zip_file = ZipFile(io.BytesIO(response.content))

        for file_name in zip_file.namelist():
            contents = zip_file.read(file_name).decode("utf-8")
            reader = csv.reader(io.StringIO(contents))

            next(reader)  # Skip header
            for line in reader:
                defs[f"CWE-{line[0]}"] = {
                    "name": line[1],
                    "description": line[4],
                    "extended_description": line[5],
                    "related_weaknesses": line[6],
                }

    return defs


async def cwe_lookup(cwe_id: CWEID):
    """
    Get cwe-id name, description from mitre.

    :param cwe_id:
    :return CWE:
    """
    logger.info(f"retrieving {cwe_id} from cve.mitre.org cwe tool.")
    validated_cwe_id = cweid_validator.validate_python(cwe_id)

    # lazy load CWE
    CACHE_DIR = config_dir
    CACHE_FILE = "cwe_full_defs.json"
    os.makedirs(CACHE_DIR, exist_ok=True)
    file_path = os.path.join(CACHE_DIR, CACHE_FILE)

    try:
        if os.path.exists(file_path):
            logger.debug(f"Loading data from cwe cached file: {file_path}")
            with open(file_path, "r") as f:
                data = json.load(f)
        else:
            logger.debug(f"No cwe cache found. Fetching and writing to: {file_path}")
            data = retrieve_cwe_definitions()
            with open(file_path, "w") as f:
                json.dump(data, f, indent=2)

        return data[validated_cwe_id]

    except Exception as e:
        logger.error(f"An error occurred: {e}")


@Tool
async def cwe_tool(ctx: RunContext[CWEDependencies], cwe_id: CWEID) -> str:
    """ """
    logger.debug(cwe_id)
    return await cwe_lookup(cwe_id)
