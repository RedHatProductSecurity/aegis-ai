# https://cwe.mitre.org/data/downloads.html
#
#
# This CWE tool could be entirely replaced by pushing mitre CWE data to vectordb.
#

import csv
import io
import json
import logging
import os
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional

from zipfile import ZipFile

import faiss
import numpy as np
import requests
from pydantic import Field
from pydantic_ai import Tool, RunContext
from pydantic_ai.toolsets import FunctionToolset
from sentence_transformers import SentenceTransformer

from aegis_ai import config_dir
from aegis_ai.data_models import CWEID, cweid_validator
from aegis_ai.tools import BaseToolOutput, default_tool_http_headers, BaseToolInput

logger = logging.getLogger(__name__)

JsonBlob = Dict[str, Any]
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

# retrieve allowed cwes from cwe.mitre.org
CWE_URLS = [
    "https://cwe.mitre.org/data/csv/699.csv.zip",  # development - the only view supported by OSIM
    "https://cwe.mitre.org/data/csv/1000.csv.zip",  # research
    "https://cwe.mitre.org/data/csv/1008.csv.zip",  # architectural
    "https://cwe.mitre.org/data/csv/1081.csv.zip",  # entries with maintenance notes
]

# cache
CACHE_DIR = Path(config_dir) / "mitre_cwe"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
CWE_DEFS_FILE = CACHE_DIR / "cwe_full_defs.json"
CWE_FAISS_INDEX_FILE = CACHE_DIR / "cwe_index.faiss"
CWE_INDEX_MAP_FILE = CACHE_DIR / "cwe_index_map.json"

# In memory cache for search
_cwe_definitions_cache: Optional[Dict[str, Dict]] = None
_faiss_index: Optional[faiss.Index] = None
_index_to_cweid: Optional[List[str]] = None
_embedding_model: Optional[SentenceTransformer] = None


class CWESearchInput(BaseToolInput):
    """Input for searching CWEs with a natural language query."""

    query: str = Field(
        ..., description="The natural language query to search for relevant CWEs."
    )
    top_k: int = Field(
        5, description="The number of top results to return.", gt=0, le=20
    )


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
        description="True if the CWE is not accepted by OSIM.",
    )
    score: Optional[float] = Field(
        None,
        description="Relevance score from similarity search (1.0 is most relevant).",
    )


def _build_and_cache_vector_index(
    cwe_data: Dict[str, Dict],
) -> Tuple[faiss.Index, List[str]]:
    """Builds and caches the FAISS index and ID mapping."""
    logger.info("Building and caching new FAISS vector index...")
    global _embedding_model
    if _embedding_model is None:
        logger.info(f"Loading sentence-transformer model: {EMBEDDING_MODEL}")
        _embedding_model = SentenceTransformer(EMBEDDING_MODEL)

    # Combine text for better embeddings
    corpus = [
        f"{cwe_id}: {details['name']}. {details['description']} {details['extended_description']}"
        for cwe_id, details in cwe_data.items()
    ]
    cwe_ids = list(cwe_data.keys())

    logger.info(
        f"Generating embeddings for {len(corpus)} CWEs. This may take a moment..."
    )
    embeddings = _embedding_model.encode(corpus, show_progress_bar=True)
    embeddings = np.array(embeddings).astype("float32")

    # Build FAISS index
    index = faiss.IndexFlatIP(embeddings.shape[1])  # Inner Product for similarity
    faiss.normalize_L2(embeddings)  # Normalize for cosine similarity
    index.add(embeddings)

    # Cache to disk
    faiss.write_index(index, str(CWE_FAISS_INDEX_FILE))
    with open(CWE_INDEX_MAP_FILE, "w") as f:
        json.dump(cwe_ids, f)

    logger.info("FAISS index built and cached successfully.")
    return index, cwe_ids


def _retrieve_cwe_definitions():
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

    if defs:
        _build_and_cache_vector_index(defs)
    return defs


async def cwe_lookup(cwe_id: CWEID) -> CWE | None:
    """
    Get cwe-id name, description from mitre.

    :param cwe_id:
    :return CWE:
    """
    logger.info(f"retrieving {cwe_id} from cve.mitre.org cwe tool.")
    validated_cwe_id = cweid_validator.validate_python(cwe_id)

    try:
        if os.path.exists(CWE_DEFS_FILE):
            logger.debug(f"Loading data from cwe cached file: {CWE_DEFS_FILE}")
            with open(CWE_DEFS_FILE, "r") as f:
                data = json.load(f)
        else:
            logger.info(f"No cwe cache found. Fetching and writing to: {CWE_DEFS_FILE}")
            data = _retrieve_cwe_definitions()
            with open(CWE_DEFS_FILE, "w") as f:
                json.dump(data, f)

        try:
            cwe = data[validated_cwe_id]
            return CWE(
                cwe_id=validated_cwe_id,
                name=cwe["name"],
                description=cwe["description"],
                extended_description=cwe["extended_description"],
                disallowed=cwe.get("disallowed", False),
            )
        except KeyError:
            # if the CWE is not in our table, mark it as disallowed
            return CWE(
                cwe_id=validated_cwe_id,
                name="UNKNOWN",
                description="UNKNOWN",
                extended_description="UNKNOWN",
                disallowed=True,
                status="not_found",
                error_message="Could not find CWE-ID.",
            )

    except Exception as e:
        logger.error(f"An error occurred: {e}")


async def _get_cwe_search_artefacts() -> Tuple[faiss.Index, List[str], Dict[str, Dict]]:
    """
    Main function to manage loading all necessary data and indexes.
    Loads from memory if available, then disk, otherwise builds from scratch.
    """
    global _cwe_definitions_cache, _faiss_index, _index_to_cweid

    # Load CWE text definitions
    if _cwe_definitions_cache is None:
        if CWE_DEFS_FILE.exists():
            logger.info("Loading CWE definitions from file cache.")
            with open(CWE_DEFS_FILE, "r") as f:
                _cwe_definitions_cache = json.load(f)
        else:
            logger.info("No CWE definitions file found. Fetching from MITRE.")
            _cwe_definitions_cache = _retrieve_cwe_definitions()
            with open(CWE_DEFS_FILE, "w") as f:
                json.dump(_cwe_definitions_cache, f)

    # Load FAISS index & ID map
    if _faiss_index is None or _index_to_cweid is None:
        if CWE_FAISS_INDEX_FILE.exists() and CWE_INDEX_MAP_FILE.exists():
            logger.info("Loading FAISS index from file cache.")
            _faiss_index = faiss.read_index(str(CWE_FAISS_INDEX_FILE))
            with open(CWE_INDEX_MAP_FILE, "r") as f:
                _index_to_cweid = json.load(f)
        else:
            # Build index if it does not exist
            _faiss_index, _index_to_cweid = _build_and_cache_vector_index(
                _cwe_definitions_cache
            )
            with open(CWE_INDEX_MAP_FILE, "w") as f:
                json.dump(_index_to_cweid, f)

    return _faiss_index, _index_to_cweid, _cwe_definitions_cache


@Tool
async def search_cwes(ctx: RunContext, inputs: CWESearchInput) -> List[CWE]:
    """
    Perform semantic search to find most relevant CWEs.
    """
    logger.info(f"Searching for candidate CWEs with query: '{inputs.query}'")
    index, id_map, cwe_defs = await _get_cwe_search_artefacts()

    global _embedding_model
    if _embedding_model is None:  # Ensure model loaded
        _embedding_model = SentenceTransformer(EMBEDDING_MODEL)

    # Vectorize query
    query_vector = _embedding_model.encode([inputs.query.lower()])
    query_vector = np.array(query_vector).astype("float32")
    faiss.normalize_L2(query_vector)

    # Search index
    distances, indices = index.search(query_vector, 3)

    results = []
    for i, idx in enumerate(indices[0]):
        cwe_id = id_map[idx]
        cwe_details = cwe_defs.get(cwe_id)
        if (
            cwe_details and float(distances[0][i]) > 0.53
        ):  # consider only those with score of .5 or higher
            try:
                logger.info(f"matched on {cwe_id} with score: {float(distances[0][i])}")
                results.append(
                    CWE(
                        cwe_id=cwe_id,
                        name=cwe_details["name"],
                        description=cwe_details["description"],
                        extended_description=cwe_details["extended_description"],
                        disallowed=cwe_details["disallowed"],
                        score=float(distances[0][i]),  # Cosine similarity score
                    )
                )
            except Exception as e:
                logger.error(f"An error occurred: {e}")

    return results


@Tool
async def retrieve_allowed_cwe_ids(ctx: RunContext) -> JsonBlob | None:
    """Retrieve all allowed cwe-ids for consideration in analysis."""
    logger.info("retrieving allowed cwe-ids.")

    try:
        if os.path.exists(CWE_INDEX_MAP_FILE):
            logger.debug(f"Loading data from cwe cached file: {CWE_INDEX_MAP_FILE}")
            with open(CWE_INDEX_MAP_FILE, "r") as f:
                data = json.load(f)
        else:
            logger.info(
                f"No cwe cache found. Fetching and writing to: {CWE_INDEX_MAP_FILE}"
            )
            data = _retrieve_cwe_definitions()
            with open(CWE_INDEX_MAP_FILE, "w") as f:
                json.dump(data, f, indent=2)

        return {"allowed_cwe_ids": data}

    except Exception as e:
        logger.error(f"An error occurred: {e}")


@Tool
async def retrieve_all_allowed_cwes(ctx: RunContext) -> JsonBlob | None:
    """Retrieve all allowed cwe-ids for consideration in analysis."""
    logger.info("retrieving all CWE definitions.")

    try:
        if os.path.exists(CWE_DEFS_FILE):
            logger.debug(f"Loading data from cwe cached file: {CWE_DEFS_FILE}")
            with open(CWE_DEFS_FILE, "r") as f:
                data = json.load(f)
        else:
            logger.info(f"No cwe cache found. Fetching and writing to: {CWE_DEFS_FILE}")
            data = _retrieve_cwe_definitions()
            with open(CWE_DEFS_FILE, "w") as f:
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
    tools=[
        search_cwes,
        retrieve_cwes,
        retrieve_allowed_cwe_ids,
        retrieve_all_allowed_cwes,
    ],
)

cwe_toolset = toolset.prefixed("mitre_cwe")
