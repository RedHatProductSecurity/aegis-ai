# https://cwe.mitre.org/data/downloads.html

import asyncio
import csv
import io
import json
import logging
from pathlib import Path
from typing import List, Optional, Dict, Tuple, no_type_check
from zipfile import ZipFile

import aiofiles
import faiss
import httpx
import numpy as np
from sentence_transformers import SentenceTransformer

from pydantic_ai import Tool, RunContext
from pydantic_ai.toolsets import FunctionToolset
from aegis_ai import config_dir
from aegis_ai.data_models import CWEID, cweid_validator
from aegis_ai.tools import default_tool_http_headers
from aegis_ai.tools.cwe.data_models import CWESearchInput, CWE, CWEToolInput

logger = logging.getLogger(__name__)

CWE_URLS = [
    "https://cwe.mitre.org/data/csv/699.csv.zip",  # development - the only view supported by OSIM auto-completions
    # "https://cwe.mitre.org/data/csv/1000.csv.zip",  # research
    # "https://cwe.mitre.org/data/csv/1008.csv.zip",  # architectural
    # "https://cwe.mitre.org/data/csv/1081.csv.zip",  # entries with maintenance notes
]

EMBEDDING_MODEL = "all-mpnet-base-v2"
CACHE_DIR = Path(config_dir) / "mitre_cwe"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
CWE_DEFS_FILE = CACHE_DIR / "cwe_full_defs.json"
CWE_FAISS_INDEX_FILE = CACHE_DIR / "cwe_index.faiss"
CWE_INDEX_MAP_FILE = CACHE_DIR / "cwe_index_map.json"

# Semantic search similarity score threshold
SIMILARITY_THRESHOLD = 0.45


class CWEManager:
    """
    Manage loading, caching, and querying of CWE data and search indexes.
    """

    @no_type_check
    def __init__(self):
        self._definitions: Optional[Dict[str, Dict]] = None
        self._faiss_index: Optional[faiss.Index] = None
        self._index_to_cweid: Optional[List[str]] = None
        self._embedding_model: Optional[SentenceTransformer] = None
        self._lock = asyncio.Lock()
        self._is_initialized = False

    async def _load_embedding_model(self):
        """Load SentenceTransformer model if not loaded."""
        if self._embedding_model is None:
            logger.info(f"Loading sentence-transformer model: {EMBEDDING_MODEL}")
            self._embedding_model = await asyncio.to_thread(
                SentenceTransformer, EMBEDDING_MODEL
            )

    async def _fetch_and_parse_cwe_data(self) -> Dict[str, Dict]:
        """Fetch CWE CSVs from MITRE, parse em, and return dict."""
        defs = {}
        async with httpx.AsyncClient(
            timeout=10, headers=default_tool_http_headers
        ) as client:
            for i, url in enumerate(CWE_URLS):
                try:
                    logger.info(f"Fetching CWE definitions from {url}...")
                    response = await client.get(url)
                    response.raise_for_status()

                    is_primary_view = i == 0
                    zip_file = ZipFile(io.BytesIO(response.content))

                    for file_name in zip_file.namelist():
                        contents = zip_file.read(file_name).decode("utf-8")
                        reader = csv.reader(io.StringIO(contents))
                        next(reader)  # Skip header

                        for line in reader:
                            cwe_id = f"CWE-{line[0]}"
                            # The first URL (699) is the source of truth for allowed CWEs
                            if cwe_id in defs and is_primary_view:
                                logger.warning(
                                    f"CWE redefinition in primary view for {cwe_id}"
                                )
                                continue
                            disallowed = not is_primary_view
                            if cwe_id not in defs:
                                if not disallowed:
                                    defs[cwe_id] = {
                                        "name": line[1],
                                        "description": line[4],
                                        "extended_description": line[5],
                                        "affected_resources": line[19],
                                        "notes": line[22],
                                        "disallowed": not is_primary_view,
                                    }
                except httpx.HTTPError as e:
                    logger.error(f"Failed to retrieve CWEs from {url}: {e}")
        return defs

    @no_type_check
    async def _build_vector_index(
        self, cwe_data: Dict[str, Dict]
    ) -> Tuple[faiss.Index, List[str]]:
        """Build/cache FAISS index from CWE data."""
        logger.info("Building and caching new FAISS vector index...")
        await self._load_embedding_model()

        corpus = [
            f"{cwe_id}: {details['name'].lower()}. {details['description'].lower()} {details['extended_description'].lower()}"
            for cwe_id, details in cwe_data.items()
        ]
        cwe_ids = list(cwe_data.keys())

        logger.info(
            f"Generating embeddings for {len(corpus)} CWEs. This may take a moment..."
        )

        embeddings = await asyncio.to_thread(
            self._embedding_model.encode, corpus, show_progress_bar=True
        )
        embeddings = np.array(embeddings).astype("float32")
        faiss.normalize_L2(embeddings)

        index = faiss.IndexFlatIP(embeddings.shape[1])
        index.add(embeddings)

        await asyncio.gather(
            asyncio.to_thread(faiss.write_index, index, str(CWE_FAISS_INDEX_FILE)),
            write_json_async(CWE_INDEX_MAP_FILE, cwe_ids),
        )

        logger.info("FAISS index built and cached successfully.")
        return index, cwe_ids

    @no_type_check
    async def initialize(self):
        """
        Initializes the manager by loading all necessary data from cache or by building it from scratch.
        This method is safe to call multiple times; it should only run its logic once.
        """
        async with self._lock:
            if self._is_initialized:
                return

            await self._load_embedding_model()

            if CWE_DEFS_FILE.exists():
                logger.info("Loading CWE definitions from file cache.")
                self._definitions = await read_json_async(CWE_DEFS_FILE)
            else:
                logger.info("No CWE definitions file found. Fetching from MITRE.")
                self._definitions = await self._fetch_and_parse_cwe_data()
                await write_json_async(CWE_DEFS_FILE, self._definitions)

            if CWE_FAISS_INDEX_FILE.exists() and CWE_INDEX_MAP_FILE.exists():
                logger.info("Loading FAISS index from file cache.")
                self._faiss_index = await asyncio.to_thread(
                    faiss.read_index, str(CWE_FAISS_INDEX_FILE)
                )
                self._index_to_cweid = await read_json_async(CWE_INDEX_MAP_FILE)
            else:
                (
                    self._faiss_index,
                    self._index_to_cweid,
                ) = await self._build_vector_index(self._definitions)

            self._is_initialized = True

    async def lookup_cwe(self, cwe_id: str) -> CWE | None:
        """Look up single CWE by its ID from in-memory cache."""
        validated_cwe_id = cweid_validator.validate_python(cwe_id)

        if not self._definitions:
            logger.error("CWE definitions not loaded. Please initialize the manager.")
            return None

        cwe_data = self._definitions.get(validated_cwe_id)
        if cwe_data:
            return CWE(cwe_id=validated_cwe_id, **cwe_data)

        return CWE(
            cwe_id=validated_cwe_id,
            name="UNKNOWN",
            description="UNKNOWN",
            extended_description="UNKNOWN",
            disallowed=True,
            status="not_found",
            error_message="Could not find CWE-ID.",
        )

    @no_type_check
    async def search_cwes(self, query: str, top_k: int = 8) -> List[CWE]:
        """Perform semantic search for CWEs using in-memory index."""
        if (
            not self._faiss_index
            or not self._embedding_model
            or not self._index_to_cweid
            or not self._definitions
        ):
            logger.error("Search artifacts not loaded. Please initialize the manager.")
            return []

        query_vector = await asyncio.to_thread(
            self._embedding_model.encode, [query.lower()]
        )
        query_vector = np.array(query_vector).astype("float32")
        faiss.normalize_L2(query_vector)

        distances, indices = await asyncio.to_thread(
            self._faiss_index.search, query_vector, top_k
        )

        results = []
        for i, idx in enumerate(indices[0]):
            score = float(distances[0][i])
            if score > SIMILARITY_THRESHOLD:
                cwe_id = self._index_to_cweid[idx]
                cwe_details = self._definitions.get(cwe_id)
                if cwe_details and not cwe_details["disallowed"]:
                    logger.info(f"Matched on allowed {cwe_id} with score: {score:.4f}")
                    results.append(CWE(cwe_id=cwe_id, score=score, **cwe_details))
        return results

    def get_allowed_cwe_ids(self) -> List[CWEID]:
        """Returnlist of all allowed CWE IDs from in-memory cache."""
        if not self._definitions:
            logger.error("CWE definitions not loaded. Please initialize the manager.")
            return []
        return [
            cwe_id
            for cwe_id, details in self._definitions.items()
            if not details.get("disallowed")
        ]


# these are aiofiles helper funcs
async def read_json_async(path: Path) -> Dict | List:
    async with aiofiles.open(path, "r", encoding="utf-8") as f:
        return json.loads(await f.read())


async def write_json_async(path: Path, data: Dict | List):
    async with aiofiles.open(path, "w", encoding="utf-8") as f:
        await f.write(json.dumps(data, indent=2))


# Init the manager
cwe_manager = CWEManager()


@Tool
async def search_cwes(ctx: RunContext, inputs: CWESearchInput) -> List[CWE]:
    """Perform semantic search to find the most relevant CWEs based on a query."""
    await cwe_manager.initialize()  # Ensures data is loaded, but only runs once
    logger.info(
        f"Searching for candidate CWEs with query: '{inputs.query.lower().replace('-', ' ')}'"
    )
    return await cwe_manager.search_cwes(inputs.query.lower().replace("-", " "))


@Tool
async def retrieve_cwes(ctx: RunContext, inputs: CWEToolInput) -> List[CWE]:
    """Look up CWE definitions by IDs."""
    await cwe_manager.initialize()
    logger.info(f"Retrieving definitions for CWEs: {inputs.cwe_ids}")

    tasks = [cwe_manager.lookup_cwe(cwe_id) for cwe_id in inputs.cwe_ids]
    results = await asyncio.gather(*tasks)

    return [cwe for cwe in results if cwe and not cwe.disallowed]


@Tool
async def retrieve_allowed_cwe_ids(ctx: RunContext) -> List[CWEID]:
    """Retrieve list of allowed CWE IDs."""
    await cwe_manager.initialize()
    logger.info("Retrieving all allowed CWE-IDs.")
    return cwe_manager.get_allowed_cwe_ids()


toolset = FunctionToolset(
    tools=[search_cwes, retrieve_cwes, retrieve_allowed_cwe_ids],
)

cwe_toolset = toolset.prefixed("mitre_cwe")
