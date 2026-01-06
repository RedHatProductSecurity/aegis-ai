# https://cwe.mitre.org/data/downloads.html

import asyncio
import csv
import io
import json
import logging
import os
import re

from math import log
from pathlib import Path
from typing import List, Optional, Dict, Tuple, no_type_check
from zipfile import ZipFile

import aiofiles
import httpx
import numpy as np

from pydantic_ai import Tool, RunContext
from pydantic_ai.toolsets import FunctionToolset
from aegis_ai import get_settings
from aegis_ai.data_models import CWEID, cweid_validator
from aegis_ai.toolsets.tools import default_tool_http_headers
from aegis_ai.toolsets.tools.cwe.data_models import CWESearchInput, CWE, CWEToolInput

logger = logging.getLogger(__name__)

CWE_URLS = [
    "https://cwe.mitre.org/data/csv/699.csv.zip",  # development - the only view supported by OSIM auto-completions
    # "https://cwe.mitre.org/data/csv/1000.csv.zip",  # research
    # "https://cwe.mitre.org/data/csv/1008.csv.zip",  # architectural
    # "https://cwe.mitre.org/data/csv/1081.csv.zip",  # entries with maintenance notes
]

CACHE_DIR = Path(get_settings().config_dir) / "mitre_cwe"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
CWE_DEFS_FILE = CACHE_DIR / "cwe_full_defs.json"
CWE_TFIDF_MATRIX_FILE = CACHE_DIR / "cwe_tfidf.npy"
CWE_VOCAB_FILE = CACHE_DIR / "cwe_vocab.json"
CWE_INDEX_MAP_FILE = CACHE_DIR / "cwe_index_map.json"

# Cosine similarity threshold for TF-IDF retrieval
SIMILARITY_THRESHOLD = 0.12

# Heuristic boosts for common CWE patterns to improve ranking
# fmt: off
KEYWORD_BOOSTS: List[Tuple[re.Pattern[str], str, float]] = [
    (re.compile(r"\buse[- ]?after[- ]?free\b"), "CWE-416", 0.25),
    (re.compile(r"\bnull (pointer|deref\w*)\b"), "CWE-476", 0.2),
    (re.compile(r"\bheap buffer overflow\b|\bout[- ]of[- ]bounds write\b|\boob write\b"), "CWE-787", 0.25),
    (re.compile(r"\bout[- ]of[- ]bounds read\b|\boob read\b"), "CWE-125", 0.2),
    (re.compile(r"\binteger (overflow|wrap|underflow)\b"), "CWE-190", 0.25),
    (re.compile(r"\bdenial[- ]of[- ]service\b|\bDoS\b|\bresource exhaustion\b|\bunbounded\b|\bno (limits|throttling)\b"), "CWE-770", 0.25),
    (re.compile(r"\b(regex|regular expression|catastrophic backtracking|exponential)\b"), "CWE-1333", 0.2),
    (re.compile(r"\bsession fixation\b"), "CWE-613", 0.25),
    (re.compile(r"\bcommand injection\b"), "CWE-78", 0.25),
    (re.compile(r"\bpath traversal\b"), "CWE-22", 0.2),
    (re.compile(r"\bimproper input validation\b"), "CWE-20", 0.15),
    (re.compile(r"\bdouble free\b"), "CWE-415", 0.25),
    (re.compile(r"\brace (condition)?\b"), "CWE-366", 0.2),
    # CWE-825: Expired/Dangling Pointer Dereference
    (re.compile(r"\b(dangling|stale|expired) pointer\b"), "CWE-825", 0.25),
    # CWE-459: Incomplete Cleanup (temp files, leftover artifacts)
    (re.compile(r"\b(incomplete|missing) cleanup\b|\bnot (deleted|removed)\b|\btemporary file\b|\bleft in (/tmp|tmp|temp)\b"), "CWE-459", 0.25),
    # CWE-772: Missing Release of Resource after Effective Lifetime (resource leak)
    (re.compile(r"\b(resource|handle|file|socket|descriptor)\b.*\b(leak|not (freed|released|closed)|missing (free|release|close))\b"), "CWE-772", 0.25),
    # CWE-354: Improper Validation of Integrity Check Value (signature/MAC/checksum not verified)
    (re.compile(r"\b(signature|sig|mac|hmac|checksum|integrity (check|value))\b.*\b(not|missing|skipped|no)\b.*\b(verify|validation|check)\b"), "CWE-354", 0.3),
]
# fmt: on


class CWEManager:
    """
    Manage loading, caching, and querying of CWE data and search indexes.
    """

    @no_type_check
    def __init__(self):
        self._definitions: Optional[Dict[str, Dict]] = None
        # Lightweight TF-IDF artifacts
        self._tfidf_matrix: Optional[np.ndarray] = None  # shape: (num_docs, vocab_size)
        self._idf_vector: Optional[np.ndarray] = None  # shape: (vocab_size,)
        self._vocab: Optional[Dict[str, int]] = None  # token -> column index
        self._index_to_cweid: Optional[List[str]] = None
        self._lock = asyncio.Lock()
        self._is_initialized = False
        self._debug = False

    async def _fetch_and_parse_cwe_data(self) -> Dict[str, Dict]:
        """Fetch CWE CSVs from MITRE, parse em, and return dict."""
        defs = {}
        async with httpx.AsyncClient(
            timeout=10, headers=default_tool_http_headers
        ) as client:
            for idx, url in enumerate(CWE_URLS):
                # The first URL (699) is the source of truth for allowed CWEs
                cwe_699_view = not idx

                try:
                    logger.info(f"Fetching CWE definitions from '{url}'...")
                    response = await client.get(url)
                    response.raise_for_status()

                    zip_file = ZipFile(io.BytesIO(response.content))

                    for file_name in zip_file.namelist():
                        contents = zip_file.read(file_name).decode("utf-8")
                        reader = csv.reader(io.StringIO(contents))
                        next(reader)  # Skip header

                        for line in reader:
                            cwe_id = f"CWE-{line[0]}"
                            if cwe_id not in defs:
                                defs[cwe_id] = {
                                    "name": line[1],
                                    "description": line[4],
                                    "extended_description": line[5],
                                    "affected_resources": line[19],
                                    "notes": line[22],
                                    "disallowed": not cwe_699_view,
                                }
                            elif cwe_699_view:
                                logger.warning(
                                    f"CWE redefinition in CWE-699 view: {cwe_id}"
                                )
                except httpx.HTTPError as e:
                    logger.error(f"Failed to retrieve CWEs from {url}: {e}")
        return defs

    @no_type_check
    async def _build_tfidf_index(
        self, cwe_data: Dict[str, Dict]
    ) -> Tuple[np.ndarray, np.ndarray, Dict[str, int], List[str]]:
        """Build/cache a TF-IDF matrix from CWE data (pure NumPy)."""
        logger.info("Building and caching new TF-IDF index...")

        def normalize(text: str) -> str:
            return text.lower()

        def tokenize(text: str) -> List[str]:
            return re.findall(r"[a-z0-9]+", text)

        # Compose corpus texts and ids
        corpus_texts: List[str] = []
        cwe_ids: List[str] = []
        for cwe_id, details in cwe_data.items():
            text = f"{cwe_id} {details.get('name', '')} {details.get('description', '')} {details.get('extended_description', '')}"
            corpus_texts.append(normalize(text))
            cwe_ids.append(cwe_id)

        # Build vocab
        vocab: Dict[str, int] = {}
        docs_tokens: List[List[str]] = []
        for text in corpus_texts:
            tokens = tokenize(text)
            docs_tokens.append(tokens)
            for tok in tokens:
                if tok not in vocab:
                    vocab[tok] = len(vocab)

        vocab_size = len(vocab)
        num_docs = len(docs_tokens)
        if self._debug:
            logger.debug(f"TF-IDF vocab size={vocab_size}, docs={num_docs}")

        # Term frequency (log-scaled)
        tf_matrix = np.zeros((num_docs, vocab_size), dtype=np.float32)
        df_counts = np.zeros(vocab_size, dtype=np.int32)
        for di, tokens in enumerate(docs_tokens):
            if not tokens:
                continue
            counts: Dict[int, int] = {}
            for tok in tokens:
                ti = vocab[tok]
                counts[ti] = counts.get(ti, 0) + 1
            for ti, cnt in counts.items():
                tf_matrix[di, ti] = 1.0 + log(cnt)
                df_counts[ti] += 1

        # Inverse document frequency (smoothed)
        idf = np.log((1.0 + num_docs) / (1.0 + df_counts.astype(np.float32))) + 1.0

        # TF-IDF and L2 normalize rows
        tfidf = tf_matrix * idf
        norms = np.linalg.norm(tfidf, axis=1, keepdims=True)
        norms[norms == 0.0] = 1.0
        tfidf = tfidf / norms

        # Persist artifacts
        await asyncio.gather(
            asyncio.to_thread(np.save, str(CWE_TFIDF_MATRIX_FILE), tfidf),
            write_json_async(CWE_VOCAB_FILE, vocab),
            write_json_async(CWE_INDEX_MAP_FILE, cwe_ids),
        )

        logger.info(f"TF-IDF index built and cached at '{CACHE_DIR}'.")
        return tfidf, idf, vocab, cwe_ids

    @no_type_check
    async def initialize(self):
        """
        Initializes the manager by loading all necessary data from cache or by building it from scratch.
        This method is safe to call multiple times; it should only run its logic once.
        """
        async with self._lock:
            if self._is_initialized:
                return

            self._debug = logger.isEnabledFor(logging.DEBUG)

            if CWE_DEFS_FILE.exists():
                logger.info(f"Loading CWE definitions from '{CWE_DEFS_FILE}'.")
                self._definitions = await read_json_async(CWE_DEFS_FILE)
            else:
                logger.info("No CWE definitions file found. Fetching from MITRE.")
                self._definitions = await self._fetch_and_parse_cwe_data()
                logger.info(f"Writing CWE definitions to '{CWE_DEFS_FILE}'.")
                await write_json_async(CWE_DEFS_FILE, self._definitions)

            if (
                CWE_TFIDF_MATRIX_FILE.exists()
                and CWE_VOCAB_FILE.exists()
                and CWE_INDEX_MAP_FILE.exists()
            ):
                logger.info(f"Loading TF-IDF index from '{CACHE_DIR}'.")
                self._tfidf_matrix = await asyncio.to_thread(
                    np.load, str(CWE_TFIDF_MATRIX_FILE)
                )
                self._vocab = await read_json_async(CWE_VOCAB_FILE)
                self._index_to_cweid = await read_json_async(CWE_INDEX_MAP_FILE)
                # Reconstruct IDF vector from matrix sparsity as an approximation
                # (exact DF not stored; this is sufficient for ranking stability)
                nonzero = (self._tfidf_matrix > 0).astype(np.int32)
                df_counts = nonzero.sum(axis=0)
                num_docs = self._tfidf_matrix.shape[0]
                self._idf_vector = np.log((1.0 + num_docs) / (1.0 + df_counts)) + 1.0
            else:
                (
                    self._tfidf_matrix,
                    self._idf_vector,
                    self._vocab,
                    self._index_to_cweid,
                ) = await self._build_tfidf_index(self._definitions)

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
            affected_resources="UNKNOWN",
            notes="UNKNOWN",
            disallowed=True,
            score=0.0,
        )

    @no_type_check
    async def search_cwes(self, query: str, top_k: int = 12) -> List[CWE]:
        """Perform lightweight TF-IDF cosine-similarity search for CWEs."""
        if (
            self._tfidf_matrix is None
            or self._idf_vector is None
            or self._vocab is None
            or not self._index_to_cweid
            or not self._definitions
        ):
            logger.error("Search artifacts not loaded. Please initialize the manager.")
            return []

        # Tokenize and build query TF-IDF vector
        def tokenize(text: str) -> List[str]:
            return re.findall(r"[a-z0-9]+", text.lower())

        tokens = tokenize(query)
        if not tokens:
            return []

        vocab = self._vocab
        counts: Dict[int, int] = {}
        for tok in tokens:
            if tok in vocab:
                ti = vocab[tok]
                counts[ti] = counts.get(ti, 0) + 1

        if not counts:
            return []

        q_vec = np.zeros(self._idf_vector.shape[0], dtype=np.float32)
        for ti, cnt in counts.items():
            q_vec[ti] = 1.0 + log(cnt)
        q_vec *= self._idf_vector
        norm = np.linalg.norm(q_vec)
        if norm > 0:
            q_vec = q_vec / norm

        sims = self._tfidf_matrix @ q_vec  # cosine similarity

        # Heuristic boosts for common CWE patterns to improve ranking
        boosts: Dict[int, float] = {}
        for pattern, cwe_id, boost in KEYWORD_BOOSTS:
            if pattern.search(query):
                try:
                    idx = self._index_to_cweid.index(cwe_id)
                except ValueError:
                    continue
                boosts[idx] = max(boosts.get(idx, 0.0), boost)
        if boosts:
            sims = sims.copy()
            for idx, add in boosts.items():
                sims[idx] += add
        k = min(top_k, sims.shape[0])
        if k <= 0:
            return []
        top_idx = np.argpartition(-sims, kth=k - 1)[:k]
        top_idx = top_idx[np.argsort(-sims[top_idx])]

        results: List[CWE] = []
        for idx in top_idx:
            score = float(sims[idx])
            if score < SIMILARITY_THRESHOLD:
                continue
            cwe_id = self._index_to_cweid[idx]
            cwe_details = self._definitions.get(cwe_id)
            if cwe_details and not cwe_details["disallowed"]:
                logger.debug(f"Matched on allowed {cwe_id} with score: {score:.4f}")
                results.append(CWE(cwe_id=cwe_id, score=score, **cwe_details))
        return results

    def get_allowed_cwe_ids(self) -> List[CWEID]:
        """Return list of all allowed CWE IDs from in-memory cache."""

        cwe_tool_allowed_cwe_ids = os.getenv("AEGIS_CWE_TOOL_ALLOWED_CWE_IDS", "")
        if cwe_tool_allowed_cwe_ids:
            return cwe_tool_allowed_cwe_ids.split(",")
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

    # log initiation of the search (debug only)
    query = inputs.query.lower().replace("-", " ")
    logger.debug(f"Searching for candidate CWEs with query: '{query}'")

    result = await cwe_manager.search_cwes(query)

    # log the search query and the resulting CWE list
    cwe_list = [cwe.cwe_id for cwe in result]
    logger.info(f"search_cwes(query='{query}') = {cwe_list}")

    return result


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
