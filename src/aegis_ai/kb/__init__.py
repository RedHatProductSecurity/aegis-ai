"""
aegis kb (Knowledge Base)


"""

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

import asyncpg
from pgvector.asyncpg import register_vector
from langchain_text_splitters import RecursiveCharacterTextSplitter
from sentence_transformers import SentenceTransformer

from pydantic_ai import (
    Agent,
)

from aegis_ai.kb.data_models import (
    DocumentInput,
    FactInput,
    RAGContext,
    RAGQuery,
    RAGResponse,
    SourceItem,
)

from jinja2 import (
    Environment,
    PackageLoader,
)

env_fs = Environment(loader=PackageLoader("aegis.kb", "."))

logger = logging.getLogger(__name__)

# Environment variables with default values
PG_CONNECTION_STRING = os.getenv(
    "PG_CONNECTION_STRING", "postgresql://postgres:password@localhost:5432/aegis"
)
TOP_K_DOCUMENTS = int(os.getenv("AEGIS_RAG_TOP_K_DOCUMENTS", "2"))
TOP_K_FACTS = int(os.getenv("AEGIS_RAG_TOP_K_FACTS", "2"))
EMBEDDING_MODEL_NAME = os.getenv(
    "AEGIS_RAG_EMBEDDING_MODEL_NAME", "sentence-transformers/all-MiniLM-L6-v2"
)
EMBEDDING_DIMENSION = int(os.getenv("AEGIS_RAG_EMBEDDING_DIMENSION", "384"))
COLLECTION_NAME_DOCUMENTS = os.getenv(
    "AEGIS_RAG_COLLECTION_NAME_DOCUMENTS", "rag_documents"
)
COLLECTION_NAME_FACTS = os.getenv("AEGIS_RAG_COLLECTION_NAME_FACTS", "rag_facts")
SIMILARITY_SCORE_GT: float = float(os.getenv("AEGIS_RAG_SIMILARITY_SCORE_GT", 0.7))
CHUNK_SIZE = int(os.getenv("AEGIS_RAG_CHUNK_SIZE", "1000"))
CHUNK_OVERLAP = int(os.getenv("AEGIS_RAG_CHUNK_OVERLAP", "200"))


@dataclass
class RagDependencies:
    pass


class RagSystem:
    """
    Aegis standalone RAG implementation with functions for adding documents & facts to a vector store,
    and performing RAG queries.
    """

    _db_pool: Optional[asyncpg.Pool] = None
    _embedding_model: Optional[SentenceTransformer] = None

    def __init__(
        self,
        pg_connection_string: str = PG_CONNECTION_STRING,
        top_k_documents: int = TOP_K_DOCUMENTS,
        top_k_facts: int = TOP_K_FACTS,
        embedding_model_name: str = EMBEDDING_MODEL_NAME,
        embedding_dimension: int = EMBEDDING_DIMENSION,
        collection_name_documents: str = COLLECTION_NAME_DOCUMENTS,
        collection_name_facts: str = COLLECTION_NAME_FACTS,
        similarity_score_gt: float = SIMILARITY_SCORE_GT,
        chunk_size: int = CHUNK_SIZE,
        chunk_overlap: int = CHUNK_OVERLAP,
    ):
        """
        Initializes the RagSystem with configuration parameters.
        """
        self._pg_connection_string = pg_connection_string
        self._top_k_documents = top_k_documents
        self._top_k_facts = top_k_facts
        self._embedding_model_name = embedding_model_name
        self._embedding_dimension = embedding_dimension
        self._collection_name_documents = collection_name_documents
        self._collection_name_facts = collection_name_facts
        self._similarity_score_gt = similarity_score_gt
        self._chunk_size = chunk_size
        self._chunk_overlap = chunk_overlap
        self._text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=self._chunk_size,
            chunk_overlap=self._chunk_overlap,
            length_function=len,
        )

    async def initialize(self):
        """
        Initializes the PostgreSQL database connection pool, sets up pgvector,
        and loads the local SentenceTransformer embedding model.
        Creates necessary tables if they do not exist.
        """
        if (
            self.__class__._db_pool is not None
            and self.__class__._embedding_model is not None
        ):
            logger.info("RagSystem already initialized.")
            return

        logger.info("Initializing RagSystem database and embedding model...")
        try:
            self.__class__._db_pool = await asyncpg.create_pool(
                self._pg_connection_string
            )

            async with self.__class__._db_pool.acquire() as conn:
                await conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
                await register_vector(conn)

                await conn.execute(f"""
                    CREATE TABLE IF NOT EXISTS {self._collection_name_documents} (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        content TEXT NOT NULL,
                        content_hash TEXT UNIQUE NOT NULL,
                        metadata JSONB DEFAULT '{{}}'::jsonb,
                        embedding VECTOR({self._embedding_dimension}) NOT NULL
                    );
                """)

                await conn.execute(f"""
                    CREATE TABLE IF NOT EXISTS {self._collection_name_facts} (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        content TEXT NOT NULL,
                        content_hash TEXT UNIQUE NOT NULL,
                        metadata JSONB DEFAULT '{{}}'::jsonb,
                        embedding VECTOR({self._embedding_dimension}) NOT NULL
                    );
                """)

            self.__class__._embedding_model = SentenceTransformer(
                self._embedding_model_name
            )
            logger.info("RagSystem initialization complete.")

        except Exception as e:
            logger.error(f"Error during RagSystem initialization: {e}")
            if self.__class__._db_pool:
                await self.__class__._db_pool.close()
                self.__class__._db_pool = None
            raise

    async def shutdown(self):
        """Closes PostgreSQL database connection pool."""
        if self.__class__._db_pool:
            logger.info("Closing RAG database connection pool...")
            await self.__class__._db_pool.close()
            self.__class__._db_pool = None
            logger.info("RAG database connection pool closed.")
        self.__class__._embedding_model = None  # Clear model reference

    async def _get_db_pool(self) -> asyncpg.Pool:
        """Internal method to get the database connection pool."""
        if self.__class__._db_pool is None:
            raise RuntimeError(
                "Database pool not initialized. Call initialize() first."
            )
        return self.__class__._db_pool

    def _get_embedding_model(self) -> SentenceTransformer:
        """Internal method to get SentenceTransformer embedding model."""
        if self.__class__._embedding_model is None:
            raise RuntimeError(
                "Embedding model not initialized. Call initialize() first."
            )
        return self.__class__._embedding_model

    async def _get_embedding(self, text: str) -> List[float]:
        """
        Generates an embedding vector for the given text using the local SentenceTransformer model.
        This is used for both document/fact ingestion and query embedding.
        """
        model = self._get_embedding_model()
        try:
            embedding_vector = model.encode(text).tolist()
            return embedding_vector
        except Exception as e:
            logger.error(f"Error generating embedding for text: '{text[:50]}...' - {e}")
            raise

    async def add_document_to_vector_store(
        self, doc_input: DocumentInput
    ) -> Dict[str, Any]:
        """
        Processes a document by chunking its text, generating embeddings for each chunk,
        and storing them in the 'rag_documents' table. Prevents exact duplicate chunks.
        """
        pool = await self._get_db_pool()
        chunks = self._text_splitter.split_text(doc_input.text)

        inserted_ids = []
        skipped_count = 0

        async with pool.acquire() as conn:
            for i, chunk in enumerate(chunks):
                chunk_hash = hashlib.sha256(chunk.encode("utf-8")).hexdigest()

                existing_id = await conn.fetchval(
                    f"SELECT id FROM {self._collection_name_documents} WHERE content_hash = $1;",
                    chunk_hash,
                )

                if existing_id:
                    logger.info(
                        f"Skipping duplicate chunk (hash: {chunk_hash[:8]}...) for document '{doc_input.metadata.get('title', 'N/A')}' (chunk index {i})."
                    )
                    skipped_count += 1
                    continue

                try:
                    embedding = await self._get_embedding(chunk)
                    chunk_metadata = {
                        **doc_input.metadata,
                        "chunk_index": i,
                        "original_text_length": len(doc_input.text),
                        "chunk_length": len(chunk),
                        "chunk_hash": chunk_hash,
                    }
                    metadata_json = json.dumps(chunk_metadata)

                    record_id = await conn.fetchval(
                        f"""
                        INSERT INTO {self._collection_name_documents} (content, content_hash, metadata, embedding)
                        VALUES ($1, $2, $3::jsonb, $4)
                        RETURNING id;
                    """,
                        chunk,
                        chunk_hash,
                        metadata_json,
                        embedding,
                    )
                    inserted_ids.append(str(record_id))
                except asyncpg.exceptions.UniqueViolationError:
                    logger.warning(
                        f"Concurrent duplicate insertion detected and skipped for chunk (hash: {chunk_hash[:8]}...)."
                    )
                    skipped_count += 1
                except Exception as e:
                    logger.error(f"Error inserting document chunk into DB: {e}")
                    continue

        return {
            "status": "success",
            "message": f"Document split into {len(chunks)} chunks. {len(inserted_ids)} new chunks stored, {skipped_count} duplicates skipped.",
            "ids": inserted_ids,
        }

    async def add_fact_to_vector_store(self, fact_input: FactInput) -> Dict[str, Any]:
        """
        Generates an embedding for a concise fact and stores it in the 'rag_facts' table.
        Prevents exact duplicate facts.
        """
        pool = await self._get_db_pool()

        fact_hash = hashlib.sha256(fact_input.fact.encode("utf-8")).hexdigest()

        async with pool.acquire() as conn:
            existing_id = await conn.fetchval(
                f"SELECT id FROM {self._collection_name_facts} WHERE content_hash = $1;",
                fact_hash,
            )

            if existing_id:
                logger.info(f"Skipping duplicate fact (hash: {fact_hash[:8]}...).")
                return {
                    "status": "skipped",
                    "message": "Fact already exists.",
                    "id": str(existing_id),
                }

            try:
                embedding = await self._get_embedding(fact_input.fact)
                fact_metadata = {
                    **fact_input.metadata,
                    "fact_hash": fact_hash,
                }
                metadata_json = json.dumps(fact_metadata)

                record_id = await conn.fetchval(
                    f"""
                    INSERT INTO {self._collection_name_facts} (content, content_hash, metadata, embedding)
                    VALUES ($1, $2, $3::jsonb, $4)
                    RETURNING id;
                """,
                    fact_input.fact,
                    fact_hash,
                    metadata_json,
                    embedding,
                )

                return {
                    "status": "success",
                    "message": "Fact stored successfully.",
                    "id": str(record_id),
                }
            except asyncpg.exceptions.UniqueViolationError:
                logger.warning(
                    f"Concurrent duplicate insertion detected and skipped for fact (hash: {fact_hash[:8]}...)."
                )
                return {
                    "status": "skipped",
                    "message": "Fact concurrently inserted and skipped.",
                    "id": None,
                }
            except Exception as e:
                logger.error(f"Error inserting fact into DB: {e}")
                raise

    def _generate_prompt(
        self, context, query: str, additional_context: str = None
    ) -> str:
        """
        Generates the prompt for the RAG agent.
        """

        template = env_fs.get_template("rag_answer_prompt.txt")
        prompt = template.render(
            {
                "context": context.model_dump(),
                "additional_context": additional_context,
                "query": query,
                "schema": RAGResponse.model_json_schema(),
            }
        )
        return prompt

    async def get_rag_context(self, query_input: RAGQuery) -> RAGContext:
        """
        Performs RAG query:
        1. Embeds the user's query.
        2. Retrieves relevant document chunks and facts from the vector store.
        3. Combines them as context.
        """
        pool = await self._get_db_pool()
        query_embedding = await self._get_embedding(query_input.query)

        retrieved_sources: List[Optional[SourceItem]] = []
        context_parts: List[str] = []

        async with pool.acquire() as conn:
            # Retrieve documents
            doc_results = await conn.fetch(
                f"""
                    SELECT content, metadata, 1 - (embedding <=> $1) AS similarity_score
                    FROM {self._collection_name_documents}
                    WHERE 1 - (embedding <=> $1) >= $3
                    ORDER BY embedding <=> $1
                    LIMIT $2;
                """,
                query_embedding,
                query_input.top_k_documents,
                self._similarity_score_gt,
            )

            for record in doc_results:
                parsed_metadata = record["metadata"]
                if isinstance(parsed_metadata, str):
                    try:
                        parsed_metadata = json.loads(parsed_metadata)
                    except json.JSONDecodeError as e:
                        logger.warning(
                            f"Warning: Could not parse document metadata string: {record['metadata']} - {e}"
                        )
                        parsed_metadata = {}

                retrieved_sources.append(
                    SourceItem(
                        content=record["content"],
                        source_type="document_chunk",
                        metadata=parsed_metadata,
                        similarity_score=record["similarity_score"],
                    )
                )
                context_parts.append(f"Document Chunk: {record['content']}")

            # Retrieve facts
            fact_results = await conn.fetch(
                f"""
                SELECT content, metadata, 1 - (embedding <=> $1) AS similarity_score
                FROM {self._collection_name_facts}
                WHERE 1 - (embedding <=> $1) >= $3
                ORDER BY embedding <=> $1
                LIMIT $2;
            """,
                query_embedding,
                query_input.top_k_facts,
                self._similarity_score_gt,
            )

            for record in fact_results:
                parsed_metadata = record["metadata"]
                if isinstance(parsed_metadata, str):
                    try:
                        parsed_metadata = json.loads(parsed_metadata)
                    except json.JSONDecodeError as e:
                        logger.warning(
                            f"Warning: Could not parse fact metadata string: {record['metadata']} - {e}"
                        )
                        parsed_metadata = {}

                retrieved_sources.append(
                    SourceItem(
                        content=record["content"],
                        source_type="fact",
                        metadata=parsed_metadata,
                        similarity_score=record["similarity_score"],
                    )
                )
                context_parts.append(f"Fact: {record['content']}")

        combined_context = " ".join(context_parts)
        return RAGContext(combined_context=combined_context, sources=retrieved_sources)

    async def perform_rag_query(self, query_input: RAGQuery, rag_agent: Agent):
        """
        Performs a full RAG query:
        1. Embeds the user's query.
        2. Retrieves relevant document chunks and facts from the vector store.
        3. Combines them as context.
        4. Uses the RAG Agent to generate a structured answer.
        """
        additional_context = query_input.additional_context
        logger.info(additional_context)
        rag_data = await self.get_rag_context(query_input)
        prompt = self._generate_prompt(
            rag_data, query_input.query, additional_context=additional_context
        )
        logger.debug(prompt)
        return await rag_agent.run(prompt, output_type=RAGResponse)
