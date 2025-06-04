"""
Aegis standalone RAG implementation with functions for adding documents and facts to vector store.

"""

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

import asyncpg

from pydantic_ai import Agent, RunContext, Tool

from pgvector.asyncpg import register_vector

from langchain_text_splitters import RecursiveCharacterTextSplitter
from sentence_transformers import SentenceTransformer

from aegis.rag.data_models import (
    DocumentInput,
    FactInput,
    RAGQuery,
    RAGResponse,
    SourceItem,
    LLMAnswer,
    RAGContext,
)

logger = logging.getLogger(__name__)

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

_db_pool: Optional[asyncpg.Pool] = None
_embedding_model: Optional[SentenceTransformer] = None  # local embedding model instance


@dataclass
class RagDependencies:
    test = 1


async def get_db_pool() -> asyncpg.Pool:
    """Return global db connection pool."""
    if _db_pool is None:
        raise RuntimeError(
            "Database pool not initialized. Call initialize_rag_db first."
        )
    return _db_pool


def get_embedding_model() -> SentenceTransformer:
    """Returns the global SentenceTransformer embedding model."""
    if _embedding_model is None:
        raise RuntimeError(
            "Embedding model not initialized. Call initialize_rag_db first."
        )
    return _embedding_model


async def initialize_rag_db(conn_string: str = PG_CONNECTION_STRING):
    """
    Initializes pg database connection pool, sets up pgvector,
    and loads the local SentenceTransformer embedding model.
    Creates necessary tables if they do not exist.
    """
    global _db_pool, _embedding_model
    logger.info("init pgvector for RAG")
    try:
        _db_pool = await asyncpg.create_pool(conn_string)

        async with _db_pool.acquire() as conn:
            await conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
            await register_vector(conn)

            # Modified documents table to include a hash column
            await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {COLLECTION_NAME_DOCUMENTS} (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    content TEXT NOT NULL,
                    content_hash TEXT UNIQUE NOT NULL, -- New: Hash for duplicate detection
                    metadata JSONB DEFAULT '{{}}'::jsonb,
                    embedding VECTOR({EMBEDDING_DIMENSION}) NOT NULL
                );
            """)

            # Modified facts table to include a hash column
            await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {COLLECTION_NAME_FACTS} (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    content TEXT NOT NULL,
                    content_hash TEXT UNIQUE NOT NULL, -- New: Hash for duplicate detection
                    metadata JSONB DEFAULT '{{}}'::jsonb,
                    embedding VECTOR({EMBEDDING_DIMENSION}) NOT NULL
                );
            """)

        _embedding_model = SentenceTransformer(EMBEDDING_MODEL_NAME)

    except Exception as e:
        print(f"Error during RAG database initialization: {e}")
        if _db_pool:
            await _db_pool.close()
        raise


async def shutdown_rag_db():
    """Closes the PostgreSQL database connection pool."""
    global _db_pool
    if _db_pool:
        print("Closing RAG database connection pool...")
        await _db_pool.close()
        _db_pool = None
        print("RAG database connection pool closed.")


async def _get_embedding(text: str) -> List[float]:
    """
    Generates an embedding vector for the given text using the local SentenceTransformer model.
    This is used for both document/fact ingestion and query embedding.
    """
    model = get_embedding_model()
    try:
        # SentenceTransformer encode method returns a numpy array, convert to list
        embedding_vector = model.encode(text).tolist()
        return embedding_vector
    except Exception as e:
        print(f"Error generating embedding for text: '{text[:50]}...' - {e}")
        raise


async def add_document_to_vector_store(doc_input: DocumentInput) -> Dict[str, Any]:
    """
    Processes a document by chunking its text, generating embeddings for each chunk,
    and storing them in the 'rag_documents' table. Prevents exact duplicate chunks.
    """
    pool = await get_db_pool()
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
        length_function=len,
    )
    chunks = text_splitter.split_text(doc_input.text)

    inserted_ids = []
    skipped_count = 0

    async with pool.acquire() as conn:
        for i, chunk in enumerate(chunks):
            # Calculate content hash for duplicate detection
            chunk_hash = hashlib.sha256(chunk.encode("utf-8")).hexdigest()

            # Check if this chunk (by hash) already exists
            existing_id = await conn.fetchval(
                f"SELECT id FROM {COLLECTION_NAME_DOCUMENTS} WHERE content_hash = $1;",
                chunk_hash,
            )

            if existing_id:
                print(
                    f"Skipping duplicate chunk (hash: {chunk_hash[:8]}...) for document '{doc_input.metadata.get('title', 'N/A')}' (chunk index {i})."
                )
                skipped_count += 1
                continue  # Skip to the next chunk

            try:
                embedding = await _get_embedding(chunk)
                chunk_metadata = {
                    **doc_input.metadata,
                    "chunk_index": i,
                    "original_text_length": len(doc_input.text),
                    "chunk_length": len(chunk),
                    "chunk_hash": chunk_hash,  # Also store hash in metadata for traceability
                }
                metadata_json = json.dumps(chunk_metadata)

                record_id = await conn.fetchval(
                    f"""
                    INSERT INTO {COLLECTION_NAME_DOCUMENTS} (content, content_hash, metadata, embedding)
                    VALUES ($1, $2, $3::jsonb, $4)
                    RETURNING id;
                """,
                    chunk,
                    chunk_hash,  # Insert the hash
                    metadata_json,
                    embedding,
                )
                inserted_ids.append(str(record_id))
            except asyncpg.exceptions.UniqueViolationError:
                # This could happen if two concurrent processes try to insert the same chunk
                print(
                    f"Concurrent duplicate insertion detected and skipped for chunk (hash: {chunk_hash[:8]}...)."
                )
                skipped_count += 1
            except Exception as e:
                print(f"Error inserting document chunk into DB: {e}")
                continue

    return {
        "status": "success",
        "message": f"Document split into {len(chunks)} chunks. {len(inserted_ids)} new chunks stored, {skipped_count} duplicates skipped.",
        "ids": inserted_ids,
    }


async def add_fact_to_vector_store(fact_input: FactInput) -> Dict[str, Any]:
    """
    Generates an embedding for a concise fact and stores it in the 'rag_facts' table.
    Prevents exact duplicate facts.
    """
    pool = await get_db_pool()

    # Calculate content hash for duplicate detection
    fact_hash = hashlib.sha256(fact_input.fact.encode("utf-8")).hexdigest()

    async with pool.acquire() as conn:
        # Check if this fact (by hash) already exists
        existing_id = await conn.fetchval(
            f"SELECT id FROM {COLLECTION_NAME_FACTS} WHERE content_hash = $1;",
            fact_hash,
        )

        if existing_id:
            print(f"Skipping duplicate fact (hash: {fact_hash[:8]}...).")
            return {
                "status": "skipped",
                "message": "Fact already exists.",
                "id": str(existing_id),
            }

        try:
            embedding = await _get_embedding(fact_input.fact)
            fact_metadata = {
                **fact_input.metadata,
                "fact_hash": fact_hash,  # Also store hash in metadata for traceability
            }
            metadata_json = json.dumps(fact_metadata)

            record_id = await conn.fetchval(
                f"""
                INSERT INTO {COLLECTION_NAME_FACTS} (content, content_hash, metadata, embedding)
                VALUES ($1, $2, $3::jsonb, $4)
                RETURNING id;
            """,
                fact_input.fact,
                fact_hash,  # Insert the hash
                metadata_json,
                embedding,
            )

            return {
                "status": "success",
                "message": "Fact stored successfully.",
                "id": str(record_id),
            }
        except asyncpg.exceptions.UniqueViolationError:
            print(
                f"Concurrent duplicate insertion detected and skipped for fact (hash: {fact_hash[:8]}...)."
            )
            # In a concurrent scenario, another process might have just inserted it
            # We can try to fetch the ID if we really need it, but for now, just acknowledge skipped
            return {
                "status": "skipped",
                "message": "Fact concurrently inserted and skipped.",
                "id": None,  # Or fetch the existing ID if critical
            }
        except Exception as e:
            print(f"Error inserting fact into DB: {e}")
            raise


def generate_prompt(context: str, query: str) -> str:
    prompt = f"""
    You are a Red Hat Product security analyst. Your task is to answer the user's question precisely
    using provided context. If the information needed to answer is not present
    in the context, you MUST state that you do not have enough information from the context.
    Do NOT make up information. Do not invent information.
    
    If the answer includes special charecters or ' do not get confused.

    Context:
    {context}

    Question: {query}

    Ensure your answer is comprehensive and directly addresses the user's question. Summarise
    the answer if supplied by context, in the answer section.
    
    """
    return prompt


async def get_rag_context(query_input: RAGQuery) -> RAGContext:
    """
    Performs RAG query:
    1. Embeds the user's query.
    2. Retrieves relevant document chunks and facts from the vector store.
    3. Combines them as context.
    """
    pool = await get_db_pool()
    query_embedding = await _get_embedding(query_input.query)

    retrieved_sources: List[SourceItem] = []
    context_parts: List[str] = []

    async with pool.acquire() as conn:
        # Retrieve documents
        doc_results = await conn.fetch(
            f"""
                SELECT content, metadata, 1 - (embedding <=> $1) AS similarity_score
                FROM {COLLECTION_NAME_DOCUMENTS} 
                WHERE 1 - (embedding <=> $1) >= $3
                ORDER BY embedding <=> $1  -- This orders by closest match (smallest distance)
                LIMIT $2;                  -- This limits to top K
            """,
            query_embedding,
            query_input.top_k_documents,
            SIMILARITY_SCORE_GT,
        )
        for record in doc_results:
            # FIX 1: Ensure metadata is a dictionary for Pydantic validation
            parsed_metadata = record["metadata"]
            if isinstance(parsed_metadata, str):
                try:
                    parsed_metadata = json.loads(parsed_metadata)
                except json.JSONDecodeError as e:
                    print(
                        f"Warning: Could not parse document metadata string: {record['metadata']} - {e}"
                    )
                    parsed_metadata = {}  # Fallback

            retrieved_sources.append(
                SourceItem(
                    content=record["content"],
                    source_type="document_chunk",
                    metadata=parsed_metadata,  # Use the parsed dictionary
                    similarity_score=record["similarity_score"],
                )
            )
            context_parts.append(f"Document Chunk: {record['content']}")

        # Retrieve facts
        fact_results = await conn.fetch(
            f"""
            SELECT content, metadata, 1 - (embedding <=> $1) AS similarity_score
            FROM {COLLECTION_NAME_FACTS} 
            WHERE 1 - (embedding <=> $1) >= $3
            ORDER BY embedding <=> $1 
            LIMIT $2;
        """,
            query_embedding,
            query_input.top_k_facts,
            SIMILARITY_SCORE_GT,
        )

        for record in fact_results:
            # FIX 1: Ensure metadata is a dictionary for Pydantic validation
            parsed_metadata = record["metadata"]
            if isinstance(parsed_metadata, str):
                try:
                    parsed_metadata = json.loads(parsed_metadata)
                except json.JSONDecodeError as e:
                    print(
                        f"Warning: Could not parse fact metadata string: {record['metadata']} - {e}"
                    )
                    parsed_metadata = {}  # Fallback

            retrieved_sources.append(
                SourceItem(
                    content=record["content"],
                    source_type="fact",
                    metadata=parsed_metadata,  # Use the parsed dictionary
                    similarity_score=record["similarity_score"],
                )
            )
            context_parts.append(f"Fact: {record['content']}")

    combined_context = " ".join(context_parts)
    return RAGContext(combined_context=combined_context, source_items=retrieved_sources)


@Tool
async def rag_lookup(ctx: RunContext[RagDependencies], query: RAGQuery) -> RAGContext:
    """
    Performs RAG query:
    1. Embeds the user's query.
    2. Retrieves relevant document chunks and facts from the vector store.
    3. returns context and sources.
    """
    try:
        rag_data = await get_rag_context(query)
        return rag_data
    except Exception as e:
        print(f"we encountered an error {e}")
        return RAGContext(combined_context="n/a", source_items=[])


async def perform_rag_query(query_input: RAGQuery, rag_agent: Agent) -> RAGResponse:
    """
    Performs RAG query:
    1. Embeds the user's query.
    2. Retrieves relevant document chunks and facts from the vector store.
    3. Combines them as context.
    4. Uses the RAG Agent to generate a structured answer.
    """

    rag_data = await get_rag_context(query_input)
    logger.debug(rag_data)
    prompt = generate_prompt(rag_data.combined_context, query_input.query)
    llm_answer = await rag_agent.run(prompt)
    llm_structured_answer = llm_answer.output

    return RAGResponse(
        answer=llm_structured_answer.answer,
        confidence=llm_structured_answer.confidence,
        explanation=llm_structured_answer.explanation,
        sources=rag_data.source_items,
    )
