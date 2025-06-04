# --- Example Usage (for testing/demonstration) ---
from dotenv import load_dotenv

import asyncio

from aegis.agents import base_agent
from aegis import default_llm_model
from aegis.rag import (
    initialize_rag_db,
    add_document_to_vector_store,
    DocumentInput,
    add_fact_to_vector_store,
    FactInput,
    perform_rag_query,
    shutdown_rag_db,
    RAGQuery,
    TOP_K_FACTS,
    TOP_K_DOCUMENTS,
)

load_dotenv()


# import logging
# logging.basicConfig(level=logging.DEBUG,
#                     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
#
async def load_facts():
    # 2. Ingest some documents
    print("\n--- Ingesting Documents ---")
    doc1_text = "The capital of France is Paris. Paris is known for its Eiffel Tower and Louvre Museum."
    doc1_meta = {
        "source": "Wikipedia",
        "category": "Geography",
        "original_text_length": len(doc1_text),
    }
    await add_document_to_vector_store(
        DocumentInput(text=doc1_text, metadata=doc1_meta)
    )

    doc2_text = "Python is a high-level, interpreted programming language. It is widely used for web development, data analysis, AI, and more."
    doc2_meta = {
        "source": "Programming Guide",
        "category": "Technology",
        "original_text_length": len(doc2_text),
    }
    await add_document_to_vector_store(
        DocumentInput(text=doc2_text, metadata=doc2_meta)
    )

    # 3. Ingest some facts
    print("\n--- Ingesting Facts ---")
    fact1 = "Mount Everest is the highest mountain in the world."
    await add_fact_to_vector_store(
        FactInput(fact=fact1, metadata={"source": "Factbook"})
    )
    fact1 = "The color of the sky is mostly blue."
    await add_fact_to_vector_store(
        FactInput(fact=fact1, metadata={"source": "Factbook"})
    )

    # Give some time for embeddings to be generated and stored (especially if it's the first time model loads)
    await asyncio.sleep(2)


async def _main():
    """
    Example of how to use the RAG library functions and SentenceTransformers (for embeddings/ingestion).
    """

    try:
        # 1. Initialize the database and components
        await initialize_rag_db()
        await load_facts()

        # 4. Perform RAG queries
        print("\n--- Performing RAG Queries ---")

        queries = [
            "What is the capital of France and what is it known for?",
            "Tell me about Python programming language.",
            "What color is Marek car ?",
        ]

        rag_agent = base_agent
        rag_agent.model = default_llm_model
        for query in queries:
            response = await perform_rag_query(
                RAGQuery(
                    query=query,
                    top_k_facts=TOP_K_FACTS,
                    top_k_documents=TOP_K_DOCUMENTS,
                ),
                rag_agent,
            )
            print(
                "\n--------------------------------------------------------------------------------"
            )

            print(f"\nQuery: {query}")
            # print(response)
            print(f"Answer: {response.answer}")
            print(f"Confidence: {response.confidence}")
            print(f"Explanation: {response.explanation}")
            print("Sources:")
            for source in response.sources:
                print(
                    f"  - [{source.source_type} - Score: {source.similarity_score:.2f}] {source.content[:70]}..."
                )

    except Exception as e:
        print(f"An error occurred in _main: {e}")
    finally:
        # 5. Shutdown the database pool
        await shutdown_rag_db()


if __name__ == "__main__":
    asyncio.run(_main())
