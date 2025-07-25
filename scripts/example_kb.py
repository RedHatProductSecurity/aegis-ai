import logging

from aegis_ai.agents import kb_agent
from aegis_ai.kb import RagSystem, DocumentInput, FactInput, RAGQuery


async def main():
    # Initialize the RAG system
    rag_system = RagSystem(
        pg_connection_string="postgresql://postgres:password@localhost:5432/aegis",
        embedding_model_name="sentence-transformers/all-MiniLM-L6-v2",
    )
    await rag_system.initialize()

    try:
        # 1. Add documents
        doc_text = "Red Hat announced OpenShift 4.10 with enhanced security features and improved developer experience."
        doc_meta = {"title": "OpenShift 4.10 Announcement", "author": "Red Hat"}
        await rag_system.add_document_to_vector_store(
            DocumentInput(text=doc_text, metadata=doc_meta)
        )

        doc_text = "The capital of France is Paris. Paris is known for its Eiffel Tower and Louvre Museum."
        doc_meta = {
            "source": "Wikipedia",
            "category": "Geography",
            "original_text_length": len(doc_text),
        }
        await rag_system.add_document_to_vector_store(
            DocumentInput(text=doc_text, metadata=doc_meta)
        )

        doc_text = "Python is a high-level, interpreted programming language. It is widely used for web development, data analysis, AI, and more."
        doc_meta = {
            "source": "Programming Guide",
            "category": "Technology",
            "original_text_length": len(doc_text),
        }
        await rag_system.add_document_to_vector_store(
            DocumentInput(text=doc_text, metadata=doc_meta)
        )

        # 2. Add facts
        fact_text = "CVE-2023-1234 is a critical vulnerability affecting OpenSSL."
        fact_metadata = {"source": "NVD", "severity": "Critical"}
        await rag_system.add_fact_to_vector_store(
            FactInput(fact=fact_text, metadata=fact_metadata)
        )

        fact = "Mount Everest is the highest mountain in the world."
        await rag_system.add_fact_to_vector_store(
            FactInput(fact=fact, metadata={"source": "Factbook"})
        )
        fact = "The color of the sky is mostly blue."
        await rag_system.add_fact_to_vector_store(
            FactInput(fact=fact, metadata={"source": "Factbook"})
        )

        # 3. Perform RAG queries
        query_text = "What is the capital of France ?"
        rag_query = RAGQuery(
            query=query_text, top_k_documents=1, top_k_facts=1, additional_context=""
        )

        rag_response = await rag_system.perform_rag_query(rag_query, kb_agent)
        print("---------------------")
        print(query_text)
        print("---------------------")
        print(rag_response)
        print("---------------------")

    finally:
        await rag_system.shutdown()


if __name__ == "__main__":
    import asyncio

    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
