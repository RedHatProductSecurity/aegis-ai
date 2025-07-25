from typing import List, Dict, Any, Optional

from pydantic import BaseModel, Field


class DocumentInput(BaseModel):
    """Input model for ingesting a document."""

    text: str = Field(..., description="The main text content of the document.")
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Optional metadata for the document."
    )


class FactInput(BaseModel):
    """Input model for ingesting a fact."""

    fact: str = Field(..., description="A concise fact string.")
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Optional metadata for the fact."
    )


class RAGQuery(BaseModel):
    """Input model for a RAG query."""

    query: str = Field(..., description="The user's question or query.")

    additional_context: Optional[str] = Field(
        ..., description="Additional query context."
    )

    top_k_documents: int = Field(
        ..., description="Number of top documents to retrieve."
    )
    top_k_facts: int = Field(..., description="Number of top facts to retrieve.")


class SourceItem(BaseModel):
    """Represents a retrieved source document or fact."""

    content: str = Field(..., description="The content of the retrieved item.")
    source_type: str = Field(
        ..., description="Type of source (e.g., 'document_chunk', 'fact')."
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Metadata associated with the source."
    )
    similarity_score: Optional[float] = Field(
        None, description="Cosine similarity score."
    )


class RAGContext(BaseModel):
    combined_context: str
    sources: List[Optional[SourceItem]] = Field(
        ..., description="A list of relevant source facts or documents or snippets."
    )


class RAGResponse(BaseModel):
    """Response model for a RAG query."""

    answer: str = Field(..., description="The generated answer from the LLM.")

    confidence: float = Field(
        ...,
        description="The confidence number between 0 and 1 relating how confident in the answer (with 1 being 100% confidence and 0 being not confident at all).",
    )
    explanation: str = Field(
        ..., description="The brief rationale explaining the answer."
    )
    # TODO: figure out the mystery here - as in we cannot use SourceItem ?????
    sources: List[str] = Field(
        ...,
        description="A list of relevant source facts or documents or snippets. prepended with Fact: or Document:",
    )
