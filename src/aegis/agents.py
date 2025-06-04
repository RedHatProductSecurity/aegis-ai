"""
aegis agents
"""

from pydantic_ai import Agent

from aegis import (
    default_data_deps,
    default_llm_model,
    llm_model,
)
from aegis.rag.data_models import LLMAnswer
from aegis.rag import rag_lookup, RAGResponse

feature_agent = Agent(
    name="PlainAgent",
    description="An agent.",
    model=default_llm_model,
    llm=llm_model,
    model_settings={
        "temperature": 0.0,  # Lower temperature for less creative/more direct output
        "top_p": 0.8,
        # "repetition_penalty": 1.05,
        # "stop": ["\n\n", "###", "</s>"],
        "response_format": {"type": "json_object"},
    },
)

base_agent = Agent(
    name="A RAG Agent",
    description="An agent for Retrieval-Augmented Generation.",
    deps_type=default_data_deps,
    model=default_llm_model,
    llm=llm_model,
    output_type=LLMAnswer,
    model_settings={
        "temperature": 0.0,  # Lower temperature for less creative/more direct output
        "top_p": 0.8,
        # "repetition_penalty": 1.0,
        # "stop": ["\n\n", "###", "</s>"],
        "response_format": {"type": "json_object"},
    },
)

rag_agent = Agent(
    name="A RAG Agent",
    description="An agent for Retrieval-Augmented Generation.",
    deps_type=default_data_deps,
    model=default_llm_model,
    llm=llm_model,
    tools=[rag_lookup],
    output_type=RAGResponse,
    model_settings={
        "temperature": 0.0,  # Lower temperature for less creative/more direct output
        "top_p": 0.8,
        # "repetition_penalty": 1.0,
        # "stop": ["\n\n", "###", "</s>"],
        "response_format": {"type": "json_object"},
    },
)
