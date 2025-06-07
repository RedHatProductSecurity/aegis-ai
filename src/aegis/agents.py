"""
aegis agents
"""

from pydantic_ai import Agent
from pydantic_ai.common_tools.duckduckgo import duckduckgo_search_tool

from aegis import (
    default_data_deps,
    default_llm_model,
    llm_model,
)
from aegis.rag.data_models import LLMAnswer
from aegis.rag import rag_lookup, RAGResponse
from aegis.tools import date_lookup
from aegis.tools.wikipedia import wikipedia_lookup

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

component_feature_agent = Agent(
    name="ComponentAgent",
    description="An agent.",
    model=default_llm_model,
    llm=llm_model,
    model_settings={
        "temperature": 0.1,  # Lower temperature for less creative/more direct output
        "top_p": 0.8,
        # "repetition_penalty": 1.05,
        # "stop": ["\n\n", "###", "</s>"],
        "response_format": {"type": "json_object"},
    },
    tools=[date_lookup, wikipedia_lookup],
)

feature_agent = Agent(
    name="FeatureAgent",
    description="An agent.",
    model=default_llm_model,
    llm=llm_model,
    model_settings={
        "temperature": 0.05,  # Lower temperature for less creative/more direct output
        "top_p": 0.8,
        # "repetition_penalty": 1.05,
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

chat_agent = Agent(
    name="ChatAgent",
    description="An agent.",
    model=default_llm_model,
    llm=llm_model,
    tools=[duckduckgo_search_tool()],
    model_settings={
        "temperature": 0.05,  # Lower temperature for less creative/more direct output
        "top_p": 0.8,
        # "repetition_penalty": 1.05,
        # "stop": ["\n\n", "###", "</s>"],
        "response_format": {"type": "json_object"},
    },
)
