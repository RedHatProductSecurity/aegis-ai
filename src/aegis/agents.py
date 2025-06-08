"""
aegis agents
"""

from pydantic_ai import Agent
from pydantic_ai.common_tools.duckduckgo import duckduckgo_search_tool
from pydantic_ai.common_tools.tavily import tavily_search_tool

from aegis import (
    default_data_deps,
    default_llm_model,
    llm_model,
    tavily_api_key,
)
from aegis.features.data_models import AegisAnswer
from aegis.rag import rag_lookup, RAGResponse
from aegis.tools import date_tool
from aegis.tools.wikipedia import wikipedia_tool


base_agent = Agent(
    name="Plain Agent",
    description="An plain agent.",
    deps_type=default_data_deps,
    model=default_llm_model,
    llm=llm_model,
    output_type=AegisAnswer,
    model_settings={
        "temperature": 0.05,
        "top_p": 0.8,
        "response_format": {"type": "json_object"},
    },
)

component_feature_agent = Agent(
    name="ComponentAgent",
    description="An agent.",
    model=default_llm_model,
    llm=llm_model,
    model_settings={
        "temperature": 0.05,
        "top_p": 0.8,
        "response_format": {"type": "json_object"},
    },
    tools=[date_tool, wikipedia_tool],
)

feature_agent = Agent(
    name="FeatureAgent",
    description="An agent.",
    model=default_llm_model,
    llm=llm_model,
    model_settings={
        "temperature": 0.05,
        "top_p": 0.8,
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
        "temperature": 0.05,
        "top_p": 0.8,
        "response_format": {"type": "json_object"},
    },
)

context_agent = Agent(
    name="ContextAgent",
    description="An agent that pulls in all the context.",
    model=default_llm_model,
    llm=llm_model,
    tools=[
        date_tool,
        tavily_search_tool(tavily_api_key),
        duckduckgo_search_tool(),
        wikipedia_tool,
    ],
    model_settings={
        "temperature": 0.05,
        "top_p": 0.8,
        "response_format": {"type": "json_object"},
    },
)
