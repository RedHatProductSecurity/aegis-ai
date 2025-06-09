"""
aegis agents
"""

from typing import Any

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

from aegis.tools import date_tool
from aegis.tools.wikipedia import wikipedia_tool


class AegisAgent(Agent):
    """
    AegisAgent: A specialized pydantic-ai Agent.
    """

    def __init__(
        self,
        **kwargs: Any,
    ):
        super().__init__(
            deps=default_data_deps,
            llm=llm_model,
            model=default_llm_model,
            model_settings={
                "temperature": 0.05,
                "top_p": 0.8,
                "response_format": {"type": "json_object"},
            },
            **kwargs,
        )


base_agent = AegisAgent(
    name="Plain Agent",
    description="An plain agent.",
    output_type=AegisAnswer,
)

feature_agent = AegisAgent(
    name="FeatureAgent",
    description="An agent.",
)

rag_agent = AegisAgent(
    name="A RAG Agent",
    description="An agent for Retrieval-Augmented Generation.",
)

context_agent = AegisAgent(
    name="ContextAgent",
    description="An agent that pulls in all the context.",
    tools=[
        date_tool,
        tavily_search_tool(tavily_api_key),
        duckduckgo_search_tool(),
        wikipedia_tool,
    ],
)
