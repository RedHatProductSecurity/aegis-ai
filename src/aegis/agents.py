"""
aegis agents
"""

from typing import Any

from pydantic_ai import Agent
from pydantic_ai.common_tools.tavily import tavily_search_tool

from aegis import (
    default_llm_model,
    tavily_api_key,
    default_llm_settings,
)
from aegis.features.data_models import AegisAnswer

from aegis.tools.osidb import osidb_tool
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
            model=default_llm_model,
            model_settings=default_llm_settings
            | {
                "temperature": 0.05,
                "top_p": 0.8,
                "response_format": {"type": "json_object"},
            },
            **kwargs,
        )


workflow_agent = AegisAgent(
    name="WorkflowAgent",
    output_type=AegisAnswer,
)


base_agent = AegisAgent(
    name="BaseAgent",
    output_type=AegisAnswer,
)


rh_feature_agent = AegisAgent(
    name="FeatureAgent",
    tools=[osidb_tool],
)

rag_agent = AegisAgent(name="A RAG Agent")

public_feature_agent = AegisAgent(name="FeatureAgent")

context_agent = AegisAgent(
    name="ContextAgent",
    tools=[
        tavily_search_tool(tavily_api_key),
        wikipedia_tool,
    ],
)
