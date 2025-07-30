"""
aegis agents
"""

from typing import Any

from pydantic_ai import Agent

from aegis_ai import (
    default_llm_model,
    default_llm_settings,
)
from aegis_ai.features.data_models import AegisAnswer
from aegis_ai.tools.osidb import osidb_tool
from aegis_ai.toolsets import public_toolset


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
                "temperature": 0.055,
                "top_p": 0.8,
                "seed": 42,
                "response_format": {"type": "json_object"},
            },
            **kwargs,
        )


simple_agent = AegisAgent(
    name="SimpleAgent",
    output_type=AegisAnswer,
)


rh_feature_agent = AegisAgent(name="RHFeatureAgent", tools=[osidb_tool])


public_feature_agent = AegisAgent(
    name="PublicFeatureAgent",
    toolsets=[public_toolset],
)

kb_agent = AegisAgent(name="KBAgent")
