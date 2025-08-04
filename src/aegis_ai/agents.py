"""
aegis agents
"""

from typing import Any

from pydantic_ai import Agent

from aegis_ai import get_settings, default_llm_model
from aegis_ai.features.data_models import AegisAnswer
from aegis_ai.tools.cwe import cwe_tool
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
            model_settings=get_settings().default_llm_settings
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


rh_feature_agent = AegisAgent(
    name="RHFeatureAgent",
    retries=2,  # FIXME: this should be made configurable, was included as brutish technique for revalidations
    tools=[osidb_tool, cwe_tool],
)


public_feature_agent = AegisAgent(
    name="PublicFeatureAgent",
    retries=5,  # FIXME: this should be made configurable, was included as brutish technique for revalidations
    toolsets=[public_toolset],
)
