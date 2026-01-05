"""
aegis agents
"""

from typing import Any

from pydantic_ai import Agent

from aegis_ai import get_env_int, get_settings
from aegis_ai.features.data_models import AegisAnswer
from aegis_ai.toolsets import (
    public_toolset,
    public_cve_toolset,
    redhat_cve_toolset,
)

agent_default_max_retries = get_env_int("AEGIS_AGENT_MAX_RETRIES", 5)


def create_aegis_agent(**kwargs: Any) -> Agent:
    """
    Factory for a pre-configured `Agent` that mirrors the previous AegisAgent defaults
    without subclassing the (final) `Agent` class.
    """
    return Agent(
        model=get_settings().default_llm_model,
        model_settings=get_settings().default_llm_settings
        | get_settings().model_kwargs
        | {
            "seed": 42,  # FIXME: we should not hardcode the seed
            "response_format": {"type": "json_object"},
        },
        **kwargs,
    )


# this object is only used by CLI
simple_agent = create_aegis_agent(
    name="SimpleAgent",
    output_type=AegisAnswer,
)

rh_feature_agent = create_aegis_agent(
    name="RHFeatureAgent",
    retries=agent_default_max_retries,
    toolsets=[redhat_cve_toolset, public_toolset],
)

public_feature_agent = create_aegis_agent(
    name="PublicFeatureAgent",
    retries=agent_default_max_retries,
    toolsets=[public_cve_toolset, public_toolset],
)
