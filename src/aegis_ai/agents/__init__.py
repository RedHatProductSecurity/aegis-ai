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


def create_aegis_agent(**kwargs: Any) -> Agent[Any, Any]:
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
        },
        # pydantic-ai default is 1, which means one internal retry before
        # raising UnexpectedModelBehavior.  With function tools present,
        # Google's API cannot enforce output schemas (no native mode), so
        # the model generates freeform JSON validated only by Pydantic.
        # 3 retries give the model enough feedback rounds to self-correct
        # validation errors (CVSS vector format, Literal fields, etc.).
        output_retries=3,
        **kwargs,
    )


# this object is only used by CLI
simple_agent = create_aegis_agent(
    name="SimpleAgent",
    output_type=AegisAnswer,
)

rh_feature_agent = create_aegis_agent(
    name="RHFeatureAgent",
    tool_retries=agent_default_max_retries,
    toolsets=[redhat_cve_toolset, public_toolset],
)

public_feature_agent = create_aegis_agent(
    name="PublicFeatureAgent",
    tool_retries=agent_default_max_retries,
    toolsets=[public_cve_toolset, public_toolset],
)
