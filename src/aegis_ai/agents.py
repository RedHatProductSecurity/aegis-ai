"""
aegis agents
"""

from typing import Any

from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider

from aegis_ai import get_settings, default_llm_model
from aegis_ai.data_models import SafetyReport
from aegis_ai.features.data_models import AegisAnswer
from aegis_ai.toolsets import public_toolset, public_cve_toolset, redhat_cve_toolset


def create_aegis_agent(**kwargs: Any) -> Agent:
    """
    Factory for a pre-configured `Agent` that mirrors the previous AegisAgent defaults
    without subclassing the (final) `Agent` class.
    """
    return Agent(
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


simple_agent = create_aegis_agent(
    name="SimpleAgent",
    output_type=AegisAnswer,
)


rh_feature_agent = create_aegis_agent(
    name="RHFeatureAgent",
    retries=5,  # FIXME: this should be made configurable, was included as brutish technique for revalidations
    toolsets=[redhat_cve_toolset, public_toolset],
)

rh_public_feature_agent = create_aegis_agent(
    name="RHFeatureAgent",
    retries=5,  # FIXME: this should be made configurable, was included as brutish technique for revalidations
    toolsets=[public_toolset, redhat_cve_toolset],
)

public_feature_agent = create_aegis_agent(
    name="PublicFeatureAgent",
    retries=5,  # FIXME: this should be made configurable, was included as brutish technique for revalidations
    toolsets=[public_toolset, public_cve_toolset],
)

safety_agent = Agent(
    model=OpenAIChatModel(
        model_name=get_settings().safety_llm_model,
        provider=OpenAIProvider(
            base_url=f"{get_settings().safety_llm_host}/v1/",
            api_key=get_settings().safety_llm_openapi_key,
        ),
    ),
    model_settings={
        "seed": 42,
        "response_format": {"type": "json_object"},
    },
    system_prompt=f"""
        You are Granite Guardian, an AI safety and security analyst. Your sole function is to
        analyze a user-submitted prompt and determine if it could lead to harmful, unethical,
        dangerous, or malicious outcomes.
        
        Evaluate the prompt against the following categories of harm:
        - Illegal Acts or Dangerous Activities
        - Hate Speech & Harassment
        - Self-Harm
        - Malicious Code & Cybersecurity Threats
        - Unqualified Professional Advice (medical, legal, financial)
        
        Respond with a JSON object that matches the following SafetyReport schema.
            {SafetyReport.model_json_schema()}
        """,
)
