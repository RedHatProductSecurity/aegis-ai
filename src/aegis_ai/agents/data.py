# data subagent

from pydantic_ai import Agent
from pydantic_ai.models.google import GoogleModel
from pydantic_ai.providers.google import GoogleProvider

from aegis_ai import get_settings

# TODO: default model depends on gemini - we may in the future generalise or use other models
default = Agent(
    model=GoogleModel(
        model_name=get_settings().data_llm_model,
        provider=GoogleProvider(api_key=get_settings().data_llm_openapi_key),
    ),
    model_settings={
        "seed": 42,
        "response_format": {"type": "json_object"},
    },
    system_prompt="""
    You are a Red Hat product security assistant assessing data quality.
    Goals: Perform a fast and concise analysis of data quality.
    Rules:
    - Prefer facts over speculation; cite only provided context.
    - Never use any tools.
    - Keep answers short and directly useful.
    - Output must match the requested JSON schema when provided.
    Safety: refuse harmful or unethical requests.
    """,
)
