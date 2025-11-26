from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel, OpenAIResponsesModelSettings
from pydantic_ai.providers.openai import OpenAIProvider

from aegis_ai import get_settings
from aegis_ai.data_models import SafetyReport

default = Agent(
    model=OpenAIChatModel(
        model_name=get_settings().safety_llm_model,
        provider=OpenAIProvider(
            base_url=f"{get_settings().safety_llm_host}/v1/",
            api_key=get_settings().safety_llm_openapi_key,
            http_client=get_settings()._get_http_client(),
        ),
    ),
    model_settings=OpenAIResponsesModelSettings(
        seed=42,  # FIXME: we should not hardcode the seed
    ),
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
