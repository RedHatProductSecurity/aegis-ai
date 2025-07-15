"""
aegis

"""

import datetime
from dataclasses import dataclass, field
import logging
import os

from dotenv import load_dotenv
from pydantic_ai.models.anthropic import AnthropicModel, AnthropicModelSettings
from pydantic_ai.models.gemini import GeminiModel, GeminiModelSettings

from rich.logging import RichHandler

from pydantic_ai.models.openai import OpenAIModel, OpenAIResponsesModelSettings
from pydantic_ai.providers.openai import OpenAIProvider

load_dotenv()

logger = logging.getLogger("aegis")

logger.info("starting aegis")

__version__ = "0.1.0"

llm_host = os.getenv("AEGIS_LLM_HOST", "localhost:11434")
llm_model = os.getenv("AEGIS_LLM_MODEL", "llama3.2:latest")

tavily_api_key = os.getenv("TAVILY_API_KEY", "   ")

# Simple logic for defining default model (TODO: we will make more sophisticated).
if "api.anthropic.com" in llm_host:
    default_llm_model = AnthropicModel(model_name=llm_model)
    default_llm_settings = AnthropicModelSettings()
elif "generativelanguage.googleapis.com" in llm_host:
    default_llm_model = GeminiModel(model_name=llm_model)
    default_llm_settings = GeminiModelSettings(
        gemini_thinking_config={"include_thoughts": True}
    )
else:
    default_llm_model = OpenAIModel(
        model_name=llm_model,
        provider=OpenAIProvider(base_url=f"{llm_host}/v1/"),
    )
    default_llm_settings = OpenAIResponsesModelSettings(
        openai_reasoning_effort="low",
        openai_reasoning_summary="detailed",
    )


@dataclass
class default_data_deps:
    """
    A dataclass to hold default data dependencies, including a dynamically
    generated current datetime string.
    """

    current_dt: str = field(
        default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )


def config_logging(level="INFO"):
    # if set to 'DEBUG' then we want all the http conversation
    if level == "DEBUG":
        import http.client as http_client

        http_client.HTTPConnection.debuglevel = 1

    message_format = "%(asctime)s %(name)s %(levelname)s %(message)s"
    logging.basicConfig(
        level=level, format=message_format, datefmt="[%X]", handlers=[RichHandler()]
    )


def check_llm_status() -> bool:
    """
    Check operational status of an LLM model
    """
    if default_llm_model:
        return True  # TODO - this check needs to compatible across all llm model types
    else:
        logging.warn("llm model health check failed")
        return False
