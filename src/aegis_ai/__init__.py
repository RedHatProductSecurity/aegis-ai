"""
aegis

"""

import datetime
import logging
import os
import sys

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict

from google.genai.types import HarmCategory, HarmBlockThreshold
from platformdirs import user_config_dir
from functools import lru_cache

import logfire
from dotenv import load_dotenv
from pydantic_ai.models.anthropic import AnthropicModel, AnthropicModelSettings
from pydantic_ai.models.google import GoogleModel, GoogleModelSettings
from pydantic_settings import BaseSettings

from _pytest._io import TerminalWriter
from _pytest.logging import ColoredLevelFormatter

from pydantic_ai.models.openai import OpenAIChatModel, OpenAIResponsesModelSettings
from pydantic_ai.providers.openai import OpenAIProvider

load_dotenv()

logger = logging.getLogger(__name__)

try:
    # populated by hatch-vcs at build time
    from ._version import __version__  # type: ignore
except Exception:  # pragma: no cover
    # fallback to Python packaging version
    from importlib.metadata import version as pkg_version

    __version__ = pkg_version(__name__)


llm_host = os.getenv("AEGIS_LLM_HOST", "localhost:11434")
llm_model = os.getenv("AEGIS_LLM_MODEL", "llama3.2:latest")

tavily_api_key = os.getenv(
    "TAVILY_API_KEY", "   "
)  # we do not want to persist in appsettings

# Simple logic for defining default model (TODO: we will make more sophisticated).
if "api.anthropic.com" in llm_host:
    default_llm_model = AnthropicModel(model_name=llm_model)
    default_llm_settings = AnthropicModelSettings()
elif "generativelanguage.googleapis.com" in llm_host:
    default_llm_model = GoogleModel(model_name=llm_model)
    default_llm_settings = GoogleModelSettings(
        google_thinking_config={"include_thoughts": False},
        google_safety_settings=[
            {
                "category": HarmCategory.HARM_CATEGORY_HARASSMENT,
                "threshold": HarmBlockThreshold.BLOCK_LOW_AND_ABOVE,
            },
            {
                "category": HarmCategory.HARM_CATEGORY_HATE_SPEECH,
                "threshold": HarmBlockThreshold.BLOCK_LOW_AND_ABOVE,
            },
            {
                "category": HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
                "threshold": HarmBlockThreshold.BLOCK_LOW_AND_ABOVE,
            },
            {
                "category": HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
                "threshold": HarmBlockThreshold.BLOCK_ONLY_HIGH,
            },
        ],
    )
else:
    default_llm_model = OpenAIChatModel(
        model_name=llm_model,
        provider=OpenAIProvider(base_url=f"{llm_host}/v1/"),
    )
    default_llm_settings = OpenAIResponsesModelSettings()

# aegis app settings
APP_NAME = "aegis_ai"
config_dir = Path(user_config_dir(appname=APP_NAME))
config_dir.mkdir(parents=True, exist_ok=True)

truthy = (
    "true",
    "1",
    "t",
    "y",
    "yes",
)

# tool flags
use_tavily_tool = os.getenv("AEGIS_USE_TAVILY_TOOL_CONTEXT", "false")
use_cwe_tool = os.getenv("AEGIS_USE_CWE_TOOL_CONTEXT", "true")
use_linux_cve_tool = os.getenv("AEGIS_USE_LINUX_CVE_TOOL_CONTEXT", "false")
use_github_mcp_tool = os.getenv("AEGIS_USE_GITHUB_MCP_TOOL_CONTEXT", "false")
use_wikipedia_mcp_tool = os.getenv("AEGIS_USE_WIKIPEDIA_MCP_CONTEXT", "false")
use_pypi_mcp_tool = os.getenv("AEGIS_USE_PYPI_MCP_CONTEXT", "false")
use_nvd_dev_tool = os.getenv("AEGIS_USE_MITRE_NVD_MCP_TOOL_CONTEXT", "false")
use_cisa_kev_tool = os.getenv("AEGIS_USE_CISA_KEV_TOOL_CONTEXT", "false")


class AppSettings(BaseSettings):
    default_llm_host: str = llm_host
    default_llm_model: str = llm_model
    default_llm_settings: Dict = default_llm_settings

    otel_enabled: bool = os.getenv("AEGIS_OTEL_ENABLED", "false").lower() in truthy

    # enables prompt.is_safe() usage
    safety_enabled: bool = os.getenv("AEGIS_SAFETY_ENABLED", "false").lower() in truthy

    safety_llm_host: str = os.getenv("AEGIS_SAFETY_LLM_HOST", "localhost:11434")
    safety_llm_model: str = os.getenv("AEGIS_SAFETY_LLM_MODEL", "granite3-guardian-2b")
    safety_llm_openapi_key: str = os.getenv("AEGIS_SAFETY_OPENAPI_KEY", "")


@dataclass
class default_data_deps:
    """
    A dataclass to hold default data dependencies, including a dynamically
    generated current datetime string.
    """

    current_dt: str = field(
        default_factory=lambda: datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )


@lru_cache
def get_settings() -> AppSettings:
    """
    Returns a cached instance of the AppSettings.
    The settings object is only created the first time this is called.
    """
    return AppSettings()


def config_logging(level="INFO"):
    # if set to 'DEBUG' then we want all the http conversation
    if level == "DEBUG":
        import http.client as http_client

        http_client.HTTPConnection.debuglevel = 1

    # iterate through the default logger (CLI/pytest) and unicorn loggers
    for logger_name in (None, "uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(logger_name)
        logger.setLevel(level)

        if not logger.handlers:
            # if no handlers are configured, use the basic logging handler
            handler = logging.StreamHandler()
            logging.basicConfig(level=level, handlers=[handler])

        for handler in logger.handlers:
            # write to stderr, enable colors if connected to a TTY
            tw = TerminalWriter(sys.stderr)
            tw.hasmarkup = sys.stderr.isatty()

            # use the same format as pytest uses by default
            log_format = (
                "%(asctime)s [%(levelname)s] %(message)s (%(filename)s:%(lineno)s)"
            )
            date_format = "%Y-%m-%d %H:%M:%S"
            formatter = ColoredLevelFormatter(tw, log_format, date_format)
            handler.setFormatter(formatter)

    # Log startup message after handlers are configured so DEBUG is visible when enabled
    logger.debug(f"starting aegis-{__version__}")

    if get_settings().otel_enabled:
        logfire.configure(send_to_logfire=False)
        logfire.instrument_pydantic_ai(event_mode="logs")
        logfire.instrument_pydantic_ai()
        logfire.instrument_httpx(capture_all=True)


def check_llm_status() -> bool:
    """
    Check operational status of an LLM model
    """
    if default_llm_model:
        return True  # TODO - this check needs to compatible across all llm model types
    else:
        logging.warning("llm model health check failed")
        return False
