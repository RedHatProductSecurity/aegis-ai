"""
aegis

"""

import logging
import os
import sys

from pathlib import Path
from typing import Any

from google.genai.types import (
    HarmCategory,
    HarmBlockThreshold,
    SafetySettingDict,
)
from platformdirs import user_config_dir
from functools import lru_cache

import logfire
from dotenv import load_dotenv
from pydantic import Field, model_validator
from pydantic_ai.models import Model
from pydantic_ai.models.anthropic import AnthropicModel, AnthropicModelSettings
from pydantic_ai.models.google import GoogleModel, GoogleModelSettings
from pydantic_settings import BaseSettings

from _pytest._io import TerminalWriter
from _pytest.logging import ColoredLevelFormatter

from pydantic_ai.models.openai import OpenAIChatModel, OpenAIResponsesModelSettings
from pydantic_ai.providers.openai import OpenAIProvider

load_dotenv()

logger = logging.getLogger(__name__)

truthy = (
    "true",
    "1",
    "t",
    "y",
    "yes",
)

try:
    # populated by hatch-vcs at build time
    from ._version import __version__  # type: ignore
except Exception:  # pragma: no cover
    # fallback to Python packaging version
    from importlib.metadata import version as pkg_version

    __version__ = pkg_version(__name__)

# setup aegis configuration
APP_NAME = "aegis_ai"
config_dir = Path(user_config_dir(appname=APP_NAME))
config_dir.mkdir(parents=True, exist_ok=True)


# Ensure console logs include project-relative path and line number
class RelativePathFilter(logging.Filter):
    def __init__(self) -> None:
        super().__init__()
        self._project_root = str(Path(__file__).resolve().parents[2])

    def filter(self, record: logging.LogRecord) -> bool:
        # Resolve project-relative path
        try:
            record.pathname = os.path.relpath(record.pathname, start=self._project_root)
        except (ValueError, OSError):
            # most likely an external dependency
            pass

        # Avoid using basename only in log messages (especially __init__.py is ambiguous)
        record.filename = record.pathname
        return True


class LivenessProbeLogFilter(logging.Filter):
    """skip logging for livenessProbe"""

    def filter(self, record: logging.LogRecord) -> bool:
        # skip logging for livenessProbe
        args = getattr(record, "args", ())
        return args[1:] != ("GET", "/healthz", "1.1", 204)


class AppSettings(BaseSettings):
    app_name: str = APP_NAME
    app_version: str = __version__
    config_dir: str = str(config_dir)
    otel_enabled: bool = os.getenv("AEGIS_OTEL_ENABLED", "false").lower() in truthy

    # Aegis top level agent
    default_llm_host: str = os.getenv("AEGIS_LLM_HOST", "localhost:11434")
    default_llm_model_name: str = os.getenv("AEGIS_LLM_MODEL", "llama3.2:latest")
    default_llm_settings: Any = Field(default_factory=dict)
    default_llm_temperature: float = float(os.getenv("AEGIS_LLM_TEMPERATURE", 0.055))
    default_llm_top_p: float = float(os.getenv("AEGIS_LLM_TOP_P", 0.8))
    default_llm_max_tokens: int = int(os.getenv("AEGIS_LLM_MAX_TOKENS", 16384))

    # Aegis safety subagent
    safety_enabled: bool = os.getenv("AEGIS_SAFETY_ENABLED", "false").lower() in truthy
    safety_llm_host: str = os.getenv("AEGIS_SAFETY_LLM_HOST", "localhost:11434")
    safety_llm_model: str = os.getenv("AEGIS_SAFETY_LLM_MODEL", "granite3-guardian-2b")
    safety_llm_openapi_key: str = os.getenv("AEGIS_SAFETY_OPENAPI_KEY", "")

    # tool flags
    use_tavily_tool: bool = (
        os.getenv("AEGIS_USE_TAVILY_TOOL_CONTEXT", "false") in truthy
    )
    use_cwe_tool: bool = os.getenv("AEGIS_USE_CWE_TOOL_CONTEXT", "true") in truthy
    use_linux_cve_tool: bool = (
        os.getenv("AEGIS_USE_LINUX_CVE_TOOL_CONTEXT", "false") in truthy
    )
    use_github_mcp_tool: bool = (
        os.getenv("AEGIS_USE_GITHUB_MCP_TOOL_CONTEXT", "false") in truthy
    )
    use_wikipedia_mcp_tool: bool = (
        os.getenv("AEGIS_USE_WIKIPEDIA_MCP_CONTEXT", "false") in truthy
    )
    use_pypi_mcp_tool: bool = os.getenv("AEGIS_USE_PYPI_MCP_CONTEXT", "false") in truthy
    use_nvd_dev_tool: bool = (
        os.getenv("AEGIS_USE_MITRE_NVD_MCP_TOOL_CONTEXT", "false") in truthy
    )
    use_cisa_kev_tool: bool = (
        os.getenv("AEGIS_USE_CISA_KEV_TOOL_CONTEXT", "false") in truthy
    )

    # tavily key
    tavily_api_key: str = os.getenv("TAVILY_API_KEY", "   ")

    @model_validator(mode="after")
    def configure_llm_provider_settings(self):
        """
        Populate default_llm_settings immediately after class initialized.
        """
        host = self.default_llm_host

        if "api.anthropic.com" in host:
            self.default_llm_settings = AnthropicModelSettings(
                temperature=self.default_llm_temperature,
                top_p=self.default_llm_top_p,
                max_tokens=self.default_llm_max_tokens,
            )

        elif "generativelanguage.googleapis.com" in host:
            google_safety_settings: list[SafetySettingDict] = [
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
            ]
            self.default_llm_settings = GoogleModelSettings(
                temperature=self.default_llm_temperature,
                top_p=self.default_llm_top_p,
                max_tokens=self.default_llm_max_tokens,
                google_safety_settings=google_safety_settings,
            )
        else:
            # Fallback to OpenAI/Local
            self.default_llm_settings = OpenAIResponsesModelSettings(
                temperature=self.default_llm_temperature,
                top_p=self.default_llm_top_p,
                max_tokens=self.default_llm_max_tokens,
            )
        return self

    @property
    def default_llm_model(self) -> Model:
        """
        Constructs pydantic-ai Model (with no side effects).
        """

        host = self.default_llm_host

        if "api.anthropic.com" in host:
            return AnthropicModel(model_name=self.default_llm_model_name)

        elif "generativelanguage.googleapis.com" in host:
            logger.info(f"model_name: {self.default_llm_model_name}")
            return GoogleModel(model_name=self.default_llm_model_name)

        else:
            return OpenAIChatModel(
                model_name=self.default_llm_model_name,
                provider=OpenAIProvider(base_url=f"{host}/v1/"),
            )


@lru_cache
def get_settings() -> AppSettings:
    """
    Returns cached instance of AppSettings.
    The settings object is only created the first time this is called.
    """
    return AppSettings()


def config_logging(level="INFO"):
    # if set to 'DEBUG' then we want all the http conversation
    if level == "DEBUG":
        import http.client as http_client

        http_client.HTTPConnection.debuglevel = 1

    # suppress noisy INFO messages: AFC is enabled with max remote calls: 10.
    logging.getLogger("google_genai.models").setLevel(logging.WARNING)

    # iterate through the default logger (CLI/pytest) and uvicorn loggers
    for logger_name in (None, "uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(logger_name)
        logger.setLevel(level)

        if not logger.handlers:
            # if no handlers are configured, use the basic logging handler
            handler = logging.StreamHandler()
            logging.basicConfig(level=level, handlers=[handler])

        # avoid duplicated uvicorn log messages
        if logger_name != "uvicorn":
            # Optional log file path: write to one file for root and uvicorn loggers
            log_file_path = os.getenv("AEGIS_LOG_FILE")
            if log_file_path:
                file_handler = logging.FileHandler(log_file_path)
                logger.addHandler(file_handler)

        for handler in logger.handlers:
            # enable colors if connected to a TTY
            tw = TerminalWriter(sys.stderr)
            is_file = isinstance(handler, logging.FileHandler)
            tw.hasmarkup = not is_file and sys.stderr.isatty()

            # use the same format as pytest uses by default
            log_format = (
                "%(asctime)s [%(levelname)s] %(message)s (%(filename)s:%(lineno)s)"
            )
            date_format = "%Y-%m-%d %H:%M:%S"
            formatter = ColoredLevelFormatter(tw, log_format, date_format)
            handler.setFormatter(formatter)

            # Avoid using basename only in log messages (especially __init__.py is ambiguous)
            handler.addFilter(RelativePathFilter())

            # Suppress liveness probe access logs on uvicorn.access
            if logger_name == "uvicorn.access":
                handler.addFilter(LivenessProbeLogFilter())

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
    if get_settings().default_llm_model:
        return True  # TODO - this check needs to compatible across all llm model types
    else:
        logging.warning("llm model health check failed")
        return False
