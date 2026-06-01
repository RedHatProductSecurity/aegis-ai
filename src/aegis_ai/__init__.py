"""
aegis

"""

import httpx
import logging
import os
import sys
import warnings
from urllib.parse import urlparse

from pathlib import Path
from typing import Dict, List, Any, Optional, TypedDict

from platformdirs import user_config_dir
from functools import lru_cache

from dotenv import load_dotenv
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings

from _pytest._io import TerminalWriter
from _pytest.logging import ColoredLevelFormatter

# google-genai uses typing._UnionGenericAlias (deprecated in 3.14, removal 3.17); filter before any google.genai import
warnings.filterwarnings(
    "ignore",
    message=r".*'_UnionGenericAlias' is deprecated.*",
    category=DeprecationWarning,
    module=r"google\.genai\.types",
)

load_dotenv()

logger = logging.getLogger(__name__)

try:
    # populated by hatch-vcs at build time
    from ._version import __version__
except Exception:  # pragma: no cover
    # fallback to Python packaging version
    from importlib.metadata import version as pkg_version

    __version__ = pkg_version(__name__)

# setup aegis configuration
APP_NAME = "aegis_ai"
config_dir = Path(user_config_dir(appname=APP_NAME))
config_dir.mkdir(parents=True, exist_ok=True)


def get_env_flag(key: str, default: bool) -> bool:
    """Return True if the value of env var "key" is interpreted as True.
    Return "default" if env var "key" is not defined.
    Otherwise return False."""
    value = os.getenv(key)
    if value is None:
        return default

    truthy = (
        "true",
        "1",
        "t",
        "y",
        "yes",
    )

    return value.strip().lower() in truthy


def get_env_float(key: str, default: float) -> float:
    """Return a float if the value of env var "key" can be interpreted as float.
    Return "default" if env var "key" is not defined.
    Otherwise throw a ValueError exception."""
    value = os.getenv(key)
    return default if value is None else float(value)


def get_env_int(key: str, default: int) -> int:
    """Return an int if the value of env var "key" can be interpreted as int.
    Return "default" if env var "key" is not defined.
    Otherwise throw a ValueError exception."""
    value = os.getenv(key)
    return default if value is None else int(value)


def _llm_base_url_hostname(host: str) -> Optional[str]:
    """Return the hostname from ``AEGIS_LLM_HOST`` for provider selection.

    Values may be ``host:port`` or a full URL. Prepends ``https://`` when no
    scheme is present so the host/port parses as netloc (not as a path).
    Use structured hostname comparison instead of substring checks on the
    raw string (see CodeQL py/incomplete-url-substring-sanitization).
    """
    raw = host.strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = f"https://{raw}"
    return urlparse(raw).hostname


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


class SuppressThirdPartyTracebackFilter(logging.Filter):
    """
    Remove exception tracebacks from selected third-party loggers (Kerberos/GSSAPI)
    when not at DEBUG level. Those libraries log ERROR with exc_info=True, which
    floods operator logs during expected missing-credential scenarios.
    """

    _LOGGER_PREFIXES = ("requests_gssapi", "gssapi")

    def __init__(self, show_tracebacks: bool) -> None:
        super().__init__()
        self._show_tracebacks = show_tracebacks

    def filter(self, record: logging.LogRecord) -> bool:
        if self._show_tracebacks or not record.exc_info:
            return True
        name = record.name
        if any(
            name == prefix or name.startswith(prefix + ".")
            for prefix in self._LOGGER_PREFIXES
        ):
            record.exc_info = None
            record.exc_text = None
            record.stack_info = None
        return True


class _ProviderKwargs(TypedDict):
    """named args of AI Providers"""

    http_client: httpx.AsyncClient


class AppSettings(BaseSettings):
    app_name: str = APP_NAME
    app_version: str = __version__
    config_dir: str = str(config_dir)
    otel_enabled: bool = get_env_flag("AEGIS_OTEL_ENABLED", False)

    # Aegis top level agent
    default_llm_host: str = os.getenv("AEGIS_LLM_HOST", "localhost:11434")
    default_llm_model_name: str = os.getenv("AEGIS_LLM_MODEL", "llama3.2:latest")
    default_llm_settings: Any = Field(default_factory=dict)
    default_llm_temperature: float = get_env_float("AEGIS_LLM_TEMPERATURE", 0.055)
    default_llm_top_p: float = get_env_float("AEGIS_LLM_TOP_P", 0.8)
    default_llm_max_tokens: int = get_env_int("AEGIS_LLM_MAX_TOKENS", 0)
    default_llm_prompt_timeout: int = get_env_int("AEGIS_LLM_TIMEOUT_SECS", 300)
    llm_max_jobs: int = get_env_int("AEGIS_LLM_MAX_JOBS", 4)

    # Aegis safety subagent
    safety_enabled: bool = get_env_flag("AEGIS_SAFETY_ENABLED", False)
    safety_llm_host: str = os.getenv("AEGIS_SAFETY_LLM_HOST", "localhost:11434")
    safety_llm_model: str = os.getenv("AEGIS_SAFETY_LLM_MODEL", "granite3-guardian-2b")
    safety_llm_openapi_key: str = os.getenv("AEGIS_SAFETY_OPENAPI_KEY", "")

    # tool flags
    use_tavily_tool: bool = get_env_flag("AEGIS_USE_TAVILY_TOOL_CONTEXT", False)
    use_cwe_tool: bool = get_env_flag("AEGIS_USE_CWE_TOOL_CONTEXT", True)
    use_linux_cve_tool: bool = get_env_flag("AEGIS_USE_LINUX_CVE_TOOL_CONTEXT", False)
    use_github_mcp_tool: bool = get_env_flag("AEGIS_USE_GITHUB_MCP_TOOL_CONTEXT", False)
    use_wikipedia_tool: bool = get_env_flag("AEGIS_USE_WIKIPEDIA_TOOL_CONTEXT", False)
    use_wikipedia_mcp_tool: bool = get_env_flag(
        "AEGIS_USE_WIKIPEDIA_MCP_CONTEXT", False
    )
    use_pypi_mcp_tool: bool = get_env_flag("AEGIS_USE_PYPI_MCP_CONTEXT", False)
    use_nvd_dev_tool: bool = get_env_flag("AEGIS_USE_MITRE_NVD_MCP_TOOL_CONTEXT", False)
    use_cisa_kev_tool: bool = get_env_flag("AEGIS_USE_CISA_KEV_TOOL_CONTEXT", False)
    use_external_references_tool: bool = get_env_flag(
        "AEGIS_USE_EXT_REFS_TOOL_CONTEXT", False
    )

    # Enables the kernel-specific XGBoost impact classifier for Linux kernel CVEs.
    # When true, kernel CVEs are routed through the patch-feature pipeline before
    # the LLM reasoning step.  Requires AEGIS_KERNEL_CLASSIFIER_DIR or the
    # co-located aegis_ai_ml source tree to be present.
    use_kernel_classifier: bool = get_env_flag("AEGIS_USE_KERNEL_CLASSIFIER", False)

    # tavily key
    tavily_api_key: str = os.getenv("TAVILY_API_KEY", "   ")

    # OSIDB
    osidb_server_url: str = os.getenv(
        "AEGIS_OSIDB_SERVER_URL", "https://localhost:8000"
    )

    # shared kwargs for model settings usage across the codebase
    model_kwargs: Dict[str, Any] = Field(default_factory=dict)

    # customized httpx.AsyncClient with enhanced logging
    http_client: Optional[httpx.AsyncClient] = Field(
        default=None, exclude=True, repr=False
    )

    def _get_http_client(self) -> httpx.AsyncClient:
        """customized httpx.AsyncClient with enhanced logging"""
        if self.http_client is None:
            # create the object only once
            async def _log_request(request: httpx.Request) -> None:
                msg = f'HTTP Request: {request.method} {request.url} "sending request"'
                logger.debug(msg)

            # Use a generous timeout so providers that map HTTP timeouts to
            # model deadlines (e.g., Gemini) do not end up with a too-short
            # deadline (below 10s).
            timeout = max(self.default_llm_prompt_timeout, 10)

            self.http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(timeout),
                event_hooks={"request": [_log_request]},
            )

        return self.http_client

    @model_validator(mode="after")
    def configure_llm_provider_settings(self):
        """
        Populate default_llm_settings immediately after class initialized.
        """
        host = self.default_llm_host
        llm_hostname = _llm_base_url_hostname(host)

        self.model_kwargs: Dict[str, Any] = {
            "temperature": self.default_llm_temperature,
            "top_p": self.default_llm_top_p,
        }

        # only override the max_tokens settings when a value is provided in env
        if self.default_llm_max_tokens != 0:
            self.model_kwargs["max_tokens"] = self.default_llm_max_tokens

        if llm_hostname == "api.anthropic.com":
            from pydantic_ai.models.anthropic import AnthropicModelSettings

            self.default_llm_settings = AnthropicModelSettings(**self.model_kwargs)

        elif llm_hostname == "generativelanguage.googleapis.com":
            # lazy import of modules to speed up Aegis CLI
            from pydantic_ai.models.google import GoogleModelSettings
            from google.genai.types import (
                HarmCategory,
                HarmBlockThreshold,
                SafetySettingDict,
            )

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
                google_thinking_config={"include_thoughts": False},
                google_safety_settings=google_safety_settings,
                **self.model_kwargs,
            )
        else:
            # Fallback to OpenAI/Local
            from pydantic_ai.models.openai import OpenAIResponsesModelSettings

            self.default_llm_settings = OpenAIResponsesModelSettings(
                **self.model_kwargs
            )

        # eagerly create the shared HTTP client to avoid race on first use
        _ = self._get_http_client()

        return self

    @property
    def default_llm_model(self):
        """
        Constructs pydantic-ai Model (with no side effects).
        """

        host = self.default_llm_host
        llm_hostname = _llm_base_url_hostname(host)

        provider_kwargs: _ProviderKwargs = {
            "http_client": self._get_http_client(),
        }

        if llm_hostname == "api.anthropic.com":
            from pydantic_ai.models.anthropic import AnthropicModel
            from pydantic_ai.providers.anthropic import AnthropicProvider

            return AnthropicModel(
                model_name=self.default_llm_model_name,
                provider=AnthropicProvider(**provider_kwargs),
            )

        elif llm_hostname == "generativelanguage.googleapis.com":
            logger.info(f"model_name: {self.default_llm_model_name}")
            from pydantic_ai.models.google import GoogleModel
            from pydantic_ai.providers.google import GoogleProvider

            return GoogleModel(
                model_name=self.default_llm_model_name,
                provider=GoogleProvider(**provider_kwargs),
            )

        else:
            from pydantic_ai.models.openai import OpenAIChatModel
            from pydantic_ai.providers.openai import OpenAIProvider

            return OpenAIChatModel(
                model_name=self.default_llm_model_name,
                provider=OpenAIProvider(base_url=f"{host}/v1/", **provider_kwargs),
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
            handler.addFilter(
                SuppressThirdPartyTracebackFilter(show_tracebacks=(level == "DEBUG"))
            )

            # Suppress liveness probe access logs on uvicorn.access
            if logger_name == "uvicorn.access":
                handler.addFilter(LivenessProbeLogFilter())

    # Log startup message after handlers are configured so DEBUG is visible when enabled
    logger.debug(f"starting aegis-{__version__}")

    if get_settings().otel_enabled:
        # Import logfire lazily to avoid importing OpenTelemetry when OTEL is disabled
        import logfire

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


def remove_keys(
    data: Optional[Dict[str, Any]], keys_to_remove: List[str]
) -> Dict[str, Any]:
    if not data:
        return {}
    return {k: v for k, v in data.items() if k not in keys_to_remove}
