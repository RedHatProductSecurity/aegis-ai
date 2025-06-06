"""
aegis

"""

import datetime
from dataclasses import dataclass, field
import logging
import os

from dotenv import load_dotenv

import requests
from rich.logging import RichHandler

from pydantic_ai.models.openai import OpenAIModel
from pydantic_ai.providers.openai import OpenAIProvider

load_dotenv()

logger = logging.getLogger("aegis")

logger.info("starting aegis")

__version__ = "0.1.0"

llm_host = os.getenv("AEGIS_LLM_HOST", "localhost:11434")
llm_model = os.getenv("AEGIS_LLM_MODEL", "llama3.2:latest")

default_llm_model = OpenAIModel(
    model_name=llm_model,
    provider=OpenAIProvider(base_url=f"{llm_host}/v1/"),
)

granite_llm_model = OpenAIModel(
    model_name="granite-3-1-8b-instruct-w4a16",
    provider=OpenAIProvider(
        base_url="https://granite-3-1-8b-instruct-w4a16-maas-apicast-production.apps.prod.rhoai.rh-aiservices-bu.com:443/v1/"
    ),
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


def check_llm_status(
    timeout_seconds: float = 3.0,  # Health checks should typically be fast
) -> bool:
    """
    Check operational status of an LLM service by hitting its /health endpoint.
    """
    return True  # TODO - this check needs to compatible across all llm model types

    logger.info(f"check if {llm_host} is available and healthy")
    try:
        health_url = f"{llm_host}"
        response = requests.get(health_url, timeout=timeout_seconds)

        if response.ok:
            logging.debug(
                f"Health check successful. Status code: {response.status_code}"
            )
            return True
        else:
            # For 4xx or 5xx status codes
            logging.warn(
                f"Health check failed with status code: {response.status_code}. Response: {response.text}"
            )
            return False

    except requests.exceptions.Timeout:
        logging.warn(
            f"AEGIS_LLM_HOST health check timed out after {timeout_seconds} seconds."
        )
        return False
    except requests.exceptions.ConnectionError:
        logging.warn(
            f"AEGIS_LLM_HOST health check timed out after {timeout_seconds} seconds."
        )
        return False
    except requests.exceptions.RequestException:
        # Catches any other requests-related errors (e.g., DNS, malformed URL)
        logging.warn(
            f"AEGIS_LLM_HOST health check timed out after {timeout_seconds} seconds."
        )
        return False
    except Exception:
        # Catch any other unexpected Python errors
        logging.warn(
            f"AEGIS_LLM_HOST health check timed out after {timeout_seconds} seconds."
        )
        return False
