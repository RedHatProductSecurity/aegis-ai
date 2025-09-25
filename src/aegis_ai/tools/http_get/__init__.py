# intentionally primitive HTTP GET retrieval tool

import logging
import os
import re
from urllib.parse import urlparse

import requests

from typing import Optional, Literal
from pydantic import BaseModel, Field
from pydantic_ai import Tool, RunContext

from aegis_ai.tools import default_tool_http_headers

logger = logging.getLogger(__name__)


def compile_allowed_hosts_regex() -> Optional[re.Pattern]:
    """
    Loads AEGIS_HTTP_GET_TOOL_ALLOW_LIST from env, which is a comma-delimited list in a string.
    Escapes non-regex characters where necessary, and compiles patterns into a single, case-insensitive
    regex using OR operator (|).
    """

    allowed_hosts_string: str = os.getenv("AEGIS_HTTP_GET_TOOL_ALLOW_LIST", "")

    if not allowed_hosts_string:
        return None

    raw_patterns = [
        pattern.strip()
        for pattern in allowed_hosts_string.split(",")
        if pattern.strip()
    ]

    cleaned_patterns = []
    for pattern in raw_patterns:
        pattern = pattern.strip("^$")
        cleaned_patterns.append(f"({pattern})")

    final_regex_pattern = f"^{'|'.join(cleaned_patterns)}$"
    return re.compile(final_regex_pattern, re.IGNORECASE)


allowed_hosts_regex = compile_allowed_hosts_regex()


def is_domain_allowed(url: str) -> bool:
    """
    Check url (more specifically host) against compiled allow-list regex.
    """
    if allowed_hosts_regex is None:
        return False  # deny access by default

    try:
        # Extract and clean hostname (handle scheme, port, etc.)
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc.lower()
        if ":" in hostname:
            hostname = hostname.split(":")[0]

        if not hostname:
            return False

        return bool(allowed_hosts_regex.fullmatch(hostname))

    except Exception:
        return False  # just deny if we get exception


class GetURLContentInput(BaseModel):
    """Input schema for the get_url_content tool."""

    url: str = Field(
        ...,
        description="The full URL (including 'http://' or 'https://') to retrieve content from.",
    )


class URLContent(BaseModel):
    """
    Structured context retrieved from a given URL using HTTP GET request.
    """

    requested_url: str = Field(..., description="The URL that was requested.")
    status_code: Optional[int] = Field(
        None, description="The HTTP status code of the response (e.g., 200, 404, 500)."
    )
    content: Optional[str] = Field(
        None,
        description="The content (body) of the HTTP response, typically HTML, JSON, or plain text.",
    )
    status: Literal[
        "success",
        "excluded_domain",
        "http_error",
        "network_error",
        "unsupported_method",
    ] = Field(
        ...,
        description="The status of the operation. 'success' means a 2xx status code; 'http_error' means a 4xx/5xx code; 'network_error' means connection failed.",
    )
    error_message: Optional[str] = Field(
        None, description="An error message if the status is not 'success'."
    )


@Tool
def http_get_tool(
    ctx: RunContext,
    input: GetURLContentInput,
) -> URLContent:
    """
    Retrieve content of a given URL via a simple HTTP GET request.
    This tool only supports HTTP and HTTPS GET methods. It does not follow
    redirects and has a fixed, short timeout.
    """
    url = input.url
    logger.info(f"http_get_tool(url='{url}')")

    try:
        if not url.startswith("http://") and not url.startswith("https://"):
            return URLContent(
                requested_url=url,
                status="unsupported_method",
                error_message="URL must start with 'http://' or 'https://'.",
            )

        if not is_domain_allowed(url):
            logger.warning(f"http_get tool is not permitted to access url: '{url}'.")
            return URLContent(
                requested_url=url,
                status="excluded_domain",
                error_message=f"'{url}' is not permitted.",
            )

        response = requests.get(
            url, timeout=5, allow_redirects=False, headers=default_tool_http_headers
        )
        response.raise_for_status()

        return URLContent(
            requested_url=url,
            status_code=response.status_code,
            content=response.text,
            status="success",
        )

    except Exception as e:
        logger.error(f"HTTP GET failed for '{url}': {e}")
        return URLContent(
            requested_url=url,
            status_code=None,
            content=None,
            status="network_error",
            error_message=f"An unexpected error occurred: {str(e)}",
        )
