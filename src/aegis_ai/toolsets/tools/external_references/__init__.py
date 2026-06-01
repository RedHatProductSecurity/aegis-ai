"""
Tool for fetching content from external reference URLs found in CVE/OSIDB data.

Only fetches from an allowlist of trusted, security-relevant HTTPS domains.
Extracts text content from HTML, JSON, and plain-text responses for use as
additional context in CVE analysis.
"""

import asyncio
import hashlib
import json
import logging
import re
from html.parser import HTMLParser
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

import httpx
from pydantic import Field
from pydantic_ai import RunContext, Tool
from pydantic_ai.toolsets import FunctionToolset

from aegis_ai.toolsets.tools import (
    BaseToolInput,
    BaseToolOutput,
    default_tool_http_headers,
)

logger = logging.getLogger(__name__)

ALLOWED_HOSTS = frozenset(
    {
        # CVE registries
        "www.cve.org",
        "cveawg.mitre.org",
        "nvd.nist.gov",
        # Git forges (commits, PRs, advisories)
        "github.com",
        "gitlab.com",
        "gitlab.gnome.org",
        # Kernel sources
        "git.kernel.org",
        "lore.kernel.org",
        # Language ecosystem advisories
        "go.dev",
        "pkg.go.dev",
        "rustsec.org",
        "crates.io",
        "www.npmjs.com",
        # Project-specific security pages
        "curl.se",
        "openssl-library.org",
        "www.openwall.com",
        "kb.isc.org",
        "www.mozilla.org",
        "nodejs.org",
        "www.jenkins.io",
        "httpd.apache.org",
        "docs.djangoproject.com",
        "www.djangoproject.com",
        "www.sudo.ws",
        "www.openssh.com",
        "www.openssh.org",
        # Vulnerability databases
        "osv.dev",
        "hackerone.com",
        "huntr.com",
        # Standards / specs
        "datatracker.ietf.org",
    }
)

MAX_CONTENT_LENGTH = 8000
MAX_READ_BYTES = 512 * 1024
MAX_CONCURRENT_FETCHES = 5
FETCH_TIMEOUT_SECONDS = 10


class ExternalReferenceInput(BaseToolInput):
    references: list[str] = Field(
        ...,
        description=(
            "List of reference URLs from the CVE/OSIDB flaw data 'references' field. "
            "Pass every URL from the flaw's references list."
        ),
    )


class ExternalReferenceResult(BaseToolOutput):
    url: str = Field(..., description="The original reference URL.")
    content_type: Optional[str] = Field(
        None, description="Content type of the response."
    )
    extracted_text: Optional[str] = Field(
        None, description="Extracted text content from the reference."
    )


def validate_url(url: str) -> bool:
    """Check that url uses HTTPS and its hostname is in the allowlist."""
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    return parsed.scheme == "https" and parsed.hostname in ALLOWED_HOSTS


def _normalize_cve_org_url(url: str) -> Optional[str]:
    """Rewrite cve.org record page URL to the CVE Services JSON API endpoint."""
    parsed = urlparse(url)
    if parsed.hostname != "www.cve.org":
        return None
    if parsed.path != "/CVERecord":
        return None
    params = parse_qs(parsed.query)
    cve_ids = params.get("id", [])
    if not cve_ids or not cve_ids[0]:
        return None
    return f"https://cveawg.mitre.org/api/cve/{cve_ids[0]}"


def _filter_cve_org_json(data: dict[str, Any]) -> dict[str, Any]:
    """Extract the most relevant fields from a CVE Services JSON response."""
    result: dict[str, Any] = {}

    cna = data.get("containers", {}).get("cna", {})
    if not cna:
        return result

    descriptions = cna.get("descriptions", [])
    if descriptions:
        result["descriptions"] = [
            {"lang": d.get("lang", ""), "value": d.get("value", "")}
            for d in descriptions
        ]

    metrics = cna.get("metrics", [])
    if metrics:
        result["metrics"] = metrics

    affected = cna.get("affected", [])
    if affected:
        result["affected"] = [
            {
                k: v
                for k, v in a.items()
                if k in ("vendor", "product", "versions", "defaultStatus")
            }
            for a in affected
        ]

    return result


class _HTMLTextExtractor(HTMLParser):
    """Minimal HTML-to-text extractor using stdlib html.parser."""

    _SKIP_TAGS = frozenset(
        {"script", "style", "head", "noscript", "svg", "nav", "header", "footer"}
    )

    def __init__(self) -> None:
        super().__init__()
        self._parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        if tag in self._SKIP_TAGS:
            self._skip_depth += 1
        elif tag in ("br", "p", "div", "li", "h1", "h2", "h3", "h4", "h5", "h6", "tr"):
            if self._skip_depth == 0:
                self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._skip_depth == 0:
            self._parts.append(data)

    def get_text(self) -> str:
        text = "".join(self._parts)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()


def extract_text_from_html(html: str) -> str:
    """Strip HTML tags and return plain text."""
    parser = _HTMLTextExtractor()
    parser.feed(html)
    return parser.get_text()


_GITHUB_CHROME_RE = re.compile(
    r"^[ \t]*(?:"
    r"Skip to content"
    r"|Dismiss alert"
    r"|\{\{ message \}\}"
    r"|You signed (?:in|out) (?:with|in) another tab or window\. Reload to refresh your session\."
    r"|You switched accounts on another tab or window\. Reload to refresh your session\."
    r"|You must be signed in to change notification settings"
    r"|Uh oh!"
    r"|There was an error while loading\. Please reload this page\."
    r"|(?:Files)?Expand file tree(?:Collapse file tree)?"
    r"|Collapse file tree"
    r"|Open diff view settings"
    r"|Filter options"
    r"|Collapse file"
    r"|Copy file name to clipboard.*"
    r"|Copy link"
    r"|Copy Markdown"
    r"|Original file line numberDiff line numberDiff line change"
    r"|[+\-]?\d+(?:-\d+)?Lines changed:.*"
    r"|Load Diff.*"
    r"|Some generated files are not rendered by default\..*"
    r"|Sorry, something went wrong\."
    r"|Loading"
    r"|No results found"
    r"|View all tags"
    r"|Choose a tag to compare"
    r")[ \t]*$",
    re.MULTILINE,
)


def _strip_github_chrome(text: str) -> str:
    """Remove GitHub page UI boilerplate from extracted text."""
    text = _GITHUB_CHROME_RE.sub("", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_TRUNCATION_MARKER = "\n[... truncated]"


def _sanitize_pii(text: str) -> str:
    """Replace email addresses with a placeholder."""
    return _EMAIL_RE.sub("[email]", text)


def _truncate(text: str, limit: int = MAX_CONTENT_LENGTH) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - len(_TRUNCATION_MARKER)] + _TRUNCATION_MARKER


async def fetch_reference(url: str) -> ExternalReferenceResult:
    """Fetch content from a single reference URL.

    This is the function monkeypatched by the eval cache fixture.
    """
    if not validate_url(url):
        return ExternalReferenceResult(
            url=url,
            status="blocked",
            error_message=f"URL not in allowlist: {urlparse(url).hostname}",
        )

    fetch_url = _normalize_cve_org_url(url) or url

    try:
        async with httpx.AsyncClient(
            headers=default_tool_http_headers,
            timeout=httpx.Timeout(FETCH_TIMEOUT_SECONDS),
            follow_redirects=True,
        ) as client:
            async with client.stream("GET", fetch_url) as resp:
                final_host = resp.url.host
                if final_host not in ALLOWED_HOSTS:
                    return ExternalReferenceResult(
                        url=url,
                        status="blocked",
                        error_message=f"Redirect to non-allowed host: {final_host}",
                    )

                resp.raise_for_status()

                chunks: list[bytes] = []
                total = 0
                async for chunk in resp.aiter_bytes():
                    chunks.append(chunk)
                    total += len(chunk)
                    if total >= MAX_READ_BYTES:
                        break
                raw = b"".join(chunks)

    except httpx.TimeoutException:
        return ExternalReferenceResult(
            url=url,
            status="timeout",
            error_message="Request timed out.",
        )
    except httpx.HTTPStatusError as exc:
        return ExternalReferenceResult(
            url=url,
            status="error",
            error_message=f"HTTP {exc.response.status_code}",
        )
    except httpx.HTTPError as exc:
        return ExternalReferenceResult(
            url=url,
            status="error",
            error_message=str(exc),
        )

    content_type = resp.headers.get("content-type", "")
    encoding = resp.encoding or "utf-8"
    body = raw.decode(encoding, errors="replace")

    if "json" in content_type:
        try:
            data = json.loads(body)
            if _normalize_cve_org_url(url):
                data = _filter_cve_org_json(data)
            text = json.dumps(data, indent=2, ensure_ascii=False)
        except (json.JSONDecodeError, ValueError):
            text = body
    elif "html" in content_type:
        text = extract_text_from_html(body)
        if urlparse(url).hostname == "github.com":
            text = _strip_github_chrome(text)
    else:
        text = body

    return ExternalReferenceResult(
        url=url,
        content_type=content_type.split(";")[0].strip(),
        extracted_text=_truncate(_sanitize_pii(text)),
    )


def cache_key_for_url(url: str) -> str:
    """Deterministic, filesystem-safe cache key for a URL."""
    return hashlib.sha256(url.encode()).hexdigest()


@Tool
async def external_references_tool(
    ctx: RunContext, input: ExternalReferenceInput
) -> list[ExternalReferenceResult]:
    """
    Fetch and extract content from external reference URLs found in CVE/OSIDB
    flaw data.  After calling osidb_flaw_tool, pass the reference URLs from
    the flaw's 'references' field to this tool.  Only fetches from trusted,
    allowlisted security-relevant domains.  Returns extracted text content
    including upstream CVSS vectors, security advisories, product info,
    and commit details.
    """
    seen: set[str] = set()
    unique_urls: list[str] = []
    for u in input.references:
        if u not in seen:
            seen.add(u)
            unique_urls.append(u)

    sem = asyncio.Semaphore(MAX_CONCURRENT_FETCHES)

    async def _guarded(u: str) -> ExternalReferenceResult:
        async with sem:
            return await fetch_reference(u)

    logger.info("Fetching %d external reference(s)...", len(unique_urls))
    results = await asyncio.gather(*[_guarded(u) for u in unique_urls])
    return list(results)


external_references_toolset = FunctionToolset(tools=[external_references_tool])
