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
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
from pydantic import Field
from pydantic_ai import RunContext, Tool
from pydantic_ai.toolsets import FunctionToolset

from aegis_ai.features.data_models import feature_deps
from aegis_ai.toolsets.tools import (
    BaseToolInput,
    BaseToolOutput,
    default_tool_http_headers,
)

logger = logging.getLogger(__name__)

ALLOWED_URL_PREFIXES = (
    # CVE registries
    "https://cveawg.mitre.org/api/cve/",
    "https://nvd.nist.gov/vuln/detail/",
    "https://www.cve.org/CVERecord",
    # GitLab — per-project prefixes
    "https://gitlab.com/gitlab-org/gitlab/",
    "https://gitlab.gnome.org/GNOME/",
    # Kernel sources
    "https://git.kernel.org/pub/scm/",
    "https://git.kernel.org/stable/c/",
    "https://lore.kernel.org/linux-cve-announce/",
    "https://lore.kernel.org/lkml/",
    # Language ecosystem advisories
    "https://crates.io/crates/",
    "https://go.dev/cl/",
    "https://go.dev/issue/",
    "https://pkg.go.dev/vuln/",
    "https://rustsec.org/advisories/",
    "https://www.npmjs.com/package/",
    # Project-specific security pages
    "https://curl.se/docs/",
    "https://docs.djangoproject.com/en/",
    "https://grafana.com/security/security-advisories/",
    "https://httpd.apache.org/security/",
    "https://kb.isc.org/docs/",
    "https://nodejs.org/en/blog/vulnerability/",
    "https://openssl-library.org/news/secadv/",
    "https://www.djangoproject.com/weblog/",
    "https://www.jenkins.io/security/advisory/",
    "https://www.mozilla.org/security/advisories/",
    "https://www.openssh.com/releasenotes",
    "https://www.openssh.org/releasenotes",
    "https://www.openwall.com/lists/oss-security/",
    "https://www.sudo.ws/security/",
    # Vulnerability databases
    "https://hackerone.com/reports/",
    "https://huntr.com/bounties/",
    "https://osv.dev/vulnerability/",
    # Standards / specs
    "https://datatracker.ietf.org/doc/",
)

# GitHub — per-repo prefixes (multi-tenant; broad "https://github.com/" is
# intentionally avoided to block untrusted PoC/exploit repositories).
# URLs must also match a path type in _GITHUB_ALLOWED_PATH_PREFIXES.
_GITHUB_REPO_PREFIXES = (
    "https://github.com/FasterXML/jackson-databind/",
    "https://github.com/FluidSynth/fluidsynth/",
    "https://github.com/FreeRDP/FreeRDP/",
    "https://github.com/HubSpot/jinjava/",
    "https://github.com/ImageMagick/ImageMagick/",
    "https://github.com/LibRaw/LibRaw/",
    "https://github.com/Mbed-TLS/TF-PSA-Crypto/",
    "https://github.com/Mbed-TLS/mbedtls/",
    "https://github.com/OpenPrinting/cups/",
    "https://github.com/OpenPrinting/cups-filters/",
    "https://github.com/OpenPrinting/libcupsfilters/",
    "https://github.com/PrefectHQ/fastmcp/",
    "https://github.com/TechnitiumSoftware/DnsServer/",
    "https://github.com/aio-libs/aiohttp/",
    "https://github.com/alexcrichton/tar-rs/",
    "https://github.com/apache/struts/",
    "https://github.com/assertj/assertj/",
    "https://github.com/astral-sh/tokio-tar/",
    "https://github.com/astral-sh/uv/",
    "https://github.com/authlib/authlib/",
    "https://github.com/axios/axios/",
    "https://github.com/browserify/pbkdf2/",
    "https://github.com/buger/jsonparser/",
    "https://github.com/coder/agentapi/",
    "https://github.com/containerd/containerd/",
    "https://github.com/containers/podman/",
    "https://github.com/coreruleset/coreruleset/",
    "https://github.com/cpan-authors/XML-Parser/",
    "https://github.com/dani-garcia/vaultwarden/",
    "https://github.com/digitalbazaar/forge/",
    "https://github.com/django/django/",
    "https://github.com/dlemstra/Magick.NET/",
    "https://github.com/dvsekhvalnov/jose2go/",
    "https://github.com/edera-dev/cve-tarmageddon/",
    "https://github.com/erlang/otp/",
    "https://github.com/external-secrets/external-secrets/",
    "https://github.com/foxcpp/maddy/",
    "https://github.com/ggml-org/llama.cpp/",
    "https://github.com/go-acme/lego/",
    "https://github.com/gogs/gogs/",
    "https://github.com/golang/go/",
    "https://github.com/golang/vulndb/",
    "https://github.com/grafana/grafana/",
    "https://github.com/grafana/loki/",
    "https://github.com/grafana/tempo/",
    "https://github.com/immutable-js/immutable-js/",
    "https://github.com/isaacs/node-glob/",
    "https://github.com/isaacs/node-tar/",
    "https://github.com/jorenbroekema/expr-eval/",
    "https://github.com/junrar/junrar/",
    "https://github.com/jupyter-server/jupyter_server/",
    "https://github.com/keylime/keylime/",
    "https://github.com/kubevirt/kubevirt/",
    "https://github.com/latchset/kdcproxy/",
    "https://github.com/ljharb/qs/",
    "https://github.com/locutusjs/locutus/",
    "https://github.com/metal3-io/baremetal-operator/",
    "https://github.com/metal3-io/metal3-docs/",
    "https://github.com/mlc-ai/xgrammar/",
    "https://github.com/nodejs/undici/",
    "https://github.com/oauth2-proxy/oauth2-proxy/",
    "https://github.com/onnx/onnx/",
    "https://github.com/open-metadata/OpenMetadata/",
    "https://github.com/openbao/openbao/",
    "https://github.com/opencontainers/runc/",
    "https://github.com/opencontainers/selinux/",
    "https://github.com/open-telemetry/opentelemetry-go/",
    "https://github.com/parallax/jsPDF/",
    "https://github.com/phpseclib/phpseclib/",
    "https://github.com/pjsip/pjproject/",
    "https://github.com/pmd/pmd/",
    "https://github.com/pnggroup/libpng/",
    "https://github.com/pnpm/pnpm/",
    "https://github.com/podofo/podofo/",
    "https://github.com/py-pdf/pypdf/",
    "https://github.com/pyca/cryptography/",
    "https://github.com/python/cpython/",
    "https://github.com/rack/rack/",
    "https://github.com/redis/redis/",
    "https://github.com/rgaufman/live555/",
    "https://github.com/roundcube/roundcubemail/",
    "https://github.com/ruby-concurrency/concurrent-ruby/",
    "https://github.com/ruby/zlib/",
    "https://github.com/run-llama/llama_index/",
    "https://github.com/rust-lang/rust/",
    "https://github.com/samtools/htslib/",
    "https://github.com/samtools/samtools/",
    "https://github.com/scoder/lupa/",
    "https://github.com/serverless-dns/serverless-dns/",
    "https://github.com/sfackler/rust-openssl/",
    "https://github.com/silentmatt/expr-eval/",
    "https://github.com/sirupsen/logrus/",
    "https://github.com/sparklemotion/nokogiri/",
    "https://github.com/spinnaker/spinnaker/",
    "https://github.com/spring-projects/spring-framework/",
    "https://github.com/squid-cache/squid/",
    "https://github.com/stefanberger/libtpms/",
    "https://github.com/step-security/harden-runner/",
    "https://github.com/strimzi/strimzi-kafka-operator/",
    "https://github.com/sudo-project/sudo/",
    "https://github.com/swaldman/c3p0/",
    "https://github.com/swaldman/mchange-commons-java/",
    "https://github.com/systemd/systemd/",
    "https://github.com/tektoncd/pipeline/",
    "https://github.com/tensorflow/tensorflow/",
    "https://github.com/theskumar/python-dotenv/",
    "https://github.com/tinytag/tinytag/",
    "https://github.com/tornadoweb/tornado/",
    "https://github.com/traccar/traccar/",
    "https://github.com/unitycatalog/unitycatalog/",
    "https://github.com/uutils/coreutils/",
    "https://github.com/vega/vega/",
    "https://github.com/vim/vim/",
    "https://github.com/vllm-project/vllm/",
    "https://github.com/xwiki/xwiki-platform/",
    "https://github.com/yt-dlp/yt-dlp/",
)

# Only fetch maintainer-controlled content types from GitHub repositories.
# User-generated paths (commit/, pull/, issues/) are excluded to reduce
# prompt injection risk from untrusted comments and issue descriptions.
_GITHUB_ALLOWED_PATH_PREFIXES = (
    "security/advisories/",
    "releases/",
    "blob/",
    "tree/",
)

MAX_CONTENT_LENGTH = 8000
MAX_READ_BYTES = 512 * 1024
MAX_CONCURRENT_FETCHES = 5
FETCH_TIMEOUT_SECONDS = 10
TOTAL_FETCH_TIMEOUT_SECONDS = 30


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
    content_type: str | None = Field(None, description="Content type of the response.")
    extracted_text: str | None = Field(
        None, description="Extracted text content from the reference."
    )


def _url_matches_prefix(url: str) -> bool:
    """Return True if *url* is allowed by the prefix allowlists.

    Non-GitHub URLs are checked against ``ALLOWED_URL_PREFIXES`` with the same
    ``startswith`` / slash-less-form logic as before.

    GitHub URLs require **two** matches: the repo must appear in
    ``_GITHUB_REPO_PREFIXES`` **and** the path after the repo prefix must start
    with one of the trusted content types in ``_GITHUB_ALLOWED_PATH_PREFIXES``
    (security advisories, releases, blob, tree).  User-generated paths
    (``commit/``, ``pull/``, ``issues/``) and bare repo URLs are rejected.
    """
    if any(url.startswith(p) or url + "/" == p for p in ALLOWED_URL_PREFIXES):
        return True
    for repo_prefix in _GITHUB_REPO_PREFIXES:
        if url.startswith(repo_prefix):
            suffix = url[len(repo_prefix) :]
            return any(
                suffix.startswith(p) or suffix + "/" == p
                for p in _GITHUB_ALLOWED_PATH_PREFIXES
            )
    return False


def validate_url(url: str) -> bool:
    """Check that url uses HTTPS and matches an allowed URL prefix."""
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme != "https":
        return False
    return _url_matches_prefix(url)


def _normalize_cve_org_url(url: str) -> str | None:
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

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self._SKIP_TAGS:
            self._skip_depth += 1
        elif tag in ("br", "p", "div", "li", "h1", "h2", "h3", "h4", "h5", "h6", "tr"):  # noqa: SIM102
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
            error_message=f"URL not in allowlist: {url}",
        )

    fetch_url = _normalize_cve_org_url(url) or url

    try:
        async with (
            httpx.AsyncClient(
                headers=default_tool_http_headers,
                timeout=httpx.Timeout(FETCH_TIMEOUT_SECONDS),
                follow_redirects=True,
            ) as client,
            client.stream("GET", fetch_url) as resp,
        ):
            if not _url_matches_prefix(str(resp.url)):
                return ExternalReferenceResult(
                    url=url,
                    status="blocked",
                    error_message=f"Redirect to non-allowed URL: {resp.url}",
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
    ctx: RunContext[feature_deps], input: ExternalReferenceInput
) -> list[ExternalReferenceResult]:
    """
    Fetch and extract content from external reference URLs found in CVE/OSIDB
    flaw data.  After calling osidb_flaw_tool, pass the reference URLs from
    the flaw's 'references' field to this tool.  Only fetches from trusted,
    allowlisted security-relevant domains.  Returns extracted text content
    including upstream CVSS vectors, security advisories, product info,
    and commit details.
    """
    allowed = ctx.deps.allowed_reference_urls
    seen: set[str] = set()
    unique_urls: list[str] = []
    for u in input.references:
        if u in seen:
            continue
        seen.add(u)
        if allowed is not None and u not in allowed:
            logger.info(
                f"external_references_tool: rejecting URL not in flaw references: {u}"
            )
            continue
        unique_urls.append(u)

    sem = asyncio.Semaphore(MAX_CONCURRENT_FETCHES)

    async def _guarded(u: str) -> ExternalReferenceResult:
        async with sem:
            return await fetch_reference(u)

    tasks = [asyncio.create_task(_guarded(u)) for u in unique_urls]
    results: list[ExternalReferenceResult] = []
    try:
        async with asyncio.timeout(TOTAL_FETCH_TIMEOUT_SECONDS):
            for coro in asyncio.as_completed(tasks):
                results.append(await coro)
    except TimeoutError:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        dropped = len(unique_urls) - len(results)
        logger.warning(
            "Total fetch timeout (%ds) reached — returning %d result(s), dropped %d",
            TOTAL_FETCH_TIMEOUT_SECONDS,
            len(results),
            dropped,
        )
    fetched = [r.url for r in results if r.status == "success"]
    if fetched:
        logger.info("Fetched %d external reference(s): %s", len(fetched), fetched)
    return results


external_references_toolset: FunctionToolset[feature_deps] = FunctionToolset(
    tools=[external_references_tool]
)
