# https://git.kernel.org/pub/scm/linux/security/vulns.git

import asyncio
import json
import logging
import re
import subprocess
import time
from pathlib import Path
from threading import Lock
from typing import Any

from pydantic import BaseModel, Field
from pydantic_ai import RunContext, Tool

from aegis_ai import get_settings
from aegis_ai.data_models import CVEID
from aegis_ai.features.data_models import feature_deps
from aegis_ai.kernel_vulns_repo import describe_git_error, sync_vulns_repo
from aegis_ai.toolsets.tools import BaseToolInput, BaseToolOutput

logger = logging.getLogger(__name__)

# Use single, thread-safe lock for git repo operations
REPO_LOCK = Lock()
# Cache git pull to avoid excessive network calls
REPO_UPDATE_INTERVAL = 600  # seconds

# Single-flight repo setup at the async level — only one to_thread worker
# runs setup() at a time; other callers await without pinning a thread pool slot.
_setup_lock = asyncio.Lock()


class LINUXCVEToolInput(BaseToolInput):
    cve_id: CVEID = Field(
        ...,
        description="The unique Common Vulnerabilities and Exposures (CVE) identifier for the security flaw.",
    )


class CVEMetadata(BaseModel):
    """A structured dictionary for returning CVE data."""

    cve_id: str = Field(
        ...,
        description="The unique Common Vulnerabilities and Exposures (CVE) identifier for the security flaw.",
    )

    source_files: list[str] = Field(
        ...,
        description="Related source files.",
    )

    commit_hashes: list[str] = Field(
        ...,
        description="related Git commit hashes.",
    )

    affected_files: list[str] = Field(
        ...,
        description="affected files.",
    )

    json_data: dict[str, Any] | None = Field(
        ...,
        description="metadata json.",
    )

    mbox_data: str | None = Field(
        ...,
        description="The email information associated with linux cve discussion.",
    )

    scraped_at: float = Field(
        ...,
        description="The time metadata was gathered.",
    )


class LINUXCVEToolResponse(BaseToolOutput):
    """"""  # noqa: D419

    cve_id: CVEID = Field(
        ...,
        description="The unique Common Vulnerabilities and Exposures (CVE) identifier for the security flaw.",
    )

    metadata: CVEMetadata | None = Field(..., description="Linux CVE metadata")

    @classmethod
    def error(cls, cve_id: CVEID, error_message: str) -> "LINUXCVEToolResponse":
        return cls(
            cve_id=cve_id, status="error", error_message=error_message, metadata=None
        )


# --- Repository Management (Thread-Safe) ---
class KernelVulnsRepo:
    """
    Manages lifecycle of the Linux vulnerabilities git repository.
    This class is thread-safe and ensures that clone/pull operations
    happen only once and are protected by lock.
    """

    def __init__(self, base_dir: Path):
        self.repo_path = base_dir / "linux_security_vulns"
        self.lock_file = base_dir / ".timestamp"  # For timestamping
        base_dir.mkdir(exist_ok=True)

    def setup(self):
        """
        Ensures the repository is cloned and up-to-date.
        This method should be safe to call from multiple threads/processes.
        """
        from aegis_ai.osidb_bot.util import log_memory

        with REPO_LOCK:
            repo_exists = self.repo_path.exists()

            if repo_exists:
                # Repo exists — only pull if the staleness interval has elapsed
                last_updated = (
                    self.lock_file.stat().st_mtime if self.lock_file.exists() else 0
                )
                if time.time() - last_updated <= REPO_UPDATE_INTERVAL:
                    return
                logger.info("Updating security vulnerabilities repo...")
            else:
                logger.info(
                    "Cloning Linux security vulnerabilities repo for the first time..."
                )
                log_memory("pre_clone")

            try:
                synced = sync_vulns_repo(self.repo_path)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                logger.error(f"Failed to clone vulns repo: {describe_git_error(e)}")
                raise

            if synced:
                self.lock_file.touch()
            if not repo_exists:
                log_memory("post_clone")


_STABLE_URL_RE = re.compile(r"https://git\.kernel\.org/stable/c/([0-9a-fA-F]{40})")


def _parse_mbox_content(content: str) -> dict[str, set[str]]:
    """Parses mbox content to extract fix commit hashes and affected files.

    Only extracts hashes from ``git.kernel.org/stable/c/`` URLs (the
    Mitigation section), avoiding introduction commits and version-range
    metadata that also appear in the mbox body.
    """
    commit_hashes = set(_STABLE_URL_RE.findall(content))
    affected_files = set(re.findall(r"diff --git a/([^\s]+)", content))
    return {"commits": commit_hashes, "files": affected_files}


def _parse_json_content(data: dict[str, Any]) -> dict[str, set[str]]:
    """Extract fix commit hashes from CVE 5.0 JSON ``references`` array.

    The ``versions`` array contains both introduction and fix commits;
    ``references`` contains only fix commit URLs.  Falls back to URL
    scanning of the full document if no references are found.
    """
    commits: set[str] = set()
    try:
        refs = data["containers"]["cna"]["references"]
        for ref in refs:
            m = _STABLE_URL_RE.search(ref.get("url", ""))
            if m:
                commits.add(m.group(1))
    except (KeyError, TypeError):
        pass

    if not commits:
        text_blob = " ".join(
            str(v) for v in data.values() if isinstance(v, (str, list, dict))
        )
        commits = set(_STABLE_URL_RE.findall(text_blob))

    return {"commits": commits}


def _find_and_parse_cve_files(repo_path: Path, cve_id: str) -> CVEMetadata | None:
    """Finds all relevant files for a CVE and parses them."""
    cve_year = cve_id.split("-")[1]

    # Prioritize known paths for speed
    possible_paths = [
        repo_path / f"cve/published/{cve_year}/{cve_id}.json",
        repo_path / f"cve/{cve_year}/{cve_id}.json",
        repo_path / f"cve/published/{cve_year}/{cve_id}.mbox",
        repo_path / f"cve/{cve_year}/{cve_id}.mbox",
    ]

    found_files = {p for p in possible_paths if p.exists()}

    # Fallback to a recursive search if no files are found in primary locations
    if not found_files:
        found_files.update(repo_path.rglob(f"*{cve_id}*"))

    if not found_files:
        logger.warning(f"No files found for {cve_id} in security repo.")
        return None

    all_commits: set[str] = set()
    all_files: set[str] = set()
    json_data: dict[str, Any] | None = None
    mbox_data: str | None = None

    for file_path in found_files:
        try:
            if file_path.suffix == ".json":
                with file_path.open("r", encoding="utf-8") as f:
                    json_data = json.load(f)
                    parsed = _parse_json_content(json_data)
                    all_commits.update(parsed.get("commits", set()))
            elif file_path.suffix == ".mbox":
                with file_path.open("r", encoding="utf-8", errors="ignore") as f:
                    mbox_data = f.read()
                    parsed = _parse_mbox_content(mbox_data)
                    all_commits.update(parsed.get("commits", set()))
                    all_files.update(parsed.get("files", set()))
        except Exception as e:
            logger.error(f"Error reading or parsing {file_path}: {e}")

    return CVEMetadata(
        cve_id=cve_id,
        source_files=[str(p) for p in found_files],
        commit_hashes=[
            f"https://git.kernel.org/stable/c/{h}" for h in sorted(all_commits)
        ],
        affected_files=sorted(all_files),
        json_data=json_data,
        mbox_data=mbox_data,
        scraped_at=time.time(),
    )


async def kernel_cve_lookup(cve_id: CVEID) -> LINUXCVEToolResponse:
    """
    Looks up a Linux kernel CVE by cloning/updating a git repository
    and parsing the relevant files for context.
    """
    try:
        await asyncio.to_thread(
            subprocess.run, ["git", "--version"], check=True, capture_output=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.warning("git is not installed or not in PATH. This tool cannot run.")
        return LINUXCVEToolResponse.error(cve_id, "Failed to run tool.")

    cache_path = Path(get_settings().config_dir) / "kernel_cves"
    repo = KernelVulnsRepo(cache_path)

    async with _setup_lock:
        try:
            await asyncio.to_thread(repo.setup)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            logger.warning("failed to setup git repo.")
            return LINUXCVEToolResponse.error(cve_id, "Failed to setup tool.")

    metadata = await asyncio.to_thread(
        _find_and_parse_cve_files, repo.repo_path, cve_id
    )
    return LINUXCVEToolResponse(cve_id=cve_id, metadata=metadata)


@Tool
async def kernel_cve_tool(
    ctx: RunContext[feature_deps], input: LINUXCVEToolInput
) -> LINUXCVEToolResponse:
    """Looks up a Linux kernel CVE definition by its ID and returns structured data,
    including related commit hashes and affected files."""
    if not ctx.deps.is_kernel_cve:
        return LINUXCVEToolResponse.error(
            input.cve_id, "Not a kernel CVE; tool not applicable."
        )
    logger.info(f"Looking up kernel context for {input.cve_id}...")
    return await kernel_cve_lookup(input.cve_id)
