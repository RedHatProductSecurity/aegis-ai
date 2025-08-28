# https://git.kernel.org/pub/scm/linux/security/vulns.git

import json
import logging
import re
import subprocess
import time
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional, Set, TypedDict

from pydantic_ai import Tool, RunContext

from aegis_ai import config_dir
from aegis_ai.data_models import CVEID

logger = logging.getLogger(__name__)

# Use single, thread-safe lock for git repo operations
REPO_LOCK = Lock()
# Cache git pull to avoid excessive network calls
REPO_UPDATE_INTERVAL = 600  # seconds


class CVEMetadata(TypedDict):
    """A structured dictionary for returning CVE data."""

    cve_id: str
    source_files: List[str]
    commit_hashes: List[str]
    affected_files: List[str]
    json_data: Optional[Dict[str, Any]]
    mbox_data: Optional[str]
    scraped_at: float


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
        with REPO_LOCK:
            if not self.repo_path.exists():
                logger.info(
                    "Cloning Linux security vulnerabilities repo for the first time..."
                )
                try:
                    subprocess.run(
                        [
                            "git",
                            "clone",
                            "https://git.kernel.org/pub/scm/linux/security/vulns.git",
                            str(self.repo_path),
                        ],
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                    self.lock_file.touch()
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to clone vulns repo: {e.stderr}")
                    raise
                return

            # If repo exists, check if it needs an update
            last_updated = (
                self.lock_file.stat().st_mtime if self.lock_file.exists() else 0
            )
            if time.time() - last_updated > REPO_UPDATE_INTERVAL:
                logger.info("Updating security vulnerabilities repo...")
                try:
                    subprocess.run(
                        ["git", "pull"],
                        cwd=self.repo_path,
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                    self.lock_file.touch()
                except subprocess.CalledProcessError as e:
                    logger.warning(
                        f"Git pull failed for vulns repo, using stale data: {e.stderr}"
                    )


def _extract_commit_hashes(text: str) -> Set[str]:
    """Extracts unique kernel commit hashes from a block of text."""
    if not text:
        return set()
    # Simplified regex to find 40-character hex strings, which is robust enough
    commit_pattern = re.compile(r"\b([0-9a-fA-F]{40})\b")
    return set(commit_pattern.findall(text))


def _parse_mbox_content(content: str) -> Dict[str, Set[str]]:
    """Parses mbox content to extract commit hashes and affected files."""
    commit_hashes = _extract_commit_hashes(content)
    # Regex to find file paths in diffs
    affected_files = set(re.findall(r"diff --git a/([^\s]+)", content))
    return {"commits": commit_hashes, "files": affected_files}


def _parse_json_content(data: Dict[str, Any]) -> Dict[str, Set[str]]:
    """Recursively searches a JSON object for text to extract commit hashes."""
    text_blob = " ".join(
        str(v) for v in data.values() if isinstance(v, (str, list, dict))
    )
    return {"commits": _extract_commit_hashes(text_blob)}


def _find_and_parse_cve_files(repo_path: Path, cve_id: str) -> Optional[CVEMetadata]:
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

    all_commits: Set[str] = set()
    all_files: Set[str] = set()
    json_data: Optional[Dict[str, Any]] = None
    mbox_data: Optional[str] = None

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
            f"https://git.kernel.org/stable/c/{h}" for h in sorted(list(all_commits))
        ],
        affected_files=sorted(list(all_files)),
        json_data=json_data,
        mbox_data=mbox_data,
        scraped_at=time.time(),
    )


async def kernel_cve_lookup(cve_id: CVEID) -> Optional[CVEMetadata]:
    """
    Looks up a Linux kernel CVE by cloning/updating a git repository
    and parsing the relevant files for context.
    """
    try:
        subprocess.run(["git", "--version"], check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.error("git is not installed or not in PATH. This tool cannot run.")
        return None

    cache_path = Path(config_dir) / "kernel_cves"
    repo = KernelVulnsRepo(cache_path)

    try:
        repo.setup()
    except subprocess.CalledProcessError:
        return None  # Failed to setup repo, can't proceed.

    return _find_and_parse_cve_files(repo.repo_path, cve_id)


@Tool
async def kernel_cve_tool(ctx: RunContext, cve_id: CVEID) -> Optional[CVEMetadata]:
    """Looks up a Linux kernel CVE definition by its ID and returns structured data,
    including related commit hashes and affected files."""
    logger.info(f"Looking up kernel context for {cve_id}...")
    return await kernel_cve_lookup(cve_id)
