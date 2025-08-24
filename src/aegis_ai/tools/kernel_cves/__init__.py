# https://git.kernel.org/pub/scm/linux/security/vulns.git

import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
import logging
from typing import Dict, Optional, Any
import json

from pydantic_ai import Tool, RunContext

from aegis_ai import config_dir
from aegis_ai.data_models import CVEID
from aegis_ai.tools.osidb import CVE


logger = logging.getLogger(__name__)


@dataclass
class kernelCVEDependencies:
    test = 1


class CVEDataScraper:
    def __init__(self, base_data_dir: str = "kernel_cves"):
        self.base_data_dir = Path(base_data_dir)
        self.base_data_dir.mkdir(exist_ok=True)
        self.vulns_repo_path = self.base_data_dir / "linux_security_vulns"

    def setup_repositories(self):
        """Clone or update security vulnerabilities repositories"""
        logger.debug("Setting up repositories...")
        self.setup_vulns_repo()
        logger.debug("All repositories setup complete")

    def setup_vulns_repo(self):
        """Clone or update the Linux security vulnerabilities repo"""
        logger.debug("Setting up Linux security vulnerabilities repository...")

        if not self.vulns_repo_path.exists():
            logger.debug("Cloning Linux security vulnerabilities repo...")
            cmd = [
                "git",
                "clone",
                "https://git.kernel.org/pub/scm/linux/security/vulns.git",
                str(self.vulns_repo_path),
            ]
            subprocess.run(cmd, check=True)
        else:
            logger.debug(
                "Security vulnerabilities repo exists. Updating with git pull..."
            )
            try:
                subprocess.run(["git", "pull"], cwd=self.vulns_repo_path, check=True)
                logger.debug("Security vulnerabilities repository updated successfully")
            except subprocess.CalledProcessError as e:
                logger.warning(
                    f"Git pull failed for vulns repo: {e}. Continuing with existing repo..."
                )

    def process_cve_from_vulns_repo(self, cve_id: str) -> Optional[Dict]:
        """Process CVE information from the security vulnerabilities repo"""
        logger.debug(f"Processing {cve_id} from security vulnerabilities repo")

        cve_dir = self.base_data_dir / cve_id
        cve_dir.mkdir(exist_ok=True)

        # Look for CVE files in the vulns repository
        cve_year = cve_id.split("-")[1]  # Extract year from CVE-YYYY-NNNNN

        # Possible file locations
        possible_paths = [
            self.vulns_repo_path / f"cve/published/{cve_year}/{cve_id}.json",
            self.vulns_repo_path / f"cve/published/{cve_year}/{cve_id}.mbox",
            self.vulns_repo_path / f"cve/{cve_year}/{cve_id}.json",
            self.vulns_repo_path / f"cve/{cve_year}/{cve_id}.mbox",
        ]

        # search recursively if not found in possible paths
        try:
            search_result = subprocess.run(
                [
                    "find",
                    str(self.vulns_repo_path),
                    "-name",
                    f"*{cve_id}*",
                    "-type",
                    "f",
                ],
                capture_output=True,
                text=True,
                check=True,
            )

            if search_result.stdout.strip():
                found_files = search_result.stdout.strip().split("\n")
                for file_path in found_files:
                    if file_path not in [str(p) for p in possible_paths]:
                        possible_paths.append(Path(file_path))

        except subprocess.CalledProcessError:
            logger.warning(f"Find command failed for {cve_id}")

        cve_data = {
            "cve_id": cve_id,
            "json_data": None,
            "mbox_data": None,
            "commit_urls": [],
            "affected_files": [],
        }

        # Process each found file
        files_found = []
        for file_path in possible_paths:
            if file_path.exists():
                files_found.append(str(file_path))
                logger.debug(f"Found CVE file: {file_path}")

                try:
                    if file_path.suffix == ".json":
                        with open(file_path, "r", encoding="utf-8") as f:
                            cve_data["json_data"] = json.load(f)

                        # Extract commit info from JSON
                        self._extract_info_from_json(cve_data)

                    elif file_path.suffix == ".mbox":
                        with open(
                            file_path, "r", encoding="utf-8", errors="ignore"
                        ) as f:
                            cve_data["mbox_data"] = f.read()

                        # Extract information from mbox
                        self._extract_info_from_mbox(cve_data)

                except Exception as e:
                    logger.error(f"Error reading {file_path}: {e}")

        if not files_found:
            logger.warning(f"No CVE files found for {cve_id} in security repo")
            return None

        metadata = {
            "cve_id": cve_id,
            "source_files": files_found,
            "json_data": cve_data["json_data"],
            "commit_urls": cve_data["commit_urls"],
            "mbox": cve_data["mbox_data"],
            "affected_files": cve_data["affected_files"],
            "scraped_at": time.time(),
        }

        logger.info(f"Successfully processed {cve_id} from security repo")
        return metadata

    def _extract_info_from_json(self, cve_data: Dict):
        """Extract commit URLs and affected files from JSON data"""
        if not cve_data["json_data"]:
            return

        json_data = cve_data["json_data"]

        # Look for commit references in various fields
        def extract_commits_from_text(text):
            if not text:
                return []

            commit_patterns = [
                r"https://git\.kernel\.org/[^/]+/[^/]+/[^/]+/[^/]+/[^/]+/commit/\?id=([0-9a-fA-F]+)",
                r"https://git\.kernel\.org/stable/c/([0-9a-fA-F]+)",
                r"https://github\.com/torvalds/linux/commit/([0-9a-fA-F]+)",
                r"commit\s+([0-9a-fA-F]{40})",
                r"([0-9a-fA-F]{40})\s+\(",
            ]

            commits = []
            for pattern in commit_patterns:
                matches = re.findall(pattern, text)
                commits.extend(matches)

            return commits

        # Search in different JSON fields
        fields_to_search = [
            "description",
            "references",
            "problemDescription",
            "mitigation",
        ]

        for field in fields_to_search:
            if field in json_data:
                field_value = json_data[field]
                if isinstance(field_value, str):
                    commits = extract_commits_from_text(field_value)
                    for commit in commits:
                        commit_url = f"https://git.kernel.org/stable/c/{commit}"
                        if commit_url not in cve_data["commit_urls"]:
                            cve_data["commit_urls"].append(commit_url)
                elif isinstance(field_value, list):
                    for item in field_value:
                        if isinstance(item, str):
                            commits = extract_commits_from_text(item)
                            for commit in commits:
                                commit_url = f"https://git.kernel.org/stable/c/{commit}"
                                if commit_url not in cve_data["commit_urls"]:
                                    cve_data["commit_urls"].append(commit_url)
                        elif isinstance(item, dict) and "url" in item:
                            commits = extract_commits_from_text(item["url"])
                            for commit in commits:
                                commit_url = f"https://git.kernel.org/stable/c/{commit}"
                                if commit_url not in cve_data["commit_urls"]:
                                    cve_data["commit_urls"].append(commit_url)

    def _extract_info_from_mbox(self, cve_data: Dict):
        """Extract commit URLs and affected files from mbox content"""
        if not cve_data["mbox_data"]:
            return

        mbox_content = cve_data["mbox_data"]

        # Extract git commit URLs
        commit_patterns = [
            r"https://git\.kernel\.org/[^/]+/[^/]+/[^/]+/[^/]+/[^/]+/commit/\?id=([0-9a-fA-F]+)",
            r"https://git\.kernel\.org/stable/c/([0-9a-fA-F]+)",
            r"https://github\.com/torvalds/linux/commit/([0-9a-fA-F]+)",
            r"commit\s+([0-9a-fA-F]{40})",
            r"([0-9a-fA-F]{40})\s+\(",
        ]

        for pattern in commit_patterns:
            matches = re.findall(pattern, mbox_content)
            for match in matches:
                commit_url = f"https://git.kernel.org/stable/c/{match}"
                if commit_url not in cve_data["commit_urls"]:
                    cve_data["commit_urls"].append(commit_url)

        # Extract affected files
        file_patterns = [
            r"The file\(s\) affected by this issue are:\s*(.*?)(?=\n\n|\nMitigation|\nThe|\Z)",
            r"Affected files:\s*(.*?)(?=\n\n|\nMitigation|\nThe|\Z)",
            r"([a-zA-Z0-9_/.-]+\.[ch])\s",
            r"diff --git a/([^\s]+)",
        ]

        for pattern in file_patterns:
            matches = re.findall(pattern, mbox_content, re.DOTALL)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                # Clean up and extract file paths
                lines = match.split("\n")
                for line in lines:
                    line = line.strip()
                    if "/" in line and "." in line and len(line) > 3:
                        # file path
                        if re.match(r"^[a-zA-Z0-9_/.-]+\.[a-zA-Z0-9]+$", line):
                            if line not in cve_data["affected_files"]:
                                cve_data["affected_files"].append(line)

    def process_single_cve(self, cve_id: str):
        """Process a single CVE using the security vulnerabilities repository"""
        logger.info(f"Processing {cve_id}")

        # Process CVE from security vulnerabilities repository
        metadata = self.process_cve_from_vulns_repo(cve_id)

        if metadata:
            return metadata
        else:
            logger.info(f"Could not find information for {cve_id}")
            return False


async def kernel_cve_lookup(cve_id: CVEID) -> CVE | None:
    cache_path = os.path.join(config_dir, "kernel_cves")
    scraper = CVEDataScraper(base_data_dir=cache_path)

    # Check if git is available
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.warn("git must be installed for this tool to be used.")
        return

    # Setup both repositories
    scraper.setup_repositories()

    return scraper.process_single_cve(cve_id)


@Tool
async def kernel_cve_tool(ctx: RunContext[kernelCVEDependencies], cve_id: CVEID) -> Any:
    """Lookup a linux kernel CVE definition by ID and return structured CVE data."""
    logger.debug(cve_id)
    return await kernel_cve_lookup(cve_id)
