import asyncio
import re
import subprocess
from typing import List, Optional, Dict, Any

from pydantic_ai import Tool, RunContext
from pydantic_ai.toolsets import FunctionToolset

JsonBlob = Dict[str, Any]


class ManPageClient:
    """
    Python client for interacting with system man pages.

    Provides methods for searching, retrieving, and listing man page content.
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.SECTIONS = {
            "1": "User Commands",
            "2": "System Calls",
            "3": "C Library Functions",
            "4": "Special Files",
            "5": "File Formats and Conventions",
            "6": "Games",
            "7": "Miscellaneous",
            "8": "System Administration Commands",
            "9": "Kernel Routines",
        }

    async def _run_command(self, cmd: List[str]) -> tuple[str, str, int]:
        """
        Run a command asynchronously with timeout.
        Returns (stdout, stderr, return_code).
        """
        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout,
            )

            return (
                stdout.decode("utf-8", errors="replace"),
                stderr.decode("utf-8", errors="replace"),
                process.returncode or 0,
            )
        except asyncio.TimeoutError:
            if process:
                process.kill()
                await process.wait()
            raise TimeoutError(f"Command timed out after {self.timeout} seconds")
        except Exception as e:
            raise Exception(f"Command failed: {str(e)}")

    @staticmethod
    def _clean_man_page_content(content: str) -> str:
        """
        Clean man page content - remove formatting codes
        and preserving readable structure.
        """
        content = re.sub(r".\x08", "", content)
        content = re.sub(r"\x1b\[[0-9;]*m", "", content)
        content = re.sub(r"\n\s*\n\s*\n", "\n\n", content)
        content = re.sub(r"[ \t]+", " ", content)
        content = "\n".join(line.rstrip() for line in content.split("\n"))
        return content.strip()

    async def search(self, keyword: str) -> List[Dict[str, str]]:
        """
        Search for man pages using apropos command.
        Returns a list of matching pages with their descriptions.
        """
        try:
            stdout, _, returncode = await self._run_command(["apropos", "--", keyword])
            if returncode != 0:
                stdout, _, returncode = await self._run_command(["man", "-k", keyword])
                if returncode != 0:
                    return []

            results = []
            for line in stdout.strip().split("\n"):
                if not line.strip():
                    continue

                match = re.match(r"^([^(]+)\s*\(([^)]+)\)\s*-\s*(.+)$", line.strip())
                if match:
                    name, section, description = match.groups()
                    results.append(
                        {
                            "name": name.strip(),
                            "section": section.strip(),
                            "description": description.strip(),
                        }
                    )
            return results
        except Exception as e:
            raise Exception(f"Failed to search man pages: {str(e)}")

    async def get_page(self, name: str, section: Optional[str] = None) -> str:
        """
        Retrieve the content of a specific man page.
        If section is not specified, retrieve the first available section.
        """
        try:
            cmd = ["man"]
            if section:
                cmd.append(section)
            cmd.append(name)

            stdout, _, returncode = await self._run_command(cmd)

            if returncode != 0:
                if section:
                    stdout, _, returncode = await self._run_command(["man", name])
                    if returncode != 0:
                        raise FileNotFoundError(f"Man page not found: {name}")
                else:
                    raise FileNotFoundError(f"Man page not found: {name}")

            cleaned_content = self._clean_man_page_content(stdout)
            if not cleaned_content:
                raise ValueError(f"Man page content is empty: {name}")

            return cleaned_content

        except Exception as e:
            raise Exception(f"Failed to get man page '{name}': {str(e)}")

    async def list_sections(self) -> Dict[str, str]:
        """
        List available man page sections with their descriptions.
        """
        available_sections = {}
        for section, description in self.SECTIONS.items():
            try:
                stdout, _, returncode = await self._run_command(
                    ["man", "-s", section, "-k", "."]
                )
                if returncode == 0 and stdout.strip():
                    available_sections[section] = description
            except (Exception, TimeoutError):
                available_sections[section] = description

        return available_sections


client = ManPageClient()


@Tool
async def search_man_pages(ctx: RunContext, keyword: str) -> str:
    """
    Search for man pages by keyword/topic.

    Args:
        keyword: The keyword or topic to search for.

    Returns:
        A formatted list of matching man pages with descriptions.
    """
    try:
        results = await client.search(keyword)
        if not results:
            return f"No man pages found for keyword: {keyword}"

        output = [f"Found {len(results)} man page(s) for '{keyword}':\n"]
        for result in results:
            output.append(
                f"• {result['name']}({result['section']}) - {result['description']}"
            )
        return "\n".join(output)
    except Exception as e:
        return f"Error searching man pages: {str(e)}"


@Tool
async def get_man_page(
    ctx: RunContext, name: str, section: Optional[str] = None
) -> str:
    """
    Get full content of a specific man page.

    Args:
        name: The name of the man page (e.g., 'ls', 'chmod').
        section: Optional section number (1-9). If not specified, returns the first available section.

    Returns:
        The full formatted content of the man page.
    """
    try:
        content = await client.get_page(name, section)
        section_info = f" (section {section})" if section else ""
        header = f"=== Man Page: {name}{section_info} ===\n\n"
        return header + content
    except FileNotFoundError:
        return (
            f"Man page not found: {name}{f' in section {section}' if section else ''}"
        )
    except Exception as e:
        return f"Error retrieving man page: {str(e)}"


@Tool
async def list_man_sections(ctx: RunContext) -> str:
    """
    List available man page sections.

    Returns:
        A formatted list of man page sections and what they contain.
    """
    try:
        sections = await client.list_sections()
        if not sections:
            return "No man page sections found."

        output = ["Available Man Page Sections:\n"]
        for section_num, description in sorted(sections.items()):
            output.append(f"Section {section_num}: {description}")

        return "\n".join(output)
    except Exception as e:
        return f"Error listing man sections: {str(e)}"


toolset = FunctionToolset(
    tools=[list_man_sections, get_man_page, search_man_pages],
)

# manpages toolset
manpages_toolset = toolset.prefixed("man_pages")
