"""
Aegis MCP - register mcp here

"""

import os
import logging
import time

from pydantic_ai.common_tools.tavily import tavily_search_tool
from pydantic_ai.mcp import MCPServerStdio
from pydantic_ai.toolsets import FunctionToolset, CombinedToolset
from pydantic_ai.toolsets.wrapper import WrapperToolset
from pydantic_ai._run_context import RunContext

from aegis_ai import get_settings

from aegis_ai.toolsets.tools.cwe import cwe_toolset
from aegis_ai.toolsets.tools.kernel_cves import kernel_cve_tool
from aegis_ai.toolsets.tools.osidb import osidb_toolset
from aegis_ai.toolsets.tools.osvdev import osv_dev_cve_tool
from aegis_ai.toolsets.tools.wikipedia import wikipedia_tool
from aegis_ai.toolsets.tools.cisakev import cisa_kev_tool

logger = logging.getLogger(__name__)


class LoggingToolset(WrapperToolset):
    async def call_tool(self, name: str, tool_args: dict, ctx: RunContext, tool):  # type: ignore[override]
        # log tool call entry
        args = str(tool_args) if tool_args else ""
        prefix = f"[tool call] {name}({args})"
        start = time.time()
        logger.info(f"{prefix} started")

        result = await self.wrapped.call_tool(name, tool_args, ctx, tool)

        # log tool call finish
        elapsed = time.time() - start
        logger.info(f"{prefix} finished after {elapsed:.4f}s")

        return result


# register any MCP tools below:

# mcp-nvd: query NIST National Vulnerability Database (NVD)
# https://github.com/marcoeg/mcp-nvd
#
# requires NVD_API_KEY=
nvd_stdio_server = MCPServerStdio(
    "uv",
    args=[
        "run",
        "mcp-nvd",
    ],
    tool_prefix="mitre_nvd",
)

# github-mcp: read only query against github.
# https://hub.docker.com/r/mcp/github-mcp-server
#
# requires
#   AEGIS_USE_GITHUB_MCP_TOOL_CONTEXT=false
#   GITHUB_PERSONAL_ACCESS_TOKEN=
github_stdio_server = MCPServerStdio(
    "podman",
    args=[
        "run",
        "-i",
        "-e",
        "GITHUB_PERSONAL_ACCESS_TOKEN",
        "-e",
        "GITHUB_TOOLSETS",
        "-e",
        "GITHUB_READ_ONLY",
        "mcp/github-mcp-server",
    ],
    env={
        "GITHUB_PERSONAL_ACCESS_TOKEN": f"{os.getenv('GITHUB_PERSONAL_ACCESS_TOKEN', '')}",
        "GITHUB_TOOLSETS": "repos,pull_requests",  # TODO: expand list of services at some point
        "GITHUB_READ_ONLY": "1",
    },
    tool_prefix="github",
)

# wikipedia-mcp: query wikipedia
# https://github.com/rudra-ravi/wikipedia-mcp
#
# requires wikipedia PAT
wikipedia_stdio_server = MCPServerStdio(
    "uv",
    args=[
        "run",
        "wikipedia-mcp",
    ],
    tool_prefix="wikipedia",
)

# mcp-pypi: query pypi
# https://github.com/kimasplund/mcp-pypi
#
pypi_stdio_server = MCPServerStdio(
    "uv",
    args=[
        "run",
        "mcp-pypi",
        "stdio",
        "--cache-dir",
        f"{get_settings().config_dir}/pypi-mcp",
    ],
    tool_prefix="pypi-mcp",
)

# Toolset for 'baked in' pydantic-ai tools
pydantic_ai_tools = []
if get_settings().use_tavily_tool:
    pydantic_ai_tools.append(tavily_search_tool(get_settings().tavily_api_key))
pydantic_ai_toolset = FunctionToolset(tools=pydantic_ai_tools)

# Enable public function tools
public_tools = [wikipedia_tool]
if get_settings().use_linux_cve_tool:
    public_tools.append(kernel_cve_tool)
if get_settings().use_cisa_kev_tool:
    public_tools.append(cisa_kev_tool)

# TODO: in the future we might enable adding wikipedia_mcp_tool - dependent on wikipedia account

public_toolset = CombinedToolset(
    [FunctionToolset(tools=public_tools), pydantic_ai_toolset]
)

# Enable toolsets
if get_settings().use_github_mcp_tool:
    public_toolset = CombinedToolset(
        [
            github_stdio_server,
            public_toolset,
        ]
    )

if get_settings().use_wikipedia_mcp_tool:
    public_toolset = CombinedToolset(
        [
            wikipedia_stdio_server,
            public_toolset,
        ]
    )

if get_settings().use_pypi_mcp_tool:
    public_toolset = CombinedToolset(
        [
            pypi_stdio_server,
            public_toolset,
        ]
    )

if get_settings().use_cwe_tool:
    public_toolset = CombinedToolset(
        [
            cwe_toolset,
            public_toolset,
        ]
    )

# Toolset containing rh specific tooling for CVE
redhat_cve_toolset = CombinedToolset(
    [
        osidb_toolset,
    ]
)


# Toolset containing generic tooling for CVE
public_cve_tools = [osv_dev_cve_tool]
public_cve_toolset = CombinedToolset(
    [
        FunctionToolset(tools=public_cve_tools),
    ]
)
if get_settings().use_nvd_dev_tool:
    public_cve_toolset = CombinedToolset(
        [
            public_cve_toolset,
            nvd_stdio_server,
        ]
    )

# chain logging wrappers
public_toolset = LoggingToolset(public_toolset)
redhat_cve_toolset = LoggingToolset(redhat_cve_toolset)
public_cve_toolset = LoggingToolset(public_cve_toolset)
