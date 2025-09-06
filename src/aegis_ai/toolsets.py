"""
Aegis MCP - register mcp here

"""

import os

from pydantic_ai.common_tools.tavily import tavily_search_tool
from pydantic_ai.mcp import MCPServerStdio
from pydantic_ai.toolsets import FunctionToolset, CombinedToolset

from aegis_ai import (
    tavily_api_key,
    truthy,
    use_tavily_tool,
    use_cwe_tool,
    use_linux_cve_tool,
    use_github_mcp_tool,
    use_wikipedia_mcp_tool,
    use_pypi_mcp_tool,
    config_dir,
    use_nvd_dev_tool,
)
from aegis_ai.tools.cwe import cwe_tool
from aegis_ai.tools.kernel_cves import kernel_cve_tool
from aegis_ai.tools.osidb import osidb_tool
from aegis_ai.tools.osvdev import osv_dev_cve_tool
from aegis_ai.tools.wikipedia import wikipedia_tool

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
        "GITHUB_TOOLSETS": "repos",
        "GITHUB_READ_ONLY": "1",
    },
    tool_prefix="github",
)

# wikipedia-mcp: query wikipedia
# https://github.com/rudra-ravi/wikipedia-mcp
#
# requires NVD_API_KEY=
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
        f"{config_dir}/pypi-mcp",
    ],
    tool_prefix="pypi-mcp",
)

# Toolset for 'baked in' pydantic-ai tools
pydantic_ai_tools = [wikipedia_tool]
if use_tavily_tool in truthy:
    pydantic_ai_tools.append(tavily_search_tool(tavily_api_key))
pydantic_ai_toolset = FunctionToolset(tools=pydantic_ai_tools)

# Enable public function tools
public_tools = []
if use_cwe_tool in truthy:
    public_tools.append(cwe_tool)
if use_linux_cve_tool in truthy:
    public_tools.append(kernel_cve_tool)
public_toolset = CombinedToolset(
    [
        FunctionToolset(tools=public_tools),
        pydantic_ai_toolset,
    ]
)

# Enable toolsets
if use_github_mcp_tool in truthy:
    public_toolset = CombinedToolset(
        [
            github_stdio_server,
            public_toolset,
        ]
    )

if use_wikipedia_mcp_tool in truthy:
    public_toolset = CombinedToolset(
        [
            wikipedia_stdio_server,
            public_toolset,
        ]
    )

if use_pypi_mcp_tool in truthy:
    public_toolset = CombinedToolset(
        [
            pypi_stdio_server,
            public_toolset,
        ]
    )

# Toolset containing rh specific tooling for CVE
redhat_cve_toolset = CombinedToolset(
    [
        FunctionToolset(tools=[osidb_tool]),
    ]
)


# Toolset containing generic tooling for CVE
public_cve_tools = [osv_dev_cve_tool]
public_cve_toolset = CombinedToolset(
    [
        FunctionToolset(tools=public_cve_tools),
    ]
)
if use_nvd_dev_tool in truthy:
    public_cve_toolset = CombinedToolset(
        [
            public_cve_toolset,
            nvd_stdio_server,
        ]
    )
