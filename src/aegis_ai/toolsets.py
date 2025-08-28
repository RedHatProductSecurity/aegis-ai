"""
Aegis MCP - register mcp here

"""

from pydantic_ai.common_tools.tavily import tavily_search_tool
from pydantic_ai.mcp import MCPServerStdio
from pydantic_ai.toolsets import FunctionToolset, CombinedToolset

from aegis_ai import (
    tavily_api_key,
    truthy,
    use_tavily_tool,
    use_cwe_tool,
    use_linux_cve_tool,
)
from aegis_ai.tools.cwe import cwe_tool
from aegis_ai.tools.kernel_cves import kernel_cve_tool
from aegis_ai.tools.osidb import osidb_tool
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
)

# Toolset for 'baked in' pydantic-ai tools
pydantic_ai_tools = [wikipedia_tool]
if use_tavily_tool in truthy:
    pydantic_ai_tools.append(tavily_search_tool(tavily_api_key))
pydantic_ai_toolset = FunctionToolset(tools=pydantic_ai_tools)

# Toolset containing public tools
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

# Toolset containing rh specific tooling for CVE
redhat_cve_toolset = CombinedToolset(
    [
        FunctionToolset(tools=[osidb_tool]),
    ]
)

# Toolset containing generic tooling for CVE
public_cve_toolset = CombinedToolset(
    [
        nvd_stdio_server,
    ]
)
