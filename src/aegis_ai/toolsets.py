"""
Aegis MCP - register mcp here

"""

from pydantic_ai.common_tools.tavily import tavily_search_tool
from pydantic_ai.mcp import MCPServerStdio, MCPServerSSE
from pydantic_ai.toolsets import FunctionToolset, CombinedToolset

from aegis_ai import tavily_api_key
from aegis_ai.tools.wikipedia import wikipedia_tool

# register any MCP tools here

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

rhtpa_sse_server = MCPServerSSE(url="http://localhost:8081/sse")

# Toolset containing public tools
public_toolset = CombinedToolset(
    [
        nvd_stdio_server,
        FunctionToolset(tools=[tavily_search_tool(tavily_api_key), wikipedia_tool]),
    ]
)
