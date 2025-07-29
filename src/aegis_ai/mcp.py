"""
Aegis MCP - register mcp here

"""

from pydantic_ai.mcp import MCPServerStdio, MCPServerSSE

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
