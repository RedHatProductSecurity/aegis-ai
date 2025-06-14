"""
Aegis MCP - register mcp here

"""

from pydantic_ai.mcp import MCPServerStdio

# mcp-nvd: query NIST National Vulnerability Database (NVD)
# https://github.com/marcoeg/mcp-nvd
#
# requires NVD_API_KEY=
nvd_server = MCPServerStdio(
    "uv",
    args=[
        "run",
        "mcp-nvd",
    ],
)
