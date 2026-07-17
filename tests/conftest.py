"""Shared pytest fixtures.

The minimal FastMCP server here is our spike target: the smallest server that
exercises the surfaces ``mcp-auth-kit`` will wrap — tool registration and request
handling. Auth-middleware tests in later sessions build on top of this fixture,
so it deliberately ships with *no* auth (representing the ~41% of public MCP
servers that have none — the starting point this kit hardens).
"""

from __future__ import annotations

import pytest
from fastmcp import FastMCP


@pytest.fixture
def server() -> FastMCP:
    """A minimal, unauthenticated FastMCP server with a single tool."""
    mcp: FastMCP = FastMCP("mcp-auth-kit-fixture")

    @mcp.tool
    def echo(message: str) -> str:
        """Return the message unchanged (a stand-in for any real tool)."""
        return message

    return mcp
