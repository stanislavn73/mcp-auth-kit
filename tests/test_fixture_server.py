"""Smoke tests for the spike fixture server.

These prove the fixture is wired correctly and give CI something real to run
before any auth code exists. They double as the baseline the auth middleware
must preserve: registering the middleware must not break tool discovery.
"""

from __future__ import annotations

from fastmcp import FastMCP

from mcp_auth_kit import __version__


async def test_server_registers_tool(server: FastMCP) -> None:
    tools = await server.list_tools()
    assert "echo" in {tool.name for tool in tools}


async def test_server_name(server: FastMCP) -> None:
    assert server.name == "mcp-auth-kit-fixture"


def test_version_is_exported() -> None:
    assert __version__ == "0.1.0"
