"""mcp-auth-kit: production-grade OAuth 2.1 auth for MCP servers.

This package gives MCP server *builders* (not just auditors) a correct-by-default
auth layer: OAuth 2.1 middleware for FastMCP, a token lifecycle with real
revocation, and a ``check`` self-test that catches the failure modes scanners flag.

v1 is deliberately small — see ``docs/design/`` and ``CLAUDE.md``.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
