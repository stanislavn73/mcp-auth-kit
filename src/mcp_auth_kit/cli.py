"""Command-line entry point for mcp-auth-kit.

For now this only reports the version and points at the design doc. The real
work — ``mcp-auth-kit check``, which verifies a server against the failure modes
scanners flag (no auth, static keys, missing revocation, scope leaks) — lands in
v1 once the middleware and token store are in place.
"""

from __future__ import annotations

import sys

from mcp_auth_kit import __version__


def main(argv: list[str] | None = None) -> int:
    """Run the CLI. Returns a process exit code."""
    args = sys.argv[1:] if argv is None else argv

    if args and args[0] in {"-V", "--version", "version"}:
        print(f"mcp-auth-kit {__version__}")
        return 0

    print(
        "mcp-auth-kit — production-grade OAuth 2.1 auth for MCP servers.\n"
        "The `check` self-test command lands in v1. "
        "See the design doc under docs/design/ for the roadmap."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
