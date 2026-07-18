# mcp-auth-kit

**Production-grade OAuth 2.1 auth for MCP servers — done right, in minutes.**

> ⚠️ **Status: early alpha (v0.1).** Scaffold + design are in place; the OAuth
> middleware and token store land next. Interfaces will change. Not yet on PyPI.

---

## Why 91.5% of MCP servers get auth wrong

The Model Context Protocol is how AI agents reach your tools and data. Yet the
auth story across public MCP servers is grim:

- **~41%** of public MCP servers ship with **no authentication at all**.
- Only **~8.5%** use OAuth.

<sub>Source: BlueRock Security, 2026.</sub>

The remaining servers lean on static API keys, home-rolled token checks, or
copy-pasted snippets that skip the parts auth is *for* — revoking a token on
logout, enforcing scopes, re-prompting for consent. These aren't exotic edge
cases; they're the exact failures that let a stale token keep working after a
user disconnects, or let one tenant's scope leak into another's.

There's a whole category of tools — **scanners** like mcp-audit, MCP-Scan,
agent-audit, and Proximity — that *diagnose* these problems for people
**installing** servers. That's valuable, but it's the wrong end of the pipe.

**Nothing helps the people *building* servers get auth right in the first place.**
That's the gap `mcp-auth-kit` fills. Scanners are the diagnosis; this is the cure.

## What it does (v1)

`mcp-auth-kit` is a drop-in auth layer for [FastMCP](https://gofastmcp.com)
servers. Three things, done impeccably:

1. **OAuth 2.1 middleware** — one provider flow, wired correctly, minimal glue.
2. **Token lifecycle done right** — issuance, caching, refresh, and *proper
   revocation* on logout/disconnect. (Built from real production bug-fix
   patterns: revoke-on-logout, `prompt`-parameter enforcement.)
3. **`mcp-auth-kit check`** — a self-test that runs your server against the
   failure modes scanners flag: no auth, static keys, missing revocation,
   scope leaks.

## What it is *not* (v1, on purpose)

Kept small so v1 ships correct instead of broad. Out of scope for now:
multiple OAuth providers, non-Python servers, runtime proxying, and
prompt-injection detection (the scanners own that).

## Install

```bash
# Not yet published. For local development:
git clone https://github.com/stanislavn73/mcp-auth-kit
cd mcp-auth-kit
uv sync
```

## Quickstart

> _Early API — expect changes. The `check` self-test is not built yet._

```python
from fastmcp import FastMCP
from mcp_auth_kit import OAuth

# Ledger-backed GitHub OAuth. FastMCP runs the OAuth dance; mcp-auth-kit adds
# the revocation ledger and enforces it on every request.
auth = OAuth.github(
    client_id="...",
    client_secret="...",
    base_url="https://my-server.example.com",  # this server's public URL
    scopes=["read:user"],
)

mcp = FastMCP("my-server", auth=auth.provider())
mcp.add_middleware(auth.middleware())

# When a user logs out or disconnects, kill their tokens — a revoked token
# fails on its very next request, with no TTL grace window:
#     await auth.logout(subject)     # revoke every token for a principal
#     await auth.revoke(access_token)
```

Using a plain `TokenVerifier` (e.g. JWT) instead of GitHub? Wrap it to get the
same revocation guarantee:

```python
from mcp_auth_kit import InMemoryTokenStore, RevocationTokenVerifier

store = InMemoryTokenStore()
verifier = RevocationTokenVerifier(my_jwt_verifier, store)
mcp = FastMCP("my-server", auth=verifier)
```

## Development

Requires [`uv`](https://docs.astral.sh/uv/) and Python 3.12+.

```bash
uv sync                       # install deps into .venv
uv run ruff check .           # lint
uv run ruff format --check .  # formatting
uv run mypy                   # strict type-check
uv run pytest                 # tests
```

## License

Apache-2.0. See [`LICENSE`](LICENSE).
