# mcp-auth-kit — Project Brief

## Who is building this
Stas — Senior Frontend Engineer (React/TS) moving into AI agent infrastructure. Production experience at Zorro (getzorro.ai): LangGraph multi-agent system, 76 MCP tools, OAuth token caching/revocation bugs debugged in production (`mcp-auth` / `mcp-remote` token lifecycle). Learning Python seriously — prefer idiomatic Python over JS-translated patterns, explain Pythonic choices when they differ from what a JS dev would expect. Uses `uv` for Python tooling.

## What we are building
**mcp-auth-kit** — an open-source Python package that gives MCP server builders production-grade auth in minutes. This is the "cure" positioning: existing tools (mcp-audit, MCP-Scan, agent-audit, Proximity) are *scanners* that diagnose problems for people installing servers. Nothing helps people *building* servers do auth correctly, even though ~41% of public MCP servers have no auth and only ~8.5% use OAuth (BlueRock Security 2026 data).

## Strategic goals (why this exists)
1. Public proof-of-work for AI consulting positioning ("production MCP quality" specialist)
2. Real Python project shipped end-to-end (not tutorials)
3. Lead magnet: users of this package are MCP server builders = exact consulting clients
4. Complementary to scanners, not competing — their communities are our distribution

## v1 scope (deliberately small — resist scope creep)
1. **OAuth 2.1 middleware for FastMCP** — one provider flow done impeccably
2. **Token lifecycle done right** — issuance, caching, refresh, and proper revocation on logout/disconnect (design doc = the Zorro bug-fix brief patterns: token revocation on logout, `prompt` parameter enforcement)
3. **Self-test command** — `mcp-auth-kit check` verifies a server against the failure modes scanners flag (no auth, static keys, missing revocation, scope leaks)

Out of scope for v1: multiple OAuth providers, non-Python servers, runtime proxying, prompt-injection detection (scanners own that).

## Tech decisions
- Python 3.12+, `uv` for env/deps, `ruff` + `mypy` strict
- Target framework: standalone `fastmcp` 3.x middleware (the actively-developed package with the Middleware + OAuth surface — chosen over the official `mcp` SDK's embedded FastMCP; see docs/design/001-auth-middleware.md)
- Tests: pytest; the self-test harness doubles as our own test fixtures
- License: MIT or Apache 2.0
- CI: GitHub Actions from day one

## Working style for Claude Code
- Ship small and iterate; every session should end with something committable
- Explain Pythonic idioms briefly when non-obvious to a JS/TS developer
- No speculative abstractions — build for the v1 scope only
- Write docstrings and README as we go (this repo is a public portfolio piece; code will be scrutinized)

## Week 1 plan
- [ ] Scaffold repo: `uv init`, package layout, ruff/mypy/pytest/CI
- [ ] Spike: minimal FastMCP server fixture to test against
- [ ] Draft the auth middleware interface (design doc first, ~1 page)
- [ ] Implement OAuth 2.1 flow against one provider
- [ ] Token store with revocation semantics + tests
- [ ] README skeleton with the positioning: "Why 91.5% of MCP servers get auth wrong"

## Parallel track (not in this repo)
Contribute 2–3 PRs to `mcp-audit` (Adam Dudley, Apache 2.0, labeled issues open) for community credibility.
