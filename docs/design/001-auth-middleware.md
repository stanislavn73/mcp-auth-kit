# Design 001 — OAuth 2.1 Auth Middleware for FastMCP

- **Status:** Accepted — decisions confirmed 2026-07-18. Ready to implement.
- **Author:** Stas · **Date:** 2026-07-18
- **Scope:** v1 middleware interface + token lifecycle. Implementation follows.

## Problem

~41% of public MCP servers ship no auth; only ~8.5% use OAuth. The ones that
*do* add auth still get the lifecycle-critical parts wrong: a token stays valid
after logout, refresh tokens aren't rotated, `prompt` is ignored so stale
sessions never re-authenticate. Scanners diagnose this from the outside.
`mcp-auth-kit` fixes it at the source, for people *building* servers.

## Framework decision (confirmed)

Target **standalone `fastmcp` 3.x** (resolves to 3.4.4), not the FastMCP embedded
in the official `mcp` SDK. 3.x is the one with a real `Middleware` system
(`on_call_tool`, `on_request`, …) and OAuth primitives — the only variant with
the surface this kit plugs into. This overrides the "official MCP Python SDK"
wording in CLAUDE.md, which has been updated to match.

## What FastMCP 3.x already gives us (so we don't reinvent)

`fastmcp.server.auth` ships `OAuthProvider`, `TokenVerifier`, `AccessToken`,
`require_scopes`, and a `Middleware` base. `OAuthProvider` defines **abstract
slots** — `verify_token`, `load_access_token`, `load_refresh_token`,
`exchange_refresh_token`, `revoke_token`. Crucially, **nothing enforces they're
implemented correctly**: `revoke_token` can be a no-op and the server still
"works" — until a revoked token keeps calling tools. That gap is the product.

## What mcp-auth-kit adds

A **correct implementation of the lifecycle-critical slots**, one provider wired
end-to-end, plus a self-test — not a new OAuth stack.

### Public interface (the thing to review)

```python
from fastmcp import FastMCP
from mcp_auth_kit import OAuth, TokenStore

auth = OAuth(
    provider="github",                 # v1: exactly one provider
    client_id=..., client_secret=...,
    scopes=["read:user"],
    store=TokenStore.in_memory(),      # pluggable; correctness lives here
    revoke_on_disconnect=True,         # secure default: ON
    prompt="consent",                  # enforce re-consent on authorize
)

mcp = FastMCP("my-server", auth=auth.provider())  # AuthProvider: verify/revoke
mcp.add_middleware(auth.middleware())             # enforces lifecycle per call
```

`OAuth` produces two things from one config: an `AuthProvider` subclass backed
by the `TokenStore`, and a `Middleware` that enforces the rules on every
request via `on_call_tool` / `on_request`.

### Token lifecycle & revocation semantics (the Zorro bug-fix patterns)

1. **Revoke-on-disconnect / logout** — session end or client disconnect calls
   `store.revoke(subject)`; a cached copy of the token can't be replayed.
2. **Immediate propagation** — `verify_token` consults the store on every call;
   a revoked token is rejected on the *next* request, no TTL grace window.
3. **Refresh rotation** — `exchange_refresh_token` invalidates the old refresh
   token; reuse of a spent one is treated as compromise → revoke the chain.
4. **`prompt` enforcement** — honor `prompt=login|consent|none` on the authorize
   redirect so stale sessions actually re-authenticate.

### `TokenStore` interface (v1)

`save(record)` · `get(access_token) -> record | None` (None if revoked/expired) ·
`revoke(access_token | subject)` · `rotate_refresh(old) -> (access, refresh)`.
v1 ships `in_memory()`; the interface is a Protocol so a Redis adapter drops in
later without touching callers.

### `mcp-auth-kit check` — self-test → scanner failure modes

| Scanner flags        | Check verifies                                   |
| -------------------- | ------------------------------------------------ |
| no auth              | server has an `AuthProvider` attached            |
| static keys          | tokens expire; a store is present                |
| missing revocation   | a revoked token fails `verify_token`             |
| scope leaks          | a tool with required scope rejects a lesser token|

The fixture in `tests/conftest.py` (unauthenticated server) is the negative
case `check` must flag.

## Decisions (confirmed 2026-07-18)

1. **Framework** — standalone `fastmcp` 3.x. ✅
2. **First provider** — **GitHub** (simplest flow, matches the builder audience). ✅
3. **Store backend v1** — **in-memory only**, behind a `Protocol` so Redis/DB
   drop in later without touching callers (resist scope creep). ✅

## Out of scope for v1

Multiple providers, non-Python servers, runtime proxying, prompt-injection
detection.

## Implementation notes (as built)

Probing `fastmcp` 3.4.4 refined the gap above. The base `OAuthProvider` leaves
`revoke_token` abstract, but the **concrete `GitHubProvider` / `OAuthProxy`
already implement** the authorize/token/refresh dance, upstream verification,
the RFC 7009 revocation *endpoint*, and consent. So the kit **composes** the
GitHub provider instead of reimplementing OAuth; the genuine additions are the
revocation ledger, its enforcement, and (still to come) the self-test.

Modules shipped:

- `tokens.py` — `TokenStore` Protocol + `InMemoryTokenStore` (the ledger).
- `verifier.py` — `enforce_revocation()` and `RevocationTokenVerifier`, which
  wrap any `TokenVerifier` so the ledger is checked at `verify_token`, the point
  FastMCP hits on every request. This is the primary enforcement chokepoint: a
  revoked token fails auth everywhere, immediately, even past the provider cache.
- `oauth.py` — `OAuth.github(...)` façade → a `GitHubProvider` subclass with the
  ledger spliced into `verify_token`, a `RevocationMiddleware` (per-call deny),
  and `logout()` / `revoke()` for the app to call on disconnect.

Still open for v1: automatic revoke-on-*disconnect* wiring (only programmatic
`logout()` exists today — no confirmed FastMCP session-end hook yet), `prompt`
enforcement, and the `mcp-auth-kit check` self-test.
