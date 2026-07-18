"""Tests for the OAuth façade and revocation middleware.

The real GitHub OAuth dance is FastMCP's code and needs a network; these tests
cover *our* glue — construction, store wiring, logout/revoke, and the per-call
middleware deny path (with the token accessor stubbed, so no live context).
"""

from __future__ import annotations

from typing import Any

import pytest
from fastmcp.exceptions import AuthorizationError
from fastmcp.server.auth import AccessToken, AuthProvider

from mcp_auth_kit.oauth import OAuth, RevocationMiddleware
from mcp_auth_kit.tokens import InMemoryTokenStore, TokenRecord


def _auth(store: InMemoryTokenStore | None = None) -> OAuth:
    return OAuth.github(
        client_id="dummy",
        client_secret="dummy",
        base_url="http://localhost:8000",
        scopes=["read:user"],
        store=store,
    )


def _access(token: str = "tok", subject: str = "user-1") -> AccessToken:
    return AccessToken(token=token, client_id="client-1", scopes=["read:user"], subject=subject)


def _record(token: str = "tok", subject: str = "user-1") -> TokenRecord:
    return TokenRecord.issue(token, subject=subject, client_id="c", scopes=[], issued_at=0.0)


def _ctx() -> Any:
    """A throwaway MiddlewareContext — the middleware never inspects it."""
    return object()


def test_github_builds_a_fastmcp_auth_provider() -> None:
    auth = _auth()
    assert isinstance(auth.provider(), AuthProvider)


def test_default_store_is_in_memory() -> None:
    auth = _auth()
    assert isinstance(auth.store, InMemoryTokenStore)


def test_supplied_store_is_used() -> None:
    store = InMemoryTokenStore()
    auth = _auth(store=store)
    assert auth.store is store
    assert auth.middleware()._store is store  # middleware shares the same ledger


async def test_logout_revokes_all_subject_tokens() -> None:
    store = InMemoryTokenStore()
    auth = _auth(store=store)
    await store.record(_record("tok"))

    assert await auth.logout("user-1") == 1
    assert await store.get("tok") is None


async def test_revoke_single_token() -> None:
    store = InMemoryTokenStore()
    auth = _auth(store=store)
    await store.record(_record("tok"))

    assert await auth.revoke("tok") is True
    assert await store.get("tok") is None


class _Recorder:
    """A stand-in for FastMCP's downstream handler."""

    def __init__(self) -> None:
        self.called = False

    async def __call__(self, context: Any) -> str:
        self.called = True
        return "tool-result"


async def test_middleware_allows_live_token(monkeypatch: pytest.MonkeyPatch) -> None:
    store = InMemoryTokenStore()
    monkeypatch.setattr("mcp_auth_kit.oauth.get_access_token", lambda: _access("tok"))
    middleware = RevocationMiddleware(store)
    call_next = _Recorder()

    result = await middleware.on_call_tool(_ctx(), call_next)

    assert result == "tool-result"
    assert call_next.called


async def test_middleware_denies_revoked_token(monkeypatch: pytest.MonkeyPatch) -> None:
    store = InMemoryTokenStore()
    await store.record(_record("tok"))
    await store.revoke("tok")
    monkeypatch.setattr("mcp_auth_kit.oauth.get_access_token", lambda: _access("tok"))
    middleware = RevocationMiddleware(store)
    call_next = _Recorder()

    with pytest.raises(AuthorizationError):
        await middleware.on_call_tool(_ctx(), call_next)
    assert not call_next.called  # denied before the tool ran


async def test_middleware_passes_through_when_no_token(monkeypatch: pytest.MonkeyPatch) -> None:
    store = InMemoryTokenStore()
    monkeypatch.setattr("mcp_auth_kit.oauth.get_access_token", lambda: None)
    middleware = RevocationMiddleware(store)
    call_next = _Recorder()

    assert await middleware.on_call_tool(_ctx(), call_next) == "tool-result"
    assert call_next.called
