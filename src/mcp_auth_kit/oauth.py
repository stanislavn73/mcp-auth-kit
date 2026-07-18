"""The ``OAuth`` façade: one config that wires FastMCP's OAuth to the ledger.

FastMCP already ships a working GitHub OAuth provider — the authorize/token
dance, upstream verification, refresh, even a consent screen. What it does not
do is give you a revocation ledger or enforce it. This module composes the two:
``OAuth.github(...)`` returns a provider whose verification consults the ledger,
a middleware that re-checks it on every tool call, and ``logout``/``revoke``
methods an app calls when a user disconnects.

v1 supports exactly one provider (GitHub). The private provider subclass and the
middleware are the only FastMCP-specific glue; all revocation logic lives in
:mod:`mcp_auth_kit.tokens` and :mod:`mcp_auth_kit.verifier`.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from typing import Any

from fastmcp.exceptions import AuthorizationError
from fastmcp.server.auth import AccessToken, AuthProvider
from fastmcp.server.auth.providers.github import GitHubProvider
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext

from mcp_auth_kit.tokens import InMemoryTokenStore, TokenStore
from mcp_auth_kit.verifier import enforce_revocation

__all__ = ["OAuth", "RevocationMiddleware"]


class _RevocationGitHubProvider(GitHubProvider):
    """FastMCP's GitHub provider with the revocation ledger spliced into
    ``verify_token`` — the one method FastMCP calls to authenticate a request.
    """

    def __init__(
        self,
        *,
        store: TokenStore,
        now: Callable[[], float],
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._store = store
        self._now = now

    async def verify_token(self, token: str) -> AccessToken | None:
        access = await super().verify_token(token)
        return await enforce_revocation(access, token, self._store, now=self._now)


class RevocationMiddleware(Middleware):
    """Reject tool calls whose token has been revoked.

    Belt-and-suspenders to the verifier: it enforces the ledger on the tool-call
    path regardless of how auth was wired, so ``OAuth.logout()`` takes effect on
    the caller's very next tool invocation.
    """

    def __init__(self, store: TokenStore) -> None:
        self._store = store

    async def on_call_tool(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any, Any],
    ) -> Any:
        token = get_access_token()
        if token is not None and await self._store.is_revoked(token.token):
            raise AuthorizationError("token has been revoked")
        return await call_next(context)


class OAuth:
    """Ledger-backed OAuth for a FastMCP server.

    Construct with :meth:`github`, then wire both pieces into your server::

        auth = OAuth.github(client_id=..., client_secret=..., base_url=...)
        mcp = FastMCP("my-server", auth=auth.provider())
        mcp.add_middleware(auth.middleware())

        # when a user disconnects / logs out:
        await auth.logout(subject)
    """

    def __init__(self, provider: AuthProvider, store: TokenStore) -> None:
        self._provider = provider
        self._store = store

    @classmethod
    def github(
        cls,
        *,
        client_id: str,
        client_secret: str,
        base_url: str,
        scopes: Sequence[str] | None = None,
        store: TokenStore | None = None,
        now: Callable[[], float] = time.time,
    ) -> OAuth:
        """Build ledger-backed GitHub OAuth.

        ``base_url`` is this server's public URL (the OAuth redirect target).
        ``store`` defaults to an in-memory ledger; pass your own for a
        persistent one. All other GitHub specifics are handled by FastMCP.
        """
        ledger = store if store is not None else InMemoryTokenStore()
        provider = _RevocationGitHubProvider(
            store=ledger,
            now=now,
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            required_scopes=list(scopes) if scopes is not None else None,
        )
        return cls(provider, ledger)

    @property
    def store(self) -> TokenStore:
        """The revocation ledger backing this OAuth instance."""
        return self._store

    def provider(self) -> AuthProvider:
        """The FastMCP ``AuthProvider`` to pass to ``FastMCP(auth=...)``."""
        return self._provider

    def middleware(self) -> RevocationMiddleware:
        """Per-call revocation enforcement to ``add_middleware``."""
        return RevocationMiddleware(self._store)

    async def logout(self, subject: str) -> int:
        """Revoke every token for a principal. Call on logout/disconnect.
        Returns the number of tokens revoked."""
        return await self._store.revoke_subject(subject)

    async def revoke(self, access_token: str) -> bool:
        """Revoke a single access token. Returns whether it was live."""
        return await self._store.revoke(access_token)
