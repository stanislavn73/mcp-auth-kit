"""Ledger enforcement at the token-verification chokepoint.

FastMCP verifies a bearer token on every authenticated request. That is the
right place to enforce revocation: wrap whatever verifier the server already
uses (a JWT verifier, GitHub's token verifier, …) so a token the ledger has
revoked fails verification *everywhere*, immediately — even if the underlying
provider still holds it in a validation cache.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from fastmcp.server.auth import AccessToken, TokenVerifier

from mcp_auth_kit.tokens import TokenRecord, TokenStore

__all__ = ["RevocationTokenVerifier", "enforce_revocation"]


async def enforce_revocation(
    access: AccessToken | None,
    token: str,
    store: TokenStore,
    *,
    now: Callable[[], float] = time.time,
) -> AccessToken | None:
    """Apply the revocation ledger to an upstream verification result.

    - upstream rejected the token -> reject.
    - ledger has revoked it -> reject (a kill overrides an upstream cache hit).
    - otherwise -> record it on first sight so it *can* be revoked later, then
      allow.

    Factored out so both :class:`RevocationTokenVerifier` and the GitHub
    provider integration enforce the ledger through identical logic.
    """
    if access is None:
        return None
    if await store.is_revoked(token):
        return None
    # subject is optional on AccessToken; fall back to client_id so every
    # record has a stable principal to revoke by.
    await store.record(
        TokenRecord.issue(
            token,
            subject=access.subject or access.client_id,
            client_id=access.client_id,
            scopes=access.scopes,
            issued_at=now(),
            expires_at=access.expires_at,
        )
    )
    return access


class RevocationTokenVerifier(TokenVerifier):
    """Wrap any :class:`TokenVerifier` and enforce the revocation ledger.

    Use this when your server verifies tokens with a plain ``TokenVerifier``
    (e.g. a JWT verifier). Pass your existing verifier as ``inner`` and this
    one to ``FastMCP(auth=...)``; revocation is then enforced on every request.
    """

    def __init__(
        self,
        inner: TokenVerifier,
        store: TokenStore,
        *,
        now: Callable[[], float] = time.time,
    ) -> None:
        # Mirror the inner verifier's advertised scopes/resource so FastMCP's
        # auth metadata is unchanged by the wrap.
        super().__init__(
            base_url=inner.base_url,
            required_scopes=inner.required_scopes,
            resource_base_url=inner.resource_base_url,
        )
        self._inner = inner
        self._store = store
        self._now = now

    async def verify_token(self, token: str) -> AccessToken | None:
        access = await self._inner.verify_token(token)
        return await enforce_revocation(access, token, self._store, now=self._now)
