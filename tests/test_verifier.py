"""Tests for ledger enforcement at the verification chokepoint.

A fake inner verifier stands in for whatever real verifier a server uses
(GitHub, JWT, …), so these exercise the revocation logic without any network.
"""

from __future__ import annotations

from fastmcp.server.auth import AccessToken, TokenVerifier

from mcp_auth_kit.tokens import InMemoryTokenStore
from mcp_auth_kit.verifier import RevocationTokenVerifier, enforce_revocation


class FakeVerifier(TokenVerifier):
    """Accepts exactly the tokens it was seeded with; rejects everything else."""

    def __init__(self, *, valid: dict[str, AccessToken]) -> None:
        super().__init__(required_scopes=["read:user"])
        self._valid = valid

    async def verify_token(self, token: str) -> AccessToken | None:
        return self._valid.get(token)


def _access(token: str = "tok", subject: str = "user-1") -> AccessToken:
    return AccessToken(
        token=token,
        client_id="client-1",
        scopes=["read:user"],
        subject=subject,
        expires_at=None,
    )


def _verifier(*, valid: dict[str, AccessToken]) -> RevocationTokenVerifier:
    return RevocationTokenVerifier(FakeVerifier(valid=valid), InMemoryTokenStore())


async def test_valid_token_passes_and_is_recorded() -> None:
    inner_valid = {"tok": _access("tok")}
    store = InMemoryTokenStore()
    verifier = RevocationTokenVerifier(FakeVerifier(valid=inner_valid), store)

    result = await verifier.verify_token("tok")

    assert result is not None
    assert result.subject == "user-1"
    # First sight recorded it, so the ledger can now target it for revocation.
    assert await store.get("tok") is not None


async def test_token_rejected_by_inner_is_rejected() -> None:
    verifier = _verifier(valid={})
    assert await verifier.verify_token("tok") is None


async def test_revoked_token_is_rejected_even_if_inner_accepts() -> None:
    # The upstream still says "valid" (e.g. cached), but the ledger revoked it.
    store = InMemoryTokenStore()
    verifier = RevocationTokenVerifier(FakeVerifier(valid={"tok": _access("tok")}), store)

    assert await verifier.verify_token("tok") is not None  # first sight: recorded
    await store.revoke("tok")
    assert await verifier.verify_token("tok") is None  # kill overrides upstream


async def test_logout_then_verify_is_rejected() -> None:
    store = InMemoryTokenStore()
    verifier = RevocationTokenVerifier(FakeVerifier(valid={"tok": _access("tok")}), store)

    await verifier.verify_token("tok")  # record under subject user-1
    await store.revoke_subject("user-1")
    assert await verifier.verify_token("tok") is None


async def test_enforce_revocation_none_passthrough() -> None:
    store = InMemoryTokenStore()
    assert await enforce_revocation(None, "tok", store) is None


async def test_enforce_revocation_falls_back_to_client_id_subject() -> None:
    store = InMemoryTokenStore()
    access = AccessToken(
        token="tok", client_id="client-9", scopes=[], subject=None, expires_at=None
    )

    await enforce_revocation(access, "tok", store)

    # No subject on the token → recorded under client_id, so client-wide logout works.
    assert await store.revoke_subject("client-9") == 1
