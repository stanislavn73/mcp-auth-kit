"""Tests for the revocation-aware token ledger.

These pin the correctness guarantees the rest of the kit relies on: a revoked
or expired token must read as not-live *immediately*, logout must kill every
token for a principal, and raw tokens must never be stored.
"""

from __future__ import annotations

import pytest

from mcp_auth_kit.tokens import InMemoryTokenStore, TokenRecord, TokenStore


class Clock:
    """A hand-cranked clock so expiry is deterministic (no sleeping)."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


def _record(
    token: str = "access-abc",
    *,
    subject: str = "user-1",
    issued_at: float = 1000.0,
    expires_at: float | None = None,
    refresh_token: str | None = None,
) -> TokenRecord:
    return TokenRecord.issue(
        token,
        subject=subject,
        client_id="client-1",
        scopes=["read:user"],
        issued_at=issued_at,
        expires_at=expires_at,
        refresh_token=refresh_token,
    )


def test_inmemory_store_satisfies_protocol() -> None:
    # Structural check: the concrete store is usable anywhere a TokenStore is.
    store: TokenStore = InMemoryTokenStore()
    assert isinstance(store, TokenStore)


async def test_record_then_get_returns_it() -> None:
    store = InMemoryTokenStore()
    await store.record(_record("access-abc"))
    got = await store.get("access-abc")
    assert got is not None
    assert got.subject == "user-1"


async def test_get_unknown_token_is_none() -> None:
    store = InMemoryTokenStore()
    assert await store.get("never-issued") is None


async def test_revoke_kills_token_immediately() -> None:
    store = InMemoryTokenStore()
    await store.record(_record("access-abc"))

    assert await store.revoke("access-abc") is True
    assert await store.get("access-abc") is None  # no grace window


async def test_revoke_is_idempotent_and_reports_liveness() -> None:
    store = InMemoryTokenStore()
    await store.record(_record("access-abc"))

    assert await store.revoke("access-abc") is True  # was live
    assert await store.revoke("access-abc") is False  # already dead


async def test_revoke_unknown_token_is_false() -> None:
    store = InMemoryTokenStore()
    assert await store.revoke("never-issued") is False


async def test_revocation_is_permanent_across_reissue() -> None:
    store = InMemoryTokenStore()
    await store.record(_record("access-abc"))
    await store.revoke("access-abc")

    # Re-recording the same token string must not resurrect it.
    await store.record(_record("access-abc"))
    assert await store.get("access-abc") is None


async def test_revoke_subject_kills_all_their_tokens() -> None:
    store = InMemoryTokenStore()
    await store.record(_record("tok-a", subject="user-1"))
    await store.record(_record("tok-b", subject="user-1"))
    await store.record(_record("tok-c", subject="user-2"))

    revoked = await store.revoke_subject("user-1")

    assert revoked == 2
    assert await store.get("tok-a") is None
    assert await store.get("tok-b") is None
    assert await store.get("tok-c") is not None  # other principal untouched


async def test_revoke_subject_unknown_is_zero() -> None:
    store = InMemoryTokenStore()
    assert await store.revoke_subject("nobody") == 0


async def test_expired_token_reads_as_not_live() -> None:
    clock = Clock(start=1000.0)
    store = InMemoryTokenStore(now=clock)
    await store.record(_record("access-abc", expires_at=1500.0))

    assert await store.get("access-abc") is not None  # still valid at t=1000
    clock.now = 1500.0  # boundary: expiry is inclusive
    assert await store.get("access-abc") is None


@pytest.mark.parametrize(
    ("now", "expired"),
    [(1499.0, False), (1500.0, True), (1600.0, True)],
)
def test_is_expired_boundary(now: float, expired: bool) -> None:
    record = _record(expires_at=1500.0)
    assert record.is_expired(now) is expired


def test_record_never_stores_raw_token() -> None:
    record = _record("super-secret-token", refresh_token="secret-refresh")
    blob = repr(record)
    assert "super-secret-token" not in blob
    assert "secret-refresh" not in blob
    # Keys are digests, not the plaintext.
    assert record.key != "super-secret-token"
    assert len(record.key) == 64  # sha256 hex
