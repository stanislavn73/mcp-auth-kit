"""Revocation-aware token ledger.

FastMCP's OAuth providers (``GitHubProvider``, ``OAuthProxy``) already run the
OAuth dance — issuance, refresh, and the RFC 7009 revocation *endpoint*. What
they don't give you is a queryable ledger of which tokens are still live, nor
any wiring that revokes a token when an MCP session ends. That is the gap this
store fills: it is the source of truth that mcp-auth-kit's verifier and the
``check`` command consult so a revoked token is dead everywhere, immediately —
with no TTL grace window.

Notes for readers coming from JS/TS:

- :class:`TokenStore` is a :class:`typing.Protocol` (structural typing), not a
  base class you must subclass. Any object with these methods *is* a
  ``TokenStore`` — closer to a TS ``interface`` than to ``extends``.
- The methods are ``async`` even though :class:`InMemoryTokenStore` never
  awaits. That is deliberate: the same interface must fit a Redis/DB adapter
  later, where every call is I/O. Paying the ``async`` cost now keeps callers
  unchanged when that adapter arrives.
- Tokens are keyed by their SHA-256 digest and never stored raw. Even an
  in-memory store should not hold plaintext bearer tokens — it sets the pattern
  the persistent adapters must follow and limits the blast radius of a leak.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

__all__ = ["InMemoryTokenStore", "TokenRecord", "TokenStore"]


def _digest(token: str) -> str:
    """Return the SHA-256 hex digest used as a token's storage key."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class TokenRecord:
    """Lifecycle metadata for one issued token. Never holds the raw token.

    ``key`` and ``refresh_key`` are SHA-256 digests, so a record is safe to log
    or dump. Instances are frozen because a ledger entry's identity should not
    mutate — revocation is tracked by the store, not by editing the record.
    """

    key: str
    """SHA-256 digest of the access token."""
    subject: str
    """Stable principal id (e.g. the GitHub user id) the token was issued for."""
    client_id: str
    scopes: frozenset[str]
    issued_at: float
    """Epoch seconds when the token was issued."""
    expires_at: float | None = None
    """Epoch seconds when the token expires; ``None`` means it never does."""
    refresh_key: str | None = None
    """SHA-256 digest of the paired refresh token, if any."""

    @classmethod
    def issue(
        cls,
        access_token: str,
        *,
        subject: str,
        client_id: str,
        scopes: Iterable[str],
        issued_at: float,
        expires_at: float | None = None,
        refresh_token: str | None = None,
    ) -> TokenRecord:
        """Build a record from raw tokens, hashing them at the boundary."""
        return cls(
            key=_digest(access_token),
            subject=subject,
            client_id=client_id,
            scopes=frozenset(scopes),
            issued_at=issued_at,
            expires_at=expires_at,
            refresh_key=_digest(refresh_token) if refresh_token else None,
        )

    def is_expired(self, now: float) -> bool:
        """Whether the token has expired as of ``now`` (epoch seconds)."""
        return self.expires_at is not None and now >= self.expires_at


@runtime_checkable
class TokenStore(Protocol):
    """The ledger interface mcp-auth-kit's verifier and ``check`` depend on.

    A store answers one question authoritatively: *is this token still live?*
    Anything unknown, revoked, or expired must read as not-live.
    """

    async def record(self, record: TokenRecord) -> None:
        """Register a freshly issued token."""
        ...

    async def get(self, access_token: str) -> TokenRecord | None:
        """Return the record iff the token is live; ``None`` if unknown,
        revoked, or expired."""
        ...

    async def revoke(self, access_token: str) -> bool:
        """Revoke one token. Returns ``True`` if a live token was revoked."""
        ...

    async def revoke_subject(self, subject: str) -> int:
        """Revoke every live token for a principal (logout). Returns the count
        revoked."""
        ...


class InMemoryTokenStore:
    """Process-memory :class:`TokenStore` for single-process servers and tests.

    Concurrency: each method is internally synchronous — no ``await`` sits
    between a read and its dependent write — so asyncio cannot interleave two
    calls mid-update. That makes the plain ``dict``/``set`` operations atomic
    under a single event loop, and no lock is needed. A multi-process
    deployment needs the (future) persistent adapter instead.

    Revocation is permanent: once a token's key is revoked it stays revoked,
    even if a record with the same key is somehow re-recorded. The safe default
    for a security primitive is that a kill cannot be silently undone.
    """

    def __init__(self, *, now: Callable[[], float] = time.time) -> None:
        # ``now`` is injectable so tests can control expiry without sleeping.
        self._now = now
        self._records: dict[str, TokenRecord] = {}
        self._by_subject: dict[str, set[str]] = {}
        self._revoked: set[str] = set()

    async def record(self, record: TokenRecord) -> None:
        self._records[record.key] = record
        self._by_subject.setdefault(record.subject, set()).add(record.key)

    async def get(self, access_token: str) -> TokenRecord | None:
        key = _digest(access_token)
        if key in self._revoked:
            return None
        record = self._records.get(key)
        if record is None or record.is_expired(self._now()):
            return None
        return record

    async def revoke(self, access_token: str) -> bool:
        return self._revoke_key(_digest(access_token))

    async def revoke_subject(self, subject: str) -> int:
        # Copy the key set first: _revoke_key mutates _by_subject as it goes.
        keys = list(self._by_subject.get(subject, ()))
        return sum(self._revoke_key(key) for key in keys)

    def _revoke_key(self, key: str) -> bool:
        """Mark ``key`` revoked and unindex it. Returns whether it was live."""
        was_live = key in self._records and key not in self._revoked
        self._revoked.add(key)
        record = self._records.pop(key, None)
        if record is not None:
            subject_keys = self._by_subject.get(record.subject)
            if subject_keys is not None:
                subject_keys.discard(key)
                if not subject_keys:
                    del self._by_subject[record.subject]
        return was_live
