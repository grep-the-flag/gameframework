"""Source-address blocking (M2-Task-Plan.md Task 4 Step 5; ADR-0007 "Failed
authentication is answered per source address, not per account";
data-model.md §3.3). The five-failure block only — the separate per-source
token-bucket throttle (api-surface.md §1) that Task 2 shipped as
`too_many_requests`'s default `code`, `rate_limited`, is not this module's
concern and nothing here touches it.
"""

import ipaddress
from datetime import UTC, datetime, timedelta

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from gameframework.config import Settings
from gameframework.db.models.identity import BlockedAddress

_FAILURE_THRESHOLD = 5


def normalize_source(addr: str) -> str:
    """The prefix the counter and `blocked_address` are kept against — an
    IPv4 source as its `/32`, an IPv6 source as its `/64` (data-model.md
    §3.3): a single IPv6 address is not a source on its own, because SLAAC
    hands one host an entire `/64` and `ip addr add` hands it the rest.
    """
    parsed = ipaddress.ip_address(addr)
    prefix = 32 if parsed.version == 4 else 64
    return str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))


_NO_PEER_SENTINEL = "0.0.0.0"


def resolve_client_address(request: Request, settings: Settings) -> str:
    """ADR-0007 rules 1-2. The socket peer decides whether any forwarding
    header is read at all — with no `trusted_proxies` configured (the
    default) or a peer outside that set, every header is ignored and the
    peer itself is the source, fail-closed. Where the peer is trusted,
    `X-Forwarded-For` is walked from the rightmost entry, skipping every
    one that is itself a trusted proxy; the first that is not is the
    client, and everything to its left arrived from outside the trusted
    chain and is never read — a client prepending its own entries only
    adds values the walk stops before reaching. If every entry is a
    trusted proxy, or the header is absent, the source is the peer.

    `request.client` is `None` only for an ASGI transport that never
    populates the scope's `client` key — unreachable for a real TCP
    deployment (Traefik always sets it), but real in the type. Rather
    than let an empty string reach `normalize_source` and crash with an
    unhandled `ValueError`, this falls back to the IPv4 unspecified
    address, `0.0.0.0` — a real, parseable, un-spoofable placeholder (no
    real client is ever seen as this address) that ADR-0007's own
    principle asks for: "never no source at all... a request whose client
    address cannot be established still has to be counted against
    something." An operator would see failures accumulating against
    `0.0.0.0/32` on `GET /security/blocked-addresses` as a clear signal
    that something is wrong with how requests reach the backend, rather
    than a silent 500.
    """
    peer = request.client.host if request.client is not None else _NO_PEER_SENTINEL
    trusted_networks = [ipaddress.ip_network(cidr) for cidr in settings.trusted_proxies]

    def is_trusted(value: str) -> bool:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        return any(address in network for network in trusted_networks)

    if not trusted_networks or not is_trusted(peer):
        return peer

    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        entries = [entry.strip() for entry in forwarded_for.split(",")]
        for entry in reversed(entries):
            if not is_trusted(entry):
                return entry
    return peer


def check_blocked(db: DbSession, source: str) -> BlockedAddress | None:
    """The active block on `source`, or `None` — never blocked, lapsed, and
    released early are the same answer here (data-model.md §3.3).
    """
    row = db.execute(
        select(BlockedAddress).where(BlockedAddress.address == source)
    ).scalar_one_or_none()
    if row is None or row.blocked_at is None or row.released_at is not None:
        return None
    if row.expires_at is not None and row.expires_at <= datetime.now(UTC):
        return None
    return row


def retry_after_seconds(row: BlockedAddress) -> int:
    """api-surface.md §2.2: `Retry-After` carries what is left of the
    block. Never zero — a lapsed block is `check_blocked`'s `None`, not a
    row reaching here with nothing left.
    """
    if row.expires_at is None:
        return 1
    remaining = (row.expires_at - datetime.now(UTC)).total_seconds()
    return max(1, int(remaining))


def register_failure(db: DbSession, source: str, block_window_minutes: int) -> BlockedAddress:
    """One more consecutive failure from `source`; blocks it once the
    count reaches five, for `block_window_minutes` from this moment
    (data-model.md §3.3, ADR-0007). `register_failure` is only ever
    called once `check_blocked` has already let the request through, so a
    row this call blocks is not re-extended by further failures against
    the same block — those are refused by `check_blocked` before reaching
    here.
    """
    now = datetime.now(UTC)
    row = db.execute(
        select(BlockedAddress).where(BlockedAddress.address == source)
    ).scalar_one_or_none()
    if row is None:
        row = BlockedAddress(address=source, failed_attempts=0, last_attempt_at=now)
        db.add(row)
    row.failed_attempts += 1
    row.last_attempt_at = now
    if row.failed_attempts >= _FAILURE_THRESHOLD and row.blocked_at is None:
        row.blocked_at = now
        row.expires_at = now + timedelta(minutes=block_window_minutes)
    db.commit()
    return row


def register_full_success(db: DbSession, source: str) -> None:
    """Resets the counter: data-model.md §3.3 — "reset only by a full
    success... a login that issues an unrestricted session, or a
    completed activation or password change." Never a restricted-session
    login, which is free to obtain for anyone who knows a username and
    would otherwise let a login/OTP-guess cycle defeat the five-attempt
    limit. A source with no row at all has nothing to reset.
    """
    row = db.execute(
        select(BlockedAddress).where(BlockedAddress.address == source)
    ).scalar_one_or_none()
    if row is None:
        return
    row.failed_attempts = 0
    row.blocked_at = None
    row.expires_at = None
    db.commit()
