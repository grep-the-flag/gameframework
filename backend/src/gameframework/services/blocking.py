"""Source-address blocking (M2-Task-Plan.md Task 4 Step 5; ADR-0007 "Failed
authentication is answered per source address, not per account";
data-model.md §3.3). The five-failure block only — the separate per-source
token-bucket throttle (api-surface.md §1) that Task 2 shipped as
`too_many_requests`'s default `code`, `rate_limited`, is not this module's
concern and nothing here touches it.

M2 security gate (Task 20) revision: `trusted_proxies` no longer describes
a chain depth to walk. It names the address(es) the *single* direct proxy
in front of this backend may present as — a set because an HA pair is two
legitimate peer identities, never because there is more than one hop. The
prior algorithm walked `X-Forwarded-For` from the right, skipping every
entry that matched *some* trusted CIDR, however many there were, and took
the first non-matching entry as the client. That is unsound the moment any
trusted address is not itself the entity that appended the value next to
it — an L4 relay sitting in front of an HTTP-aware reverse proxy is
trusted (its address may legitimately be the socket peer) but never
touches the header, so whatever a client puts to the left of the proxy's
own append passes through unexamined, indistinguishable in shape from a
value a further, genuine hop would have appended. No walk depth or entry
count can tell the two apart from the header's content alone — both
scenarios produce byte-identical headers. The fix drops the capability
rather than carry a rule that cannot make the distinction: only the
peer's own rightmost append is ever consulted, never anything to its
left, so a forged value is unreachable by construction. Multi-hop
resolution is deliberately not supported (ADR-0007) — `log_trusted_
proxies_model` below is what states this at boot for any configured
`trusted_proxies`: there is no way to tell a correctly configured HA pair
(several legitimate identities of the same peer) from an actual chained
hop from the configuration alone, so the log line describes the model
rather than trying to detect the bad case, and an operator running a
genuine chain has to recognise their own topology against it.
"""

import ipaddress
import logging
from datetime import UTC, datetime, timedelta

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from gameframework.config import Settings
from gameframework.db.models.identity import BlockedAddress

_FAILURE_THRESHOLD = 5
_logger = logging.getLogger(__name__)


def normalize_source(addr: str) -> str:
    """The prefix the counter and `blocked_address` are kept against — an
    IPv4 source as its `/32`, an IPv6 source as its `/64` (data-model.md
    §3.3): a single IPv6 address is not a source on its own, because SLAAC
    hands one host an entire `/64` and `ip addr add` hands it the rest.

    An IPv4-mapped IPv6 literal (`::ffff:a.b.c.d`) parses as an
    `IPv6Address` but names an IPv4 host exactly as `a.b.c.d` does — the
    mapped payload sits in the address's *last* 32 bits, all of which a
    `/64` truncation discards, collapsing every such address to the
    identical key regardless of which real host it names. Unwrapping it
    first is what keeps two spellings of one host normalizing to the same
    prefix, and two different mapped hosts normalizing to two different
    ones.
    """
    parsed = ipaddress.ip_address(addr)
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    prefix = 32 if parsed.version == 4 else 64
    return str(ipaddress.ip_network(f"{parsed}/{prefix}", strict=False))


_NO_PEER_SENTINEL = "0.0.0.0"


def log_trusted_proxies_model(settings: Settings) -> None:
    """Called once at boot (`main.py`'s `create_app()`), whenever
    `trusted_proxies` is configured at all. This states the model rather
    than detecting a misconfiguration: there is no observable difference
    between a correctly configured HA pair (several legitimate identities
    of the *same* peer) and an actual chained hop (a topology this
    function no longer supports) — that is the same indistinguishability
    `resolve_client_address`'s own docstring rests its whole design on.
    Warning only above some entry count would fire on every correct HA
    deployment and teach operators to ignore it, which is exactly the one
    case this must not be ignored. So it logs at `INFO`, unconditionally,
    for any non-empty configuration: the fact stated is true regardless of
    how many addresses are listed, and an operator running a genuine chain
    has to recognise their own topology against it, because nothing here
    can recognise it for them.
    """
    if settings.trusted_proxies:
        _logger.info(
            "trusted_proxies is configured (%d address(es): %s). The "
            "framework honours only the direct socket peer's own "
            "X-Forwarded-For append; every listed address is treated as "
            "an alternate identity of that one peer. If any of them is "
            "instead a chained hop, client addresses resolve to the inner "
            "proxy and the per-source auth throttle becomes "
            "installation-wide (ADR-0007).",
            len(settings.trusted_proxies),
            ", ".join(settings.trusted_proxies),
        )


def resolve_client_address(request: Request, settings: Settings) -> str:
    """`trusted_proxies` names the addresses the single direct proxy in
    front of this backend may present as (ADR-0007) — never a chain to
    walk. If the socket peer itself is not one of them, `X-Forwarded-For`
    is an unverified claim from whoever sent the request and is ignored
    outright; the socket peer is the source, fail-closed. If the peer is
    trusted, exactly its own rightmost append is consulted — the one
    entry any hop this installation trusts actually wrote — and nothing
    further left, however many entries follow: an attacker can pad
    arbitrary content there, but this function never looks at it, so a
    forged value is unreachable by construction rather than by a rule
    that has to out-argue it (module docstring).

    `request.client` is `None` only for an ASGI transport that never
    populates the scope's `client` key — unreachable for a real TCP
    deployment (Traefik always sets it), but real in the type. Rather
    than let an empty string reach `normalize_source` and crash with an
    unhandled `ValueError`, this falls back to the IPv4 unspecified
    address, `0.0.0.0` — a real, parseable, un-spoofable placeholder (no
    real client is ever seen as this address) that ADR-0007's own
    principle asks for: "never no source at all... a request whose client
    address cannot be established still has to be counted against
    something." The same reasoning covers the trusted peer's own append:
    if it does not parse as an address at all, it is a malformed proxy,
    not a client — falling back to the peer keeps a garbled header from
    reaching `normalize_source` unguarded the same way a missing peer
    would.
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
    if not forwarded_for:
        return peer

    rightmost = forwarded_for.rsplit(",", 1)[-1].strip()
    try:
        ipaddress.ip_address(rightmost)
    except ValueError:
        return peer
    return rightmost


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
