"""`current_session`: the eight-position pipeline M2-Task-Plan.md Task 3
calls load-bearing rather than stylistic — every step assumes the one
before it, so the order is fixed here even though one position is still
a no-op today. An empty position disappears at the next refactor; a
named one can only be filled.

Filled through this step: (1) the one-cookie check, (2) JWT
signature/`exp`, (3) the live `sid` row, (4) the restricted-session
allowlist, (5) the route's role requirement, (6) `require_csrf`, (8)
sliding renewal. Still a no-op: (7) object-scope resolution (Task 18 and
the routes that need it).
"""

import uuid
from collections.abc import Callable
from datetime import UTC, datetime

from fastapi import Depends, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from gameframework.api.errors import ProblemError, forbidden
from gameframework.config import Settings, get_settings
from gameframework.db.models.identity import Role, User
from gameframework.db.models.identity import Session as SessionModel
from gameframework.db.models.runs import EventParticipation, Team
from gameframework.db.session import get_session
from gameframework.services.sessions import (
    CSRF_TOKEN_TTL,
    PRESESSION_COOKIE_NAME,
    RENEWAL_THRESHOLD,
    SESSION_COOKIE_NAME,
    SESSION_TTL,
    AuthContext,
    InvalidCsrfToken,
    InvalidSessionToken,
    cookie_domain,
    decode_token,
    renew_token,
    verify_csrf_token,
)

_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _count_named_cookies(cookie_header: str, name: str) -> int:
    count = 0
    for part in cookie_header.split(";"):
        key, _, _ = part.strip().partition("=")
        if key == name:
            count += 1
    return count


def set_session_cookie(response: Response, token: str, settings: Settings) -> None:
    """The one place a session `Set-Cookie` is ever built — `api/auth.py`
    imports this rather than keeping its own copy, so there is exactly
    one call site to route through `cookie_domain()` correctly, not two
    that have to be kept in step.
    """
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        path="/",
        domain=cookie_domain(settings),
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=int(SESSION_TTL.total_seconds()),
    )


def expire_session_cookie(response: Response, settings: Settings) -> None:
    """ADR-0007: the server expires only the pair it set itself — one
    `Set-Cookie` with this cookie's own name/domain/path clears every
    instance of it a compliant browser holds at that path; it cannot
    address a duplicate planted on another `Path`. The one place this is
    built, for the same reason as `set_session_cookie` above: a clearing
    cookie whose `Domain` does not match what the browser stored clears
    nothing, silently.
    """
    response.delete_cookie(
        SESSION_COOKIE_NAME,
        path="/",
        domain=cookie_domain(settings),
        httponly=True,
        secure=True,
        samesite="lax",
    )


def set_presession_cookie(response: Response, value: str) -> None:
    """The `__Host-` pre-session cookie `POST /auth/login` requires before
    a `sid` exists (ADR-0007 "Session model" — CSRF): the `__Host-` prefix
    makes it host-only — no `Domain` attribute, `Path=/`, `Secure` — so no
    subdomain can set or read it. `GET /auth/csrf` is the one place this
    is built, mirroring `set_session_cookie` above.
    """
    response.set_cookie(
        PRESESSION_COOKIE_NAME,
        value,
        path="/",
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=int(CSRF_TOKEN_TTL.total_seconds()),
    )


_RESTRICTED_ALLOWLIST = frozenset(
    {
        ("GET", "/api/v1/auth/session"),
        ("GET", "/api/v1/auth/csrf"),
        ("POST", "/api/v1/auth/password"),
    }
)


def check_restricted_allowlist(auth: AuthContext, request: Request) -> None:
    """A restricted session (`session.restricted`) may reach exactly
    `GET /auth/session`, `GET /auth/csrf` and `POST /auth/password`
    (ADR-0007 "Onboarding") — anything else is `409 session_restricted`,
    not `403`: the caller's role may reach the route and the session is
    valid, what collides is the session's own state (api-surface.md's
    cookie/codes table). Public rather than `current_session`-private:
    `GET /auth/csrf`'s own session-optional resolver below applies it
    too, so a restricted session's reach through that route is governed
    by the same list as its reach through any other.
    """
    if not auth.session.restricted:
        return
    if (request.method, request.url.path) not in _RESTRICTED_ALLOWLIST:
        raise ProblemError(409, "session_restricted")


def resolve_optional_session(
    request: Request, response: Response, db: DbSession, settings: Settings
) -> AuthContext | None:
    """`GET /auth/csrf` is the one route outside `current_session` that
    still reads the session cookie (ADR-0007 "Session model" — "public,
    and reads the session anyway"). The duplicate-cookie rule applies
    exactly as it does at `current_session` position (1) — the attack it
    exists for reaches this route as much as any other. The signature,
    `exp` and `sid`-row checks are **tolerant** instead of refusing: a
    cookie failing any of them is treated as no session at all, so the
    caller falls back to a pre-session token rather than being refused —
    refusing here would deadlock the one route a login needs, since a
    browser whose session was ended elsewhere could never obtain a token
    again. Returns `None` for "no session", never raises for that case;
    it still raises for the ambiguous-cookie case, exactly as
    `current_session` does.
    """
    cookie_header = request.headers.get("cookie", "")
    count = _count_named_cookies(cookie_header, SESSION_COOKIE_NAME)
    if count > 1:
        expire_session_cookie(response, settings)
        raise ProblemError(401, "session_cookie_ambiguous")
    if count == 0:
        return None
    token = request.cookies[SESSION_COOKIE_NAME]

    try:
        claims = decode_token(token, settings)
    except InvalidSessionToken:
        return None

    session_row = db.get(SessionModel, uuid.UUID(str(claims["sid"])))
    if session_row is None:
        return None
    user = db.get(User, session_row.user_id)
    if user is None:
        return None

    return AuthContext(user=user, session=session_row)


def _require_csrf(auth: AuthContext, request: Request, settings: Settings) -> None:
    """A keyed MAC bound to the session's `sid`, under `csrf_key()`
    (ADR-0007 "Session model" — CSRF). Missing or invalid alike answer
    `403 csrf_token_invalid` (api-surface.md §1).
    """
    token = request.headers.get("X-CSRF-Token")
    if token is None:
        raise ProblemError(403, "csrf_token_invalid")
    try:
        verify_csrf_token(token, str(auth.session.id), settings)
    except InvalidCsrfToken as exc:
        raise ProblemError(403, "csrf_token_invalid") from exc


def resolve_captaincy(db: DbSession, user: User) -> Team | None:
    """The team `user` currently captains, or `None` if they captain none.
    `captain` is derived from `team.captain_user_id` (data-model.md
    §3.1/§3.11), never a stored role, so every route that needs to tell a
    captain from an ordinary player — the login activation gate, the
    `POST /auth/otp` own-team scope check, and the player branch of
    `POST /auth/password` (M2-Task-Plan.md Task 4) — resolves it the same
    way, through the live participation, rather than trusting a claim.

    Walks every participation the user holds rather than a single "current
    run" one: that resolution is Task 12's, and this milestone's fixtures
    give each participant exactly one, so the first match is unambiguous
    for now.
    """
    participations = (
        db.execute(select(EventParticipation).where(EventParticipation.user_id == user.id))
        .scalars()
        .all()
    )
    for participation in participations:
        if participation.team_id is None:
            continue
        team = db.get(Team, participation.team_id)
        if team is not None and team.captain_user_id == user.id:
            return team
    return None


def _resolve_object_scope(auth: AuthContext, request: Request) -> None:
    """No-op. Task 18 and the routes that need it fill this in: `self`/
    `own team` resolved from the live participation (api-surface.md
    §2.17), never trusted from a path id."""


def current_session(*roles: Role) -> Callable[..., AuthContext]:
    """A dependency factory: `Depends(current_session(Role.admin, ...))`.
    `roles` is position (5), the route's role requirement — always named
    explicitly by the route, never defaulted to "any role".
    """
    if not roles:
        raise ValueError("current_session requires at least one allowed role")

    def _dependency(
        request: Request,
        response: Response,
        db: DbSession = Depends(get_session),
        settings: Settings = Depends(get_settings),
    ) -> AuthContext:
        # (1) exactly one cookie of the session's name.
        cookie_header = request.headers.get("cookie", "")
        count = _count_named_cookies(cookie_header, SESSION_COOKIE_NAME)
        if count > 1:
            expire_session_cookie(response, settings)
            raise ProblemError(401, "session_cookie_ambiguous")
        if count == 0:
            raise ProblemError(401, "session_required")
        token = request.cookies[SESSION_COOKIE_NAME]

        # (2) JWT signature and exp under ensure_signing_key's bytes.
        try:
            claims = decode_token(token, settings)
        except InvalidSessionToken as exc:
            raise ProblemError(401, "session_invalid") from exc

        # (3) the live sid row, reads included.
        session_row = db.get(SessionModel, uuid.UUID(str(claims["sid"])))
        if session_row is None:
            raise ProblemError(401, "session_invalid")
        user = db.get(User, session_row.user_id)
        if user is None:
            raise ProblemError(401, "session_invalid")

        auth = AuthContext(user=user, session=session_row)

        # (4) restricted-session allowlist.
        check_restricted_allowlist(auth, request)

        # (5) the route's role requirement.
        if user.role not in roles:
            forbidden("role_denied")

        # (6) require_csrf on mutating routes.
        if request.method in _MUTATING_METHODS:
            _require_csrf(auth, request, settings)

        # (7) the route's object-scope resolution — no-op, Task 18.
        _resolve_object_scope(auth, request)

        # (8) sliding renewal, only once every check above has passed.
        now = datetime.now(UTC)
        if session_row.expires_at - now < RENEWAL_THRESHOLD:
            new_token = renew_token(user, session_row, settings)
            db.commit()
            set_session_cookie(response, new_token, settings)

        return auth

    return _dependency
