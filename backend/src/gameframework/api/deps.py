"""`current_session`: the eight-position pipeline M2-Task-Plan.md Task 3
calls load-bearing rather than stylistic — every step assumes the one
before it, so the order is fixed here even though three positions are
named no-ops today. An empty position disappears at the next refactor;
a named one can only be filled.

Filled in this step: (1) the one-cookie check, (2) JWT signature/`exp`,
(3) the live `sid` row, (5) the route's role requirement, (8) sliding
renewal. Still no-ops: (4) the restricted-session allowlist (Step 6),
(6) `require_csrf` (Step 6), (7) object-scope resolution (Task 18 and the
routes that need it).
"""

import uuid
from collections.abc import Callable
from datetime import UTC, datetime

from fastapi import Depends, Request, Response
from sqlalchemy.orm import Session as DbSession

from gameframework.api.errors import ProblemError, forbidden
from gameframework.config import Settings, get_settings
from gameframework.db.models.identity import Role, User
from gameframework.db.models.identity import Session as SessionModel
from gameframework.db.session import get_session
from gameframework.services.sessions import (
    RENEWAL_THRESHOLD,
    SESSION_COOKIE_NAME,
    SESSION_TTL,
    AuthContext,
    InvalidSessionToken,
    cookie_domain,
    decode_token,
    renew_token,
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


def _check_restricted_allowlist(auth: AuthContext, request: Request) -> None:
    """No-op. Step 6 fills this in: a restricted session (`session.restricted`)
    may reach only `GET /auth/session`, `GET /auth/csrf` and
    `POST /auth/password`."""


def _require_csrf(auth: AuthContext, request: Request) -> None:
    """No-op. Step 6 fills this in: a keyed MAC over the session's `sid`
    and the token's own expiry, under `csrf_key()` (ADR-0007)."""


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

        # (4) restricted-session allowlist — no-op, Step 6.
        _check_restricted_allowlist(auth, request)

        # (5) the route's role requirement.
        if user.role not in roles:
            forbidden("role_denied")

        # (6) require_csrf on mutating routes — no-op, Step 6.
        if request.method in _MUTATING_METHODS:
            _require_csrf(auth, request)

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
