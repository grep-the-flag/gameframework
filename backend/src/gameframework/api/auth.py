"""`POST /auth/login`, `POST /auth/logout`, `GET /auth/session`,
`GET /auth/csrf`, `POST /auth/password` (api-surface.md §2.2).
"""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from gameframework.api.deps import (
    check_restricted_allowlist,
    current_session,
    expire_session_cookie,
    resolve_optional_session,
    set_presession_cookie,
    set_session_cookie,
)
from gameframework.api.errors import ProblemError
from gameframework.config import Settings, get_settings
from gameframework.db.models.feedback import AuditScope
from gameframework.db.models.identity import Role, User
from gameframework.db.models.identity import Session as SessionModel
from gameframework.db.models.runs import EventParticipation, EventRun, RunStatus
from gameframework.db.session import get_session
from gameframework.services.audit import write_audit
from gameframework.services.passwords import hash_password, verify_password
from gameframework.services.sessions import (
    CSRF_TOKEN_TTL,
    PRESESSION_COOKIE_NAME,
    AuthContext,
    InvalidCsrfToken,
    issue_session,
    mint_csrf_token,
    verify_csrf_token,
)

router = APIRouter(prefix="/auth", tags=["auth"])

_ANY_AUTHENTICATED_ROLE = (Role.admin, Role.gameadmin, Role.player)


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login")
def login(
    request: Request,
    body: LoginRequest,
    response: Response,
    db: DbSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, object]:
    # Public and mutating with no `sid` yet to bind to: the pre-session
    # `__Host-` cookie `GET /auth/csrf` sets is the binding instead
    # (ADR-0007 "Session model" — CSRF). Not exempt — a forged login puts
    # the victim into the attacker's account.
    csrf_token = request.headers.get("X-CSRF-Token")
    presession_id = request.cookies.get(PRESESSION_COOKIE_NAME)
    if csrf_token is None or presession_id is None:
        raise ProblemError(403, "csrf_token_invalid")
    try:
        verify_csrf_token(csrf_token, presession_id, settings)
    except InvalidCsrfToken as exc:
        raise ProblemError(403, "csrf_token_invalid") from exc

    user = db.execute(select(User).where(User.username == body.username)).scalar_one_or_none()
    if user is None:
        raise ProblemError(401, "invalid_credentials")

    if user.role is Role.player:
        participation = (
            db.execute(select(EventParticipation).where(EventParticipation.user_id == user.id))
            .scalars()
            .first()
        )
        if participation is not None:
            run = db.get(EventRun, participation.event_run_id)
            if run is not None and run.status is RunStatus.created:
                scheduled_start = (
                    run.scheduled_start.isoformat() if run.scheduled_start is not None else None
                )
                raise ProblemError(
                    409, "run_not_started", extensions={"scheduled_start": scheduled_start}
                )

    if not verify_password(body.password, user.password_hash):
        raise ProblemError(401, "invalid_credentials")

    token, _session_row = issue_session(db, user, settings)

    if body.password == user.username:
        # ADR-0007's risk register: a login that succeeded on the
        # account's own username, not every login. Referenced by
        # user_id only — write_audit's installation-scope PII guard
        # refuses a `username` key in `details` (data-model.md §3.23).
        write_audit(
            db,
            actor_user_id=user.id,
            scope=AuditScope.installation,
            event_run_id=None,
            action="login_on_own_username",
            target_type="user",
            target_id=user.id,
            details={},
        )

    set_session_cookie(response, token, settings)
    response.delete_cookie(
        PRESESSION_COOKIE_NAME,
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )
    return {}


@router.post("/logout")
def logout(
    response: Response,
    auth: AuthContext = Depends(current_session(*_ANY_AUTHENTICATED_ROLE)),
    db: DbSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, object]:
    db.delete(auth.session)
    db.commit()
    expire_session_cookie(response, settings)
    return {}


@router.get("/session")
def read_session(
    auth: AuthContext = Depends(current_session(*_ANY_AUTHENTICATED_ROLE)),
) -> dict[str, object]:
    return {
        "user_id": str(auth.user.id),
        "role": auth.user.role.value,
        "must_change_password": auth.user.must_change_password,
    }


@router.get("/csrf")
def get_csrf(
    request: Request,
    response: Response,
    db: DbSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, str]:
    """Reads the session through the session-optional resolver rather
    than standing outside the pipeline (ADR-0007 "Session model"): a
    live session binds the token to its own `sid` and runs the restricted
    allowlist; with none — the pre-login case `POST /auth/login` needs,
    or a cookie the resolver tolerated rather than refused — it binds to
    the `__Host-` pre-session cookie, minting one if the caller does not
    already carry one. No role check, no `require_csrf`, no sliding
    renewal: the route is public, it is a read, and renewal belongs to
    the authenticated pipeline this route deliberately does not run.
    """
    auth = resolve_optional_session(request, response, db, settings)

    binding: str | None = None
    if auth is not None:
        check_restricted_allowlist(auth, request)
        binding = str(auth.session.id)

    if binding is None:
        presession_id = request.cookies.get(PRESESSION_COOKIE_NAME) or uuid.uuid4().hex
        set_presession_cookie(response, presession_id)
        binding = presession_id

    expires_at = datetime.now(UTC) + CSRF_TOKEN_TTL
    token = mint_csrf_token(binding, expires_at, settings)
    return {"csrf_token": token}


class PasswordChangeRequest(BaseModel):
    old_password: str
    new_password: str


@router.post("/password")
def change_password(
    body: PasswordChangeRequest,
    response: Response,
    auth: AuthContext = Depends(current_session(*_ANY_AUTHENTICATED_ROLE)),
    db: DbSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, object]:
    if not verify_password(body.old_password, auth.user.password_hash):
        raise ProblemError(401, "invalid_credentials")

    auth.user.password_hash = hash_password(body.new_password)
    auth.user.must_change_password = False

    # Every session this user holds, not only the caller's (ADR-0007
    # "Session model" — Revocation): the forced change exists wherever
    # the password was not chosen by its holder, so anyone else standing
    # on the admin-set or guessable one may already hold a session of
    # their own.
    other_sessions = (
        db.execute(select(SessionModel).where(SessionModel.user_id == auth.user.id)).scalars().all()
    )
    for session_row in other_sessions:
        db.delete(session_row)
    db.commit()

    token, _new_session_row = issue_session(db, auth.user, settings)
    set_session_cookie(response, token, settings)
    return {}
