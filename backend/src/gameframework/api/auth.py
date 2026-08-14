"""`POST /auth/login`, `POST /auth/logout`, `GET /auth/session`
(api-surface.md §2.2). `GET /auth/csrf` and the staff/captain
`POST /auth/password` are Steps 5 and 6's, not this step's.
"""

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from gameframework.api.deps import current_session, expire_session_cookie, set_session_cookie
from gameframework.api.errors import ProblemError
from gameframework.config import Settings, get_settings
from gameframework.db.models.feedback import AuditScope
from gameframework.db.models.identity import Role, User
from gameframework.db.models.runs import EventParticipation, EventRun, RunStatus
from gameframework.db.session import get_session
from gameframework.services.audit import write_audit
from gameframework.services.passwords import verify_password
from gameframework.services.sessions import (
    PRESESSION_COOKIE_NAME,
    AuthContext,
    issue_session,
)

router = APIRouter(prefix="/auth", tags=["auth"])

_ANY_AUTHENTICATED_ROLE = (Role.admin, Role.gameadmin, Role.player)


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login")
def login(
    body: LoginRequest,
    response: Response,
    db: DbSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, object]:
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
