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
    resolve_captaincy,
    resolve_optional_session,
    set_presession_cookie,
    set_session_cookie,
)
from gameframework.api.errors import ProblemError, too_many_requests
from gameframework.config import Settings, get_settings
from gameframework.db.models.feedback import AuditScope
from gameframework.db.models.identity import Role, User
from gameframework.db.models.identity import Session as SessionModel
from gameframework.db.models.runs import RunStatus
from gameframework.db.session import get_session
from gameframework.services.audit import write_audit
from gameframework.services.blocking import (
    check_blocked,
    normalize_source,
    register_failure,
    register_full_success,
    resolve_client_address,
    retry_after_seconds,
)
from gameframework.services.bootstrap import (
    INITIAL_ADMIN_USERNAME,
    remove_initial_admin_credentials_if_present,
)
from gameframework.services.passwords import DUMMY_PASSWORD_HASH, hash_password, verify_password
from gameframework.services.runs import resolve_current_run
from gameframework.services.sessions import (
    CSRF_TOKEN_TTL,
    PRESESSION_COOKIE_NAME,
    AuthContext,
    InvalidCsrfToken,
    issue_session,
    mint_csrf_token,
    verify_csrf_token,
)
from gameframework.services.users import normalize_username

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
    # api-surface.md §2.2 codes table / ADR-0007 "Failed authentication is
    # answered per source address": checked first and outright, ahead of
    # CSRF — a blocked source gets `429 source_blocked` regardless of
    # what else is wrong with the request.
    source = normalize_source(resolve_client_address(request, settings))
    blocked = check_blocked(db, source)
    if blocked is not None:
        too_many_requests(retry_after_seconds(blocked), code="source_blocked")

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

    user = db.execute(
        select(User).where(User.username == normalize_username(body.username))
    ).scalar_one_or_none()
    if user is None:
        # M2 security gate Task 20 (finding: Medium): pay the same Argon2id
        # cost a known username's wrong-password path pays a few lines
        # below, against a fixed dummy hash nothing derives from real
        # data — the result is discarded, since the answer is
        # unconditionally "unknown account." Without this, response
        # latency alone told a real staff username apart from a
        # nonexistent one, both answering the byte-identical 401
        # invalid_credentials — an oracle ADR-0007's accepted login
        # oracle never names.
        verify_password(body.password, DUMMY_PASSWORD_HASH)
        register_failure(db, source, settings.block_window_minutes)
        raise ProblemError(401, "invalid_credentials")

    # data-model.md §3.1 `is_active` / api-surface.md §2.2: deactivation
    # must refuse the *next* login, or the switch stops nothing — the same
    # account that was just revoked signs straight back in a second later.
    # Checked here, once the account is known to exist and before any
    # role-specific gate: is_active is not player-only, so nesting it under
    # `if user.role is Role.player` below would leave a deactivated staff
    # account unchecked. Ahead of password verification too, joining
    # run_not_started/activation_required in the same accepted-oracle
    # family (ADR-0007's risk register) — the credentials are not what
    # collides here, the account's own state is, so confirming the
    # password first would tell an attacker nothing this check does not
    # already tell them, and would wrongly count a legitimate holder's
    # correct password as a registered failure.
    if not user.is_active:
        raise ProblemError(409, "account_deactivated")

    if user.role is Role.player:
        # api-surface.md §2.6 "Current run, resolved": the run that decides
        # this refusal is the tiered current-run resolution — a readable
        # run (running/paused/finished) always outranks a created one, so
        # a fresh roster import must not sever a participant's access to a
        # run they are still reading or rating. An arbitrary participation
        # lookup here would answer this refusal from whichever run a
        # query happened to return first.
        run = resolve_current_run(db, user)
        if run is not None and run.status is RunStatus.created:
            scheduled_start = (
                run.scheduled_start.isoformat() if run.scheduled_start is not None else None
            )
            raise ProblemError(
                409, "run_not_started", extensions={"scheduled_start": scheduled_start}
            )

        # A not-yet-activated player is refused outright while no OTP
        # is outstanding — but only a player: a captain's own first
        # login carries the same must_change_password and needs no
        # OTP at all (ADR-0007 "Why captains need no OTP"), so this
        # gate applies only once resolve_captaincy rules that out.
        if user.must_change_password and resolve_captaincy(db, user) is None:
            otp_outstanding = (
                user.otp_hash is not None
                and user.otp_consumed_at is None
                and user.otp_expires_at is not None
                and user.otp_expires_at > datetime.now(UTC)
            )
            if not otp_outstanding:
                raise ProblemError(409, "activation_required")

    if not verify_password(body.password, user.password_hash):
        register_failure(db, source, settings.block_window_minutes)
        raise ProblemError(401, "invalid_credentials")

    token, _session_row = issue_session(db, user, settings)

    if user.username == INITIAL_ADMIN_USERNAME and user.role is Role.admin:
        # data-model.md §5 / ADR-0007: removed on this account's first
        # successful login, not on a later password change — an admin who
        # never gets round to choosing their own password would otherwise
        # leave a recoverable credential in the data volume for the life
        # of the installation. Idempotent, so every login after the first
        # is a no-op here.
        remove_initial_admin_credentials_if_present(settings)

    # data-model.md §3.3: only a login that issues an *unrestricted*
    # session resets the counter — one that merely opens a restricted
    # session (username-as-password) is free to obtain for anyone who
    # knows a username, and resetting on it would let a login/OTP-guess
    # cycle defeat the five-attempt limit.
    if not user.must_change_password:
        register_full_success(db, source)

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
    otp: str | None = None


@router.post("/password")
def change_password(
    request: Request,
    body: PasswordChangeRequest,
    response: Response,
    auth: AuthContext = Depends(current_session(*_ANY_AUTHENTICATED_ROLE)),
    db: DbSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, object]:
    source = normalize_source(resolve_client_address(request, settings))

    if not verify_password(body.old_password, auth.user.password_hash):
        raise ProblemError(401, "invalid_credentials")

    # A player's forced first change additionally consumes an OTP — a
    # captain's does not (ADR-0007 "Why captains need no OTP"), so this
    # only applies once resolve_captaincy rules a captain out. Consuming
    # the OTP and changing the password happen on the same `auth.user`
    # row ahead of the one `db.commit()` below, so the two are one
    # transaction: neither can happen without the other. The block gates
    # this OTP submission specifically (api-surface.md §2.16) — not the
    # `old_password` check above, which needs an already-valid session to
    # even reach.
    if auth.user.role is Role.player and auth.user.must_change_password:
        if resolve_captaincy(db, auth.user) is None:
            blocked = check_blocked(db, source)
            if blocked is not None:
                too_many_requests(retry_after_seconds(blocked), code="source_blocked")

            otp_valid = (
                body.otp is not None
                and auth.user.otp_hash is not None
                and verify_password(body.otp, auth.user.otp_hash)
                and auth.user.otp_consumed_at is None
                and auth.user.otp_expires_at is not None
                and auth.user.otp_expires_at > datetime.now(UTC)
            )
            if not otp_valid:
                register_failure(db, source, settings.block_window_minutes)
                raise ProblemError(403, "otp_invalid")
            auth.user.otp_consumed_at = datetime.now(UTC)

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

    # data-model.md §3.3: "a completed activation or password change"
    # resets the counter too, not only an unrestricted login — deliberate
    # (ADR-0007 line 115), not a bypass: several players activating in
    # sequence on one shared PC must not accumulate mistyped OTPs with no
    # reset between them and block the machine on the fifth.
    register_full_success(db, source)

    token, _new_session_row = issue_session(db, auth.user, settings)
    set_session_cookie(response, token, settings)
    return {}
