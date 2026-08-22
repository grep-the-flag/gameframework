"""OTP activation (M2-Task-Plan.md Task 4; ADR-0007 "Onboarding, initial
password and OTP" + "OTP properties"; data-model.md §3.1; api-surface.md
§2.2, §2.17). Tests written in Step 2, implementation in Step 3.

Conventions inherited from Task 3 (`M2-Task-Plan.md` Task 3, `conftest.py`):
`client` fetches and attaches a live CSRF token to every mutating request on
its own, so every call below drives it directly; `raw_client` is not used
because no test here asserts anything about a token being absent or wrong.
Each fixture participant holds exactly one participation — the multi-
participation "current run" resolution of §2.6 is Task 12's. `captain` is
never a stored role: a fixture makes one by pointing `team.captain_user_id`
at a `Role.player` user and giving that same user a participation whose
`team_id` names the same team, matching how object scope is resolved from
the live session (§2.17).

Two request-body field names are not in any document — api-surface.md
states plainly that "request/response body schemas are deliberately out of
scope" — so they are chosen here rather than transcribed: `otp` (both the
`POST /auth/otp` response and the field `POST /auth/password` adds beside
`old_password`/`new_password`) and `user_id` (the `POST /auth/otp` target,
since the route carries no path id). Both follow the existing snake_case
`PasswordChangeRequest` fields in `api/auth.py` rather than inventing a new
shape.

A wrong, expired, used or superseded OTP submitted at `POST /auth/password`
is `403 otp_invalid`, one code for all four — api-surface.md's "Cookies,
CSRF transport and codes" table, current as of Step 3. Not `401`: the
session is valid and stays valid, and a client reading `401` as a dead
session would drop the player out of the activation they are in the middle
of. (Step 2 asserted `401 invalid_credentials` here, inferred rather than
transcribed at the time; corrected once the row landed — see the Step 3
report for which tests changed.)

The login refusal is conditional, not blanket: a not-yet-activated player
is refused `409 activation_required` only while no OTP is outstanding for
them. With one outstanding, login succeeds on the username-as-password
every participant starts with and issues a restricted session — the only
way `POST /auth/password`, where the OTP is consumed, is reachable for a
player at all (api-surface.md §2.2). No test below asserts the refusal
regardless of an outstanding OTP; every test that needs a restricted
session for a player with a still-valid OTP goes through a real login to
get one, and only the used/expired/superseded-OTP tests mint a session
directly, because in each of those the OTP is deliberately *not*
outstanding (§2.2's own condition) and a real login would refuse before
`POST /auth/password` was ever reached.

`GET /auth/session`'s `must_change_password` field (Task 3) is what proves
activation completed or did not, exactly as test_login.py's captain test
uses it — no route beyond the restricted allowlist exists at this task's
start to check a full session's reach instead.

The OTP is returned once, at issue, and is never retrievable again
(ADR-0007 "OTP properties" — At rest): every test that needs a real code to
submit either captures it from a `POST /auth/otp` response body at the
moment of issue, or sets a known plaintext directly via `hash_password` in
the fixture — the same pattern `password_hash` fixtures already use
(test_login.py). No test reads `otp_hash` back out of the database and
treats it as the code; that column holds only the hash.
"""

from datetime import UTC, datetime, timedelta

import jwt
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from gameframework.config import get_settings
from gameframework.db.models.identity import Role, User
from gameframework.db.models.identity import Session as SessionModel
from gameframework.db.models.runs import EventRun, RunStatus
from gameframework.services.passwords import hash_password
from gameframework.services.secrets import ensure_signing_key

from ..conftest import make_event_run, make_participation, make_team, make_user

SESSION_COOKIE = "__Secure-gf_session"
_ALGORITHM = "HS256"


def _authenticate(client: TestClient, db_session: Session, user: User) -> SessionModel:
    """Mints a session row and its JWT directly and sets it as the
    client's session cookie, bypassing `POST /auth/login` — the same
    helper `test_session_lifecycle.py` and `test_restricted_session.py`
    use, duplicated rather than imported (conftest.py's own stated reason
    for the same choice: a test module importing from another lets an
    unrelated suite's change break this one). Needed here specifically
    for the used/expired/superseded-OTP tests below, which must reach
    `POST /auth/password` with a restricted session whose OTP state a
    real login could not produce — a consumed or expired OTP is not
    *outstanding*, and login itself refuses outright without one
    (ADR-0007), so those three tests would never get past `POST
    /auth/login` if they tried to.
    """
    key = ensure_signing_key(get_settings())
    session_row = SessionModel(
        user_id=user.id,
        restricted=user.must_change_password,
        expires_at=datetime.now(UTC) + timedelta(hours=12),
    )
    db_session.add(session_row)
    db_session.commit()
    claims = {
        "sub": str(user.id),
        "role": user.role.value,
        "sid": str(session_row.id),
        "iat": int(datetime.now(UTC).timestamp()),
        "exp": int(session_row.expires_at.timestamp()),
    }
    token = jwt.encode(claims, key, algorithm=_ALGORITHM)
    client.cookies.set(SESSION_COOKIE, token)
    return session_row


def test_player_without_outstanding_otp_cannot_log_in(
    client: TestClient, db_session: Session
) -> None:
    """api-surface.md §2.2 codes table: "a player who is not yet activated,
    with no OTP outstanding" answers `409 activation_required`. Asserted
    alongside the code rather than the status alone — `409` is shared with
    `run_not_started` and `session_restricted`, so a status-only check
    would pass against an implementation refusing for the wrong reason.
    The submitted password is the account's actual, correct one
    (username-as-password), so an implementation that fell through to
    `401 invalid_credentials` here would be provably wrong rather than
    merely untested.
    """
    run = make_event_run(db_session, status=RunStatus.running)
    username = "player-no-otp"
    user = make_user(
        db_session,
        username=username,
        role=Role.player,
        must_change_password=True,
        password_hash=hash_password(username),
    )
    make_participation(db_session, user=user, run=run)

    response = client.post("/api/v1/auth/login", json={"username": username, "password": username})

    assert response.status_code == 409
    assert response.json()["code"] == "activation_required"


def test_activation_consumes_otp_via_password_change(
    client: TestClient, db_session: Session
) -> None:
    """ADR-0007 Onboarding: "The player submits it together with the new
    password at the forced change, which consumes it." Proven by
    `otp_consumed_at` moving off null and `must_change_password` flipping
    to `False` (data-model.md §3.1) — not by re-reading the OTP itself back
    out of the database, which holds only its hash.
    """
    run = make_event_run(db_session, status=RunStatus.running)
    username = "player-activates"
    raw_otp = "ABCDEFGH"
    user = make_user(
        db_session,
        username=username,
        role=Role.player,
        must_change_password=True,
        password_hash=hash_password(username),
        otp_hash=hash_password(raw_otp),
        otp_expires_at=datetime.now(UTC) + timedelta(minutes=5),
        otp_consumed_at=None,
    )
    make_participation(db_session, user=user, run=run)

    login_response = client.post(
        "/api/v1/auth/login", json={"username": username, "password": username}
    )
    assert login_response.status_code == 200

    response = client.post(
        "/api/v1/auth/password",
        json={"old_password": username, "otp": raw_otp, "new_password": "New-Passw0rd!"},
    )

    assert response.status_code == 200
    db_session.expire_all()
    db_session.refresh(user)
    assert user.must_change_password is False
    assert user.otp_consumed_at is not None


def test_activation_with_no_otp_field_is_rejected(client: TestClient, db_session: Session) -> None:
    """`PasswordChangeRequest.otp` is `str | None = None`, so a request
    that omits the field entirely is indistinguishable from one that sends
    `"otp": null` — both must be refused exactly like a wrong code, never
    silently accepted as "no OTP to check." Every other activation test
    sends the field, so none of them would catch a route that only
    validates when it is present; this is the one that does.
    """
    run = make_event_run(db_session, status=RunStatus.running)
    username = "player-omits-otp-field"
    raw_otp = "OMITTED1"
    user = make_user(
        db_session,
        username=username,
        role=Role.player,
        must_change_password=True,
        password_hash=hash_password(username),
        otp_hash=hash_password(raw_otp),
        otp_expires_at=datetime.now(UTC) + timedelta(minutes=5),
        otp_consumed_at=None,
    )
    make_participation(db_session, user=user, run=run)

    login_response = client.post(
        "/api/v1/auth/login", json={"username": username, "password": username}
    )
    assert login_response.status_code == 200

    response = client.post(
        "/api/v1/auth/password",
        json={"old_password": username, "new_password": "New-Passw0rd!"},
    )

    assert response.status_code == 403
    assert response.json()["code"] == "otp_invalid"
    db_session.expire_all()
    db_session.refresh(user)
    assert user.must_change_password is True


def test_used_otp_is_rejected_at_password_change(client: TestClient, db_session: Session) -> None:
    """data-model.md §3.1 `otp_consumed_at`: "A consumed OTP is never
    accepted again." The restricted session is minted directly rather than
    through `POST /auth/login`: a consumed OTP is not *outstanding*, so
    login would refuse it outright before `POST /auth/password` is ever
    reached — this isolates the second check from the first.
    """
    password = "player-used-otp"
    raw_otp = "USEDCODE"
    user = make_user(
        db_session,
        role=Role.player,
        must_change_password=True,
        password_hash=hash_password(password),
        otp_hash=hash_password(raw_otp),
        otp_expires_at=datetime.now(UTC) + timedelta(minutes=5),
        otp_consumed_at=datetime.now(UTC) - timedelta(minutes=1),
    )
    _authenticate(client, db_session, user)

    response = client.post(
        "/api/v1/auth/password",
        json={"old_password": password, "otp": raw_otp, "new_password": "New-Passw0rd!"},
    )

    assert response.status_code == 403
    assert response.json()["code"] == "otp_invalid"
    db_session.expire_all()
    db_session.refresh(user)
    assert user.must_change_password is True


def test_expired_otp_is_rejected_at_password_change(
    client: TestClient, db_session: Session
) -> None:
    """data-model.md §3.1 `otp_expires_at`: "an expired OTP is refused like
    a wrong one." Same isolation reasoning as the used-OTP test above: an
    expired OTP is not *outstanding* either, so the restricted session is
    minted directly.
    """
    password = "player-expired-otp"
    raw_otp = "EXPIRED1"
    user = make_user(
        db_session,
        role=Role.player,
        must_change_password=True,
        password_hash=hash_password(password),
        otp_hash=hash_password(raw_otp),
        otp_expires_at=datetime.now(UTC) - timedelta(minutes=1),
        otp_consumed_at=None,
    )
    _authenticate(client, db_session, user)

    response = client.post(
        "/api/v1/auth/password",
        json={"old_password": password, "otp": raw_otp, "new_password": "New-Passw0rd!"},
    )

    assert response.status_code == 403
    assert response.json()["code"] == "otp_invalid"
    db_session.expire_all()
    db_session.refresh(user)
    assert user.must_change_password is True


def test_superseded_otp_is_rejected_at_password_change(
    client: TestClient, db_session: Session
) -> None:
    """data-model.md §3.1: "issuing a new [OTP] supersedes any outstanding
    one... a single overwrite of `otp_hash`/`otp_expires_at`." The user
    carries only the *new* code's hash; submitting the stale one that was
    superseded must fail even though it once was outstanding.
    """
    password = "player-superseded-otp"
    stale_otp = "STALEOLD"
    current_otp = "FRESHNEW"
    user = make_user(
        db_session,
        role=Role.player,
        must_change_password=True,
        password_hash=hash_password(password),
        otp_hash=hash_password(current_otp),
        otp_expires_at=datetime.now(UTC) + timedelta(minutes=5),
        otp_consumed_at=None,
    )
    _authenticate(client, db_session, user)

    response = client.post(
        "/api/v1/auth/password",
        json={"old_password": password, "otp": stale_otp, "new_password": "New-Passw0rd!"},
    )

    assert response.status_code == 403
    assert response.json()["code"] == "otp_invalid"
    db_session.expire_all()
    db_session.refresh(user)
    assert user.must_change_password is True


def test_wrong_otp_leaves_outstanding_one_valid(client: TestClient, db_session: Session) -> None:
    """ADR-0007 "Retry limit": "a wrong OTP leaves the outstanding one
    valid — burning it on wrong guesses would hand anyone who knows a
    username a way to destroy a player's access code by typing nonsense
    five times." Proven by submitting a wrong code first, in the same
    restricted session a real login issued, and then completing activation
    with the real one right after.
    """
    run = make_event_run(db_session, status=RunStatus.running)
    username = "player-wrong-guess"
    raw_otp = "REALCODE"
    user = make_user(
        db_session,
        username=username,
        role=Role.player,
        must_change_password=True,
        password_hash=hash_password(username),
        otp_hash=hash_password(raw_otp),
        otp_expires_at=datetime.now(UTC) + timedelta(minutes=5),
        otp_consumed_at=None,
    )
    make_participation(db_session, user=user, run=run)

    login_response = client.post(
        "/api/v1/auth/login", json={"username": username, "password": username}
    )
    assert login_response.status_code == 200

    wrong_response = client.post(
        "/api/v1/auth/password",
        json={"old_password": username, "otp": "WRONGONE", "new_password": "New-Passw0rd!"},
    )
    assert wrong_response.status_code == 403
    assert wrong_response.json()["code"] == "otp_invalid"

    correct_response = client.post(
        "/api/v1/auth/password",
        json={"old_password": username, "otp": raw_otp, "new_password": "New-Passw0rd!"},
    )
    assert correct_response.status_code == 200
    db_session.expire_all()
    db_session.refresh(user)
    assert user.must_change_password is False


def test_otp_expiry_resolved_at_issue_and_survives_later_setting_change(
    client: TestClient, db_session: Session
) -> None:
    """ADR-0007 "OTP properties" — Lifetime: "resolved at issue so a later
    change of that setting never moves an OTP already in someone's hand"
    (data-model.md §3.1 `otp_expires_at`). Two assertions, not one: the
    first shows the expiry actually reads the run's `otp_lifetime_minutes`
    rather than a hardcoded default — 42 is deliberately not the model's
    own default of 5, so an implementation that ignored the run's setting
    could not pass by coincidence; the second shows a later change to that
    same run's setting does not reach back and move the OTP already issued.
    `PATCH /runs/{id}` (api-surface.md §2.6) does not exist this early in
    the milestone, so the setting change is written directly to the row,
    same as the run itself is built.
    """
    run = make_event_run(db_session, status=RunStatus.running, otp_lifetime_minutes=42)
    admin = make_user(
        db_session,
        role=Role.admin,
        must_change_password=False,
        password_hash=hash_password("Admin-Passw0rd!"),
    )
    _authenticate(client, db_session, admin)
    player = make_user(
        db_session,
        role=Role.player,
        must_change_password=True,
        password_hash=hash_password("player-expiry-target"),
    )
    make_participation(db_session, user=player, run=run)

    before_issue = datetime.now(UTC)
    response = client.post("/api/v1/auth/otp", json={"user_id": str(player.id)})
    after_issue = datetime.now(UTC)

    assert response.status_code == 200
    db_session.expire_all()
    db_session.refresh(player)
    assert player.otp_expires_at is not None
    assert before_issue + timedelta(minutes=42) <= player.otp_expires_at
    assert player.otp_expires_at <= after_issue + timedelta(minutes=42) + timedelta(seconds=5)
    issued_expiry = player.otp_expires_at

    run.otp_lifetime_minutes = 99
    db_session.add(run)
    db_session.commit()

    db_session.expire_all()
    db_session.refresh(player)
    assert player.otp_expires_at == issued_expiry


def _own_team_and_other_team(db_session: Session) -> tuple[EventRun, User, User, User]:
    """A run with two teams, each with its own captain and one player, for
    the api-surface.md §2.17 `POST /auth/otp` scope row: `players of own
    team` for a captain, `any` for admin/gameadmin. `captain` is derived
    (data-model.md §3.1/§3.11), never a stored role: the returned captain
    is a `Role.player` user who is both `own_team.captain_user_id` and
    holds a participation whose `team_id` names that same team, matching
    how object scope is resolved from the live session.
    """
    run = make_event_run(db_session, status=RunStatus.running)
    captain = make_user(
        db_session,
        role=Role.player,
        must_change_password=False,
        password_hash=hash_password("captain-passw0rd"),
    )
    own_team = make_team(db_session, run=run, captain=captain)
    make_participation(db_session, user=captain, run=run, team_id=own_team.id)

    own_player = make_user(
        db_session,
        role=Role.player,
        must_change_password=True,
        password_hash=hash_password("own-team-player"),
    )
    make_participation(db_session, user=own_player, run=run, team_id=own_team.id)

    other_team = make_team(db_session, run=run)
    other_player = make_user(
        db_session,
        role=Role.player,
        must_change_password=True,
        password_hash=hash_password("other-team-player"),
    )
    make_participation(db_session, user=other_player, run=run, team_id=other_team.id)

    return run, captain, own_player, other_player


def test_captain_issues_otp_for_own_team_player(client: TestClient, db_session: Session) -> None:
    _run, captain, own_player, _other_player = _own_team_and_other_team(db_session)
    _authenticate(client, db_session, captain)

    response = client.post("/api/v1/auth/otp", json={"user_id": str(own_player.id)})

    assert response.status_code == 200
    assert isinstance(response.json()["otp"], str)


def test_captain_refused_issuing_otp_for_other_teams_player(
    client: TestClient, db_session: Session
) -> None:
    """The negative half of the scope check: the same captain who succeeds
    against their own team's player above is refused against a player on a
    different team in the same run — otherwise the positive case alone
    would be consistent with a captain able to issue for anybody. §1's
    denial split: the caller's role may call this route at all, so what
    collides is the object's scope, which is non-disclosure (`404
    object_not_found`), never `403`.
    """
    _run, captain, _own_player, other_player = _own_team_and_other_team(db_session)
    _authenticate(client, db_session, captain)

    response = client.post("/api/v1/auth/otp", json={"user_id": str(other_player.id)})

    assert response.status_code == 404
    assert response.json()["code"] == "object_not_found"
