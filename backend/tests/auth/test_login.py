"""The api-surface.md §2.2 login matrix (M2-Task-Plan.md Task 3 Step 3). No
route in this milestone implements `POST /auth/login` yet — Step 4 does —
so every test here is expected to fail on a missing route (`404` from
FastAPI's own routing, not from `problem_error_handler`), not on a broken
fixture. `uv run pytest tests/auth -x` must show that.

Fixtures insert `User`/`EventRun`/`EventParticipation`/`Team` rows directly.
Each fixture participant holds exactly one participation: the multi-
participation "current run" resolution of §2.6 is Task 12's, and
`resolve_current_run` has no place here.

`password_hash` fixtures use `hash_password` (`services/passwords.py`,
Argon2id via argon2-cffi) directly — Step 3's, not Step 6's, so that no
fixture here is satisfiable by a plaintext-equality login route.

CSRF is deliberately absent from every mutating call below: `require_csrf`
and the login route's `__Host-`-bound pre-session token arrive in Steps 5
and 6 (api-surface.md §1, §2.2).

The three codes asserted below — `run_not_started`, `invalid_credentials`,
and (in `test_session_lifecycle.py`) `session_cookie_ambiguous` — are named
in api-surface.md §1/§2.2. They are not invented here.
"""

import statistics
import time
import uuid
from datetime import UTC, datetime

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete
from sqlalchemy.orm import Session

from gameframework.config import get_settings
from gameframework.db.models.identity import BlockedAddress, Role
from gameframework.db.models.runs import RunStatus
from gameframework.main import app
from gameframework.services.passwords import hash_password

from ..conftest import make_event_run, make_participation, make_team, make_user

SESSION_COOKIE = "__Secure-gf_session"
PRESESSION_COOKIE = "__Host-gf_presession"


def _parse_dt(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _find_set_cookie(response: httpx.Response, cookie_name: str) -> str:
    """The raw `Set-Cookie` header for `cookie_name`, not httpx's cookie
    jar: the jar carries name and value only, drops `HttpOnly` entirely,
    and exposes neither `SameSite` nor `Domain` — an attribute assertion
    against it would be bound to nothing.
    """
    headers = response.headers.get_list("set-cookie")
    for header in headers:
        if header.startswith(f"{cookie_name}="):
            return header
    raise AssertionError(f"no Set-Cookie header for {cookie_name!r} among {headers!r}")


def _cookie_attribute(header: str, name: str) -> str | bool | None:
    """The exact value of one `Set-Cookie` attribute, bounded by the `;`
    delimiters either side — not a substring match against the whole
    header, which a longer or malformed value could also satisfy (a
    `Domain` carrying extra trailing characters, or the expected text
    turning up in some other attribute). A flag attribute (`Secure`,
    `HttpOnly`) with no `=` returns `True`; a name not present returns
    `None`.
    """
    for part in header.split(";"):
        key, sep, value = part.strip().partition("=")
        if key.strip().lower() == name.lower():
            return value if sep else True
    return None


STAFF_ROLES = [Role.admin, Role.gameadmin]
ANY_RUN_STATE: list[RunStatus | None] = [
    None,
    RunStatus.created,
    RunStatus.running,
    RunStatus.paused,
    RunStatus.finished,
    RunStatus.destroyed,
]


@pytest.mark.parametrize("run_state", ANY_RUN_STATE)
@pytest.mark.parametrize("role", STAFF_ROLES)
def test_staff_logs_in_regardless_of_run_state(
    client: TestClient,
    db_session: Session,
    role: Role,
    run_state: RunStatus | None,
) -> None:
    """api-surface.md §2.2: "Admins and gameadmins authenticate at any
    time, whether or not a run exists or has started" — staff hold no
    participation, so no run state can gate them.
    """
    if run_state is not None:
        make_event_run(db_session, status=run_state)
    password = "Staff-Passw0rd!"
    user = make_user(
        db_session,
        role=role,
        must_change_password=False,
        password_hash=hash_password(password),
    )

    response = client.post(
        "/api/v1/auth/login", json={"username": user.username, "password": password}
    )

    assert response.status_code == 200
    assert SESSION_COOKIE in response.cookies


def test_login_response_sets_session_cookie_and_expires_presession_cookie(
    client: TestClient, db_session: Session
) -> None:
    """api-surface.md §2.2's cookie table, checked once and completely
    rather than piecemeal across the parametrized cases above: the session
    cookie's exact attributes, and the other half of the same response —
    `POST /auth/login` also expires the `__Host-gf_presession` cookie that
    covered the login itself. A `__Host-gf_presession` cookie is sent on
    the request so the expiry assertion is about clearing something that
    was actually there; without it, an implementation that clears nothing
    would pass the same assertion for free.
    """
    password = "Staff-Passw0rd!"
    user = make_user(
        db_session,
        role=Role.admin,
        must_change_password=False,
        password_hash=hash_password(password),
    )
    client.cookies.set(PRESESSION_COOKIE, "presession-token-under-test")

    response = client.post(
        "/api/v1/auth/login", json={"username": user.username, "password": password}
    )

    assert response.status_code == 200

    session_header = _find_set_cookie(response, SESSION_COOKIE).lower()
    assert _cookie_attribute(session_header, "path") == "/"
    assert _cookie_attribute(session_header, "domain") == ".event.example.com"
    assert _cookie_attribute(session_header, "httponly") is True
    assert _cookie_attribute(session_header, "secure") is True
    assert _cookie_attribute(session_header, "samesite") == "lax"

    presession_header = _find_set_cookie(response, PRESESSION_COOKIE).lower()
    assert _cookie_attribute(presession_header, "max-age") == "0"
    assert _cookie_attribute(presession_header, "path") == "/"
    assert _cookie_attribute(presession_header, "secure") is True
    assert _cookie_attribute(presession_header, "domain") is None


def test_login_response_session_cookie_domain_follows_the_settings(
    client: TestClient, db_session: Session
) -> None:
    """The `Domain=` attribute assertion above binds to `Settings.cookie_domain`
    only once a *second* value proves it: with the test environment's own
    `GF_COOKIE_DOMAIN` unchanged, an implementation that kept a hardcoded
    constant would pass that assertion by coincidence — the two sources
    happen to agree. Driving a different value through `get_settings` and
    checking the cookie follows it is what makes them two sources rather
    than one.
    """
    other_settings = get_settings().model_copy(update={"cookie_domain": "other.example.org"})
    app.dependency_overrides[get_settings] = lambda: other_settings
    try:
        password = "Staff-Passw0rd!"
        user = make_user(
            db_session,
            role=Role.admin,
            must_change_password=False,
            password_hash=hash_password(password),
        )

        response = client.post(
            "/api/v1/auth/login", json={"username": user.username, "password": password}
        )
    finally:
        app.dependency_overrides.pop(get_settings, None)

    assert response.status_code == 200
    session_header = _find_set_cookie(response, SESSION_COOKIE).lower()
    assert _cookie_attribute(session_header, "domain") == ".other.example.org"


def test_login_response_session_cookie_domain_strips_a_leading_dot_the_operator_typed(
    client: TestClient, db_session: Session
) -> None:
    """`cookie_domain()`'s normalisation itself is unexercised above — both
    values so far are bare domains. This is the path an operator who
    copies `.event.example.com` straight out of documentation actually
    takes: a leading dot in, exactly one dot out. Getting it wrong yields
    `Domain=..third.example.net`, which every browser drops silently —
    the same failure class as the hardcoded constant, one level down.
    """
    other_settings = get_settings().model_copy(update={"cookie_domain": ".third.example.net"})
    app.dependency_overrides[get_settings] = lambda: other_settings
    try:
        password = "Staff-Passw0rd!"
        user = make_user(
            db_session,
            role=Role.admin,
            must_change_password=False,
            password_hash=hash_password(password),
        )

        response = client.post(
            "/api/v1/auth/login", json={"username": user.username, "password": password}
        )
    finally:
        app.dependency_overrides.pop(get_settings, None)

    assert response.status_code == 200
    session_header = _find_set_cookie(response, SESSION_COOKIE).lower()
    assert _cookie_attribute(session_header, "domain") == ".third.example.net"


def test_wrong_password_is_refused_with_invalid_credentials(
    client: TestClient, db_session: Session
) -> None:
    username = "staff-wrong-password"
    make_user(
        db_session,
        username=username,
        role=Role.admin,
        must_change_password=False,
        password_hash=hash_password("correct-password"),
    )

    response = client.post(
        "/api/v1/auth/login", json={"username": username, "password": "wrong-password"}
    )

    assert response.status_code == 401
    assert response.json()["code"] == "invalid_credentials"


def test_participant_refused_while_run_created_with_scheduled_start(
    client: TestClient, db_session: Session
) -> None:
    """Refused with the pre-event splash state, not a wrong-credentials
    error — the credential submitted here (username-as-password) is the
    participant's actual, correct one, so a `401 invalid_credentials`
    result would prove the run-state gate is missing rather than merely
    untested.
    """
    scheduled_start = datetime(2026, 9, 1, 18, 0, tzinfo=UTC)
    run = make_event_run(db_session, status=RunStatus.created, scheduled_start=scheduled_start)
    username = "participant-created-with-start"
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
    body = response.json()
    assert body["code"] == "run_not_started"
    assert _parse_dt(body["scheduled_start"]) == scheduled_start


def test_participant_refused_while_run_created_without_scheduled_start(
    client: TestClient, db_session: Session
) -> None:
    run = make_event_run(db_session, status=RunStatus.created, scheduled_start=None)
    username = "participant-created-no-start"
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
    body = response.json()
    assert body["code"] == "run_not_started"
    assert body["scheduled_start"] is None


def test_captain_login_on_username_as_password_leaves_must_change_password_true(
    client: TestClient, db_session: Session
) -> None:
    """ADR-0007: "Captain, first login — username as password, forced
    change, no OTP." This shows only that `must_change_password` reads
    `True` right after login via `GET /auth/session` — it does **not**
    show the session is restricted, since an unrestricted session carrying
    the same flag would read identically here. No route outside the
    restricted allowlist exists yet in this step to tell the two apart;
    the restriction claim itself — that only `GET /auth/session`,
    `GET /auth/csrf` and `POST /auth/password` are reachable — belongs to
    `test_restricted_session.py` (Step 5).
    """
    run = make_event_run(db_session, status=RunStatus.running)
    username = "captain-first-login"
    user = make_user(
        db_session,
        username=username,
        role=Role.player,
        must_change_password=True,
        password_hash=hash_password(username),
    )
    participation = make_participation(db_session, user=user, run=run)
    team = make_team(db_session, run=run, captain=user)
    participation.team_id = team.id
    db_session.add(participation)
    db_session.commit()

    login_response = client.post(
        "/api/v1/auth/login", json={"username": username, "password": username}
    )
    assert login_response.status_code == 200

    session_response = client.get("/api/v1/auth/session")
    assert session_response.status_code == 200
    assert session_response.json()["must_change_password"] is True


@pytest.mark.parametrize("run_state", [RunStatus.paused, RunStatus.finished])
def test_participant_login_works_in_paused_and_finished(
    client: TestClient, db_session: Session, run_state: RunStatus
) -> None:
    """api-surface.md §2.2: a pause keeps chat and tickets open, and Phase
    3 rating happens in `finished` — an already-activated participant's
    login must work in both.
    """
    run = make_event_run(db_session, status=run_state)
    password = "Chosen-Passw0rd!"
    username = f"player-{run_state.value}"
    user = make_user(
        db_session,
        username=username,
        role=Role.player,
        must_change_password=False,
        password_hash=hash_password(password),
    )
    make_participation(db_session, user=user, run=run)

    response = client.post("/api/v1/auth/login", json={"username": username, "password": password})

    assert response.status_code == 200
    assert SESSION_COOKIE in response.cookies


def test_login_response_time_does_not_distinguish_unknown_staff_username_from_wrong_password(
    client: TestClient, db_session: Session
) -> None:
    """M2 security gate Task 20, finding: Medium. Before this fix, an
    unknown username short-circuited before `verify_password` ran at all,
    while a known username with a wrong password paid a full Argon2id
    verification a few lines later — both answer the byte-identical `401
    invalid_credentials`, so response latency alone (tens of milliseconds
    against sub-millisecond) told the two apart. For staff there is no
    other tell: the participant-specific 409s never fire for `admin`/
    `gameadmin`, so timing was the *only* channel, and ADR-0007's accepted
    login oracle names four categories, all distinguished by response
    *content* — never by latency, and none of the four is "a privileged
    account's existence."

    `services.passwords.DUMMY_PASSWORD_HASH` is what closes it: an unknown
    username now pays the same Argon2id cost against a fixed hash nothing
    derives from real data, so both paths do one lookup plus one
    verification. The two medians can never be made exactly equal —
    scheduling noise and the unknown path's `SELECT` finding no row
    against the known path's finding one are both real, small differences
    — so this asserts a **2x band** rather than equality: tight enough
    that the ~30-50x gap the pre-fix code produced (Argon2id dominates at
    tens of ms; a failed lookup is sub-millisecond) would still fail it
    outright, loose enough that ordinary interleaved-sample jitter on a
    shared CI runner does not make the test flaky.
    """
    n_samples = 30
    password = "Correct-Staff-Passw0rd!"
    username = f"staff-{uuid.uuid4().hex}"
    make_user(
        db_session,
        username=username,
        role=Role.admin,
        must_change_password=False,
        password_hash=hash_password(password),
    )

    def reset_block() -> None:
        # This is a timing measurement, not a test of the block itself
        # (test_blocking.py's job) — driving far more than five attempts
        # from one source needs the counter cleared between every call.
        db_session.execute(delete(BlockedAddress))
        db_session.commit()

    known_wrong_password_times: list[float] = []
    unknown_username_times: list[float] = []

    # Interleaved, not block-then-block, so a shared warm-up effect
    # cannot itself explain a gap between the two groups.
    for _ in range(n_samples):
        reset_block()
        start = time.perf_counter()
        known_response = client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": "definitely-wrong-password"},
        )
        known_wrong_password_times.append(time.perf_counter() - start)
        assert known_response.status_code == 401
        assert known_response.json()["code"] == "invalid_credentials"

        reset_block()
        start = time.perf_counter()
        unknown_response = client.post(
            "/api/v1/auth/login",
            json={
                "username": f"no-such-user-{uuid.uuid4().hex}",
                "password": "irrelevant-password",
            },
        )
        unknown_username_times.append(time.perf_counter() - start)
        assert unknown_response.status_code == 401
        assert unknown_response.json()["code"] == "invalid_credentials"

    known_median = statistics.median(known_wrong_password_times)
    unknown_median = statistics.median(unknown_username_times)
    ratio = known_median / unknown_median

    assert 0.5 <= ratio <= 2.0, (
        f"known-username/wrong-password median={known_median * 1000:.2f}ms, "
        f"unknown-username median={unknown_median * 1000:.2f}ms, "
        f"ratio={ratio:.2f} -- expected within a 2x band of each other now "
        "that both paths pay one Argon2id verification; a ratio outside "
        "this band means account existence is learnable via timing again"
    )
