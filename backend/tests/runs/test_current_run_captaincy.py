"""M2-Task-Plan.md Task 12 Step 4: captaincy and the session's team resolve
inside the caller's *current run* (api-surface.md §2.6 "current run",
§2.17, §2.2), never across every participation the account holds.

Two accounts, each holding two participations — one in a `finished` run,
one in the `running` run — mirror each other:

- Account A captains its team in the `finished` run and is a plain member
  of a team in the `running` one. Where it now plays it is no captain, so
  it is refused as any player is: `PATCH /teams/{its old team}` and
  `POST /auth/otp` for an old teammate answer `403 role_denied`, and its
  login is held to the OTP gate (`409 activation_required`).
- Account B is the mirror: plain member in the `finished` run, captain in
  the `running` one. It renames its current team and issues an OTP for a
  current teammate. B's cases are green before the fix — they exist to
  bind the fix against over-narrowing, not to prove the defect.

Every case runs over both insertion orders of the account's two
participation rows. An unordered query returns whichever row the heap
yields first, so one order passes by accident; running both is what makes
the defect visible rather than order-dependent (Working-Agreement.md,
"Verification standards that earned their place").

`GET /auth/session` names the caller's team in the current run and whether
they captain it as `team_id` and `is_captain`; an admin has no team.
Absent keys are read with a sentinel so a missing field fails as an
assertion showing `<missing>`, never as a `KeyError`, and an admin's
`team_id: null` cannot be satisfied by the key's absence.
"""

import uuid
from dataclasses import dataclass
from typing import Literal

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from gameframework.db.models.identity import Role, User
from gameframework.db.models.runs import EventRun, RunStatus, Team
from gameframework.services.passwords import hash_password

from ..conftest import make_event_run, make_participation, make_team, make_user

InsertionOrder = Literal["finished_row_first", "running_row_first"]

# Both orders of the account's two participation rows, for every case.
BOTH_ORDERS: list[InsertionOrder] = ["finished_row_first", "running_row_first"]

_MISSING = "<missing>"


@dataclass(frozen=True)
class TwoRunAccount:
    """One account with a participation in a `finished` run and one in the
    `running` run, plus the teammate each of its teams holds besides it.
    """

    user: User
    finished_run: EventRun
    running_run: EventRun
    finished_team: Team
    running_team: Team
    finished_teammate: User
    running_teammate: User


def _player(db_session: Session, *, must_change_password: bool = False) -> User:
    username = f"player-{uuid.uuid4().hex[:8]}"
    return make_user(
        db_session,
        username=username,
        role=Role.player,
        must_change_password=must_change_password,
        password_hash=hash_password(username),
    )


def _build_account(
    db_session: Session,
    *,
    captain_in: Literal["finished", "running"],
    order: InsertionOrder,
    must_change_password: bool = False,
) -> TwoRunAccount:
    """The account captains its team in `captain_in` and is a plain member
    of the other run's team, whose captain is a different player. Every
    other participation is written first; the account's own two rows go in
    last, in `order`, so that `order` is the only thing that varies the
    physical row sequence the account's participations are read in.
    """
    account = _player(db_session, must_change_password=must_change_password)
    rival_captain = _player(db_session)
    finished_teammate = _player(db_session)
    running_teammate = _player(db_session)

    finished_run = make_event_run(db_session, status=RunStatus.finished)
    running_run = make_event_run(db_session, status=RunStatus.running)

    finished_team = make_team(
        db_session,
        finished_run,
        captain=account if captain_in == "finished" else rival_captain,
    )
    running_team = make_team(
        db_session,
        running_run,
        captain=account if captain_in == "running" else rival_captain,
    )

    # The rival captain plays in the run where the account is a plain member.
    rival_run, rival_team = (
        (running_run, running_team) if captain_in == "finished" else (finished_run, finished_team)
    )
    make_participation(db_session, user=rival_captain, run=rival_run, team_id=rival_team.id)
    make_participation(
        db_session, user=finished_teammate, run=finished_run, team_id=finished_team.id
    )
    make_participation(db_session, user=running_teammate, run=running_run, team_id=running_team.id)

    own_rows = {
        "finished_row_first": [(finished_run, finished_team), (running_run, running_team)],
        "running_row_first": [(running_run, running_team), (finished_run, finished_team)],
    }[order]
    for run, team in own_rows:
        make_participation(db_session, user=account, run=run, team_id=team.id)

    return TwoRunAccount(
        user=account,
        finished_run=finished_run,
        running_run=running_run,
        finished_team=finished_team,
        running_team=running_team,
        finished_teammate=finished_teammate,
        running_teammate=running_teammate,
    )


def _login(client: TestClient, user: User) -> None:
    """Username-as-password, the way every participant starts."""
    response = client.post(
        "/api/v1/auth/login", json={"username": user.username, "password": user.username}
    )
    assert response.status_code == 200, response.text


def _session_fields(client: TestClient) -> dict[str, object]:
    response = client.get("/api/v1/auth/session")
    assert response.status_code == 200, response.text
    body = response.json()
    return {
        "team_id": body.get("team_id", _MISSING),
        "is_captain": body.get("is_captain", _MISSING),
    }


# ---------------------------------------------------------------------------
# Account A — captain in the finished run, plain member in the running one
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("order", BOTH_ORDERS)
def test_former_captain_cannot_rename_the_team_it_captained_in_the_finished_run(
    client: TestClient, db_session: Session, order: InsertionOrder
) -> None:
    """Where A plays now it captains nothing, so `PATCH /teams/{id}` on the
    old team is refused at the role level, exactly as for any player
    (api-surface.md §2.17: `own team`, resolved in the current run) — and
    the old team's name is unchanged.
    """
    scenario = _build_account(db_session, captain_in="finished", order=order)
    old_name = scenario.finished_team.name
    _login(client, scenario.user)

    response = client.patch(
        f"/api/v1/teams/{scenario.finished_team.id}", json={"name": "Renamed By A"}
    )

    assert response.status_code == 403, response.text
    assert response.json()["code"] == "role_denied"
    db_session.refresh(scenario.finished_team)
    assert scenario.finished_team.name == old_name


@pytest.mark.parametrize("order", BOTH_ORDERS)
def test_former_captain_cannot_issue_an_otp_for_an_old_teammate(
    client: TestClient, db_session: Session, order: InsertionOrder
) -> None:
    """`POST /auth/otp` is `players of own team` (api-surface.md §2.17) in
    the caller's current run. A is a plain player there, so it is refused
    as any player is — `role_denied` — and no OTP is written for the old
    teammate.
    """
    scenario = _build_account(db_session, captain_in="finished", order=order)
    _login(client, scenario.user)

    response = client.post("/api/v1/auth/otp", json={"user_id": str(scenario.finished_teammate.id)})

    assert response.status_code == 403, response.text
    assert response.json()["code"] == "role_denied"
    db_session.refresh(scenario.finished_teammate)
    assert scenario.finished_teammate.otp_hash is None


@pytest.mark.parametrize("order", BOTH_ORDERS)
def test_former_captain_with_must_change_password_is_held_to_the_otp_gate(
    client: TestClient, db_session: Session, order: InsertionOrder
) -> None:
    """The login activation gate exempts a captain only (ADR-0007 "Why
    captains need no OTP"). A captains nothing in its current run, so with
    `must_change_password` and no OTP outstanding it is refused
    `409 activation_required` — not issued a restricted session.
    """
    scenario = _build_account(
        db_session, captain_in="finished", order=order, must_change_password=True
    )

    response = client.post(
        "/api/v1/auth/login",
        json={"username": scenario.user.username, "password": scenario.user.username},
    )

    assert response.status_code == 409, response.text
    assert response.json()["code"] == "activation_required"


# ---------------------------------------------------------------------------
# Account B — plain member in the finished run, captain in the running one.
# Green before the fix: these guard the fix against over-narrowing.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("order", BOTH_ORDERS)
def test_current_captain_renames_its_current_team(
    client: TestClient, db_session: Session, order: InsertionOrder
) -> None:
    scenario = _build_account(db_session, captain_in="running", order=order)
    _login(client, scenario.user)

    response = client.patch(
        f"/api/v1/teams/{scenario.running_team.id}", json={"name": "Renamed By B"}
    )

    assert response.status_code == 200, response.text
    assert response.json()["name"] == "Renamed By B"
    db_session.refresh(scenario.running_team)
    assert scenario.running_team.name == "Renamed By B"


@pytest.mark.parametrize("order", BOTH_ORDERS)
def test_current_captain_issues_an_otp_for_a_current_teammate(
    client: TestClient, db_session: Session, order: InsertionOrder
) -> None:
    scenario = _build_account(db_session, captain_in="running", order=order)
    _login(client, scenario.user)

    response = client.post("/api/v1/auth/otp", json={"user_id": str(scenario.running_teammate.id)})

    assert response.status_code == 200, response.text
    assert response.json()["otp"]
    db_session.refresh(scenario.running_teammate)
    assert scenario.running_teammate.otp_hash is not None


# ---------------------------------------------------------------------------
# GET /auth/session — the caller's team in the current run, and whether they
# captain it (api-surface.md §2.2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("order", BOTH_ORDERS)
def test_session_names_the_running_runs_team_and_no_captaincy_for_the_former_captain(
    client: TestClient, db_session: Session, order: InsertionOrder
) -> None:
    scenario = _build_account(db_session, captain_in="finished", order=order)
    _login(client, scenario.user)

    assert _session_fields(client) == {
        "team_id": str(scenario.running_team.id),
        "is_captain": False,
    }


@pytest.mark.parametrize("order", BOTH_ORDERS)
def test_session_names_the_running_runs_team_and_captaincy_for_the_current_captain(
    client: TestClient, db_session: Session, order: InsertionOrder
) -> None:
    scenario = _build_account(db_session, captain_in="running", order=order)
    _login(client, scenario.user)

    assert _session_fields(client) == {
        "team_id": str(scenario.running_team.id),
        "is_captain": True,
    }


def test_session_names_no_team_for_staff(client: TestClient, db_session: Session) -> None:
    """A run with a team exists, so a `null` is the staff rule and not an
    empty installation. The account holds no participation, so there is no
    insertion order to vary.
    """
    admin_password = "Admin-Passw0rd!"
    admin = make_user(
        db_session,
        role=Role.admin,
        must_change_password=False,
        password_hash=hash_password(admin_password),
    )
    run = make_event_run(db_session, status=RunStatus.running)
    make_team(db_session, run)
    response = client.post(
        "/api/v1/auth/login", json={"username": admin.username, "password": admin_password}
    )
    assert response.status_code == 200, response.text

    assert _session_fields(client) == {"team_id": None, "is_captain": False}
