"""M2-Task-Plan.md Task 8 Step 4: solo mode (api-surface.md §2.4/§2.5;
data-model.md §3.4). "`solo` events are teams of one: the import creates
one team per participant, each their own captain" — the one place a team
is formed without §2.5's `POST /runs/{id}/teams`, wired through
`create_team` in `services/participants.py`'s own write loop rather than a
second team-writing path.
"""

import re

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.db.models.authoring import ParticipationMode
from gameframework.db.models.identity import Role, User
from gameframework.db.models.runs import EventParticipation, RunStatus, Team
from gameframework.services.passwords import hash_password

from ..conftest import make_event_run, make_user

ADMIN_PASSWORD = "Admin-Passw0rd!"
_HANDLE_RE = re.compile(r"[a-z][a-z0-9-]{1,27}")


def _login_as_admin(client: TestClient, db_session: Session) -> User:
    admin = make_user(
        db_session,
        role=Role.admin,
        must_change_password=False,
        password_hash=hash_password(ADMIN_PASSWORD),
    )
    response = client.post(
        "/api/v1/auth/login", json={"username": admin.username, "password": ADMIN_PASSWORD}
    )
    assert response.status_code == 200
    return admin


def _teams_for_run(db_session: Session, run_id: object) -> list[Team]:
    return list(db_session.execute(select(Team).where(Team.event_run_id == run_id)).scalars().all())


def test_solo_import_creates_one_team_per_participant_each_their_own_captain(
    client: TestClient, db_session: Session
) -> None:
    """data-model.md §3.4: "one team per participant, each their own
    captain" — every imported participant gets a team of exactly one,
    captained by themself, and their own participation points at it.
    """
    _login_as_admin(client, db_session)
    run = make_event_run(
        db_session, status=RunStatus.created, participation_mode=ParticipationMode.solo
    )

    response = client.post(
        f"/api/v1/runs/{run.id}/users/import",
        json=[
            {"username": "alice", "name": "Alice", "email": None},
            {"username": "bob", "name": "Bob", "email": None},
            {"username": "carol", "name": "Carol", "email": None},
        ],
    )

    assert response.status_code == 200
    usernames = {row["username"] for row in response.json()["participants"]}
    assert usernames == {"alice", "bob", "carol"}

    teams = _teams_for_run(db_session, run.id)
    assert len(teams) == 3

    participations = (
        db_session.execute(
            select(EventParticipation).where(EventParticipation.event_run_id == run.id)
        )
        .scalars()
        .all()
    )
    assert len(participations) == 3

    teams_by_id = {team.id: team for team in teams}
    for participation in participations:
        assert participation.team_id is not None
        team = teams_by_id[participation.team_id]
        assert team.captain_user_id == participation.user_id

        other_members = [
            p for p in participations if p.team_id == team.id and p.id != participation.id
        ]
        assert other_members == []


def test_solo_import_teams_get_unique_handles(client: TestClient, db_session: Session) -> None:
    """data-model.md §3.11: `team.handle` is run-unique and
    grammar-matching. A batch of ten is the first real caller minting many
    team handles in one call — six hex characters do not collide by
    accident in a batch this size, but this is where `mint_handle`'s
    run-scoped `existing` set is actually exercised across repeated calls
    within one run, rather than the two-team proof in
    `test_atomic_creation.py`.
    """
    _login_as_admin(client, db_session)
    run = make_event_run(
        db_session, status=RunStatus.created, participation_mode=ParticipationMode.solo
    )

    rows = [{"username": f"solo{i}", "name": f"Solo {i}", "email": None} for i in range(10)]
    response = client.post(f"/api/v1/runs/{run.id}/users/import", json=rows)

    assert response.status_code == 200
    teams = _teams_for_run(db_session, run.id)
    assert len(teams) == 10

    handles = [team.handle for team in teams]
    assert len(set(handles)) == 10
    for handle in handles:
        assert _HANDLE_RE.fullmatch(handle)


def test_non_solo_import_creates_no_teams(client: TestClient, db_session: Session) -> None:
    """The negative that keeps "solo" from becoming "always": a `teams`-
    mode run's import (the default `make_event_run` builds) writes
    participations only, exactly as Task 7 left it — no team is formed
    without a `POST /runs/{id}/teams` call.
    """
    _login_as_admin(client, db_session)
    run = make_event_run(
        db_session, status=RunStatus.created, participation_mode=ParticipationMode.teams
    )

    response = client.post(
        f"/api/v1/runs/{run.id}/users/import",
        json=[{"username": "dave", "name": "Dave", "email": None}],
    )

    assert response.status_code == 200
    assert _teams_for_run(db_session, run.id) == []

    participation = db_session.execute(
        select(EventParticipation).where(EventParticipation.event_run_id == run.id)
    ).scalar_one()
    assert participation.team_id is None
