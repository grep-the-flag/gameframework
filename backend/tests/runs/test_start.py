"""M2-Task-Plan.md Task 13 Step 3: the `start` transition
(api-surface.md §2.6; data-model.md §3.12, §6).

`POST /runs/{id}/transition` does not exist on `develop` at the start of
this step, so a first run of this file fails every test on FastAPI's own
routing `404` — a routing red, not proof any individual assertion here
catches what it names (Working-Agreement "a collection error is not a red
proof"). This suite drives everything through the HTTP client rather than
importing `services.runs.start_run` directly, so the red is a `404`
rather than an import error.
"""

import uuid

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.db.models.authoring import Challenge
from gameframework.db.models.feedback import AuditLog
from gameframework.db.models.identity import Role, User
from gameframework.db.models.play import TeamChallenge, TeamChallengeState
from gameframework.db.models.runs import EventRun, RunStatus, Team
from gameframework.services.passwords import hash_password

from ..conftest import (
    make_event_run,
    make_installed_artifact,
    make_participation,
    make_team,
    make_user,
)

ADMIN_PASSWORD = "Admin-Passw0rd!"


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


def _login_as_gameadmin(client: TestClient, db_session: Session) -> User:
    gameadmin = make_user(
        db_session,
        role=Role.gameadmin,
        must_change_password=False,
        password_hash=hash_password(ADMIN_PASSWORD),
    )
    response = client.post(
        "/api/v1/auth/login", json={"username": gameadmin.username, "password": ADMIN_PASSWORD}
    )
    assert response.status_code == 200
    return gameadmin


def _install_minigame(db_session: Session, *, minigame_id: str, digest_char: str = "a") -> None:
    digest = "sha256:" + digest_char * 64
    make_installed_artifact(
        db_session,
        artifact_id=minigame_id,
        version="1.0.0",
        manifest={
            "id": minigame_id,
            "version": "1.0.0",
            "image": f"ghcr.io/org/{minigame_id}@{digest}",
        },
        image_digest=digest,
    )


def _publish_two_challenges_b_depends_on_a(client: TestClient) -> dict[str, object]:
    """`chal-a` has no dependency (startable at `start`); `chal-b` depends
    on `chal-a` (locked at `start`) — the minimal dependency graph the
    materialization claim needs both states from."""
    draft = client.post("/api/v1/event-definitions")
    assert draft.status_code == 201, draft.text
    draft_body = draft.json()
    patched = client.patch(
        f"/api/v1/event-definitions/{draft_body['id']}",
        json={
            "challenges": [
                {
                    "id": "chal-a",
                    "order": 1,
                    "title": {"en": "A"},
                    "text": {"en": "A text"},
                    "minigame": {"id": "mini-a", "version": ">=1.0,<2.0"},
                    "points": 10,
                },
                {
                    "id": "chal-b",
                    "order": 2,
                    "title": {"en": "B"},
                    "text": {"en": "B text"},
                    "minigame": {"id": "mini-b", "version": ">=1.0,<2.0"},
                    "points": 10,
                    "depends_on": ["chal-a"],
                },
            ]
        },
        headers={"If-Match": "1"},
    )
    assert patched.status_code == 200, patched.text
    published = client.post(f"/api/v1/event-definitions/{patched.json()['id']}/publish")
    assert published.status_code == 200, published.text
    return published.json()


def _create_run(client: TestClient, definition_id: str) -> dict[str, object]:
    response = client.post(f"/api/v1/event-definitions/{definition_id}/runs")
    assert response.status_code == 201, response.text
    return response.json()


def _setup_preflighted_run(
    client: TestClient, db_session: Session, *, team_count: int = 2
) -> tuple[dict[str, object], EventRun, list[Team]]:
    """A published two-challenge definition (`chal-a` -> `chal-b`), a run
    of it, `team_count` fully-teamed teams, and a passed preflight —
    exactly what `start` needs to be accepted."""
    _install_minigame(db_session, minigame_id="mini-a", digest_char="a")
    _install_minigame(db_session, minigame_id="mini-b", digest_char="b")
    published = _publish_two_challenges_b_depends_on_a(client)
    run_body = _create_run(client, str(published["id"]))
    run_row = db_session.get(EventRun, uuid.UUID(str(run_body["id"])))
    assert run_row is not None

    teams = []
    for _ in range(team_count):
        team = make_team(db_session, run=run_row)
        make_participation(db_session, run=run_row, team_id=team.id)
        teams.append(team)

    preflight = client.post(f"/api/v1/runs/{run_body['id']}/preflight")
    assert preflight.status_code == 200, preflight.text
    assert preflight.json()["passed"] is True, preflight.json()["errors"]
    db_session.refresh(run_row)

    return run_body, run_row, teams


def _start(client: TestClient, run_id: str) -> httpx.Response:
    return client.post(f"/api/v1/runs/{run_id}/transition", json={"action": "start"})


# ---------------------------------------------------------------------------
# preflight gate
# ---------------------------------------------------------------------------


def test_start_is_409_with_no_passed_preflight(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)
    _install_minigame(db_session, minigame_id="mini-a", digest_char="a")
    _install_minigame(db_session, minigame_id="mini-b", digest_char="b")
    published = _publish_two_challenges_b_depends_on_a(client)
    run_body = _create_run(client, str(published["id"]))
    run_row = db_session.get(EventRun, uuid.UUID(str(run_body["id"])))
    assert run_row is not None
    team = make_team(db_session, run=run_row)
    make_participation(db_session, run=run_row, team_id=team.id)

    response = _start(client, str(run_body["id"]))

    assert response.status_code == 409
    assert response.json()["code"] == "preflight_not_current"


def test_start_accepted_with_a_current_preflight(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)
    run_body, run_row, _teams = _setup_preflighted_run(client, db_session)

    response = _start(client, str(run_body["id"]))

    assert response.status_code == 200, response.text
    db_session.refresh(run_row)
    assert run_row.status == RunStatus.running


def test_start_is_409_again_after_roster_change_stales_hash(
    client: TestClient, db_session: Session
) -> None:
    _login_as_admin(client, db_session)
    run_body, run_row, _teams = _setup_preflighted_run(client, db_session)

    new_team = make_team(db_session, run=run_row)
    new_user = make_user(db_session)
    make_participation(db_session, user=new_user, run=run_row, team_id=new_team.id)

    response = _start(client, str(run_body["id"]))

    assert response.status_code == 409
    assert response.json()["code"] == "preflight_not_current"


# ---------------------------------------------------------------------------
# role gate
# ---------------------------------------------------------------------------


def test_gameadmin_start_is_403(client: TestClient, db_session: Session) -> None:
    _login_as_gameadmin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)

    response = _start(client, str(run.id))

    assert response.status_code == 403
    assert response.json()["code"] == "role_denied"


# ---------------------------------------------------------------------------
# run status / second-run gates
# ---------------------------------------------------------------------------


def test_start_on_non_created_run_is_409(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.running)

    response = _start(client, str(run.id))

    assert response.status_code == 409
    assert response.json()["code"] == "invalid_status_transition"


def test_start_refused_against_second_concurrent_run(
    client: TestClient, db_session: Session
) -> None:
    _login_as_admin(client, db_session)
    # `create_run` itself already refuses a second run while one is
    # active (Task 12), so the "other active run" fixture must land
    # *after* this run exists — both created while neither was active,
    # exactly the sequence that leaves a second `created` run behind
    # once the first one starts.
    run_body, _run_row, _teams = _setup_preflighted_run(client, db_session)
    make_event_run(db_session, status=RunStatus.running)

    response = _start(client, str(run_body["id"]))

    assert response.status_code == 409
    assert response.json()["code"] == "run_active"


def test_start_on_unknown_run_is_404(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)

    response = _start(client, str(uuid.uuid4()))

    assert response.status_code == 404
    assert response.json()["code"] == "object_not_found"


# ---------------------------------------------------------------------------
# materialization
# ---------------------------------------------------------------------------


def test_start_materializes_team_challenge_rows_per_dependency_graph(
    client: TestClient, db_session: Session
) -> None:
    """data-model.md §3.12/§6: one row per team and per challenge,
    `startable` where no dependency stands and `locked` otherwise —
    `chal-a` has none, `chal-b` depends on it."""
    _login_as_admin(client, db_session)
    run_body, run_row, teams = _setup_preflighted_run(client, db_session, team_count=2)

    response = _start(client, str(run_body["id"]))
    assert response.status_code == 200, response.text

    challenges = {
        c.slug: c.id
        for c in db_session.execute(
            select(Challenge).where(Challenge.event_definition_id == run_row.event_definition_id)
        )
        .scalars()
        .all()
    }
    rows = (
        db_session.execute(
            select(TeamChallenge).where(TeamChallenge.team_id.in_([t.id for t in teams]))
        )
        .scalars()
        .all()
    )
    assert len(rows) == 4  # 2 teams x 2 challenges

    by_team_and_challenge = {(r.team_id, r.challenge_id): r.state for r in rows}
    for team in teams:
        assert (
            by_team_and_challenge[(team.id, challenges["chal-a"])] == TeamChallengeState.startable
        )
        assert by_team_and_challenge[(team.id, challenges["chal-b"])] == TeamChallengeState.locked
        assert rows[0].provision_attempts == 0


def test_start_materializes_team_challenge_rows_in_the_same_transaction_as_status_change(
    client: TestClient, db_session: Session
) -> None:
    """data-model.md §6: "the start transition materializes progress:
    one team_challenge row per team and per challenge, written in the
    same transaction as the status change" — bound by mutation in the
    Step 3 report, not merely asserted here: this test's own two
    assertions (status + row count) are what a split-commit mutation is
    read against."""
    _login_as_admin(client, db_session)
    run_body, run_row, teams = _setup_preflighted_run(client, db_session, team_count=1)

    response = _start(client, str(run_body["id"]))
    assert response.status_code == 200, response.text

    db_session.refresh(run_row)
    assert run_row.status == RunStatus.running

    rows = (
        db_session.execute(
            select(TeamChallenge).where(TeamChallenge.team_id.in_([t.id for t in teams]))
        )
        .scalars()
        .all()
    )
    assert len(rows) == 2  # 1 team x 2 challenges


def test_start_is_audited(client: TestClient, db_session: Session) -> None:
    """M2-Task-Plan.md Task 14 Step 2 correction: api-surface.md §2.17's
    "Run lifecycle, keep, legal hold, destroy" row is audited (✅) and
    names `start` explicitly — "start is admin's, like the preflight that
    gates it". Task 13 built the transition without this row; contrast the
    **preflight** row directly above it in the same table, marked `—`: the
    check stays unaudited by design, only the transition it gates is.
    """
    admin = _login_as_admin(client, db_session)
    run_body, run_row, _teams = _setup_preflighted_run(client, db_session)

    response = _start(client, str(run_body["id"]))
    assert response.status_code == 200, response.text

    rows = (
        db_session.execute(
            select(AuditLog).where(
                AuditLog.target_id == run_row.id, AuditLog.action == "event_run_started"
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].actor_user_id == admin.id
