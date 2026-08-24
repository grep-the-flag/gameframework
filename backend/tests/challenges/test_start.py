"""M2-Task-Plan.md Task 15 Step 2: `POST /challenges/{id}/start`
(api-surface.md §2.7, §2.17; data-model.md §3.12, §3.24, §6).

Fixtures build `team_challenge` rows directly rather than driving a full
definition-authoring + preflight + `start` flow: Task 13's `start`
transition is what materializes one row per team and per challenge
(`startable`/`locked` by the dependency graph at that moment) — this task
transitions a row, it does not create the set, so a fixture standing in
for "the set already exists" is the right level for this suite.

The lowest-eligible-order claim is built on a **branching** DAG (one root,
two children with different `order`, both unlocked by the same solved
root) rather than a chain: on a chain, "lowest eligible order" and "the
only eligible one" are the same answer, and a test built on one cannot
tell a correct implementation from one that returns whatever it finds
first.

This suite drives everything through the HTTP client, so the first red is
FastAPI's own routing `404` — a routing miss, not proof any individual
assertion catches what it names (Working-Agreement "a collection error is
not a red proof"; `tests/runs/test_start.py` notes the same).
"""

import uuid
from datetime import UTC, datetime, timedelta

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.db.models.authoring import Challenge, EventDefinition, UnlockMode
from gameframework.db.models.identity import Role, User
from gameframework.db.models.infrastructure import Job
from gameframework.db.models.play import TeamChallenge, TeamChallengeState
from gameframework.db.models.runs import EventRun, RunStatus, Team
from gameframework.services.passwords import hash_password

from ..conftest import (
    make_challenge,
    make_challenge_dependency,
    make_event_definition,
    make_event_run,
    make_participation,
    make_team,
    make_team_challenge,
    make_user,
)

ADMIN_PASSWORD = "Admin-Passw0rd!"


def _setup_team_in_run(
    db_session: Session,
    *,
    run_status: RunStatus = RunStatus.running,
    unlock_mode: UnlockMode = UnlockMode.manual,
    captain: bool = False,
) -> tuple[EventDefinition, EventRun, Team, User]:
    definition = make_event_definition(db_session, unlock_mode=unlock_mode)
    run = make_event_run(
        db_session, definition=definition, status=run_status, unlock_mode=unlock_mode
    )
    username = f"player-{uuid.uuid4().hex[:8]}"
    player = make_user(
        db_session,
        username=username,
        role=Role.player,
        must_change_password=False,
        password_hash=hash_password(username),
    )
    if captain:
        team = make_team(db_session, run=run, captain=player)
    else:
        team = make_team(db_session, run=run)
    make_participation(db_session, user=player, run=run, team_id=team.id)
    return definition, run, team, player


def _login(client: TestClient, player: User) -> None:
    response = client.post(
        "/api/v1/auth/login", json={"username": player.username, "password": player.username}
    )
    assert response.status_code == 200, response.text


def _start(client: TestClient, challenge_id: uuid.UUID, **kwargs: object) -> httpx.Response:
    return client.post(f"/api/v1/challenges/{challenge_id}/start", **kwargs)  # type: ignore[arg-type]


def _make_branching_dag(
    db_session: Session, definition: EventDefinition
) -> tuple[Challenge, Challenge, Challenge]:
    """One root, two children — `child_a` (`order` 2) and `child_b`
    (`order` 3) — each depending on the root alone, so both become
    eligible the moment the root is solved. A chain (`a` -> `b` -> `c`)
    cannot distinguish "lowest eligible order" from "the only eligible
    one"; this can."""
    root = make_challenge(db_session, definition=definition, order_num=1, minigame_id="mini-root")
    child_a = make_challenge(db_session, definition=definition, order_num=2, minigame_id="mini-a")
    child_b = make_challenge(db_session, definition=definition, order_num=3, minigame_id="mini-b")
    make_challenge_dependency(db_session, child_a, root)
    make_challenge_dependency(db_session, child_b, root)
    return root, child_a, child_b


# ---------------------------------------------------------------------------
# occupancy — two halves, two rows (data-model.md §6)
# ---------------------------------------------------------------------------


def test_start_refused_while_team_has_a_provisioning_challenge(
    client: TestClient, db_session: Session
) -> None:
    definition, _run, team, player = _setup_team_in_run(db_session)
    challenge_a = make_challenge(
        db_session, definition=definition, order_num=1, minigame_id="mini-a"
    )
    challenge_b = make_challenge(
        db_session, definition=definition, order_num=2, minigame_id="mini-b"
    )
    make_team_challenge(db_session, team, challenge_a, state=TeamChallengeState.provisioning)
    make_team_challenge(db_session, team, challenge_b, state=TeamChallengeState.startable)
    _login(client, player)

    response = _start(client, challenge_b.id)

    assert response.status_code == 409, response.text
    body = response.json()
    assert body["code"] == "team_occupied"
    assert body["challenge_id"] == str(challenge_a.id)
    assert body["challenge_state"] == "provisioning"


def test_start_refused_while_team_has_a_provision_failed_challenge(
    client: TestClient, db_session: Session
) -> None:
    """§2.7/§6: `provision_failed` occupies the team exactly like
    `provisioning`/`active`, but sits outside data-model.md §3.12's
    partial unique index — this service check is the only thing that
    enforces this half."""
    definition, _run, team, player = _setup_team_in_run(db_session)
    challenge_a = make_challenge(
        db_session, definition=definition, order_num=1, minigame_id="mini-a"
    )
    challenge_b = make_challenge(
        db_session, definition=definition, order_num=2, minigame_id="mini-b"
    )
    make_team_challenge(db_session, team, challenge_a, state=TeamChallengeState.provision_failed)
    make_team_challenge(db_session, team, challenge_b, state=TeamChallengeState.startable)
    _login(client, player)

    response = _start(client, challenge_b.id)

    assert response.status_code == 409, response.text
    body = response.json()
    assert body["code"] == "team_occupied"
    assert body["challenge_id"] == str(challenge_a.id)
    assert body["challenge_state"] == "provision_failed"


# ---------------------------------------------------------------------------
# eligibility — dependency solved, fixture-solved rows unlock dependents
# ---------------------------------------------------------------------------


def test_start_refused_when_dependency_unsolved(client: TestClient, db_session: Session) -> None:
    definition, _run, team, player = _setup_team_in_run(db_session)
    challenge_a = make_challenge(
        db_session, definition=definition, order_num=1, minigame_id="mini-a"
    )
    challenge_b = make_challenge(
        db_session, definition=definition, order_num=2, minigame_id="mini-b"
    )
    make_challenge_dependency(db_session, challenge_b, challenge_a)
    make_team_challenge(db_session, team, challenge_a, state=TeamChallengeState.startable)
    make_team_challenge(db_session, team, challenge_b, state=TeamChallengeState.locked)
    _login(client, player)

    response = _start(client, challenge_b.id)

    assert response.status_code == 409, response.text
    body = response.json()
    assert body["code"] == "challenge_not_offered"
    # api-surface.md §2.7: deliberately no discriminator — "dependency
    # unmet" is a fact about the challenge graph, and the graph is what
    # ADR-0004's hidden titles withhold. The base Problem Details shape
    # only, nothing naming what specifically disqualified it.
    assert set(body.keys()) == {"type", "title", "status", "code", "request_id"}


def test_start_succeeds_when_fixture_solved_dependency_unlocks_dependent(
    client: TestClient, db_session: Session
) -> None:
    """The dependent's own `state` column is still `locked` — Task 13's
    materialization, and nothing in M2 moves it forward as dependencies
    solve — so this only passes if eligibility is recomputed from the
    dependency graph and current states rather than trusted off that
    label (data-model.md §6: "in one snapshot")."""
    definition, _run, team, player = _setup_team_in_run(db_session)
    challenge_a = make_challenge(
        db_session, definition=definition, order_num=1, minigame_id="mini-a"
    )
    challenge_b = make_challenge(
        db_session, definition=definition, order_num=2, minigame_id="mini-b"
    )
    make_challenge_dependency(db_session, challenge_b, challenge_a)
    make_team_challenge(db_session, team, challenge_a, state=TeamChallengeState.solved)
    make_team_challenge(db_session, team, challenge_b, state=TeamChallengeState.locked)
    _login(client, player)

    response = _start(client, challenge_b.id)

    assert response.status_code == 200, response.text
    assert response.json()["state"] == "provisioning"
    row = db_session.get(TeamChallenge, (team.id, challenge_b.id))
    assert row is not None
    assert row.state == TeamChallengeState.provisioning
    assert row.started_at is not None


# ---------------------------------------------------------------------------
# manual mode offers every eligible challenge
# ---------------------------------------------------------------------------


def test_manual_mode_offers_every_eligible_challenge(
    client: TestClient, db_session: Session
) -> None:
    definition, _run, team, player = _setup_team_in_run(db_session, unlock_mode=UnlockMode.manual)
    challenge_a = make_challenge(
        db_session, definition=definition, order_num=1, minigame_id="mini-a"
    )
    challenge_b = make_challenge(
        db_session, definition=definition, order_num=2, minigame_id="mini-b"
    )
    make_team_challenge(db_session, team, challenge_a, state=TeamChallengeState.startable)
    make_team_challenge(db_session, team, challenge_b, state=TeamChallengeState.startable)
    _login(client, player)

    response = _start(client, challenge_b.id)

    assert response.status_code == 200, response.text


# ---------------------------------------------------------------------------
# guided mode — branching DAG
# ---------------------------------------------------------------------------


def test_guided_mode_offers_the_lowest_order_eligible_challenge_on_a_branching_dag(
    client: TestClient, db_session: Session
) -> None:
    definition, _run, team, player = _setup_team_in_run(db_session, unlock_mode=UnlockMode.guided)
    root, child_a, _child_b = _make_branching_dag(db_session, definition)
    make_team_challenge(db_session, team, root, state=TeamChallengeState.solved)
    make_team_challenge(db_session, team, child_a, state=TeamChallengeState.locked)
    make_team_challenge(db_session, team, _child_b, state=TeamChallengeState.locked)
    _login(client, player)

    response = _start(client, child_a.id)

    assert response.status_code == 200, response.text


def test_guided_mode_refuses_the_higher_order_eligible_challenge_on_a_branching_dag(
    client: TestClient, db_session: Session
) -> None:
    definition, _run, team, player = _setup_team_in_run(db_session, unlock_mode=UnlockMode.guided)
    root, child_a, child_b = _make_branching_dag(db_session, definition)
    make_team_challenge(db_session, team, root, state=TeamChallengeState.solved)
    make_team_challenge(db_session, team, child_a, state=TeamChallengeState.locked)
    make_team_challenge(db_session, team, child_b, state=TeamChallengeState.locked)
    _login(client, player)

    response = _start(client, child_b.id)

    assert response.status_code == 409, response.text
    body = response.json()
    assert body["code"] == "challenge_not_offered"
    # api-surface.md §2.7: "not the lowest order" is withheld the same way
    # as "dependency unmet" — no discriminator distinguishing the two.
    assert set(body.keys()) == {"type", "title", "status", "code", "request_id"}


def test_manual_mode_allows_the_higher_order_eligible_challenge_on_the_same_dag(
    client: TestClient, db_session: Session
) -> None:
    """The mirror of the two guided tests above, same DAG: manual mode
    places no order constraint on an otherwise-eligible challenge."""
    definition, _run, team, player = _setup_team_in_run(db_session, unlock_mode=UnlockMode.manual)
    root, child_a, child_b = _make_branching_dag(db_session, definition)
    make_team_challenge(db_session, team, root, state=TeamChallengeState.solved)
    make_team_challenge(db_session, team, child_a, state=TeamChallengeState.locked)
    make_team_challenge(db_session, team, child_b, state=TeamChallengeState.locked)
    _login(client, player)

    response = _start(client, child_b.id)

    assert response.status_code == 200, response.text


# ---------------------------------------------------------------------------
# the provision job row, and the idempotent replay it enables
# ---------------------------------------------------------------------------


def test_start_writes_a_provision_job_with_the_expected_business_key(
    client: TestClient, db_session: Session
) -> None:
    definition, _run, team, player = _setup_team_in_run(db_session)
    challenge = make_challenge(db_session, definition=definition, minigame_id="mini-solo")
    make_team_challenge(db_session, team, challenge, state=TeamChallengeState.startable)
    _login(client, player)

    response = _start(client, challenge.id)

    assert response.status_code == 200, response.text
    jobs = (
        db_session.execute(select(Job).where(Job.business_key == f"mini-solo:{team.id}"))
        .scalars()
        .all()
    )
    assert len(jobs) == 1
    assert jobs[0].job_type == "provision"


def test_malformed_idempotency_key_is_refused_422(client: TestClient, db_session: Session) -> None:
    """api-surface.md §1: the header is validated (format/length) on every
    route that names it, `POST /challenges/{id}/start` among them —
    format-only, since replay safety comes from the job's business key
    rather than the header's value (proven separately below)."""
    definition, _run, team, player = _setup_team_in_run(db_session)
    challenge = make_challenge(db_session, definition=definition)
    make_team_challenge(db_session, team, challenge, state=TeamChallengeState.startable)
    _login(client, player)

    response = _start(client, challenge.id, headers={"Idempotency-Key": "bad key with spaces!"})

    assert response.status_code == 422
    assert response.json()["code"] == "idempotency_key_invalid"


def test_repeated_start_with_same_idempotency_key_writes_one_job_row(
    client: TestClient, db_session: Session
) -> None:
    """The business key — not a replay store — is what makes this route
    idempotent (api-surface.md §1; data-model.md §3.24's unique
    `(job_type, business_key)`). Asserting the row count is the point: a
    route answering `200` twice while inserting twice would still pass a
    response-only assertion."""
    definition, _run, team, player = _setup_team_in_run(db_session)
    challenge = make_challenge(db_session, definition=definition, minigame_id="mini-solo")
    make_team_challenge(db_session, team, challenge, state=TeamChallengeState.startable)
    _login(client, player)
    headers = {"Idempotency-Key": "retry-key-1"}

    first = _start(client, challenge.id, headers=headers)
    assert first.status_code == 200, first.text

    second = _start(client, challenge.id, headers=headers)
    assert second.status_code == 200, second.text
    assert second.json() == first.json()

    jobs = (
        db_session.execute(select(Job).where(Job.business_key == f"mini-solo:{team.id}"))
        .scalars()
        .all()
    )
    assert len(jobs) == 1


# ---------------------------------------------------------------------------
# lifecycle gate, role/scope, object scope
# ---------------------------------------------------------------------------


def test_start_refused_when_run_is_paused(client: TestClient, db_session: Session) -> None:
    definition, _run, team, player = _setup_team_in_run(db_session, run_status=RunStatus.paused)
    challenge = make_challenge(db_session, definition=definition)
    make_team_challenge(db_session, team, challenge, state=TeamChallengeState.startable)
    _login(client, player)

    response = _start(client, challenge.id)

    assert response.status_code == 409, response.text
    body = response.json()
    assert body["code"] == "run_not_running"
    assert body["run_status"] == "paused"


def test_start_refused_when_run_is_finished(client: TestClient, db_session: Session) -> None:
    definition, _run, team, player = _setup_team_in_run(db_session, run_status=RunStatus.finished)
    challenge = make_challenge(db_session, definition=definition)
    make_team_challenge(db_session, team, challenge, state=TeamChallengeState.startable)
    _login(client, player)

    response = _start(client, challenge.id)

    assert response.status_code == 409, response.text
    body = response.json()
    assert body["code"] == "run_not_running"
    assert body["run_status"] == "finished"


def test_start_refused_when_run_resolves_to_a_created_run_via_fallback(
    client: TestClient, db_session: Session
) -> None:
    """api-surface.md §2.7: all three of `created`, `paused` and
    `finished` reach this gate — `created` by way of
    `resolve_current_run`'s fallback tier, which returns a participant's
    `created` run when they hold no readable one (running/paused/
    finished). `POST /auth/login` refuses a *new* login into a `created`
    run, but it does not retire a session already issued (§2.2) — so a
    player who logged in while a different run was still readable, and
    whose only remaining participation is now on a fresh `created` run,
    reaches this route with `run_status: "created"`.
    """
    username = f"player-{uuid.uuid4().hex[:8]}"
    player = make_user(
        db_session,
        username=username,
        role=Role.player,
        must_change_password=False,
        password_hash=hash_password(username),
    )
    finished_run = make_event_run(db_session, status=RunStatus.finished)
    make_participation(db_session, user=player, run=finished_run)
    _login(client, player)

    # Make the finished run unreadable so `resolve_current_run` falls
    # through past tier 2 (running/paused/finished), and give the player
    # a second, `created` run — the session obtained above survives both
    # changes, since sessions carry no run. Postgres freezes `now()` for
    # the life of a transaction (Working-Agreement), so the two
    # participations would otherwise share one `created_at` and the
    # fallback tier's tie-break (`id DESC`, a random UUID) would pick
    # between them arbitrarily — the second `created_at` is set from
    # Python to make the ordering deterministic rather than lucky.
    finished_run.status = RunStatus.destroyed
    db_session.commit()
    created_definition = make_event_definition(db_session)
    challenge = make_challenge(db_session, definition=created_definition)
    created_run = make_event_run(
        db_session, definition=created_definition, status=RunStatus.created
    )
    make_participation(
        db_session,
        user=player,
        run=created_run,
        created_at=datetime.now(UTC) + timedelta(seconds=1),
    )

    response = _start(client, challenge.id)

    assert response.status_code == 409, response.text
    body = response.json()
    assert body["code"] == "run_not_running"
    assert body["run_status"] == "created"


def test_captain_can_start_own_team_challenge(client: TestClient, db_session: Session) -> None:
    definition, _run, team, player = _setup_team_in_run(db_session, captain=True)
    assert team.captain_user_id == player.id
    challenge = make_challenge(db_session, definition=definition)
    make_team_challenge(db_session, team, challenge, state=TeamChallengeState.startable)
    _login(client, player)

    response = _start(client, challenge.id)

    assert response.status_code == 200, response.text


def test_admin_start_is_403(client: TestClient, db_session: Session) -> None:
    definition, _run, team, _player = _setup_team_in_run(db_session)
    challenge = make_challenge(db_session, definition=definition)
    make_team_challenge(db_session, team, challenge, state=TeamChallengeState.startable)
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

    response = _start(client, challenge.id)

    assert response.status_code == 403
    assert response.json()["code"] == "role_denied"


def test_start_unknown_challenge_is_404(client: TestClient, db_session: Session) -> None:
    _definition, _run, _team, player = _setup_team_in_run(db_session)
    _login(client, player)

    response = _start(client, uuid.uuid4())

    assert response.status_code == 404
    assert response.json()["code"] == "object_not_found"


def test_start_with_no_current_run_is_404(client: TestClient, db_session: Session) -> None:
    """A player holding no participation at all still logs in — login
    gates on run state only once a participation exists (`api/auth.py`)
    — and then resolves no current run either."""
    username = f"player-{uuid.uuid4().hex[:8]}"
    make_user(
        db_session,
        username=username,
        role=Role.player,
        must_change_password=False,
        password_hash=hash_password(username),
    )
    response = client.post("/api/v1/auth/login", json={"username": username, "password": username})
    assert response.status_code == 200, response.text

    response = _start(client, uuid.uuid4())

    assert response.status_code == 404
    assert response.json()["code"] == "object_not_found"
