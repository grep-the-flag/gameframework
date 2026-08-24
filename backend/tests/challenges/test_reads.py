"""M2-Task-Plan.md Task 15 Step 2: `GET /challenges`, `GET /challenges/{id}`
(api-surface.md §2.7, §2.17, §3.2). Placeholders stay in the authored text —
substitution arrives with the port map in M3 (§2.7) — and the state-based
visibility rules (text hidden until start, titles until solve) are M5's
(§3.2's "endpoints exist from M2, the substitution lands with the port map
in M3"). Neither is built here: these routes serve the definition's
authored `title`/`text` maps unchanged, for every allowed role alike.

This suite drives everything through the HTTP client rather than importing
`services.challenges` directly, so the first red is FastAPI's own routing
`404` (Working-Agreement "a collection error is not a red proof" — a
routing miss is the accepted form of it, as `tests/runs/test_start.py`
notes for the same reason).
"""

import uuid

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from gameframework.db.models.identity import Role, User
from gameframework.db.models.runs import EventRun, RunStatus
from gameframework.services.passwords import hash_password

from ..conftest import (
    make_challenge,
    make_event_definition,
    make_event_run,
    make_participation,
    make_user,
)

ADMIN_PASSWORD = "Admin-Passw0rd!"

_PLACEHOLDER_TEXT = {"en": "Connect to {{minigame.host}}:{{minigame.port}} as {{player.handle}}"}


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


def _login_as_player(client: TestClient, db_session: Session, run: EventRun) -> User:
    username = f"player-{uuid.uuid4().hex[:8]}"
    player = make_user(
        db_session,
        username=username,
        role=Role.player,
        must_change_password=False,
        password_hash=hash_password(username),
    )
    make_participation(db_session, user=player, run=run)
    response = client.post(
        "/api/v1/auth/login", json={"username": player.username, "password": player.username}
    )
    assert response.status_code == 200, response.text
    return player


def test_list_challenges_as_admin_serves_authored_text_with_placeholders_intact(
    client: TestClient, db_session: Session
) -> None:
    definition = make_event_definition(db_session)
    challenge = make_challenge(
        db_session,
        definition=definition,
        order_num=1,
        title={"en": "Challenge One"},
        text=_PLACEHOLDER_TEXT,
    )
    make_event_run(db_session, definition=definition, status=RunStatus.created)
    _login_as_admin(client, db_session)

    response = client.get("/api/v1/challenges")

    assert response.status_code == 200, response.text
    items = response.json()["items"]
    assert len(items) == 1
    assert items[0]["id"] == str(challenge.id)
    assert items[0]["title"] == {"en": "Challenge One"}
    assert items[0]["text"] == _PLACEHOLDER_TEXT


def test_get_challenge_as_admin_serves_authored_text_with_placeholders_intact(
    client: TestClient, db_session: Session
) -> None:
    definition = make_event_definition(db_session)
    challenge = make_challenge(db_session, definition=definition, text=_PLACEHOLDER_TEXT)
    make_event_run(db_session, definition=definition, status=RunStatus.created)
    _login_as_admin(client, db_session)

    response = client.get(f"/api/v1/challenges/{challenge.id}")

    assert response.status_code == 200, response.text
    assert response.json()["text"] == _PLACEHOLDER_TEXT


def test_list_challenges_as_player_serves_the_same_authored_text(
    client: TestClient, db_session: Session
) -> None:
    definition = make_event_definition(db_session)
    make_challenge(db_session, definition=definition, text=_PLACEHOLDER_TEXT)
    run = make_event_run(db_session, definition=definition, status=RunStatus.running)
    _login_as_player(client, db_session, run)

    response = client.get("/api/v1/challenges")

    assert response.status_code == 200, response.text
    items = response.json()["items"]
    assert len(items) == 1
    assert items[0]["text"] == _PLACEHOLDER_TEXT


def test_get_challenge_unknown_id_is_404(client: TestClient, db_session: Session) -> None:
    definition = make_event_definition(db_session)
    make_event_run(db_session, definition=definition, status=RunStatus.created)
    _login_as_admin(client, db_session)

    response = client.get(f"/api/v1/challenges/{uuid.uuid4()}")

    assert response.status_code == 404
    assert response.json()["code"] == "object_not_found"


def test_get_challenge_from_another_definition_is_404(
    client: TestClient, db_session: Session
) -> None:
    """Object scope, not merely existence: a challenge that exists but does
    not belong to the caller's current run's definition is non-disclosure,
    the same `object_not_found` an out-of-scope object answers everywhere
    else (api-surface.md §1)."""
    current_definition = make_event_definition(db_session)
    make_event_run(db_session, definition=current_definition, status=RunStatus.created)
    other_definition = make_event_definition(db_session)
    other_challenge = make_challenge(db_session, definition=other_definition)
    _login_as_admin(client, db_session)

    response = client.get(f"/api/v1/challenges/{other_challenge.id}")

    assert response.status_code == 404
    assert response.json()["code"] == "object_not_found"


def test_challenges_with_no_current_run_is_404(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)

    response = client.get("/api/v1/challenges")

    assert response.status_code == 404
    assert response.json()["code"] == "object_not_found"


def test_get_challenge_with_no_current_run_is_404(client: TestClient, db_session: Session) -> None:
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

    response = client.get(f"/api/v1/challenges/{uuid.uuid4()}")

    assert response.status_code == 404
    assert response.json()["code"] == "object_not_found"
