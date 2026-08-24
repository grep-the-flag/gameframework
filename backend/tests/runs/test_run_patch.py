"""M2-Task-Plan.md Task 14 Step 2: `PATCH /runs/{id}` — the run-operational
whitelist (api-surface.md §2.6, §1, §2.17; data-model.md §3.9).

Step 2a, per Daniel's redirect after the gamemaster-hash question: in M2 no
field of this whitelist is an input to `compute_config_hash` (M2-Task-Plan.md
Task 13; `services/preflight.py`) — a preflight validates none of them, the
same principle that lets a post-publication content fix skip a re-preflight.
The tests below bind that as the property it is: with a passed preflight in
place, every whitelist `PATCH` the route accepts leaves the recorded hash
unchanged and `start` still succeeds. `services/preflight.py` itself is not
touched by this task; only mutation-tested and reverted (see the Step 2
report).
"""

import uuid
from typing import Any

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.api.runs import PatchRunRequest
from gameframework.db.models.feedback import AuditLog
from gameframework.db.models.identity import Role, User
from gameframework.db.models.runs import EventRun
from gameframework.services.passwords import hash_password
from gameframework.services.runs import PATCH_WHITELIST_FIELDS

from ..conftest import (
    make_event_run,
    make_installed_artifact,
    make_participation,
    make_team,
    make_user,
)


def test_patch_request_fields_match_the_whitelist() -> None:
    """Task 10's finding, mirrored (Working-Agreement.md): two hand-
    written lists for one field set are a divergence on a timer.
    `PatchRunRequest`'s declared fields and `PATCH_WHITELIST_FIELDS` are
    maintained separately — one for FastAPI/pydantic typing, one as the
    constant `patch_run` documents itself against — so this structural
    test is what keeps a field added to one from silently drifting from
    the other, the way `DOCUMENT_FIELD_NAMES` is bound against the SDK
    schema in `tests/definitions/test_authoring.py`.
    """
    assert set(PatchRunRequest.model_fields) == set(PATCH_WHITELIST_FIELDS)


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


def _patch(client: TestClient, run_id: str, body: dict[str, Any]) -> httpx.Response:
    return client.patch(f"/api/v1/runs/{run_id}", json=body)


def _audit_rows(db_session: Session, run_id: uuid.UUID, action: str) -> list[AuditLog]:
    return list(
        db_session.execute(
            select(AuditLog).where(AuditLog.target_id == run_id, AuditLog.action == action)
        )
        .scalars()
        .all()
    )


# ---------------------------------------------------------------------------
# the whitelist: accepted fields, grace_period_days admin-only, refusal of
# anything else
# ---------------------------------------------------------------------------


def test_gameadmin_patches_the_operational_whitelist(
    client: TestClient, db_session: Session
) -> None:
    gameadmin = _login_as_gameadmin(client, db_session)
    run = make_event_run(db_session)

    response = _patch(
        client,
        str(run.id),
        {
            "scheduled_end": "2026-09-01T12:00:00Z",
            "theme_ref": "midnight",
            "gamemaster_enabled": True,
            "gamemaster_provider": "openai/gpt-4o",
            "gamemaster_endpoint": "https://example.test",
            "otp_lifetime_minutes": 42,
        },
    )

    assert response.status_code == 200, response.text
    db_run = db_session.get(EventRun, run.id)
    assert db_run is not None
    assert db_run.theme_ref == "midnight"
    assert db_run.gamemaster_enabled is True
    assert db_run.gamemaster_provider == "openai/gpt-4o"
    assert db_run.gamemaster_endpoint == "https://example.test"
    assert db_run.otp_lifetime_minutes == 42
    assert db_run.scheduled_end is not None
    assert db_run.scheduled_end.isoformat().startswith("2026-09-01T12:00:00")

    rows = _audit_rows(db_session, run.id, "event_run_patched")
    assert len(rows) == 1
    assert rows[0].actor_user_id == gameadmin.id


def test_gameadmin_naming_grace_period_days_is_403(client: TestClient, db_session: Session) -> None:
    _login_as_gameadmin(client, db_session)
    run = make_event_run(db_session, grace_period_days=7)

    response = _patch(client, str(run.id), {"grace_period_days": 30})

    assert response.status_code == 403
    assert response.json()["code"] == "role_denied"
    db_run = db_session.get(EventRun, run.id)
    assert db_run is not None
    assert db_run.grace_period_days == 7


def test_admin_sets_grace_period_days(client: TestClient, db_session: Session) -> None:
    admin = _login_as_admin(client, db_session)
    run = make_event_run(db_session, grace_period_days=7)

    response = _patch(client, str(run.id), {"grace_period_days": 30})

    assert response.status_code == 200, response.text
    db_run = db_session.get(EventRun, run.id)
    assert db_run is not None
    assert db_run.grace_period_days == 30

    rows = _audit_rows(db_session, run.id, "event_run_patched")
    assert len(rows) == 1
    assert rows[0].actor_user_id == admin.id


def test_field_outside_whitelist_is_refused(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)
    run = make_event_run(db_session)

    response = _patch(client, str(run.id), {"status": "paused"})

    assert response.status_code == 422
    assert response.json()["code"] == "field_not_writable"


# ---------------------------------------------------------------------------
# the cross-mechanism case: the operational whitelist is not an input to
# the preflight config hash, so patching it never stales a passed preflight
# ---------------------------------------------------------------------------


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


def _publish_one_challenge(client: TestClient) -> dict[str, object]:
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
                }
            ]
        },
        headers={"If-Match": "1"},
    )
    assert patched.status_code == 200, patched.text
    published = client.post(f"/api/v1/event-definitions/{patched.json()['id']}/publish")
    assert published.status_code == 200, published.text
    return published.json()


def _setup_preflighted_run(client: TestClient, db_session: Session) -> tuple[EventRun, str]:
    """A published one-challenge definition, a run of it, one fully-teamed
    team, and a passed preflight — the same shape `test_start.py` builds,
    minimal here since only the recorded hash and `start`'s outcome matter.
    """
    _install_minigame(db_session, minigame_id="mini-a")
    published = _publish_one_challenge(client)
    run_response = client.post(f"/api/v1/event-definitions/{published['id']}/runs")
    assert run_response.status_code == 201, run_response.text
    run_id = run_response.json()["id"]
    run_row = db_session.get(EventRun, uuid.UUID(run_id))
    assert run_row is not None

    team = make_team(db_session, run=run_row)
    make_participation(db_session, run=run_row, team_id=team.id)

    preflight = client.post(f"/api/v1/runs/{run_id}/preflight")
    assert preflight.status_code == 200, preflight.text
    assert preflight.json()["passed"] is True, preflight.json()["errors"]
    db_session.refresh(run_row)
    return run_row, run_id


def _start(client: TestClient, run_id: str) -> httpx.Response:
    return client.post(f"/api/v1/runs/{run_id}/transition", json={"action": "start"})


_GAMEADMIN_WHITELIST_PATCHES: list[tuple[str, object]] = [
    ("scheduled_end", "2026-09-01T12:00:00Z"),
    ("theme_ref", "midnight"),
    ("gamemaster_enabled", True),
    ("gamemaster_provider", "openai/gpt-4o"),
    ("gamemaster_endpoint", "https://example.test"),
    ("otp_lifetime_minutes", 42),
]


def test_patch_of_gameadmin_whitelist_field_leaves_hash_unchanged_and_start_still_works(
    client: TestClient, db_session: Session
) -> None:
    _login_as_admin(client, db_session)
    run_row, run_id = _setup_preflighted_run(client, db_session)
    hash_before = run_row.preflight_config_hash
    assert hash_before is not None

    for field, value in _GAMEADMIN_WHITELIST_PATCHES:
        response = _patch(client, run_id, {field: value})
        assert response.status_code == 200, response.text

    db_session.refresh(run_row)
    assert run_row.preflight_config_hash == hash_before

    response = _start(client, run_id)
    assert response.status_code == 200, response.text


def test_patch_of_grace_period_days_leaves_hash_unchanged_and_start_still_works(
    client: TestClient, db_session: Session
) -> None:
    _login_as_admin(client, db_session)
    run_row, run_id = _setup_preflighted_run(client, db_session)
    hash_before = run_row.preflight_config_hash
    assert hash_before is not None

    response = _patch(client, run_id, {"grace_period_days": 3})
    assert response.status_code == 200, response.text

    db_session.refresh(run_row)
    assert run_row.preflight_config_hash == hash_before

    response = _start(client, run_id)
    assert response.status_code == 200, response.text
