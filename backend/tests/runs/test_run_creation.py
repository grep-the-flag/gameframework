"""M2-Task-Plan.md Task 12 Step 2: run creation — the §3.9 config snapshot,
the definition-must-be-published precondition, and the single-active-run
rule (api-surface.md §2.6). Also binds `definition_revision` as a
structural rather than content snapshot, since without a test that claim
is only a sentence in data-model.md §3.9.
"""

import uuid
from typing import cast

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from gameframework.db.models.authoring import (
    DefinitionStatus,
    ParticipationMode,
    ScoringMode,
    UnlockMode,
)
from gameframework.db.models.identity import Role, User
from gameframework.db.models.runs import RunStatus
from gameframework.services.passwords import hash_password

from ..conftest import make_event_definition, make_event_run, make_installed_artifact, make_user

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


def _create_publishable_draft(
    client: TestClient, db_session: Session, minigame_id: str
) -> dict[str, object]:
    """A published definition with exactly one challenge, pinned to an
    installed artifact — the minimal document `validate_event` accepts
    (mirrors tests/definitions/test_whitelist.py's own helper)."""
    make_installed_artifact(
        db_session,
        artifact_id=minigame_id,
        version="1.0.0",
        manifest={"id": minigame_id, "version": "1.0.0"},
        image_digest="sha256:" + "1" * 64,
    )
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
                    "minigame": {"id": minigame_id, "version": ">=1.0,<2.0"},
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


def test_run_of_published_definition_snapshots_the_config(
    client: TestClient, db_session: Session
) -> None:
    """data-model.md §3.9: `unlock_mode`, `scoring_mode`,
    `participation_mode`, `theme_ref`, `gamemaster_enabled`,
    `language_default` and `grace_period_days` are snapshotted onto the
    run at creation. `gamemaster_provider`, `gamemaster_endpoint` and
    `otp_lifetime_minutes` are the operator's own infrastructure and
    security knobs and are never copied from anywhere — they start at
    their defaults on every run. Proven against a *prior* run of this
    same definition carrying non-default values for those three: the only
    plausible way they could leak, since `event_definition` carries no
    matching columns for any of them at all.
    """
    _login_as_admin(client, db_session)
    definition = make_event_definition(
        db_session,
        status=DefinitionStatus.published,
        unlock_mode=UnlockMode.guided,
        scoring_mode=ScoringMode.challenge,
        participation_mode=ParticipationMode.solo,
        theme_ref="nautical",
        gamemaster_enabled=True,
        language_default="de",
        grace_period_days=14,
    )
    make_event_run(
        db_session,
        definition=definition,
        status=RunStatus.destroyed,
        gamemaster_provider="ollama/llama3",
        gamemaster_endpoint="http://localhost:11434",
        otp_lifetime_minutes=45,
    )

    response = client.post(f"/api/v1/event-definitions/{definition.id}/runs")

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["unlock_mode"] == "guided"
    assert body["scoring_mode"] == "challenge"
    assert body["participation_mode"] == "solo"
    assert body["theme_ref"] == "nautical"
    assert body["gamemaster_enabled"] is True
    assert body["language_default"] == "de"
    assert body["grace_period_days"] == 14

    assert body["gamemaster_provider"] is None
    assert body["gamemaster_endpoint"] is None
    assert body["otp_lifetime_minutes"] == 5


def test_definition_revision_is_structural_not_a_content_snapshot(
    client: TestClient, db_session: Session
) -> None:
    """data-model.md §3.9: `definition_revision` records the structural
    state a run was created from and is deliberately not a content
    snapshot — a post-publication content edit (api-surface.md §2.6, the
    mid-event typo fix) bumps the definition's live `revision` and must
    reach `GET /event` without moving the run's own `definition_revision`.
    """
    _login_as_admin(client, db_session)
    published = _create_publishable_draft(client, db_session, "mini-run-revision")
    revision_at_publish = cast(int, published["revision"])

    run_response = client.post(f"/api/v1/event-definitions/{published['id']}/runs")
    assert run_response.status_code == 201, run_response.text
    assert run_response.json()["definition_revision"] == revision_at_publish

    patch_response = client.patch(
        f"/api/v1/event-definitions/{published['id']}",
        json={"story": {"en": "Corrected mid-event story"}},
        headers={"If-Match": str(revision_at_publish)},
    )
    assert patch_response.status_code == 200, patch_response.text
    assert patch_response.json()["revision"] == revision_at_publish + 1

    event_response = client.get("/api/v1/event")
    assert event_response.status_code == 200, event_response.text
    event_body = event_response.json()
    assert event_body["definition"]["story"] == {"en": "Corrected mid-event story"}
    assert event_body["run"]["definition_revision"] == revision_at_publish


def test_create_run_for_unknown_definition_is_404(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)

    response = client.post(f"/api/v1/event-definitions/{uuid.uuid4()}/runs")

    assert response.status_code == 404
    assert response.json()["code"] == "object_not_found"


def test_get_event_is_404_when_no_run_exists(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)

    response = client.get("/api/v1/event")

    assert response.status_code == 404
    assert response.json()["code"] == "object_not_found"


def test_draft_definition_refuses_run_creation(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)
    draft = make_event_definition(db_session, status=DefinitionStatus.draft)

    response = client.post(f"/api/v1/event-definitions/{draft.id}/runs")

    assert response.status_code == 409
    assert response.json()["code"] == "definition_not_published"


def test_second_run_refused_while_another_is_active(
    client: TestClient, db_session: Session
) -> None:
    """api-surface.md §2.6: "409 while another run is running/paused" —
    asserted on the `code`, not the bare status, and against a *different*
    definition's run: the single-run rule is installation-wide, not
    per-definition (data-model.md §3.9's partial index carries no
    definition scoping at all).
    """
    _login_as_admin(client, db_session)
    active_definition = make_event_definition(db_session, status=DefinitionStatus.published)
    make_event_run(db_session, definition=active_definition, status=RunStatus.paused)

    other_definition = make_event_definition(db_session, status=DefinitionStatus.published)

    response = client.post(f"/api/v1/event-definitions/{other_definition.id}/runs")

    assert response.status_code == 409
    assert response.json()["code"] == "run_active"


def test_further_created_runs_and_multiple_definitions_coexist_freely(
    client: TestClient, db_session: Session
) -> None:
    """The negative case for the rule above: nothing but `running`/`paused`
    blocks creation — further `created` runs of the same definition, and
    runs of a second definition, are all accepted freely."""
    _login_as_admin(client, db_session)
    definition_a = make_event_definition(db_session, status=DefinitionStatus.published)
    definition_b = make_event_definition(db_session, status=DefinitionStatus.published)

    first = client.post(f"/api/v1/event-definitions/{definition_a.id}/runs")
    assert first.status_code == 201, first.text

    second_same_definition = client.post(f"/api/v1/event-definitions/{definition_a.id}/runs")
    assert second_same_definition.status_code == 201, second_same_definition.text

    third_other_definition = client.post(f"/api/v1/event-definitions/{definition_b.id}/runs")
    assert third_other_definition.status_code == 201, third_other_definition.text

    ids = {
        first.json()["id"],
        second_same_definition.json()["id"],
        third_other_definition.json()["id"],
    }
    assert len(ids) == 3
