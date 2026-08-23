"""M2-Task-Plan.md Task 10 Step 3: the definition lifecycle — publish,
unpublish, clone, archive, unarchive (api-surface.md §2.6, §2.17;
data-model.md §3.4). The routes and services landed whole in Step 2, so
this file writes tests and binds them by mutation rather than watching a
missing route go from 404 to 200 (Working-Agreement: "where a task's routes
land whole in one step, the later steps write tests and bind them by
mutation").

Step 3 found exactly one gap this way: `archive()` in services/
definitions.py carried no guard against a `running`/`paused` run, though
api-surface.md §2.6 requires a `409` there. That test is written first and
is genuinely red — the guard does not exist yet — before the fix lands.
"""

import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.db.models.authoring import (
    Challenge,
    ChallengeDependency,
    DependencySource,
    EventDefinition,
)
from gameframework.db.models.feedback import AuditLog
from gameframework.db.models.identity import Role, User
from gameframework.db.models.infrastructure import InstalledArtifact
from gameframework.db.models.runs import RunStatus
from gameframework.services.passwords import hash_password

from ..conftest import make_event_run, make_installed_artifact, make_user

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


def _create_draft(client: TestClient) -> dict[str, object]:
    response = client.post("/api/v1/event-definitions")
    assert response.status_code == 201, response.text
    return response.json()


def _create_publishable_draft(
    client: TestClient, db_session: Session, minigame_id: str, digest: str
) -> dict[str, object]:
    """A draft with exactly one challenge, pinned to an installed artifact
    — the minimal document `validate_event` accepts (test_authoring.py
    builds the same shape for its own PATCH tests)."""
    make_installed_artifact(
        db_session,
        artifact_id=minigame_id,
        version="1.0.0",
        manifest={"id": minigame_id, "version": "1.0.0"},
        image_digest=digest,
    )
    draft = _create_draft(client)
    response = client.patch(
        f"/api/v1/event-definitions/{draft['id']}",
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
    assert response.status_code == 200, response.text
    return response.json()


def _publish(client: TestClient, definition_id: object) -> dict[str, object]:
    response = client.post(f"/api/v1/event-definitions/{definition_id}/publish")
    assert response.status_code == 200, response.text
    return response.json()


def _get_definition_row(db_session: Session, definition_id: object) -> EventDefinition:
    row = db_session.get(EventDefinition, uuid.UUID(str(definition_id)))
    assert row is not None
    return row


def _audit_rows(db_session: Session, target_id: object, action: str) -> list[AuditLog]:
    return list(
        db_session.execute(
            select(AuditLog).where(AuditLog.target_id == target_id, AuditLog.action == action)
        )
        .scalars()
        .all()
    )


# ---------------------------------------------------------------------------
# publish
# ---------------------------------------------------------------------------


def test_publish_freezes_structure(client: TestClient, db_session: Session) -> None:
    """api-surface.md §2.6: publish freezes the structure. One structural
    field (a challenge's `order`) is enough to prove the transition itself
    routes a later `PATCH` through the whitelist branch instead of the
    draft one — the whitelist's full contents are Step 4's matrix, not
    re-litigated here.
    """
    _login_as_admin(client, db_session)
    definition = _create_publishable_draft(client, db_session, "mini-freeze", "sha256:" + "1" * 64)
    published = _publish(client, definition["id"])
    assert published["status"] == "published"

    response = client.patch(
        f"/api/v1/event-definitions/{definition['id']}",
        json={
            "challenges": [
                {
                    "id": "chal-a",
                    "order": 2,
                    "title": {"en": "A"},
                    "text": {"en": "A text"},
                    "minigame": {"id": "mini-freeze", "version": ">=1.0,<2.0"},
                    "points": 10,
                }
            ]
        },
        headers={"If-Match": str(published["revision"])},
    )
    assert response.status_code == 409, response.text
    assert response.json()["code"] == "structural_change_rejected"


def test_publish_writes_audit_row(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)
    definition = _create_publishable_draft(client, db_session, "mini-aud-pub", "sha256:" + "2" * 64)
    _publish(client, definition["id"])
    rows = _audit_rows(db_session, uuid.UUID(str(definition["id"])), "event_definition_published")
    assert len(rows) == 1


def test_publish_fails_when_pinned_artifact_left_the_store(
    client: TestClient, db_session: Session
) -> None:
    """sdk-contract-v1.md §3.4 pin-once-resolve-against-pins: publish
    re-validates through `PinnedResolver` over the recorded pins, so an
    artifact removed from the store since the draft `PATCH` must fail
    here, naming the minigame — the exact case that is why `unarchive`
    routes a run-less definition through `draft` instead of straight back
    to `published` (api-surface.md §2.6): a publish that could silently
    succeed over a vanished pin would make that ruling groundless.
    """
    _login_as_admin(client, db_session)
    definition = _create_publishable_draft(client, db_session, "mini-vanish", "sha256:" + "3" * 64)

    artifact = db_session.execute(
        select(InstalledArtifact).where(InstalledArtifact.artifact_id == "mini-vanish")
    ).scalar_one()
    db_session.delete(artifact)
    db_session.commit()

    response = client.post(f"/api/v1/event-definitions/{definition['id']}/publish")
    assert response.status_code == 422, response.text
    assert any("mini-vanish" in error for error in response.json()["errors"])

    unchanged = client.get(f"/api/v1/event-definitions/{definition['id']}")
    assert unchanged.json()["status"] == "draft"


def test_publish_fails_when_pinned_version_now_carries_a_different_digest(
    client: TestClient, db_session: Session
) -> None:
    """The other failure shape of the same bind: the `(artifact_id,
    version)` pair is still installed, but the digest under it changed —
    a drop-in replaced under the same version number. `PinnedResolver`
    matches on both halves of the pair, so this must fail exactly like a
    removed artifact, naming the minigame.
    """
    _login_as_admin(client, db_session)
    definition = _create_publishable_draft(client, db_session, "mini-swap", "sha256:" + "4" * 64)

    artifact = db_session.execute(
        select(InstalledArtifact).where(InstalledArtifact.artifact_id == "mini-swap")
    ).scalar_one()
    artifact.image_digest = "sha256:" + "9" * 64
    db_session.commit()

    response = client.post(f"/api/v1/event-definitions/{definition['id']}/publish")
    assert response.status_code == 422, response.text
    assert any("mini-swap" in error for error in response.json()["errors"])

    unchanged = client.get(f"/api/v1/event-definitions/{definition['id']}")
    assert unchanged.json()["status"] == "draft"


# ---------------------------------------------------------------------------
# unpublish
# ---------------------------------------------------------------------------


def test_unpublish_succeeds_without_a_referencing_run(
    client: TestClient, db_session: Session
) -> None:
    _login_as_admin(client, db_session)
    definition = _create_publishable_draft(
        client, db_session, "mini-unpub-ok", "sha256:" + "5" * 64
    )
    _publish(client, definition["id"])

    response = client.post(f"/api/v1/event-definitions/{definition['id']}/unpublish")
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "draft"
    rows = _audit_rows(db_session, uuid.UUID(str(definition["id"])), "event_definition_unpublished")
    assert len(rows) == 1


def test_unpublish_refused_while_a_run_references_the_definition(
    client: TestClient, db_session: Session
) -> None:
    _login_as_admin(client, db_session)
    definition = _create_publishable_draft(
        client, db_session, "mini-unpub-blocked", "sha256:" + "6" * 64
    )
    _publish(client, definition["id"])
    definition_row = _get_definition_row(db_session, definition["id"])
    make_event_run(db_session, definition=definition_row)

    response = client.post(f"/api/v1/event-definitions/{definition['id']}/unpublish")
    assert response.status_code == 409, response.text
    assert response.json()["code"] == "run_references_definition"


# ---------------------------------------------------------------------------
# clone
# ---------------------------------------------------------------------------


def test_clone_copies_structure_and_pins_into_an_editable_draft_sharing_the_slug(
    client: TestClient, db_session: Session
) -> None:
    """api-surface.md §2.6: "the real clone" — challenges, explicit and
    reward-derived dependencies, reward wiring and the recorded pins all
    travel; `status` does not, because the copy is a fresh, editable
    draft. `slug` is deliberately not unique (data-model.md §3.4), so the
    clone sharing the source's slug — while both remain independently
    addressable rows — is correct, not an oversight.
    """
    _login_as_admin(client, db_session)
    make_installed_artifact(
        db_session,
        artifact_id="mini-clone-a",
        version="1.0.0",
        manifest={
            "id": "mini-clone-a",
            "version": "1.0.0",
            "rewards": {"produces": [{"name": "cred", "type": "password"}]},
        },
        image_digest="sha256:" + "7" * 64,
    )
    make_installed_artifact(
        db_session,
        artifact_id="mini-clone-b",
        version="1.0.0",
        manifest={
            "id": "mini-clone-b",
            "version": "1.0.0",
            "rewards": {"consumes": [{"name": "cred"}]},
        },
        image_digest="sha256:" + "8" * 64,
    )
    make_installed_artifact(
        db_session,
        artifact_id="mini-clone-c",
        version="1.0.0",
        manifest={"id": "mini-clone-c", "version": "1.0.0"},
        image_digest="sha256:" + "9" * 64,
    )
    draft = _create_draft(client)
    patched = client.patch(
        f"/api/v1/event-definitions/{draft['id']}",
        json={
            "challenges": [
                {
                    "id": "chal-a",
                    "order": 1,
                    "title": {"en": "A"},
                    "text": {"en": "A text"},
                    "minigame": {"id": "mini-clone-a", "version": ">=1.0,<2.0"},
                    "points": 10,
                    "rewards": {"produces": [{"name": "cred", "type": "password"}]},
                },
                {
                    "id": "chal-b",
                    "order": 2,
                    "title": {"en": "B"},
                    "text": {"en": "B text"},
                    "minigame": {"id": "mini-clone-b", "version": ">=1.0,<2.0"},
                    "points": 10,
                    "rewards": {"consumes": [{"name": "cred"}]},
                },
                {
                    "id": "chal-c",
                    "order": 3,
                    "title": {"en": "C"},
                    "text": {"en": "C text"},
                    "minigame": {"id": "mini-clone-c", "version": ">=1.0,<2.0"},
                    "points": 10,
                    "depends_on": ["chal-a"],
                },
            ]
        },
        headers={"If-Match": "1"},
    )
    assert patched.status_code == 200, patched.text
    source = patched.json()
    published_source = _publish(client, source["id"])

    clone_response = client.post(f"/api/v1/event-definitions/{source['id']}/clone")
    assert clone_response.status_code == 201, clone_response.text
    clone_body = clone_response.json()

    assert clone_body["id"] != source["id"]
    assert clone_body["status"] == "draft"
    assert clone_body["revision"] == 1
    assert clone_body["slug"] == published_source["slug"]

    clone_challenges = {c["id"]: c for c in clone_body["challenges"]}
    assert clone_challenges.keys() == {"chal-a", "chal-b", "chal-c"}
    assert clone_challenges["chal-a"]["rewards"]["produces"] == [
        {"name": "cred", "type": "password"}
    ]
    assert clone_challenges["chal-b"]["rewards"]["consumes"] == [{"name": "cred"}]
    assert clone_challenges["chal-c"]["depends_on"] == ["chal-a"]

    clone_rows = {
        row.slug: row
        for row in db_session.execute(
            select(Challenge).where(
                Challenge.event_definition_id == uuid.UUID(str(clone_body["id"]))
            )
        )
        .scalars()
        .all()
    }
    assert clone_rows["chal-a"].minigame_version == "1.0.0"
    assert clone_rows["chal-a"].minigame_image_digest == "sha256:" + "7" * 64
    assert clone_rows["chal-b"].minigame_version == "1.0.0"
    assert clone_rows["chal-b"].minigame_image_digest == "sha256:" + "8" * 64

    # Definitions coexist freely (api-surface.md §2.6): the published
    # source and the fresh draft clone are both live rows at once, sharing
    # a slug — no singleton anywhere in the model.
    source_get = client.get(f"/api/v1/event-definitions/{source['id']}")
    assert source_get.json()["status"] == "published"
    assert source_get.json()["slug"] == clone_body["slug"]


def test_clone_does_not_write_an_audit_row(client: TestClient, db_session: Session) -> None:
    """api-surface.md §2.17: clone creates a definition rather than
    transitioning one — unlike publish/unpublish/archive/unarchive it is
    not audited."""
    _login_as_admin(client, db_session)
    source = _create_draft(client)

    clone_response = client.post(f"/api/v1/event-definitions/{source['id']}/clone")
    assert clone_response.status_code == 201, clone_response.text
    clone_id = uuid.UUID(str(clone_response.json()["id"]))

    rows = (
        db_session.execute(select(AuditLog).where(AuditLog.target_id == clone_id)).scalars().all()
    )
    assert rows == []


# ---------------------------------------------------------------------------
# archive / unarchive
# ---------------------------------------------------------------------------


def test_archive_then_unarchive_without_a_run_lands_on_draft(
    client: TestClient, db_session: Session
) -> None:
    """data-model.md §3.4/api-surface.md §2.6: nothing records the status a
    definition was archived from — the way back is derived. No `event_run`
    ever referenced this definition, so `unarchive` lands on `draft`: a
    fresh `publish` must re-run the pipeline before it is runnable again.
    """
    _login_as_admin(client, db_session)
    definition = _create_publishable_draft(
        client, db_session, "mini-arch-draft", "sha256:" + "a" * 64
    )
    _publish(client, definition["id"])

    archive_response = client.post(f"/api/v1/event-definitions/{definition['id']}/archive")
    assert archive_response.status_code == 200, archive_response.text
    assert archive_response.json()["status"] == "archived"
    assert (
        len(_audit_rows(db_session, uuid.UUID(str(definition["id"])), "event_definition_archived"))
        == 1
    )

    unarchive_response = client.post(f"/api/v1/event-definitions/{definition['id']}/unarchive")
    assert unarchive_response.status_code == 200, unarchive_response.text
    assert unarchive_response.json()["status"] == "draft"
    assert (
        len(
            _audit_rows(db_session, uuid.UUID(str(definition["id"])), "event_definition_unarchived")
        )
        == 1
    )


def test_archive_then_unarchive_with_a_referencing_run_lands_on_published(
    client: TestClient, db_session: Session
) -> None:
    """The other half of the same derivation, differing from the test
    above only in whether an `event_run` references the definition — the
    run here is `created`, not `running`/`paused`, so archiving it is
    allowed (the negative case of the new running/paused guard below) and
    `unarchive` lands on `published` because a run already depends on this
    exact frozen structure.
    """
    _login_as_admin(client, db_session)
    definition = _create_publishable_draft(
        client, db_session, "mini-arch-pub", "sha256:" + "b" * 64
    )
    _publish(client, definition["id"])
    definition_row = _get_definition_row(db_session, definition["id"])
    make_event_run(db_session, definition=definition_row, status=RunStatus.created)

    archive_response = client.post(f"/api/v1/event-definitions/{definition['id']}/archive")
    assert archive_response.status_code == 200, archive_response.text

    unarchive_response = client.post(f"/api/v1/event-definitions/{definition['id']}/unarchive")
    assert unarchive_response.status_code == 200, unarchive_response.text
    assert unarchive_response.json()["status"] == "published"


def test_archive_refused_while_a_run_is_running(client: TestClient, db_session: Session) -> None:
    """api-surface.md §2.6: "409 while a run of this definition is running
    or paused" — `archived` shares the `status` column with `published`,
    so archiving behind a live run would make that run's own definition
    read as un-published to anything checking status."""
    _login_as_admin(client, db_session)
    definition = _create_publishable_draft(
        client, db_session, "mini-arch-run", "sha256:" + "c" * 64
    )
    _publish(client, definition["id"])
    definition_row = _get_definition_row(db_session, definition["id"])
    make_event_run(db_session, definition=definition_row, status=RunStatus.running)

    response = client.post(f"/api/v1/event-definitions/{definition['id']}/archive")
    assert response.status_code == 409, response.text
    assert response.json()["code"] == "run_active"

    unchanged = client.get(f"/api/v1/event-definitions/{definition['id']}")
    assert unchanged.json()["status"] == "published"


# ---------------------------------------------------------------------------
# wrong-starting-status refusals — each transition guarded against being
# called from any status but the one it expects (services/definitions.py's
# `if definition.status is (not) X: raise StructuralChangeRejectedError`).
# ---------------------------------------------------------------------------


def test_publish_refused_when_already_published(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)
    definition = _create_publishable_draft(
        client, db_session, "mini-pub-twice", "sha256:" + "1" * 63 + "2"
    )
    _publish(client, definition["id"])

    response = client.post(f"/api/v1/event-definitions/{definition['id']}/publish")
    assert response.status_code == 409, response.text
    assert response.json()["code"] == "invalid_status_transition"

    unchanged = client.get(f"/api/v1/event-definitions/{definition['id']}")
    assert unchanged.json()["status"] == "published"


def test_unpublish_refused_when_still_draft(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)
    draft = _create_draft(client)

    response = client.post(f"/api/v1/event-definitions/{draft['id']}/unpublish")
    assert response.status_code == 409, response.text
    assert response.json()["code"] == "invalid_status_transition"

    unchanged = client.get(f"/api/v1/event-definitions/{draft['id']}")
    assert unchanged.json()["status"] == "draft"


def test_archive_refused_when_already_archived(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)
    definition = _create_publishable_draft(
        client, db_session, "mini-arch-twice", "sha256:" + "2" * 63 + "3"
    )
    _publish(client, definition["id"])
    first = client.post(f"/api/v1/event-definitions/{definition['id']}/archive")
    assert first.status_code == 200, first.text

    response = client.post(f"/api/v1/event-definitions/{definition['id']}/archive")
    assert response.status_code == 409, response.text
    assert response.json()["code"] == "invalid_status_transition"

    unchanged = client.get(f"/api/v1/event-definitions/{definition['id']}")
    assert unchanged.json()["status"] == "archived"


def test_unarchive_refused_when_not_archived(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)
    draft = _create_draft(client)

    response = client.post(f"/api/v1/event-definitions/{draft['id']}/unarchive")
    assert response.status_code == 409, response.text
    assert response.json()["code"] == "invalid_status_transition"

    unchanged = client.get(f"/api/v1/event-definitions/{draft['id']}")
    assert unchanged.json()["status"] == "draft"


# ---------------------------------------------------------------------------
# reads
# ---------------------------------------------------------------------------


def test_list_definitions_returns_status_across_all_of_them(
    client: TestClient, db_session: Session
) -> None:
    """api-surface.md §2.6/§1: `GET /event-definitions` lists definitions
    with their status, across every status at once — "definitions coexist
    freely". Role coverage over this route is Task 18's generated matrix
    (§2.17), not this test.
    """
    _login_as_admin(client, db_session)
    draft = _create_draft(client)
    published_source = _create_publishable_draft(
        client, db_session, "mini-list-pub", "sha256:" + "3" * 63 + "4"
    )
    published = _publish(client, published_source["id"])
    archived_source = _create_publishable_draft(
        client, db_session, "mini-list-arch", "sha256:" + "4" * 63 + "5"
    )
    _publish(client, archived_source["id"])
    archived = client.post(f"/api/v1/event-definitions/{archived_source['id']}/archive")
    assert archived.status_code == 200, archived.text

    response = client.get("/api/v1/event-definitions")
    assert response.status_code == 200, response.text
    items = {item["id"]: item["status"] for item in response.json()["items"]}
    assert items[draft["id"]] == "draft"
    assert items[published["id"]] == "published"
    assert items[archived_source["id"]] == "archived"


def test_get_unknown_definition_is_404(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)

    response = client.get(f"/api/v1/event-definitions/{uuid.uuid4()}")
    assert response.status_code == 404, response.text
    assert response.json()["code"] == "object_not_found"


# ---------------------------------------------------------------------------
# draft authoring: scalar fields and the wholesale-replace branch
# ---------------------------------------------------------------------------


def test_document_field_names_the_api_can_write_are_schema_properties() -> None:
    """The class of bug behind the `scoring`/`scoring_mode` mismatch: any
    name added to `DOCUMENT_FIELD_NAMES` (api/definitions.py) that is not
    literally a top-level property of the SDK's own `event.schema.json`
    will 422 every draft `PATCH` that sets it, unconditionally
    (`additionalProperties: false`) — exactly what `scoring_mode` did.
    Derived from `DOCUMENT_FIELD_NAMES` itself, never a hand-written list
    here, so this cannot pass while the code has already drifted.
    """
    import json
    from pathlib import Path

    import gameframework_sdk

    from gameframework.api.definitions import DOCUMENT_FIELD_NAMES

    schema_path = Path(gameframework_sdk.__file__).parent / "schemas" / "event.schema.json"
    schema_properties = set(json.loads(schema_path.read_text())["properties"])

    unknown = set(DOCUMENT_FIELD_NAMES) - schema_properties
    assert unknown == set(), (
        f"{unknown} in DOCUMENT_FIELD_NAMES names no property of "
        "event.schema.json — a PATCH setting it will 422 unconditionally"
    )


def test_draft_patch_sets_and_reads_back_scalar_fields(
    client: TestClient, db_session: Session
) -> None:
    """data-model.md §3.4: the draft-authoring branch's non-`challenges`
    fields — `name`, `story`, `unlock_mode`, `scoring`,
    `participation_mode` — persist and read back. A `PATCH` silently
    dropping `story` passed every test before this one; writing this test
    also found that the request body's `scoring` key had drifted to
    `scoring_mode`, which the SDK's own `event.schema.json` does not
    declare — every draft `PATCH` naming it 422ed unconditionally
    (`additionalProperties`), so no draft's scoring mode could ever be
    changed via the API. Fixed alongside this test: the PATCH body mirrors
    the event document's own vocabulary (`scoring`), and the one
    row↔document mapping stays in `default_document_fields`
    (services/definitions.py). The response mirrors it too — `_definition_
    out` also emits `scoring`, not `scoring_mode` — so a client reading a
    definition and writing it back is not translating a field twice over.
    """
    _login_as_admin(client, db_session)
    make_installed_artifact(
        db_session,
        artifact_id="mini-scalars",
        version="1.0.0",
        manifest={"id": "mini-scalars", "version": "1.0.0"},
        image_digest="sha256:" + "5" * 63 + "6",
    )
    draft = _create_draft(client)

    response = client.patch(
        f"/api/v1/event-definitions/{draft['id']}",
        json={
            "name": {"en": "Renamed", "de": "Umbenannt"},
            "story": {"en": "New story"},
            "unlock_mode": "guided",
            "scoring": "challenge",
            "participation_mode": "solo",
            "challenges": [
                {
                    "id": "chal-a",
                    "order": 1,
                    "title": {"en": "A"},
                    "text": {"en": "A text"},
                    "minigame": {"id": "mini-scalars", "version": ">=1.0,<2.0"},
                    "points": 10,
                }
            ],
        },
        headers={"If-Match": "1"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["name"] == {"en": "Renamed", "de": "Umbenannt"}
    assert body["story"] == {"en": "New story"}
    assert body["unlock_mode"] == "guided"
    assert body["scoring"] == "challenge"
    assert body["participation_mode"] == "solo"

    reread = client.get(f"/api/v1/event-definitions/{draft['id']}").json()
    assert reread["name"] == {"en": "Renamed", "de": "Umbenannt"}
    assert reread["story"] == {"en": "New story"}
    assert reread["unlock_mode"] == "guided"
    assert reread["scoring"] == "challenge"
    assert reread["participation_mode"] == "solo"


def test_second_draft_patch_replaces_challenges_wholesale(
    client: TestClient, db_session: Session
) -> None:
    """`_persist_challenges` (services/definitions.py): a draft `PATCH`
    resends the whole document (api-surface.md §2.6, "whole-document
    nested authoring"), so a *second* challenge-setting `PATCH` on a
    definition that already has challenges is the ordinary editing flow —
    delete-then-reinsert, not an edge case nothing exercises. A challenge
    dropped from the document is gone; one that survives keeps its pin and
    its reward-derived dependency, rebuilt fresh rather than carried over
    by accident.
    """
    _login_as_admin(client, db_session)
    make_installed_artifact(
        db_session,
        artifact_id="mini-replace-a",
        version="1.0.0",
        manifest={
            "id": "mini-replace-a",
            "version": "1.0.0",
            "rewards": {"produces": [{"name": "loot", "type": "password"}]},
        },
        image_digest="sha256:" + "e" * 64,
    )
    make_installed_artifact(
        db_session,
        artifact_id="mini-replace-b",
        version="1.0.0",
        manifest={
            "id": "mini-replace-b",
            "version": "1.0.0",
            "rewards": {"consumes": [{"name": "loot"}]},
        },
        image_digest="sha256:" + "f" * 64,
    )
    make_installed_artifact(
        db_session,
        artifact_id="mini-replace-c",
        version="1.0.0",
        manifest={"id": "mini-replace-c", "version": "1.0.0"},
        image_digest="sha256:" + "0" * 64,
    )
    draft = _create_draft(client)

    first = client.patch(
        f"/api/v1/event-definitions/{draft['id']}",
        json={
            "challenges": [
                {
                    "id": "chal-a",
                    "order": 1,
                    "title": {"en": "A"},
                    "text": {"en": "A text"},
                    "minigame": {"id": "mini-replace-a", "version": ">=1.0,<2.0"},
                    "points": 10,
                    "rewards": {"produces": [{"name": "loot", "type": "password"}]},
                },
                {
                    "id": "chal-b",
                    "order": 2,
                    "title": {"en": "B"},
                    "text": {"en": "B text"},
                    "minigame": {"id": "mini-replace-b", "version": ">=1.0,<2.0"},
                    "points": 10,
                    "rewards": {"consumes": [{"name": "loot"}]},
                },
                {
                    "id": "chal-c",
                    "order": 3,
                    "title": {"en": "C"},
                    "text": {"en": "C text"},
                    "minigame": {"id": "mini-replace-c", "version": ">=1.0,<2.0"},
                    "points": 10,
                },
            ]
        },
        headers={"If-Match": "1"},
    )
    assert first.status_code == 200, first.text

    second = client.patch(
        f"/api/v1/event-definitions/{draft['id']}",
        json={
            "challenges": [
                {
                    "id": "chal-a",
                    "order": 1,
                    "title": {"en": "A"},
                    "text": {"en": "A text"},
                    "minigame": {"id": "mini-replace-a", "version": ">=1.0,<2.0"},
                    "points": 10,
                    "rewards": {"produces": [{"name": "loot", "type": "password"}]},
                },
                {
                    "id": "chal-b",
                    "order": 2,
                    "title": {"en": "B"},
                    "text": {"en": "B text"},
                    "minigame": {"id": "mini-replace-b", "version": ">=1.0,<2.0"},
                    "points": 10,
                    "rewards": {"consumes": [{"name": "loot"}]},
                },
            ]
        },
        headers={"If-Match": "2"},
    )
    assert second.status_code == 200, second.text
    body = second.json()

    challenge_ids = {c["id"] for c in body["challenges"]}
    assert challenge_ids == {"chal-a", "chal-b"}

    rows = {
        row.slug: row
        for row in db_session.execute(
            select(Challenge).where(Challenge.event_definition_id == uuid.UUID(str(draft["id"])))
        )
        .scalars()
        .all()
    }
    assert rows.keys() == {"chal-a", "chal-b"}
    assert rows["chal-a"].minigame_version == "1.0.0"
    assert rows["chal-a"].minigame_image_digest == "sha256:" + "e" * 64
    assert rows["chal-b"].minigame_version == "1.0.0"
    assert rows["chal-b"].minigame_image_digest == "sha256:" + "f" * 64

    deps = (
        db_session.execute(
            select(ChallengeDependency).where(
                ChallengeDependency.challenge_id.in_([rows["chal-a"].id, rows["chal-b"].id])
            )
        )
        .scalars()
        .all()
    )
    dep_pairs = {(d.challenge_id, d.depends_on_id, d.source) for d in deps}
    assert dep_pairs == {(rows["chal-b"].id, rows["chal-a"].id, DependencySource.reward)}


def test_explicit_and_reward_dependency_on_same_pair_dedupes_to_one_row(
    client: TestClient, db_session: Session
) -> None:
    """`_add_dependency`'s de-dupe (services/definitions.py): an explicit
    `depends_on` and a reward-derived edge naming the same producer/
    consumer pair collapse to one `ChallengeDependency` row — "the first
    source to name a pair wins and the second is skipped" — exercised here
    so that comment is proven rather than assumed.
    """
    _login_as_admin(client, db_session)
    make_installed_artifact(
        db_session,
        artifact_id="mini-dedupe-a",
        version="1.0.0",
        manifest={
            "id": "mini-dedupe-a",
            "version": "1.0.0",
            "rewards": {"produces": [{"name": "key", "type": "token"}]},
        },
        image_digest="sha256:" + "6" * 63 + "7",
    )
    make_installed_artifact(
        db_session,
        artifact_id="mini-dedupe-b",
        version="1.0.0",
        manifest={
            "id": "mini-dedupe-b",
            "version": "1.0.0",
            "rewards": {"consumes": [{"name": "key"}]},
        },
        image_digest="sha256:" + "7" * 63 + "8",
    )
    draft = _create_draft(client)

    response = client.patch(
        f"/api/v1/event-definitions/{draft['id']}",
        json={
            "challenges": [
                {
                    "id": "chal-a",
                    "order": 1,
                    "title": {"en": "A"},
                    "text": {"en": "A text"},
                    "minigame": {"id": "mini-dedupe-a", "version": ">=1.0,<2.0"},
                    "points": 10,
                    "rewards": {"produces": [{"name": "key", "type": "token"}]},
                },
                {
                    "id": "chal-b",
                    "order": 2,
                    "title": {"en": "B"},
                    "text": {"en": "B text"},
                    "minigame": {"id": "mini-dedupe-b", "version": ">=1.0,<2.0"},
                    "points": 10,
                    "depends_on": ["chal-a"],
                    "rewards": {"consumes": [{"name": "key"}]},
                },
            ]
        },
        headers={"If-Match": "1"},
    )
    assert response.status_code == 200, response.text

    rows = {
        row.slug: row
        for row in db_session.execute(
            select(Challenge).where(Challenge.event_definition_id == uuid.UUID(str(draft["id"])))
        )
        .scalars()
        .all()
    }
    deps = (
        db_session.execute(
            select(ChallengeDependency).where(
                ChallengeDependency.challenge_id == rows["chal-b"].id,
                ChallengeDependency.depends_on_id == rows["chal-a"].id,
            )
        )
        .scalars()
        .all()
    )
    assert len(deps) == 1
    assert deps[0].source == DependencySource.explicit


def test_archive_refused_while_a_run_is_paused(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)
    definition = _create_publishable_draft(
        client, db_session, "mini-arch-paused", "sha256:" + "d" * 64
    )
    _publish(client, definition["id"])
    definition_row = _get_definition_row(db_session, definition["id"])
    make_event_run(db_session, definition=definition_row, status=RunStatus.paused)

    response = client.post(f"/api/v1/event-definitions/{definition['id']}/archive")
    assert response.status_code == 409, response.text
    assert response.json()["code"] == "run_active"

    unchanged = client.get(f"/api/v1/event-definitions/{definition['id']}")
    assert unchanged.json()["status"] == "published"
