"""M2-Task-Plan.md Task 10 Step 2: definition authoring while `draft`
(api-surface.md §2.6; data-model.md §3.4-§3.8; sdk-contract-v1.md §3.4).

`services/definitions.py` and `api/definitions.py` do not exist on `develop`
at the start of this task, so a first run of this file is expected to fail
on FastAPI's own routing `404` (or an import error, for the DB-row
assertions) rather than on `problem_error_handler` — a collection/routing
red, not proof any individual assertion here catches what it names
(Working-Agreement "a collection error is not a red proof"). The mutation
table in the Step 2 report is what actually binds each assertion, once the
routes exist.
"""

import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.db.models.authoring import (
    Challenge,
    ChallengeDependency,
    DependencySource,
    RewardConsumption,
    RewardDefinition,
)
from gameframework.db.models.identity import Role, User
from gameframework.services.passwords import hash_password

from ..conftest import make_installed_artifact, make_user

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


def test_create_empty_draft(client: TestClient, db_session: Session) -> None:
    """api-surface.md §2.6: `POST /event-definitions` — "Create an empty
    draft", no body needed."""
    _login_as_admin(client, db_session)

    body = _create_draft(client)

    assert body["status"] == "draft"
    assert body["revision"] == 1
    assert body["challenges"] == []
    assert uuid.UUID(str(body["id"]))


def test_patch_persists_challenges_dependencies_and_reward_wiring(
    client: TestClient, db_session: Session
) -> None:
    """data-model.md §3.5-§3.8: a draft `PATCH` carrying challenges,
    explicit + auto-derived dependencies and reward wiring writes all of
    it in one call, including the `source: reward` rows §3.6 says are
    "never authored by hand" — chal-b consumes what chal-a produces with
    no `depends_on` entry of its own, and chal-c's `depends_on: [chal-a]`
    proves the explicit source persists alongside it.
    """
    _login_as_admin(client, db_session)
    make_installed_artifact(
        db_session,
        artifact_id="mini-a",
        version="1.0.0",
        manifest={
            "id": "mini-a",
            "version": "1.0.0",
            "rewards": {"produces": [{"name": "cred", "type": "password"}]},
        },
        image_digest="sha256:" + "a" * 64,
    )
    make_installed_artifact(
        db_session,
        artifact_id="mini-b",
        version="1.0.0",
        manifest={"id": "mini-b", "version": "1.0.0", "rewards": {"consumes": [{"name": "cred"}]}},
        image_digest="sha256:" + "b" * 64,
    )
    make_installed_artifact(
        db_session,
        artifact_id="mini-c",
        version="1.0.0",
        manifest={"id": "mini-c", "version": "1.0.0"},
        image_digest="sha256:" + "c" * 64,
    )

    draft = _create_draft(client)
    patch_body = {
        "challenges": [
            {
                "id": "chal-a",
                "order": 1,
                "title": {"en": "A"},
                "text": {"en": "A text"},
                "minigame": {"id": "mini-a", "version": ">=1.0,<2.0"},
                "points": 10,
                "rewards": {"produces": [{"name": "cred", "type": "password"}]},
            },
            {
                "id": "chal-b",
                "order": 2,
                "title": {"en": "B"},
                "text": {"en": "B text"},
                "minigame": {"id": "mini-b", "version": ">=1.0,<2.0"},
                "points": 10,
                "rewards": {"consumes": [{"name": "cred"}]},
            },
            {
                "id": "chal-c",
                "order": 3,
                "title": {"en": "C"},
                "text": {"en": "C text"},
                "minigame": {"id": "mini-c", "version": ">=1.0,<2.0"},
                "points": 10,
                "depends_on": ["chal-a"],
            },
        ]
    }

    response = client.patch(
        f"/api/v1/event-definitions/{draft['id']}",
        json=patch_body,
        headers={"If-Match": "1"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["revision"] == 2

    challenges = {
        c.slug: c
        for c in db_session.execute(
            select(Challenge).where(Challenge.event_definition_id == uuid.UUID(str(draft["id"])))
        )
        .scalars()
        .all()
    }
    assert challenges.keys() == {"chal-a", "chal-b", "chal-c"}
    # Pins recorded on resolve (data-model.md §3.5): both halves of the
    # pair, not only the version.
    assert challenges["chal-a"].minigame_version == "1.0.0"
    assert challenges["chal-a"].minigame_image_digest == "sha256:" + "a" * 64
    assert challenges["chal-b"].minigame_version == "1.0.0"
    assert challenges["chal-b"].minigame_image_digest == "sha256:" + "b" * 64

    deps = (
        db_session.execute(
            select(ChallengeDependency).where(
                ChallengeDependency.challenge_id.in_([c.id for c in challenges.values()])
            )
        )
        .scalars()
        .all()
    )
    dep_pairs = {(d.challenge_id, d.depends_on_id, d.source) for d in deps}
    assert (
        challenges["chal-b"].id,
        challenges["chal-a"].id,
        DependencySource.reward,
    ) in dep_pairs
    assert (
        challenges["chal-c"].id,
        challenges["chal-a"].id,
        DependencySource.explicit,
    ) in dep_pairs
    assert len(dep_pairs) == 2

    reward = db_session.execute(
        select(RewardDefinition).where(
            RewardDefinition.producer_challenge_id == challenges["chal-a"].id
        )
    ).scalar_one()
    assert reward.name == "cred"
    consumption = db_session.execute(
        select(RewardConsumption).where(RewardConsumption.reward_definition_id == reward.id)
    ).scalar_one()
    assert consumption.consumer_challenge_id == challenges["chal-b"].id


def test_pin_records_highest_satisfying_version_and_its_own_digest(
    client: TestClient, db_session: Session
) -> None:
    """sdk-contract-v1.md §3.4: "the highest version that satisfies it" —
    and the digest recorded is that version's own, not a neighbour's
    (Task 9's review finding on the reading side; this is the write side).
    """
    _login_as_admin(client, db_session)
    make_installed_artifact(
        db_session,
        artifact_id="dual-game",
        version="1.0.0",
        manifest={"id": "dual-game", "version": "1.0.0"},
        image_digest="sha256:" + "1" * 64,
    )
    make_installed_artifact(
        db_session,
        artifact_id="dual-game",
        version="1.5.0",
        manifest={"id": "dual-game", "version": "1.5.0"},
        image_digest="sha256:" + "5" * 64,
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
                    "minigame": {"id": "dual-game", "version": ">=1.0,<2.0"},
                    "points": 10,
                }
            ]
        },
        headers={"If-Match": "1"},
    )
    assert response.status_code == 200, response.text

    row = db_session.execute(
        select(Challenge).where(Challenge.event_definition_id == uuid.UUID(str(draft["id"])))
    ).scalar_one()
    assert row.minigame_version == "1.5.0"
    assert row.minigame_image_digest == "sha256:" + "5" * 64


def test_patch_with_unknown_minigame_is_refused_naming_it(
    client: TestClient, db_session: Session
) -> None:
    """sdk-contract-v1.md §3.4 check 1: the store does not hold
    'ghost-game' — refused, and the refusal names it, with nothing
    persisted."""
    _login_as_admin(client, db_session)
    draft = _create_draft(client)

    response = client.patch(
        f"/api/v1/event-definitions/{draft['id']}",
        json={
            "challenges": [
                {
                    "id": "chal-x",
                    "order": 1,
                    "title": {"en": "X"},
                    "text": {"en": "X text"},
                    "minigame": {"id": "ghost-game", "version": ">=1.0,<2.0"},
                    "points": 10,
                }
            ]
        },
        headers={"If-Match": "1"},
    )

    assert response.status_code == 422, response.text
    body = response.json()
    assert body["code"] == "definition_invalid"
    assert any("ghost-game" in error for error in body["errors"])

    unchanged = client.get(f"/api/v1/event-definitions/{draft['id']}")
    assert unchanged.json()["revision"] == 1
    assert unchanged.json()["challenges"] == []


def test_patch_without_current_if_match_is_412_with_current_revision(
    client: TestClient, db_session: Session
) -> None:
    """api-surface.md §1: "PATCH /event-definitions/{id} requires
    If-Match and answers 412 with the current revision on a lost race"."""
    _login_as_admin(client, db_session)
    draft = _create_draft(client)

    missing = client.patch(
        f"/api/v1/event-definitions/{draft['id']}", json={"name": {"en": "Renamed"}}
    )
    assert missing.status_code == 412
    assert missing.json()["revision"] == 1

    stale = client.patch(
        f"/api/v1/event-definitions/{draft['id']}",
        json={"name": {"en": "Renamed"}},
        headers={"If-Match": "999"},
    )
    assert stale.status_code == 412
    assert stale.json()["revision"] == 1

    unchanged = client.get(f"/api/v1/event-definitions/{draft['id']}")
    assert unchanged.json()["name"] == {"en": "Untitled event"}
    assert unchanged.json()["revision"] == 1


def _one_challenge_document(minigame_id: str, host_label: str) -> dict[str, object]:
    return {
        "challenges": [
            {
                "id": "chal-x",
                "order": 1,
                "title": {"en": "X"},
                "text": {"en": "X text"},
                "minigame": {
                    "id": minigame_id,
                    "version": ">=1.0,<2.0",
                    "host_label": host_label,
                },
                "points": 10,
            }
        ]
    }


def test_patch_refuses_callback_host_label_with_no_configured_labels(
    client: TestClient, db_session: Session
) -> None:
    """sdk-contract-v1.md §3.4 check 14: `callback` is the SDK's own
    floor (`gameframework_sdk.validation.RESERVED_HOST_LABELS`), refused
    with or without any installation-configured list — this must hold
    with `reserved_host_labels` left at its empty default, proving the
    floor is not itself dependent on the setting being wired at all.
    """
    _login_as_admin(client, db_session)
    make_installed_artifact(
        db_session,
        artifact_id="mini-cb",
        version="1.0.0",
        manifest={"id": "mini-cb", "version": "1.0.0"},
        image_digest="sha256:" + "c" * 64,
    )
    draft = _create_draft(client)

    response = client.patch(
        f"/api/v1/event-definitions/{draft['id']}",
        json=_one_challenge_document("mini-cb", "callback"),
        headers={"If-Match": "1"},
    )

    assert response.status_code == 422, response.text
    assert any("callback" in error and "reserved" in error for error in response.json()["errors"])


def test_patch_refuses_host_label_configured_as_reserved(
    client: TestClient, db_session: Session
) -> None:
    """The installation half of check 14: a label that is not the SDK's
    own floor is refused only when `Settings.reserved_host_labels` names
    it — proving the setting is actually read, not only the hardcoded
    floor (data-model.md §3.15, sdk-contract-v1.md §3.4 check 14).
    """
    from gameframework.config import get_settings
    from gameframework.main import app

    _login_as_admin(client, db_session)
    make_installed_artifact(
        db_session,
        artifact_id="mini-rs",
        version="1.0.0",
        manifest={"id": "mini-rs", "version": "1.0.0"},
        image_digest="sha256:" + "d" * 64,
    )
    draft = _create_draft(client)

    settings = get_settings().model_copy(update={"reserved_host_labels": ["custom-surface"]})
    app.dependency_overrides[get_settings] = lambda: settings
    try:
        response = client.patch(
            f"/api/v1/event-definitions/{draft['id']}",
            json=_one_challenge_document("mini-rs", "custom-surface"),
            headers={"If-Match": "1"},
        )
    finally:
        app.dependency_overrides.pop(get_settings, None)

    assert response.status_code == 422, response.text
    assert any(
        "custom-surface" in error and "reserved" in error for error in response.json()["errors"]
    )


def test_patch_persists_nothing_when_refused_for_a_non_resolver_reason(
    client: TestClient, db_session: Session
) -> None:
    """The transactional half of "refused ⇒ nothing persisted"
    (Working-Agreement: "this codebase binds those individually",
    Task 1a): a two-challenge dependency cycle is refused by
    `validate_event`'s own graph check (sdk-contract-v1.md §3.4 check 10),
    not by minigame resolution — both challenges' minigames resolve
    cleanly and carry distinct `order` values, so nothing here trips a
    database constraint of its own (unlike a duplicate `order`, which
    `challenge`'s `UniqueConstraint` refuses before persistence-ordering
    is ever in question). This isolates the persist-after-validate
    ordering from every other safety net.
    """
    _login_as_admin(client, db_session)
    make_installed_artifact(
        db_session,
        artifact_id="mini-p",
        version="1.0.0",
        manifest={"id": "mini-p", "version": "1.0.0"},
        image_digest="sha256:" + "p" * 64,
    )
    make_installed_artifact(
        db_session,
        artifact_id="mini-q",
        version="1.0.0",
        manifest={"id": "mini-q", "version": "1.0.0"},
        image_digest="sha256:" + "q" * 64,
    )
    draft = _create_draft(client)

    response = client.patch(
        f"/api/v1/event-definitions/{draft['id']}",
        json={
            "challenges": [
                {
                    "id": "chal-p",
                    "order": 1,
                    "title": {"en": "P"},
                    "text": {"en": "P text"},
                    "minigame": {"id": "mini-p", "version": ">=1.0,<2.0"},
                    "points": 10,
                    "depends_on": ["chal-q"],
                },
                {
                    "id": "chal-q",
                    "order": 2,
                    "title": {"en": "Q"},
                    "text": {"en": "Q text"},
                    "minigame": {"id": "mini-q", "version": ">=1.0,<2.0"},
                    "points": 10,
                    "depends_on": ["chal-p"],
                },
            ]
        },
        headers={"If-Match": "1"},
    )

    assert response.status_code == 422, response.text
    assert any("dependency cycle" in error for error in response.json()["errors"])

    unchanged = client.get(f"/api/v1/event-definitions/{draft['id']}")
    assert unchanged.json()["revision"] == 1
    assert unchanged.json()["challenges"] == []
    persisted = (
        db_session.execute(
            select(Challenge).where(Challenge.event_definition_id == uuid.UUID(str(draft["id"])))
        )
        .scalars()
        .all()
    )
    assert persisted == []
