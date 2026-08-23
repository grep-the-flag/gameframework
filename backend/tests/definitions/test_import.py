"""M2-Task-Plan.md Task 11 Step 2: `POST /event-definitions/import` — the
SDK pipeline over an uploaded `event.yaml` (api-surface.md §2.6;
sdk-contract-v1.md §3, §3.4).

`services/importer.py` does not exist on `develop` at the start of this
task, so a first run of this file is expected to fail on FastAPI's own
routing `404` (or an import error) rather than on `problem_error_handler` —
a collection/routing red, not proof any individual assertion here catches
what it names (Working-Agreement "a collection error is not a red proof").
The mutation table in the Step 2 report is what actually binds each
assertion, once the route exists.

Every fixture minigame is staged through Task 9's `make_installed_artifact`
factory rather than the drop-in reader — the reader is already bound by
Task 9's own tests, and a test here should not re-prove another task's
mechanism (Task 11 briefing, REUSE section).
"""

import io
import uuid

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.db.models.authoring import (
    Challenge,
    ChallengeDependency,
    DependencySource,
    EventDefinition,
    RewardConsumption,
    RewardDefinition,
)
from gameframework.db.models.identity import Role, User
from gameframework.db.models.infrastructure import InstalledArtifact
from gameframework.services.fetch import FetchError
from gameframework.services.passwords import hash_password

from ..conftest import make_event_definition, make_installed_artifact, make_user

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


def _import(client: TestClient, document: dict[str, object]) -> httpx.Response:
    raw = yaml.safe_dump(document).encode("utf-8")
    return client.post(
        "/api/v1/event-definitions/import",
        files={"file": ("event.yaml", io.BytesIO(raw), "application/x-yaml")},
    )


def _base_document(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": 1,
        "contract": ">=0.1,<1.0",
        "id": "demo-heist",
        "version": "0.1.0",
        "name": {"en": "The Demo Heist", "de": "Der Demo-Coup"},
        "story": {"en": "One continuous story."},
        "scoring": "challenge",
        "unlock_mode": "manual",
        "challenges": [],
    }
    document.update(overrides)
    return document


def test_import_persists_slugs_language_maps_challenges_dependencies_and_reward_wiring(
    client: TestClient, db_session: Session
) -> None:
    """The main happy path: slugs, `source_version`, language maps,
    challenges, both dependency sources, reward wiring, and each
    challenge's pinned `(version, image_digest)` — all in one call.
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

    document = _base_document(
        challenges=[
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
    )

    response = _import(client, document)
    assert response.status_code == 201, response.text
    body = response.json()

    assert body["slug"] == "demo-heist"
    assert body["source_version"] == "0.1.0"
    assert body["name"] == {"en": "The Demo Heist", "de": "Der Demo-Coup"}
    assert body["story"] == {"en": "One continuous story."}
    assert body["status"] == "draft"
    assert body["revision"] == 1

    definition_row = db_session.execute(
        select(EventDefinition).where(EventDefinition.id == uuid.UUID(str(body["id"])))
    ).scalar_one()
    assert definition_row.language_default == "en"
    assert definition_row.source is None  # a direct upload, not a URL import
    assert definition_row.contract_version == ">=0.1,<1.0"

    challenges = {
        c.slug: c
        for c in db_session.execute(
            select(Challenge).where(Challenge.event_definition_id == definition_row.id)
        )
        .scalars()
        .all()
    }
    assert challenges.keys() == {"chal-a", "chal-b", "chal-c"}
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
    consumption = db_session.execute(
        select(RewardConsumption).where(RewardConsumption.reward_definition_id == reward.id)
    ).scalar_one()
    assert consumption.consumer_challenge_id == challenges["chal-b"].id


def test_import_derives_language_default_alphabetically_when_name_has_no_english(
    client: TestClient, db_session: Session
) -> None:
    """No `event.yaml` field states `language_default` (data-model.md
    §3.4): `en` wins when present (the happy-path test above), and
    otherwise the alphabetically first key of `name` wins — not
    dict-insertion order, since a YAML mapping's key order is typing
    order, not significance.
    """
    _login_as_admin(client, db_session)
    make_installed_artifact(
        db_session,
        artifact_id="mini-x",
        version="1.0.0",
        manifest={"id": "mini-x", "version": "1.0.0"},
        image_digest="sha256:" + "x" * 64,
    )
    document = _base_document(
        name={"fr": "Le Casse", "de": "Der Coup"},
        challenges=[
            {
                "id": "chal-x",
                "order": 1,
                "title": {"fr": "X"},
                "text": {"fr": "X text"},
                "minigame": {"id": "mini-x", "version": ">=1.0,<2.0"},
                "points": 10,
            }
        ],
    )

    response = _import(client, document)
    assert response.status_code == 201, response.text

    definition_row = db_session.execute(
        select(EventDefinition).where(EventDefinition.id == uuid.UUID(str(response.json()["id"])))
    ).scalar_one()
    assert definition_row.language_default == "de"


def test_import_rejects_a_json_body_with_no_url(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)

    response = client.post("/api/v1/event-definitions/import", json={"not_url": "x"})

    assert response.status_code == 422, response.text
    assert response.json()["code"] == "event_yaml_required"


def test_import_rejects_a_body_that_is_neither_multipart_nor_json(
    client: TestClient, db_session: Session
) -> None:
    _login_as_admin(client, db_session)

    response = client.post(
        "/api/v1/event-definitions/import",
        content=b"not json, not multipart",
        headers={"content-type": "text/plain"},
    )

    assert response.status_code == 422, response.text
    assert response.json()["code"] == "event_yaml_required"


def test_import_via_url_calls_fetch_hardened_and_persists_the_stripped_source(
    client: TestClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The wiring proof: the deep hardening mechanics (redirects, caps,
    archive safety) are `test_fetch_hardening.py`'s job and are not
    re-driven here — this only proves the route calls `fetch_hardened`
    with the caller's URL, feeds its bytes through the same
    `import_definition` path the upload branch uses, and records `source`
    with the userinfo stripped (data-model.md §3.4)."""
    _login_as_admin(client, db_session)
    make_installed_artifact(
        db_session,
        artifact_id="mini-x",
        version="1.0.0",
        manifest={"id": "mini-x", "version": "1.0.0"},
        image_digest="sha256:" + "x" * 64,
    )
    document = _base_document(
        challenges=[
            {
                "id": "chal-x",
                "order": 1,
                "title": {"en": "X"},
                "text": {"en": "X text"},
                "minigame": {"id": "mini-x", "version": ">=1.0,<2.0"},
                "points": 10,
            }
        ]
    )
    raw = yaml.safe_dump(document).encode("utf-8")

    calls: list[str] = []

    def fake_fetch_hardened(url: str) -> bytes:
        calls.append(url)
        return raw

    monkeypatch.setattr("gameframework.api.definitions.fetch_hardened", fake_fetch_hardened)

    url_with_credentials = "https://token:secret@registry.example:8443/demo-heist/event.yaml"
    response = client.post("/api/v1/event-definitions/import", json={"url": url_with_credentials})

    assert response.status_code == 201, response.text
    assert calls == [url_with_credentials]

    definition_row = db_session.execute(
        select(EventDefinition).where(EventDefinition.id == uuid.UUID(str(response.json()["id"])))
    ).scalar_one()
    # The port survives the strip; only the userinfo (user:pass@) is removed.
    assert definition_row.source == "https://registry.example:8443/demo-heist/event.yaml"
    assert "token" not in definition_row.source
    assert "secret" not in definition_row.source


def test_import_via_url_translates_a_fetch_error_to_its_code(
    client: TestClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_fetch_hardened(url: str) -> bytes:
        raise FetchError("redirect_host_changed")

    monkeypatch.setattr("gameframework.api.definitions.fetch_hardened", fake_fetch_hardened)

    _login_as_admin(client, db_session)
    response = client.post(
        "/api/v1/event-definitions/import", json={"url": "https://registry.example/event.yaml"}
    )

    assert response.status_code == 422, response.text
    assert response.json()["code"] == "redirect_host_changed"
    assert db_session.execute(select(EventDefinition)).scalars().all() == []


def test_import_rejects_multipart_with_no_file_field(
    client: TestClient, db_session: Session
) -> None:
    _login_as_admin(client, db_session)

    response = client.post(
        "/api/v1/event-definitions/import",
        files={"not-file": ("x.txt", io.BytesIO(b"x"), "text/plain")},
    )

    assert response.status_code == 422, response.text
    assert response.json()["code"] == "event_yaml_required"


def test_import_rejects_malformed_yaml(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)

    response = client.post(
        "/api/v1/event-definitions/import",
        files={"file": ("event.yaml", io.BytesIO(b"key: [unclosed"), "application/x-yaml")},
    )

    assert response.status_code == 422, response.text
    assert response.json()["code"] == "event_yaml_invalid"
    assert db_session.execute(select(EventDefinition)).scalars().all() == []


def test_import_rejects_yaml_that_is_not_a_mapping(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)

    response = client.post(
        "/api/v1/event-definitions/import",
        files={"file": ("event.yaml", io.BytesIO(b"- one\n- two\n"), "application/x-yaml")},
    )

    assert response.status_code == 422, response.text
    assert response.json()["code"] == "event_yaml_invalid"
    assert db_session.execute(select(EventDefinition)).scalars().all() == []


def test_refused_import_does_not_roll_back_a_prior_committed_artifact(
    client: TestClient, db_session: Session
) -> None:
    """Probe for `import_definition`'s `db.rollback()` on a refused
    pipeline pass: under `tests/conftest.py`'s SAVEPOINT-joined session
    (`join_transaction_mode="create_savepoint"`), every data-factory call
    commits — "a durable checkpoint, so a later rollback for an expected
    violation elsewhere in the same test can't also undo a prerequisite
    row" (Task 1a). `make_installed_artifact`'s own commit is exactly such
    a checkpoint, staged before the refused import; this asserts the
    checkpoint held rather than assuming it did.
    """
    _login_as_admin(client, db_session)
    artifact = make_installed_artifact(
        db_session,
        artifact_id="mini-survivor",
        version="1.0.0",
        manifest={"id": "mini-survivor", "version": "1.0.0"},
        image_digest="sha256:" + "s" * 64,
    )

    document = _base_document(
        challenges=[
            {
                "id": "chal-ghost",
                "order": 1,
                "title": {"en": "Ghost"},
                "text": {"en": "Text"},
                "minigame": {"id": "ghost-game", "version": ">=1.0,<2.0"},
                "points": 10,
            }
        ]
    )
    response = _import(client, document)
    assert response.status_code == 422, response.text

    survivor = db_session.execute(
        select(InstalledArtifact).where(InstalledArtifact.id == artifact.id)
    ).scalar_one_or_none()
    assert survivor is not None


def test_refused_import_does_not_roll_back_a_prior_committed_definition(
    client: TestClient, db_session: Session
) -> None:
    """The second half of the same probe: an `EventDefinition` created
    (and committed by `make_event_definition`) before a later refused
    import must still be readable afterwards."""
    _login_as_admin(client, db_session)
    existing = make_event_definition(db_session, slug="pre-existing")

    document = _base_document(
        challenges=[
            {
                "id": "chal-ghost",
                "order": 1,
                "title": {"en": "Ghost"},
                "text": {"en": "Text"},
                "minigame": {"id": "ghost-game", "version": ">=1.0,<2.0"},
                "points": 10,
            }
        ]
    )
    response = _import(client, document)
    assert response.status_code == 422, response.text

    survivor = db_session.execute(
        select(EventDefinition).where(EventDefinition.id == existing.id)
    ).scalar_one_or_none()
    assert survivor is not None
    assert survivor.slug == "pre-existing"


def test_import_rejects_explicit_dependency_cycle(client: TestClient, db_session: Session) -> None:
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
    document = _base_document(
        challenges=[
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
    )

    response = _import(client, document)

    assert response.status_code == 422, response.text
    body = response.json()
    assert body["code"] == "definition_invalid"
    assert any("dependency cycle" in error for error in body["errors"])
    assert db_session.execute(select(EventDefinition)).scalars().all() == []


def test_import_rejects_reward_derived_dependency_cycle(
    client: TestClient, db_session: Session
) -> None:
    """A cycle built entirely from reward wiring — chal-a consumes what
    chal-b produces and chal-b consumes what chal-a produces — with no
    `depends_on` entry naming either side."""
    _login_as_admin(client, db_session)
    make_installed_artifact(
        db_session,
        artifact_id="mini-a",
        version="1.0.0",
        manifest={
            "id": "mini-a",
            "version": "1.0.0",
            "rewards": {
                "produces": [{"name": "reward_y", "type": "token"}],
                "consumes": [{"name": "reward_x", "type": "token"}],
            },
        },
        image_digest="sha256:" + "1" * 64,
    )
    make_installed_artifact(
        db_session,
        artifact_id="mini-b",
        version="1.0.0",
        manifest={
            "id": "mini-b",
            "version": "1.0.0",
            "rewards": {
                "produces": [{"name": "reward_x", "type": "token"}],
                "consumes": [{"name": "reward_y", "type": "token"}],
            },
        },
        image_digest="sha256:" + "2" * 64,
    )
    document = _base_document(
        challenges=[
            {
                "id": "chal-a",
                "order": 1,
                "title": {"en": "A"},
                "text": {"en": "A text"},
                "minigame": {"id": "mini-a", "version": ">=1.0,<2.0"},
                "points": 10,
                "rewards": {
                    "produces": [{"name": "reward_y", "type": "token"}],
                    "consumes": [{"name": "reward_x"}],
                },
            },
            {
                "id": "chal-b",
                "order": 2,
                "title": {"en": "B"},
                "text": {"en": "B text"},
                "minigame": {"id": "mini-b", "version": ">=1.0,<2.0"},
                "points": 10,
                "rewards": {
                    "produces": [{"name": "reward_x", "type": "token"}],
                    "consumes": [{"name": "reward_y"}],
                },
            },
        ]
    )

    response = _import(client, document)

    assert response.status_code == 422, response.text
    body = response.json()
    assert body["code"] == "definition_invalid"
    assert any("dependency cycle" in error for error in body["errors"])
    assert db_session.execute(select(EventDefinition)).scalars().all() == []


def test_import_rejects_mixed_dependency_cycle(client: TestClient, db_session: Session) -> None:
    """A cycle combining both edge sources: chal-c -> chal-a (explicit),
    chal-a -> chal-b (reward: b consumes what a produces), chal-b ->
    chal-c (explicit) — no single edge source has a cycle of its own."""
    _login_as_admin(client, db_session)
    make_installed_artifact(
        db_session,
        artifact_id="mini-a",
        version="1.0.0",
        manifest={
            "id": "mini-a",
            "version": "1.0.0",
            "rewards": {"produces": [{"name": "reward_z", "type": "token"}]},
        },
        image_digest="sha256:" + "3" * 64,
    )
    make_installed_artifact(
        db_session,
        artifact_id="mini-b",
        version="1.0.0",
        manifest={
            "id": "mini-b",
            "version": "1.0.0",
            "rewards": {"consumes": [{"name": "reward_z", "type": "token"}]},
        },
        image_digest="sha256:" + "4" * 64,
    )
    make_installed_artifact(
        db_session,
        artifact_id="mini-c",
        version="1.0.0",
        manifest={"id": "mini-c", "version": "1.0.0"},
        image_digest="sha256:" + "5" * 64,
    )
    document = _base_document(
        challenges=[
            {
                "id": "chal-a",
                "order": 1,
                "title": {"en": "A"},
                "text": {"en": "A text"},
                "minigame": {"id": "mini-a", "version": ">=1.0,<2.0"},
                "points": 10,
                "depends_on": ["chal-c"],
                "rewards": {"produces": [{"name": "reward_z", "type": "token"}]},
            },
            {
                "id": "chal-b",
                "order": 2,
                "title": {"en": "B"},
                "text": {"en": "B text"},
                "minigame": {"id": "mini-b", "version": ">=1.0,<2.0"},
                "points": 10,
                "rewards": {"consumes": [{"name": "reward_z"}]},
            },
            {
                "id": "chal-c",
                "order": 3,
                "title": {"en": "C"},
                "text": {"en": "C text"},
                "minigame": {"id": "mini-c", "version": ">=1.0,<2.0"},
                "points": 10,
                "depends_on": ["chal-b"],
            },
        ]
    )

    response = _import(client, document)

    assert response.status_code == 422, response.text
    body = response.json()
    assert body["code"] == "definition_invalid"
    assert any("dependency cycle" in error for error in body["errors"])
    assert db_session.execute(select(EventDefinition)).scalars().all() == []


def test_import_rejects_consumed_reward_nothing_produces(
    client: TestClient, db_session: Session
) -> None:
    _login_as_admin(client, db_session)
    make_installed_artifact(
        db_session,
        artifact_id="mini-lonely",
        version="1.0.0",
        manifest={
            "id": "mini-lonely",
            "version": "1.0.0",
            "rewards": {"consumes": [{"name": "ghost_reward", "type": "token"}]},
        },
        image_digest="sha256:" + "6" * 64,
    )
    document = _base_document(
        challenges=[
            {
                "id": "chal-lonely",
                "order": 1,
                "title": {"en": "Lonely"},
                "text": {"en": "Text"},
                "minigame": {"id": "mini-lonely", "version": ">=1.0,<2.0"},
                "points": 10,
                "rewards": {"consumes": [{"name": "ghost_reward"}]},
            }
        ]
    )

    response = _import(client, document)

    assert response.status_code == 422, response.text
    body = response.json()
    assert body["code"] == "definition_invalid"
    assert any(
        "ghost_reward" in error and "not produced by any challenge" in error
        for error in body["errors"]
    )
    assert db_session.execute(select(EventDefinition)).scalars().all() == []


def test_import_rejects_unknown_minigame_naming_it(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)
    document = _base_document(
        challenges=[
            {
                "id": "chal-ghost",
                "order": 1,
                "title": {"en": "Ghost"},
                "text": {"en": "Text"},
                "minigame": {"id": "ghost-game", "version": ">=1.0,<2.0"},
                "points": 10,
            }
        ]
    )

    response = _import(client, document)

    assert response.status_code == 422, response.text
    body = response.json()
    assert body["code"] == "definition_invalid"
    assert any("ghost-game" in error for error in body["errors"])
    assert db_session.execute(select(EventDefinition)).scalars().all() == []


def test_import_rejects_tcp_port_challenge_missing_placeholder_in_one_language(
    client: TestClient, db_session: Session
) -> None:
    """sdk-contract-v1.md §3.4 check 15: a challenge on a `tcp_ports`
    minigame must carry a `port` placeholder in every language its own
    text is written in — `en` carries it, `de` does not."""
    _login_as_admin(client, db_session)
    make_installed_artifact(
        db_session,
        artifact_id="mini-ssh",
        version="1.0.0",
        manifest={
            "id": "mini-ssh",
            "version": "1.0.0",
            "tcp_ports": [{"port": 22, "protocol": "tcp"}],
        },
        image_digest="sha256:" + "7" * 64,
    )
    document = _base_document(
        challenges=[
            {
                "id": "chal-ssh",
                "order": 1,
                "title": {"en": "SSH", "de": "SSH"},
                "text": {
                    "en": "ssh player@{{minigame.host}} -p {{minigame.port}}",
                    "de": "Keine Verbindungsdaten hier.",
                },
                "minigame": {"id": "mini-ssh", "version": ">=1.0,<2.0"},
                "points": 10,
            }
        ]
    )

    response = _import(client, document)

    assert response.status_code == 422, response.text
    body = response.json()
    assert body["code"] == "definition_invalid"
    assert any(
        "chal-ssh" in error and "/de" in error and "tcp_ports" in error for error in body["errors"]
    )
    assert db_session.execute(select(EventDefinition)).scalars().all() == []


def test_import_then_publish_after_newer_version_installed_still_reads_the_pinned_one(
    client: TestClient, db_session: Session
) -> None:
    """sdk-contract-v1.md §3.4: "highest-satisfying is the rule for the
    first resolution... every later one resolves against what that first
    one pinned." A newer satisfying version installed after import must
    not move the pin when the definition is re-validated (here, at
    publish)."""
    _login_as_admin(client, db_session)
    make_installed_artifact(
        db_session,
        artifact_id="dual-game",
        version="1.0.0",
        manifest={"id": "dual-game", "version": "1.0.0"},
        image_digest="sha256:" + "1" * 64,
    )
    document = _base_document(
        challenges=[
            {
                "id": "chal-a",
                "order": 1,
                "title": {"en": "A"},
                "text": {"en": "A text"},
                "minigame": {"id": "dual-game", "version": ">=1.0,<2.0"},
                "points": 10,
            }
        ]
    )

    response = _import(client, document)
    assert response.status_code == 201, response.text
    definition_id = response.json()["id"]

    make_installed_artifact(
        db_session,
        artifact_id="dual-game",
        version="1.5.0",
        manifest={"id": "dual-game", "version": "1.5.0"},
        image_digest="sha256:" + "5" * 64,
    )

    publish_response = client.post(f"/api/v1/event-definitions/{definition_id}/publish")
    assert publish_response.status_code == 200, publish_response.text

    row = db_session.execute(
        select(Challenge).where(Challenge.event_definition_id == uuid.UUID(definition_id))
    ).scalar_one()
    assert row.minigame_version == "1.0.0"
    assert row.minigame_image_digest == "sha256:" + "1" * 64


def test_dry_run_on_a_valid_definition_reports_no_errors(
    client: TestClient, db_session: Session
) -> None:
    _login_as_admin(client, db_session)
    make_installed_artifact(
        db_session,
        artifact_id="mini-dry",
        version="1.0.0",
        manifest={"id": "mini-dry", "version": "1.0.0"},
        image_digest="sha256:" + "d" * 64,
    )
    document = _base_document(
        challenges=[
            {
                "id": "chal-dry",
                "order": 1,
                "title": {"en": "Dry"},
                "text": {"en": "Dry text"},
                "minigame": {"id": "mini-dry", "version": ">=1.0,<2.0"},
                "points": 10,
            }
        ]
    )
    definition_id = _import(client, document).json()["id"]

    response = client.post(f"/api/v1/event-definitions/{definition_id}/dry-run")

    assert response.status_code == 200, response.text
    assert response.json()["errors"] == []


def test_dry_run_reports_the_same_error_import_would_when_a_pin_leaves_the_store(
    client: TestClient, db_session: Session
) -> None:
    """sdk-contract-v1.md §3.4: "a pin that has left the store fails...
    by name". Dry-run re-runs the canonical pipeline over the same
    `PinnedResolver` import and publish already use — no second
    validation logic — so removing the pinned artifact after import makes
    dry-run answer the same "does not resolve to a manifest" error an
    import referencing an unknown minigame would."""
    _login_as_admin(client, db_session)
    artifact = make_installed_artifact(
        db_session,
        artifact_id="mini-vanish",
        version="1.0.0",
        manifest={"id": "mini-vanish", "version": "1.0.0"},
        image_digest="sha256:" + "e" * 64,
    )
    document = _base_document(
        challenges=[
            {
                "id": "chal-vanish",
                "order": 1,
                "title": {"en": "Vanish"},
                "text": {"en": "Vanish text"},
                "minigame": {"id": "mini-vanish", "version": ">=1.0,<2.0"},
                "points": 10,
            }
        ]
    )
    definition_id = _import(client, document).json()["id"]

    db_session.delete(db_session.get(InstalledArtifact, artifact.id))
    db_session.commit()

    response = client.post(f"/api/v1/event-definitions/{definition_id}/dry-run")

    assert response.status_code == 200, response.text
    errors = response.json()["errors"]
    assert any("mini-vanish" in error and "does not resolve" in error for error in errors)
