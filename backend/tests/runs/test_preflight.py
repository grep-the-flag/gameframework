"""M2-Task-Plan.md Task 13 Step 2/2a: the run preflight's database half
(api-surface.md §2.6; data-model.md §3.9, §3.15, §3.16).

`services/preflight.py` and `services/ports.py` do not exist on `develop`
at the start of this task, so a first run of this file is expected to fail
on an import error rather than on the route's own logic — a
collection/routing red, not proof any individual assertion here catches
what it names (Working-Agreement "a collection error is not a red proof").
The mutation table in the Step 2 report is what actually binds each
assertion, once the route exists.
"""

import uuid
from typing import cast

from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from gameframework.config import get_settings
from gameframework.db.models.authoring import Challenge
from gameframework.db.models.identity import Role, User
from gameframework.db.models.infrastructure import InstalledArtifact
from gameframework.db.models.runs import EventRun, RunStatus
from gameframework.db.models.runtime import MinigameInstance, MinigamePort, PortSource, SolveMode
from gameframework.main import app
from gameframework.services.passwords import hash_password
from gameframework.services.preflight import compute_config_hash

from ..conftest import (
    make_event_run,
    make_installed_artifact,
    make_minigame_instance,
    make_minigame_port,
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


def _install_minigame(
    db_session: Session,
    *,
    minigame_id: str,
    version: str = "1.0.0",
    digest_char: str = "a",
    manifest_overrides: dict[str, object] | None = None,
) -> str:
    digest = "sha256:" + digest_char * 64
    manifest: dict[str, object] = {
        "id": minigame_id,
        "version": version,
        "image": f"ghcr.io/org/{minigame_id}@{digest}",
    }
    if manifest_overrides:
        manifest.update(manifest_overrides)
    make_installed_artifact(
        db_session,
        artifact_id=minigame_id,
        version=version,
        manifest=manifest,
        image_digest=digest,
    )
    return digest


def _publish_definition(
    client: TestClient, challenges_spec: list[dict[str, object]]
) -> dict[str, object]:
    draft = client.post("/api/v1/event-definitions")
    assert draft.status_code == 201, draft.text
    draft_body = draft.json()

    challenges = []
    for order, spec in enumerate(challenges_spec, start=1):
        minigame: dict[str, object] = {
            "id": spec["minigame_id"],
            "version": spec.get("version_range", ">=1.0,<2.0"),
        }
        if "host_label" in spec:
            minigame["host_label"] = spec["host_label"]
        challenges.append(
            {
                "id": spec["id"],
                "order": order,
                "title": {"en": str(spec["id"])},
                "text": spec.get("text", {"en": f"{spec['id']} text"}),
                "minigame": minigame,
                "points": 10,
            }
        )

    patched = client.patch(
        f"/api/v1/event-definitions/{draft_body['id']}",
        json={"challenges": challenges},
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


def _teamed_run(
    client: TestClient, db_session: Session, challenges_spec: list[dict[str, object]]
) -> tuple[dict[str, object], EventRun]:
    """A published definition, a run of it, and one fully-teamed
    participation — the minimal roster every non-roster-focused test
    starts from."""
    published = _publish_definition(client, challenges_spec)
    run_body = _create_run(client, str(published["id"]))
    run_row = db_session.get(EventRun, uuid.UUID(str(run_body["id"])))
    assert run_row is not None
    team = make_team(db_session, run=run_row)
    make_participation(db_session, run=run_row, team_id=team.id)
    return run_body, run_row


# ---------------------------------------------------------------------------
# roster: every participation must carry a team
# ---------------------------------------------------------------------------


def test_preflight_fails_naming_teamless_participation(
    client: TestClient, db_session: Session
) -> None:
    _login_as_admin(client, db_session)
    _install_minigame(db_session, minigame_id="mini-roster")
    published = _publish_definition(client, [{"id": "chal-a", "minigame_id": "mini-roster"}])
    run_body = _create_run(client, str(published["id"]))
    run_row = db_session.get(EventRun, uuid.UUID(str(run_body["id"])))
    assert run_row is not None
    team = make_team(db_session, run=run_row)
    make_participation(db_session, run=run_row, team_id=team.id)
    ghost = make_user(db_session, username="ghost-player")
    make_participation(db_session, user=ghost, run=run_row)  # team_id left null

    response = client.post(f"/api/v1/runs/{run_body['id']}/preflight")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["passed"] is False
    assert any("ghost-player" in error for error in body["errors"])


# ---------------------------------------------------------------------------
# pinned artifact presence — looked up, never re-resolved
# ---------------------------------------------------------------------------


def test_preflight_fails_naming_pin_absent_from_store(
    client: TestClient, db_session: Session
) -> None:
    _login_as_admin(client, db_session)
    _install_minigame(db_session, minigame_id="mini-pin")
    _run_body, run_row = _teamed_run(
        client, db_session, [{"id": "chal-a", "minigame_id": "mini-pin"}]
    )

    db_session.execute(delete(InstalledArtifact).where(InstalledArtifact.artifact_id == "mini-pin"))
    db_session.commit()

    response = client.post(f"/api/v1/runs/{run_row.id}/preflight")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["passed"] is False
    assert any("mini-pin" in error for error in body["errors"])


def test_preflight_still_fails_when_a_newer_satisfying_version_is_installed(
    client: TestClient, db_session: Session
) -> None:
    """The pin is looked up, never re-resolved: a newer version satisfying
    the same range must not let the preflight silently adopt it once the
    originally-pinned one has left the store (data-model.md §3.5,
    sdk-contract-v1.md §3.4)."""
    _login_as_admin(client, db_session)
    _install_minigame(db_session, minigame_id="mini-newer", version="1.0.0", digest_char="a")
    _run_body, run_row = _teamed_run(
        client, db_session, [{"id": "chal-a", "minigame_id": "mini-newer"}]
    )

    db_session.execute(
        delete(InstalledArtifact).where(InstalledArtifact.artifact_id == "mini-newer")
    )
    _install_minigame(db_session, minigame_id="mini-newer", version="1.1.0", digest_char="b")

    response = client.post(f"/api/v1/runs/{run_row.id}/preflight")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["passed"] is False
    assert any("mini-newer" in error for error in body["errors"])


# ---------------------------------------------------------------------------
# reserved host labels — the SDK's check 14, re-run with the CURRENT list
# ---------------------------------------------------------------------------


def test_preflight_fails_on_label_newly_added_to_reserved_list(
    client: TestClient, db_session: Session
) -> None:
    _login_as_admin(client, db_session)
    _install_minigame(db_session, minigame_id="mini-label")
    _run_body, run_row = _teamed_run(
        client,
        db_session,
        [{"id": "chal-a", "minigame_id": "mini-label", "host_label": "ahab"}],
    )

    settings = get_settings().model_copy(update={"reserved_host_labels": ["ahab"]})
    app.dependency_overrides[get_settings] = lambda: settings
    try:
        response = client.post(f"/api/v1/runs/{run_row.id}/preflight")
    finally:
        app.dependency_overrides.pop(get_settings, None)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["passed"] is False
    assert any("ahab" in error and "reserved" in error for error in body["errors"])


# ---------------------------------------------------------------------------
# port capacity — naming the size the range would need
# ---------------------------------------------------------------------------


def test_preflight_fails_naming_port_range_size_needed(
    client: TestClient, db_session: Session
) -> None:
    _login_as_admin(client, db_session)
    _install_minigame(
        db_session,
        minigame_id="mini-2ports",
        manifest_overrides={"tcp_ports": [{"port": 22}, {"port": 2222}]},
    )
    _run_body, run_row = _teamed_run(
        client,
        db_session,
        [
            {
                "id": "chal-a",
                "minigame_id": "mini-2ports",
                "text": {"en": "ssh player@{{minigame.host}} -p {{minigame.port.22}}"},
            }
        ],
    )

    settings = get_settings().model_copy(update={"tcp_port_range": (20000, 20000)})
    app.dependency_overrides[get_settings] = lambda: settings
    try:
        response = client.post(f"/api/v1/runs/{run_row.id}/preflight")
    finally:
        app.dependency_overrides.pop(get_settings, None)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["passed"] is False
    assert any("2" in error and "1" in error for error in body["errors"])


def test_preflight_allocation_skips_a_port_another_run_still_holds(
    client: TestClient, db_session: Session
) -> None:
    """sdk-contract-v1.md §4.1: allocation is installation-wide, not
    per-run — "skipping published ports another live run still holds"."""
    _login_as_admin(client, db_session)
    other_run = make_event_run(db_session)
    other_instance = make_minigame_instance(db_session, run=other_run)
    settings = get_settings()
    range_start = settings.tcp_port_range[0]
    make_minigame_port(
        db_session,
        other_instance,
        container_port=22,
        host_port=range_start,
        source=PortSource.allocated,
    )

    _install_minigame(
        db_session,
        minigame_id="mini-skip",
        manifest_overrides={"tcp_ports": [{"port": 22}]},
    )
    _run_body, run_row = _teamed_run(
        client,
        db_session,
        [
            {
                "id": "chal-a",
                "minigame_id": "mini-skip",
                "text": {"en": "ssh player@{{minigame.host}} -p {{minigame.port}}"},
            }
        ],
    )

    response = client.post(f"/api/v1/runs/{run_row.id}/preflight")

    assert response.status_code == 200, response.text
    assert response.json()["passed"] is True, response.json()["errors"]

    instance = db_session.execute(
        select(MinigameInstance).where(
            MinigameInstance.event_run_id == run_row.id, MinigameInstance.minigame_id == "mini-skip"
        )
    ).scalar_one()
    port = db_session.execute(
        select(MinigamePort).where(MinigamePort.minigame_instance_id == instance.id)
    ).scalar_one()
    assert port.host_port == range_start + 1


# ---------------------------------------------------------------------------
# run status gate
# ---------------------------------------------------------------------------


def test_preflight_on_non_created_run_is_409(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.running)

    response = client.post(f"/api/v1/runs/{run.id}/preflight")

    assert response.status_code == 409
    assert response.json()["code"] == "invalid_status_transition"


def test_preflight_on_unknown_run_is_404(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)

    response = client.post(f"/api/v1/runs/{uuid.uuid4()}/preflight")

    assert response.status_code == 404
    assert response.json()["code"] == "object_not_found"


def test_preflight_requires_admin_not_gameadmin(client: TestClient, db_session: Session) -> None:
    _login_as_gameadmin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)

    response = client.post(f"/api/v1/runs/{run.id}/preflight")

    assert response.status_code == 403
    assert response.json()["code"] == "role_denied"


# ---------------------------------------------------------------------------
# first success: materialization
# ---------------------------------------------------------------------------


def test_first_successful_preflight_materializes_instance_from_pinned_manifest(
    client: TestClient, db_session: Session
) -> None:
    digest = "sha256:" + "e" * 64
    _login_as_admin(client, db_session)
    _install_minigame(
        db_session,
        minigame_id="mini-moby",
        digest_char="e",
        manifest_overrides={"solve_mode": "callback"},
    )
    run_body, run_row = _teamed_run(
        client,
        db_session,
        [{"id": "chal-a", "minigame_id": "mini-moby", "host_label": "moby"}],
    )
    settings = get_settings()

    response = client.post(f"/api/v1/runs/{run_body['id']}/preflight")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["passed"] is True, body["errors"]

    instance = db_session.execute(
        select(MinigameInstance).where(
            MinigameInstance.event_run_id == run_row.id, MinigameInstance.minigame_id == "mini-moby"
        )
    ).scalar_one()
    assert instance.hostname == f"moby.{settings.event_domain}"
    assert instance.solve_mode == SolveMode.callback
    assert instance.image_ref == f"ghcr.io/org/mini-moby@{digest}"
    assert instance.image_digest == digest

    db_session.refresh(run_row)
    assert run_row.preflight_passed_at is not None
    assert run_row.preflight_config_hash is not None


def test_repeated_preflight_reconciles_without_duplicating_and_never_reassigns_override(
    client: TestClient, db_session: Session
) -> None:
    """data-model.md §3.15/§3.16: a repeated preflight materializes each
    instance exactly once and never reassigns a row whose `source` is
    `override` — the column exists for exactly this."""
    _login_as_admin(client, db_session)
    pinned_digest = _install_minigame(
        db_session,
        minigame_id="mini-multi",
        manifest_overrides={"tcp_ports": [{"port": 22}, {"port": 2222}]},
    )
    run_body, run_row = _teamed_run(
        client,
        db_session,
        [
            {
                "id": "chal-a",
                "minigame_id": "mini-multi",
                "text": {"en": "ssh player@{{minigame.host}} -p {{minigame.port.22}}"},
            }
        ],
    )

    existing_instance = make_minigame_instance(
        db_session,
        run=run_row,
        minigame_id="mini-multi",
        image_ref="stale-ref",
        image_digest="sha256:" + "a" * 64,
    )
    override_port = make_minigame_port(
        db_session,
        existing_instance,
        container_port=22,
        host_port=25000,
        source=PortSource.override,
        override_reason="operator pinned this one",
    )

    first = client.post(f"/api/v1/runs/{run_body['id']}/preflight")
    assert first.status_code == 200, first.text
    assert first.json()["passed"] is True, first.json()["errors"]

    instances_after_first = (
        db_session.execute(
            select(MinigameInstance).where(
                MinigameInstance.event_run_id == run_row.id,
                MinigameInstance.minigame_id == "mini-multi",
            )
        )
        .scalars()
        .all()
    )
    assert len(instances_after_first) == 1
    assert instances_after_first[0].image_digest == pinned_digest

    db_session.refresh(override_port)
    assert override_port.source == PortSource.override
    assert override_port.host_port == 25000

    new_port = db_session.execute(
        select(MinigamePort).where(
            MinigamePort.minigame_instance_id == existing_instance.id,
            MinigamePort.container_port == 2222,
        )
    ).scalar_one()
    assert new_port.source == PortSource.allocated

    # Second call: reconciles, still exactly one instance, still exactly
    # two ports, override still untouched.
    second = client.post(f"/api/v1/runs/{run_body['id']}/preflight")
    assert second.status_code == 200, second.text
    assert second.json()["passed"] is True, second.json()["errors"]

    instances_after_second = (
        db_session.execute(
            select(MinigameInstance).where(
                MinigameInstance.event_run_id == run_row.id,
                MinigameInstance.minigame_id == "mini-multi",
            )
        )
        .scalars()
        .all()
    )
    assert len(instances_after_second) == 1
    assert instances_after_second[0].image_digest == pinned_digest

    ports_after_second = (
        db_session.execute(
            select(MinigamePort).where(MinigamePort.minigame_instance_id == existing_instance.id)
        )
        .scalars()
        .all()
    )
    assert len(ports_after_second) == 2

    db_session.refresh(override_port)
    assert override_port.host_port == 25000
    assert override_port.source == PortSource.override


# ---------------------------------------------------------------------------
# config hash staleness — bound input by input (Step 2 report holds the
# mutation table; these assertions are what the mutations are read against)
# ---------------------------------------------------------------------------


def test_config_hash_stales_on_roster_change(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)
    _install_minigame(db_session, minigame_id="mini-hash-a")
    _run_body, run_row = _teamed_run(
        client, db_session, [{"id": "chal-a", "minigame_id": "mini-hash-a"}]
    )
    settings = get_settings()
    hash_before = compute_config_hash(db_session, run_row, settings)

    new_team = make_team(db_session, run=run_row)
    make_participation(db_session, run=run_row, team_id=new_team.id)

    hash_after = compute_config_hash(db_session, run_row, settings)
    assert hash_after != hash_before


def test_config_hash_stales_on_reserved_label_change(
    client: TestClient, db_session: Session
) -> None:
    _login_as_admin(client, db_session)
    _install_minigame(db_session, minigame_id="mini-hash-b")
    _run_body, run_row = _teamed_run(
        client, db_session, [{"id": "chal-a", "minigame_id": "mini-hash-b"}]
    )
    settings_before = get_settings()
    hash_before = compute_config_hash(db_session, run_row, settings_before)

    settings_after = settings_before.model_copy(update={"reserved_host_labels": ["new-surface"]})
    hash_after = compute_config_hash(db_session, run_row, settings_after)

    assert hash_after != hash_before


def test_config_hash_does_not_stale_on_whitelist_content_edit(
    client: TestClient, db_session: Session
) -> None:
    """The asymmetry that is the whole point (data-model.md §3.9): a
    post-publication content fix changes the definition's live `revision`
    but must not stale a passed preflight — the hash covers the run's
    pinned `definition_revision`, never the live one."""
    _login_as_admin(client, db_session)
    _install_minigame(db_session, minigame_id="mini-hash-c")
    published = _publish_definition(client, [{"id": "chal-a", "minigame_id": "mini-hash-c"}])
    run_body = _create_run(client, str(published["id"]))
    run_row = db_session.get(EventRun, uuid.UUID(str(run_body["id"])))
    assert run_row is not None
    team = make_team(db_session, run=run_row)
    make_participation(db_session, run=run_row, team_id=team.id)
    settings = get_settings()
    hash_before = compute_config_hash(db_session, run_row, settings)

    patch_response = client.patch(
        f"/api/v1/event-definitions/{published['id']}",
        json={
            "challenges": [
                {
                    "id": "chal-a",
                    "order": 1,
                    "title": {"en": "Edited title"},
                    "text": {"en": "chal-a text"},
                    "minigame": {"id": "mini-hash-c", "version": ">=1.0,<2.0"},
                    "points": 10,
                }
            ]
        },
        headers={"If-Match": str(published["revision"])},
    )
    assert patch_response.status_code == 200, patch_response.text
    assert patch_response.json()["revision"] == cast(int, published["revision"]) + 1

    db_session.refresh(run_row)
    hash_after = compute_config_hash(db_session, run_row, settings)

    assert hash_after == hash_before


def test_config_hash_stales_when_a_pin_leaves_the_store(
    client: TestClient, db_session: Session
) -> None:
    _login_as_admin(client, db_session)
    _install_minigame(db_session, minigame_id="mini-hash-d")
    _run_body, run_row = _teamed_run(
        client, db_session, [{"id": "chal-a", "minigame_id": "mini-hash-d"}]
    )
    settings = get_settings()
    hash_before = compute_config_hash(db_session, run_row, settings)

    db_session.execute(
        delete(InstalledArtifact).where(InstalledArtifact.artifact_id == "mini-hash-d")
    )
    db_session.commit()

    hash_after = compute_config_hash(db_session, run_row, settings)
    assert hash_after != hash_before


def test_config_hash_stales_on_port_range_change(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)
    _install_minigame(db_session, minigame_id="mini-hash-e")
    _run_body, run_row = _teamed_run(
        client, db_session, [{"id": "chal-a", "minigame_id": "mini-hash-e"}]
    )
    settings_before = get_settings()
    hash_before = compute_config_hash(db_session, run_row, settings_before)

    settings_after = settings_before.model_copy(update={"tcp_port_range": (21000, 21999)})
    hash_after = compute_config_hash(db_session, run_row, settings_after)

    assert hash_after != hash_before


def test_config_hash_stales_on_player_tcp_host_change(
    client: TestClient, db_session: Session
) -> None:
    _login_as_admin(client, db_session)
    _install_minigame(db_session, minigame_id="mini-hash-f")
    _run_body, run_row = _teamed_run(
        client, db_session, [{"id": "chal-a", "minigame_id": "mini-hash-f"}]
    )
    settings_before = get_settings()
    hash_before = compute_config_hash(db_session, run_row, settings_before)

    settings_after = settings_before.model_copy(
        update={"player_tcp_host": "play.event.example.com"}
    )
    hash_after = compute_config_hash(db_session, run_row, settings_after)

    assert hash_after != hash_before


def test_config_hash_stales_on_event_domain_change(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)
    _install_minigame(db_session, minigame_id="mini-hash-g")
    _run_body, run_row = _teamed_run(
        client, db_session, [{"id": "chal-a", "minigame_id": "mini-hash-g"}]
    )
    settings_before = get_settings()
    hash_before = compute_config_hash(db_session, run_row, settings_before)

    settings_after = settings_before.model_copy(update={"event_domain": "other.example.com"})
    hash_after = compute_config_hash(db_session, run_row, settings_after)

    assert hash_after != hash_before


def test_config_hash_stales_on_definition_revision_change(
    client: TestClient, db_session: Session
) -> None:
    """No live route ever moves `run.definition_revision` — it is pinned
    at run creation and frozen for the run's life (data-model.md §3.9) —
    so this mutates the row directly, the only way the claim "it is a
    hash input" can be tested at all."""
    _login_as_admin(client, db_session)
    _install_minigame(db_session, minigame_id="mini-hash-h")
    _run_body, run_row = _teamed_run(
        client, db_session, [{"id": "chal-a", "minigame_id": "mini-hash-h"}]
    )
    settings = get_settings()
    hash_before = compute_config_hash(db_session, run_row, settings)

    run_row.definition_revision += 1

    hash_after = compute_config_hash(db_session, run_row, settings)
    assert hash_after != hash_before


def test_config_hash_stales_on_pin_identity_change(client: TestClient, db_session: Session) -> None:
    """The pinned artifact set is hashed by identity, not only by whether
    it currently resolves (data-model.md §3.5/§3.9) — no live route ever
    changes a published challenge's pin, so this mutates the row directly.

    The store copy is deleted first so `present` reads `False` on both
    sides of the mutation: a first version of this test left it installed
    and mutated `minigame_version` alone, which also flips `present` to
    `False` as a side effect (the presence lookup is keyed by that same
    version) — a mutation removing `version` from the hash payload still
    passed, undetected, because `present`'s own change carried the
    assertion. Holding `present` constant is what isolates `version` as
    its own input.
    """
    _login_as_admin(client, db_session)
    _install_minigame(db_session, minigame_id="mini-hash-i")
    _run_body, run_row = _teamed_run(
        client, db_session, [{"id": "chal-a", "minigame_id": "mini-hash-i"}]
    )
    db_session.execute(
        delete(InstalledArtifact).where(InstalledArtifact.artifact_id == "mini-hash-i")
    )
    db_session.commit()
    settings = get_settings()
    hash_before = compute_config_hash(db_session, run_row, settings)

    challenge = db_session.execute(
        select(Challenge).where(Challenge.event_definition_id == run_row.event_definition_id)
    ).scalar_one()
    challenge.minigame_version = "9.9.9"  # still absent from the store: `present` stays False

    hash_after = compute_config_hash(db_session, run_row, settings)
    assert hash_after != hash_before


# ---------------------------------------------------------------------------
# Step 2a: a failing preflight after a prior pass leaves the pass recorded
# ---------------------------------------------------------------------------


def test_failing_preflight_after_a_pass_leaves_the_recorded_pass_and_hash_stale(
    client: TestClient, db_session: Session
) -> None:
    """`preflight_passed_at` is written by the last SUCCESSFUL preflight and
    by nothing else (data-model.md §3.9): a later preflight that fails for
    an unrelated reason must not clear it. What refuses `start` in that
    state is the stale hash, not a cleared timestamp — each mechanism
    tested alone would let a bug in their interaction through.
    """
    _login_as_admin(client, db_session)
    _install_minigame(db_session, minigame_id="mini-2a")
    run_body, run_row = _teamed_run(
        client, db_session, [{"id": "chal-a", "minigame_id": "mini-2a"}]
    )

    first = client.post(f"/api/v1/runs/{run_body['id']}/preflight")
    assert first.status_code == 200, first.text
    assert first.json()["passed"] is True, first.json()["errors"]

    db_session.refresh(run_row)
    passed_at_after_first = run_row.preflight_passed_at
    hash_after_first = run_row.preflight_config_hash
    assert passed_at_after_first is not None
    assert hash_after_first is not None

    ghost = make_user(db_session, username="ghost-2a")
    make_participation(db_session, user=ghost, run=run_row)  # teamless

    second = client.post(f"/api/v1/runs/{run_body['id']}/preflight")
    assert second.status_code == 200, second.text
    assert second.json()["passed"] is False
    assert any("ghost-2a" in error for error in second.json()["errors"])

    db_session.refresh(run_row)
    assert run_row.preflight_passed_at == passed_at_after_first
    assert run_row.preflight_config_hash == hash_after_first

    settings = get_settings()
    current_hash = compute_config_hash(db_session, run_row, settings)
    assert current_hash != run_row.preflight_config_hash
