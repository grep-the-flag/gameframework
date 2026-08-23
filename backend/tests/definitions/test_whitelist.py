"""M2-Task-Plan.md Task 10 Step 4: the post-publication content whitelist
(api-surface.md §2.6; sdk-contract-v1.md §3.4). After publication a
`PATCH` accepts `name`, `story`, `challenges[].title`/`text`/`points`/
`hint_cost`/`hint_cap`, and `privacy_notice_md` (not a document field at
all); everything else — challenge set, `order`, `depends_on`, reward
wiring, minigame reference, `unlock_mode`, `scoring` — is frozen at
publication, permanently. Every row of that table gets both an assertion
that it refuses and, for the changeable ones, an assertion that it
persists: a whitelist proven only by its refusals is indistinguishable
from a route that refuses everything.

Also carries the archived-`PATCH` guard found while closing Step 3
(`apply_patch`'s own `if definition.status is archived: raise` — a route
guard, not a content-whitelist decision, but it belongs here because this
is the PATCH route's test file).
"""

import uuid
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.db.models.identity import Role, User
from gameframework.db.models.infrastructure import InstalledArtifact
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


def _digest() -> str:
    return "sha256:" + (uuid.uuid4().hex * 2)


def _create_draft(client: TestClient) -> dict[str, object]:
    response = client.post("/api/v1/event-definitions")
    assert response.status_code == 201, response.text
    return response.json()


def _publish(client: TestClient, definition_id: object) -> dict[str, object]:
    response = client.post(f"/api/v1/event-definitions/{definition_id}/publish")
    assert response.status_code == 200, response.text
    return response.json()


def _create_publishable_draft(
    client: TestClient, db_session: Session, minigame_id: str
) -> dict[str, object]:
    """A published draft with exactly one challenge, no rewards — the
    shape every top-level-only row (`unlock_mode`, `scoring`, `name`,
    `story`) and the privacy/pipeline tests mutate against.
    """
    make_installed_artifact(
        db_session,
        artifact_id=minigame_id,
        version="1.0.0",
        manifest={"id": minigame_id, "version": "1.0.0"},
        image_digest=_digest(),
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
    return _publish(client, response.json()["id"])


def _wired_pair_challenges(minigame_a: str, minigame_b: str) -> list[dict[str, Any]]:
    return [
        {
            "id": "chal-a",
            "order": 1,
            "title": {"en": "A"},
            "text": {"en": "A text"},
            "minigame": {"id": minigame_a, "version": ">=1.0,<2.0"},
            "points": 10,
            "rewards": {"produces": [{"name": "loot", "type": "password"}]},
        },
        {
            "id": "chal-b",
            "order": 2,
            "title": {"en": "B"},
            "text": {"en": "B text"},
            "minigame": {"id": minigame_b, "version": ">=1.0,<2.0"},
            "points": 10,
            "rewards": {"consumes": [{"name": "loot"}]},
        },
    ]


def _publish_wired_pair(client: TestClient, db_session: Session, tag: str) -> dict[str, Any]:
    """A published definition with two challenges, chal-a's reward
    consumed by chal-b — the shared structure every frozen-field row
    below mutates exactly one axis of. Returns the published resource
    plus the two minigame ids, since each row test needs to rebuild the
    unchanged halves of the document around its own one mutation.
    """
    minigame_a, minigame_b = f"mini-{tag}-a", f"mini-{tag}-b"
    make_installed_artifact(
        db_session,
        artifact_id=minigame_a,
        version="1.0.0",
        manifest={
            "id": minigame_a,
            "version": "1.0.0",
            "rewards": {"produces": [{"name": "loot", "type": "password"}]},
        },
        image_digest=_digest(),
    )
    make_installed_artifact(
        db_session,
        artifact_id=minigame_b,
        version="1.0.0",
        manifest={
            "id": minigame_b,
            "version": "1.0.0",
            "rewards": {"consumes": [{"name": "loot"}]},
        },
        image_digest=_digest(),
    )
    draft = _create_draft(client)
    patched = client.patch(
        f"/api/v1/event-definitions/{draft['id']}",
        json={"challenges": _wired_pair_challenges(minigame_a, minigame_b)},
        headers={"If-Match": "1"},
    )
    assert patched.status_code == 200, patched.text
    published = _publish(client, patched.json()["id"])
    return {"definition": published, "minigame_a": minigame_a, "minigame_b": minigame_b}


# ---------------------------------------------------------------------------
# the archived-PATCH guard (carried over from Step 3's closing round)
# ---------------------------------------------------------------------------


def test_patch_refused_while_archived(client: TestClient, db_session: Session) -> None:
    """`apply_patch`'s own guard (services/definitions.py), ahead of the
    draft/whitelist dispatch: once a definition is archived, every
    `PATCH` is refused — including a field that would otherwise be freely
    editable, like `name`.
    """
    _login_as_admin(client, db_session)
    published = _create_publishable_draft(client, db_session, "mini-archived-patch")
    archived = client.post(f"/api/v1/event-definitions/{published['id']}/archive")
    assert archived.status_code == 200, archived.text

    response = client.patch(
        f"/api/v1/event-definitions/{published['id']}",
        json={"name": {"en": "New Name"}},
        headers={"If-Match": str(archived.json()["revision"])},
    )
    assert response.status_code == 409, response.text
    assert response.json()["code"] == "definition_archived"


# ---------------------------------------------------------------------------
# frozen rows: challenge set, order, depends_on, reward wiring, minigame
# reference, unlock_mode, scoring
# ---------------------------------------------------------------------------


def test_whitelist_refuses_challenge_set_change(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)
    pair = _publish_wired_pair(client, db_session, "cset")
    definition = pair["definition"]
    challenges = _wired_pair_challenges(pair["minigame_a"], pair["minigame_b"])
    challenges.append(
        {
            "id": "chal-c",
            "order": 3,
            "title": {"en": "C"},
            "text": {"en": "C text"},
            "minigame": {
                "id": pair["minigame_a"],
                "version": ">=1.0,<2.0",
                "host_label": "chal-c-host",
            },
            "points": 5,
        }
    )

    response = client.patch(
        f"/api/v1/event-definitions/{definition['id']}",
        json={"challenges": challenges},
        headers={"If-Match": str(definition["revision"])},
    )
    assert response.status_code == 409, response.text
    assert response.json()["code"] == "structural_change_rejected"

    unchanged = client.get(f"/api/v1/event-definitions/{definition['id']}")
    assert len(unchanged.json()["challenges"]) == 2


def test_whitelist_refuses_order_change(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)
    pair = _publish_wired_pair(client, db_session, "order")
    definition = pair["definition"]
    challenges = _wired_pair_challenges(pair["minigame_a"], pair["minigame_b"])
    challenges[0]["order"] = 99

    response = client.patch(
        f"/api/v1/event-definitions/{definition['id']}",
        json={"challenges": challenges},
        headers={"If-Match": str(definition["revision"])},
    )
    assert response.status_code == 409, response.text
    assert response.json()["code"] == "structural_change_rejected"

    unchanged = client.get(f"/api/v1/event-definitions/{definition['id']}")
    order_by_id = {c["id"]: c["order"] for c in unchanged.json()["challenges"]}
    assert order_by_id["chal-a"] == 1


def test_whitelist_refuses_depends_on_change(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)
    pair = _publish_wired_pair(client, db_session, "deps")
    definition = pair["definition"]
    challenges = _wired_pair_challenges(pair["minigame_a"], pair["minigame_b"])
    challenges[1]["depends_on"] = ["chal-a"]

    response = client.patch(
        f"/api/v1/event-definitions/{definition['id']}",
        json={"challenges": challenges},
        headers={"If-Match": str(definition["revision"])},
    )
    assert response.status_code == 409, response.text
    assert response.json()["code"] == "structural_change_rejected"

    unchanged = client.get(f"/api/v1/event-definitions/{definition['id']}")
    by_id = {c["id"]: c for c in unchanged.json()["challenges"]}
    assert by_id["chal-b"]["depends_on"] == []


def test_whitelist_refuses_reward_wiring_change(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)
    pair = _publish_wired_pair(client, db_session, "reward")
    definition = pair["definition"]
    challenges = _wired_pair_challenges(pair["minigame_a"], pair["minigame_b"])
    challenges[0]["rewards"] = {"produces": [{"name": "loot", "type": "token"}]}

    response = client.patch(
        f"/api/v1/event-definitions/{definition['id']}",
        json={"challenges": challenges},
        headers={"If-Match": str(definition["revision"])},
    )
    assert response.status_code == 409, response.text
    assert response.json()["code"] == "structural_change_rejected"

    unchanged = client.get(f"/api/v1/event-definitions/{definition['id']}")
    by_id = {c["id"]: c for c in unchanged.json()["challenges"]}
    assert by_id["chal-a"]["rewards"]["produces"] == [{"name": "loot", "type": "password"}]


def test_whitelist_refuses_reward_consumption_change(
    client: TestClient, db_session: Session
) -> None:
    """The `consumes` half of the same reward-wiring row — a separate
    check in the code (`_reward_signature` compared a second time) from
    the `produces` half above, so it needs its own case rather than
    trusting the sibling check to cover it.
    """
    _login_as_admin(client, db_session)
    pair = _publish_wired_pair(client, db_session, "consume")
    definition = pair["definition"]
    challenges = _wired_pair_challenges(pair["minigame_a"], pair["minigame_b"])
    challenges[1]["rewards"] = {"consumes": [{"name": "different-loot"}]}

    response = client.patch(
        f"/api/v1/event-definitions/{definition['id']}",
        json={"challenges": challenges},
        headers={"If-Match": str(definition["revision"])},
    )
    assert response.status_code == 409, response.text
    assert response.json()["code"] == "structural_change_rejected"

    unchanged = client.get(f"/api/v1/event-definitions/{definition['id']}")
    by_id = {c["id"]: c for c in unchanged.json()["challenges"]}
    assert by_id["chal-b"]["rewards"]["consumes"] == [{"name": "loot"}]


def test_whitelist_refuses_minigame_reference_change(
    client: TestClient, db_session: Session
) -> None:
    _login_as_admin(client, db_session)
    pair = _publish_wired_pair(client, db_session, "mgref")
    definition = pair["definition"]
    challenges = _wired_pair_challenges(pair["minigame_a"], pair["minigame_b"])
    challenges[0]["minigame"]["version"] = ">=2.0,<3.0"

    response = client.patch(
        f"/api/v1/event-definitions/{definition['id']}",
        json={"challenges": challenges},
        headers={"If-Match": str(definition["revision"])},
    )
    assert response.status_code == 409, response.text
    assert response.json()["code"] == "structural_change_rejected"

    unchanged = client.get(f"/api/v1/event-definitions/{definition['id']}")
    by_id = {c["id"]: c for c in unchanged.json()["challenges"]}
    assert by_id["chal-a"]["minigame"]["version"] == ">=1.0,<2.0"


def test_whitelist_refuses_unlock_mode_change(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)
    pair = _publish_wired_pair(client, db_session, "unlock")
    definition = pair["definition"]
    assert definition["unlock_mode"] == "manual"

    response = client.patch(
        f"/api/v1/event-definitions/{definition['id']}",
        json={"unlock_mode": "guided"},
        headers={"If-Match": str(definition["revision"])},
    )
    assert response.status_code == 409, response.text
    assert response.json()["code"] == "structural_change_rejected"

    unchanged = client.get(f"/api/v1/event-definitions/{definition['id']}")
    assert unchanged.json()["unlock_mode"] == "manual"


def test_whitelist_refuses_scoring_change(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)
    pair = _publish_wired_pair(client, db_session, "scoring")
    definition = pair["definition"]
    assert definition["scoring"] == "casual"

    response = client.patch(
        f"/api/v1/event-definitions/{definition['id']}",
        json={"scoring": "challenge"},
        headers={"If-Match": str(definition["revision"])},
    )
    assert response.status_code == 409, response.text
    assert response.json()["code"] == "structural_change_rejected"

    unchanged = client.get(f"/api/v1/event-definitions/{definition['id']}")
    assert unchanged.json()["scoring"] == "casual"


# ---------------------------------------------------------------------------
# changeable rows: name, story, and the per-challenge content fields
# ---------------------------------------------------------------------------


def test_whitelist_allows_name_and_story_change(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)
    published = _create_publishable_draft(client, db_session, "mini-wl-toplevel")

    response = client.patch(
        f"/api/v1/event-definitions/{published['id']}",
        json={"name": {"en": "New Name"}, "story": {"en": "New Story"}},
        headers={"If-Match": str(published["revision"])},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["name"] == {"en": "New Name"}
    assert body["story"] == {"en": "New Story"}

    reread = client.get(f"/api/v1/event-definitions/{published['id']}").json()
    assert reread["name"] == {"en": "New Name"}
    assert reread["story"] == {"en": "New Story"}


def test_whitelist_allows_all_challenge_content_fields_at_once(
    client: TestClient, db_session: Session
) -> None:
    """Every whitelisted per-challenge field changes together in one
    `PATCH`, not one at a time — proving none of the five is silently
    dropped while its siblings persist, the same class of bug the draft
    branch's `scoring`/`story` fix (Step 3's closing round) found.
    """
    _login_as_admin(client, db_session)
    published = _create_publishable_draft(client, db_session, "mini-wl-content")

    response = client.patch(
        f"/api/v1/event-definitions/{published['id']}",
        json={
            "challenges": [
                {
                    "id": "chal-a",
                    "order": 1,
                    "title": {"en": "New title"},
                    "text": {"en": "New text"},
                    "minigame": {"id": "mini-wl-content", "version": ">=1.0,<2.0"},
                    "points": 25,
                    "hint_cost": 3,
                    "hint_cap": 15,
                }
            ]
        },
        headers={"If-Match": str(published["revision"])},
    )
    assert response.status_code == 200, response.text
    challenge = response.json()["challenges"][0]
    assert challenge["title"] == {"en": "New title"}
    assert challenge["text"] == {"en": "New text"}
    assert challenge["points"] == 25
    assert challenge["hint_cost"] == 3
    assert challenge["hint_cap"] == 15

    reread = client.get(f"/api/v1/event-definitions/{published['id']}").json()["challenges"][0]
    assert reread["title"] == {"en": "New title"}
    assert reread["text"] == {"en": "New text"}
    assert reread["points"] == 25
    assert reread["hint_cost"] == 3
    assert reread["hint_cap"] == 15


# ---------------------------------------------------------------------------
# the canonical pipeline re-runs on a text edit, and against the pin
# ---------------------------------------------------------------------------


def test_whitelist_text_edit_with_mangled_placeholder_in_one_language_is_refused(
    client: TestClient, db_session: Session
) -> None:
    """SDK contract §3.4 check 13, api-surface.md §2.6: a text edit
    re-runs the canonical pipeline against the edited document, which is
    what catches a typo that breaks one language's placeholder while
    leaving another's intact — "a placeholder correct in `en` and
    misspelled in `de` is a broken text for German-speaking players
    only".
    """
    _login_as_admin(client, db_session)
    make_installed_artifact(
        db_session,
        artifact_id="mini-mangle",
        version="1.0.0",
        manifest={"id": "mini-mangle", "version": "1.0.0"},
        image_digest=_digest(),
    )
    draft = _create_draft(client)
    patched = client.patch(
        f"/api/v1/event-definitions/{draft['id']}",
        json={
            "challenges": [
                {
                    "id": "chal-a",
                    "order": 1,
                    "title": {"en": "A", "de": "A"},
                    "text": {"en": "Hi {{player.handle}}", "de": "Hallo {{player.handle}}"},
                    "minigame": {"id": "mini-mangle", "version": ">=1.0,<2.0"},
                    "points": 10,
                }
            ]
        },
        headers={"If-Match": "1"},
    )
    assert patched.status_code == 200, patched.text
    published = _publish(client, patched.json()["id"])

    response = client.patch(
        f"/api/v1/event-definitions/{published['id']}",
        json={
            "challenges": [
                {
                    "id": "chal-a",
                    "order": 1,
                    "title": {"en": "A", "de": "A"},
                    "text": {"en": "Hi {{player.handle}}", "de": "Hallo {{player.handle"},
                    "minigame": {"id": "mini-mangle", "version": ">=1.0,<2.0"},
                    "points": 10,
                }
            ]
        },
        headers={"If-Match": str(published["revision"])},
    )
    assert response.status_code == 422, response.text
    assert any("de" in error and "unterminated" in error for error in response.json()["errors"])

    unchanged = client.get(f"/api/v1/event-definitions/{published['id']}")
    assert unchanged.json()["revision"] == published["revision"]
    assert unchanged.json()["challenges"][0]["text"]["de"] == "Hallo {{player.handle}}"


def test_whitelist_text_edit_validates_against_the_pinned_manifest_not_a_newer_one(
    client: TestClient, db_session: Session
) -> None:
    """sdk-contract-v1.md §3.4, pin-once-resolve-against-pins: the
    whitelist re-validation uses `PinnedResolver`, never `StoreResolver`.
    Bound rather than assumed: the pinned version (1.0.0) declares no
    `tcp_ports`, so the challenge text carries no port placeholder; a
    *newer* satisfying version (1.5.0), installed after publication,
    does declare `tcp_ports` — which would demand one (check 15) if the
    highest-satisfying resolver were consulted instead. The edit must
    still succeed, because it validates the pinned manifest, not the
    newest one — if it passed with either resolver, the pinning would not
    be doing the work.
    """
    _login_as_admin(client, db_session)
    make_installed_artifact(
        db_session,
        artifact_id="mini-pin-vs-store",
        version="1.0.0",
        manifest={"id": "mini-pin-vs-store", "version": "1.0.0"},
        image_digest=_digest(),
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
                    "text": {"en": "No placeholder here"},
                    "minigame": {"id": "mini-pin-vs-store", "version": ">=1.0,<2.0"},
                    "points": 10,
                }
            ]
        },
        headers={"If-Match": "1"},
    )
    assert patched.status_code == 200, patched.text
    published = _publish(client, patched.json()["id"])

    make_installed_artifact(
        db_session,
        artifact_id="mini-pin-vs-store",
        version="1.5.0",
        manifest={
            "id": "mini-pin-vs-store",
            "version": "1.5.0",
            "tcp_ports": [{"port": 2222}],
        },
        image_digest=_digest(),
    )

    response = client.patch(
        f"/api/v1/event-definitions/{published['id']}",
        json={
            "challenges": [
                {
                    "id": "chal-a",
                    "order": 1,
                    "title": {"en": "A"},
                    "text": {"en": "Still no placeholder, revised"},
                    "minigame": {"id": "mini-pin-vs-store", "version": ">=1.0,<2.0"},
                    "points": 10,
                }
            ]
        },
        headers={"If-Match": str(published["revision"])},
    )
    assert response.status_code == 200, response.text
    assert response.json()["challenges"][0]["text"] == {"en": "Still no placeholder, revised"}


# ---------------------------------------------------------------------------
# privacy_notice_md: not a document field, editable at any non-archived
# status
# ---------------------------------------------------------------------------


def test_privacy_notice_md_editable_at_any_non_archived_status_and_bypasses_validation(
    client: TestClient, db_session: Session
) -> None:
    """data-model.md §3.4/api-surface.md §2.6: `privacy_notice_md` is
    operator content, no `event.yaml` field — it never reaches
    `validate_event`, so it stays writable at draft and at published,
    even in a state where `validate_event` would certainly fail. Proven
    by deliberately breaking the definition's own pin (removing the
    installed artifact, as Step 3's publish-pipeline tests do) and
    showing a `privacy_notice_md`-only edit still succeeds there, while a
    document-touching edit in that same broken state does not.
    """
    _login_as_admin(client, db_session)
    make_installed_artifact(
        db_session,
        artifact_id="mini-privacy",
        version="1.0.0",
        manifest={"id": "mini-privacy", "version": "1.0.0"},
        image_digest=_digest(),
    )
    draft = _create_draft(client)

    draft_patch = client.patch(
        f"/api/v1/event-definitions/{draft['id']}",
        json={"privacy_notice_md": "Draft notice"},
        headers={"If-Match": "1"},
    )
    assert draft_patch.status_code == 200, draft_patch.text
    assert draft_patch.json()["privacy_notice_md"] == "Draft notice"

    challenge_patch = client.patch(
        f"/api/v1/event-definitions/{draft['id']}",
        json={
            "challenges": [
                {
                    "id": "chal-a",
                    "order": 1,
                    "title": {"en": "A"},
                    "text": {"en": "A text"},
                    "minigame": {"id": "mini-privacy", "version": ">=1.0,<2.0"},
                    "points": 10,
                }
            ]
        },
        headers={"If-Match": str(draft_patch.json()["revision"])},
    )
    assert challenge_patch.status_code == 200, challenge_patch.text
    published = _publish(client, draft["id"])

    artifact = db_session.execute(
        select(InstalledArtifact).where(InstalledArtifact.artifact_id == "mini-privacy")
    ).scalar_one()
    db_session.delete(artifact)
    db_session.commit()

    privacy_patch = client.patch(
        f"/api/v1/event-definitions/{draft['id']}",
        json={"privacy_notice_md": "Published notice, provider changed"},
        headers={"If-Match": str(published["revision"])},
    )
    assert privacy_patch.status_code == 200, privacy_patch.text
    assert privacy_patch.json()["privacy_notice_md"] == "Published notice, provider changed"

    text_patch = client.patch(
        f"/api/v1/event-definitions/{draft['id']}",
        json={
            "challenges": [
                {
                    "id": "chal-a",
                    "order": 1,
                    "title": {"en": "A"},
                    "text": {"en": "Different text"},
                    "minigame": {"id": "mini-privacy", "version": ">=1.0,<2.0"},
                    "points": 10,
                }
            ]
        },
        headers={"If-Match": str(privacy_patch.json()["revision"])},
    )
    assert text_patch.status_code == 422, text_patch.text
