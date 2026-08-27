"""Cross-role auth E2E over the full run lifecycle (M2-Task-Plan.md Task 19;
api-surface.md §2.2, §2.6). One API-level flow against the real app and
database, exercising **only public routes** — no service calls, no fixture
shortcuts past a login — because this is the evidence for two M2
acceptance criteria (login of all four roles; pre-event login), and a step
that cheated past a route would prove nothing about that route.

Sequential by construction, one test function: `client` and `db_session`
are function-scoped (Task 1a), so the only way to carry one admin, one
gameadmin, one captain, one player, one run through start/pause/finish and
a second run is to keep them all in the same test. `_switch_to` ends
whatever session the client currently holds (if any) and logs in as the
next identity — the same way a person would move between browser tabs —
because `POST /auth/login` binds its CSRF token to the pre-session cookie
that only exists when no session does (api-surface.md §1), so a stale
session cookie left over from the previous identity makes the next login
fail on CSRF before it ever reaches credentials.

Two preconditions are built directly against `db_session` rather than
through a route, and both are deliberate, disclosed exceptions to
"public routes only" rather than shortcuts through the auth surface this
flow exists to prove:

- `make_installed_artifact` stages the one minigame the imported event
  references in the local artifact store. That staging is Task 9's own
  drop-in/store mechanism, filesystem-based and outside this flow's
  concern entirely — every other definition-import test in this suite
  (`tests/definitions/test_import.py`, `test_lifecycle.py`) stages it the
  same way rather than re-proving Task 9's mechanism here.
- `EventRun.scheduled_start` has **no public writer anywhere in the
  current API surface** — `POST /event-definitions/{id}/runs` takes no
  body and `PATCH /runs/{id}`'s whitelist does not carry it (`api/runs.py`
  `PatchRunRequest`). api-surface.md §2.2 requires `run_not_started` to
  carry `scheduled_start` "null when the run has none", which is exactly
  the only shape a run created through this flow's own routes can ever
  have, so that is the shape asserted below, through the real flow. The
  non-null shape is asserted at the unit level in
  `tests/auth/test_login.py` (Task 3), built directly against
  `db_session` there for the same reason — no route produces it. Building
  a non-null run through this E2E's own DB session, on the very run this
  flow created through its own routes, would be cheating past the one
  thing this flow exists to test; this file does not do that. See the
  Task 19 report for this named as its own finding.

Run 2 is created immediately after run 1 — both sitting in `created`
together — rather than later, after run 1 finishes, and `play-one` is
imported into run 2 *before* run 1. `POST /event-definitions/{id}/runs`
only refuses while another run is `running`/`paused` (api-surface.md
§2.6), so two `created` runs may coexist, and nothing here requires
waiting. The order matters: if `play-one`'s run-1 participation were
inserted first (as it would be if run 2 were created only after run 1
finished), an unordered `SELECT ... LIMIT 1` over their participations
would return it first purely because Postgres tends to scan a small,
freshly written table back in insertion order — passing against a
resolver that only ever looked at "some" participation rather than the
tiered one §2.6 specifies, for a reason that has nothing to do with
correctness. Importing into run 2 first makes the two orders — insertion
and §2.6 precedence — disagree, so a resolver that isn't actually doing
the tiered lookup has a chance to get it wrong. Verified: the E2E flow
below stayed green, unmodified, against both the fixed `resolve_current_
run`-based login and the original ad hoc `.first()` lookup it replaced,
until this reordering — see the Task 19 report.
"""

import io
from typing import cast

import httpx
import yaml
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from gameframework.config import get_settings
from gameframework.services.bootstrap import credentials_path

from ..conftest import make_installed_artifact

SESSION_COOKIE = "__Secure-gf_session"

MINIGAME_ID = "e2e-heist-mini"
MINIGAME_DIGEST = "sha256:" + "e" * 64

GAMEADMIN_USERNAME = "gm-lead"
GAMEADMIN_INITIAL_PASSWORD = "Admin-Set-Gm-Pw1!"
GAMEADMIN_CHOSEN_PASSWORD = "Gm-Chosen-Pw2!"

CAPTAIN_USERNAME = "cap-one"
CAPTAIN_CHOSEN_PASSWORD = "Cap-Chosen-Pw3!"

PLAYER_USERNAME = "play-one"
PLAYER_CHOSEN_PASSWORD = "Player-Chosen-Pw4!"

SOLE_RUN2_USERNAME = "only-run2"


def _switch_to(client: TestClient, username: str, password: str, step: str) -> httpx.Response:
    """Ends whatever session `client` currently holds, if any, then
    attempts a login as `username`/`password`. A previous *failed* login
    leaves no session cookie behind, so logout is skipped then — calling
    it with no session would itself be refused (`session_required`) and
    would prove nothing about the login this call is here to attempt.
    """
    if client.cookies.get(SESSION_COOKIE) is not None:
        logout_response = client.post("/api/v1/auth/logout")
        assert logout_response.status_code == 200, (
            f"{step}: logout of the previous session failed — "
            f"{logout_response.status_code} {logout_response.text}"
        )
    return client.post("/api/v1/auth/login", json={"username": username, "password": password})


def _expect_status(response: httpx.Response, expected: int, step: str) -> dict[str, object]:
    assert response.status_code == expected, (
        f"{step}: expected {expected}, got {response.status_code} — {response.text}"
    )
    return response.json()


def _expect_code(body: dict[str, object], expected_code: str, step: str) -> None:
    assert body.get("code") == expected_code, (
        f"{step}: expected code {expected_code!r}, got {body!r}"
    )


def _import_event_document() -> bytes:
    document = {
        "schema_version": 1,
        "contract": ">=0.1,<1.0",
        "id": "e2e-heist",
        "version": "0.1.0",
        "name": {"en": "The E2E Heist"},
        "story": {"en": "One continuous story."},
        "scoring": "challenge",
        "unlock_mode": "manual",
        "challenges": [
            {
                "id": "chal-a",
                "order": 1,
                "title": {"en": "A"},
                "text": {"en": "A text"},
                "minigame": {"id": MINIGAME_ID, "version": ">=1.0,<2.0"},
                "points": 10,
            }
        ],
    }
    return yaml.safe_dump(document).encode("utf-8")


def test_four_role_auth_flow_across_run_lifecycle(client: TestClient, db_session: Session) -> None:
    settings = get_settings()
    credentials_file = credentials_path(settings)

    # --- Initial admin logs in; the credential file disappears ---------
    assert credentials_file.exists(), (
        "initial admin: expected the framework-minted credential file to "
        "exist before the first login"
    )
    admin_username, admin_password = credentials_file.read_text().splitlines()

    response = client.post(
        "/api/v1/auth/login", json={"username": admin_username, "password": admin_password}
    )
    _expect_status(response, 200, "initial admin login")
    assert not credentials_file.exists(), (
        "initial admin login: expected the credential file removed after the first successful login"
    )

    # --- Admin creates a gameadmin, who is forced to change password ---
    response = client.post(
        "/api/v1/users",
        json={
            "username": GAMEADMIN_USERNAME,
            "initial_password": GAMEADMIN_INITIAL_PASSWORD,
            "role": "gameadmin",
        },
    )
    body = _expect_status(response, 200, "create gameadmin")
    assert body["must_change_password"] is True, "create gameadmin: expected a forced first change"

    response = _switch_to(
        client, GAMEADMIN_USERNAME, GAMEADMIN_INITIAL_PASSWORD, "gameadmin first login"
    )
    _expect_status(response, 200, "gameadmin first login")
    body = _expect_status(client.get("/api/v1/auth/session"), 200, "gameadmin session read")
    assert body["must_change_password"] is True, (
        "gameadmin first login: expected a restricted session before the forced change"
    )

    response = client.post(
        "/api/v1/auth/password",
        json={
            "old_password": GAMEADMIN_INITIAL_PASSWORD,
            "new_password": GAMEADMIN_CHOSEN_PASSWORD,
        },
    )
    _expect_status(response, 200, "gameadmin forced password change")
    body = _expect_status(client.get("/api/v1/auth/session"), 200, "gameadmin session re-read")
    assert body["must_change_password"] is False, (
        "gameadmin forced password change: expected an unrestricted session afterwards"
    )

    # --- Admin imports a definition and creates a run ------------------
    response = _switch_to(client, admin_username, admin_password, "admin re-login for import")
    _expect_status(response, 200, "admin re-login for import")

    make_installed_artifact(
        db_session,
        artifact_id=MINIGAME_ID,
        version="1.0.0",
        manifest={
            "id": MINIGAME_ID,
            "version": "1.0.0",
            "image": f"ghcr.io/org/{MINIGAME_ID}@{MINIGAME_DIGEST}",
        },
        image_digest=MINIGAME_DIGEST,
    )
    response = client.post(
        "/api/v1/event-definitions/import",
        files={"file": ("event.yaml", io.BytesIO(_import_event_document()), "application/x-yaml")},
    )
    body = _expect_status(response, 201, "import event definition")
    definition_id = body["id"]

    response = client.post(f"/api/v1/event-definitions/{definition_id}/publish")
    body = _expect_status(response, 200, "publish event definition")
    assert body["status"] == "published", (
        f"publish event definition: expected published, got {body}"
    )

    response = client.post(f"/api/v1/event-definitions/{definition_id}/runs")
    body = _expect_status(response, 201, "create run 1")
    assert body["status"] == "created", f"create run 1: expected created, got {body}"
    run1_id = body["id"]

    # A second run, off the same definition, created now — while run 1 is
    # still `created` and therefore not "active" (api-surface.md §2.6) —
    # rather than later. `play-one` is imported into it here, before their
    # run-1 participation exists, so that participation's insertion order
    # disagrees with §2.6 precedence order (see the module docstring).
    # `only-run2`'s own refusal case does not depend on the ordering, but
    # it is built here too, alongside run 2's other setup, rather than
    # split across the file.
    response = client.post(f"/api/v1/event-definitions/{definition_id}/runs")
    body = _expect_status(response, 201, "create run 2")
    assert body["status"] == "created", f"create run 2: expected created, got {body}"
    run2_id = body["id"]

    response = client.post(
        f"/api/v1/runs/{run2_id}/users/import",
        json=[
            {"username": SOLE_RUN2_USERNAME, "name": "Only Run Two", "email": None},
            {"username": PLAYER_USERNAME, "name": "Player One", "email": None},
        ],
    )
    body = _expect_status(response, 200, "import run 2 roster")
    run2_participants = cast(list[dict[str, object]], body["participants"])
    run2_imported = {p["username"]: p for p in run2_participants}
    assert run2_imported[PLAYER_USERNAME]["reused"] is False, (
        f"import run 2 roster: expected play-one's account newly created here, got {body}"
    )

    # --- Admin imports run 1's own participants and forms teams ----------
    response = client.post(
        f"/api/v1/runs/{run1_id}/users/import",
        json=[
            {"username": CAPTAIN_USERNAME, "name": "Captain One", "email": None},
            {"username": PLAYER_USERNAME, "name": "Player One", "email": None},
        ],
    )
    body = _expect_status(response, 200, "import run 1 participants")
    run1_participants = cast(list[dict[str, object]], body["participants"])
    imported = {p["username"]: p for p in run1_participants}
    captain_id = imported[CAPTAIN_USERNAME]["user_id"]
    player_id = imported[PLAYER_USERNAME]["user_id"]
    assert imported[PLAYER_USERNAME]["reused"] is True, (
        f"import run 1 participants: expected play-one's account reused from run 2, got {body}"
    )
    assert player_id == run2_imported[PLAYER_USERNAME]["user_id"], (
        "import run 1 participants: expected the same account reused across "
        f"both runs, got {player_id} vs {run2_imported[PLAYER_USERNAME]['user_id']}"
    )

    response = client.post(
        f"/api/v1/runs/{run1_id}/teams",
        json={
            "name": "Alpha",
            "member_user_ids": [captain_id, player_id],
            "captain_user_id": captain_id,
        },
    )
    body = _expect_status(response, 200, "create team")
    assert body["captain_user_id"] == captain_id, (
        f"create team: expected captain {captain_id}, got {body}"
    )

    # --- Preflight, then start -------------------------------------------
    response = client.post(f"/api/v1/runs/{run1_id}/preflight")
    body = _expect_status(response, 200, "preflight run 1")
    assert body["passed"] is True, f"preflight run 1: expected passed, got errors {body['errors']}"

    response = client.post(f"/api/v1/runs/{run1_id}/transition", json={"action": "start"})
    body = _expect_status(response, 200, "start run 1")
    assert body["status"] == "running", f"start run 1: expected running, got {body}"

    # --- Captain logs in on username, forced to change -------------------
    response = _switch_to(client, CAPTAIN_USERNAME, CAPTAIN_USERNAME, "captain first login")
    _expect_status(response, 200, "captain first login")
    body = _expect_status(client.get("/api/v1/auth/session"), 200, "captain session read")
    assert body["must_change_password"] is True, (
        "captain first login: expected a restricted session before the forced change"
    )

    response = client.post(
        "/api/v1/auth/password",
        json={"old_password": CAPTAIN_USERNAME, "new_password": CAPTAIN_CHOSEN_PASSWORD},
    )
    _expect_status(response, 200, "captain forced password change")

    # --- Player is refused without an OTP ---------------------------------
    response = _switch_to(client, PLAYER_USERNAME, PLAYER_USERNAME, "player login without OTP")
    body = _expect_status(response, 409, "player login without OTP")
    _expect_code(body, "activation_required", "player login without OTP")

    # --- Captain issues an OTP; player activates with it -------------------
    response = _switch_to(
        client, CAPTAIN_USERNAME, CAPTAIN_CHOSEN_PASSWORD, "captain re-login to issue OTP"
    )
    _expect_status(response, 200, "captain re-login to issue OTP")

    response = client.post("/api/v1/auth/otp", json={"user_id": player_id})
    body = _expect_status(response, 200, "issue player OTP")
    raw_otp = body["otp"]

    response = _switch_to(
        client, PLAYER_USERNAME, PLAYER_USERNAME, "player login with OTP outstanding"
    )
    _expect_status(response, 200, "player login with OTP outstanding")
    body = _expect_status(
        client.get("/api/v1/auth/session"), 200, "player session read before activation"
    )
    assert body["must_change_password"] is True, (
        "player login with OTP outstanding: expected a restricted session before activation"
    )

    response = client.post(
        "/api/v1/auth/password",
        json={
            "old_password": PLAYER_USERNAME,
            "otp": raw_otp,
            "new_password": PLAYER_CHOSEN_PASSWORD,
        },
    )
    _expect_status(response, 200, "player activation")

    # --- Trap 1: after activation, the username no longer authenticates —
    # only the chosen password does. Both halves asserted, separately: a
    # test proving only the new credential works would also pass an
    # implementation that accepts both.
    response = _switch_to(
        client, PLAYER_USERNAME, PLAYER_USERNAME, "player login on username after activation"
    )
    body = _expect_status(response, 401, "player login on username after activation")
    _expect_code(body, "invalid_credentials", "player login on username after activation")

    response = _switch_to(
        client, PLAYER_USERNAME, PLAYER_CHOSEN_PASSWORD, "player login on chosen password"
    )
    _expect_status(response, 200, "player login on chosen password")

    # --- Login keeps working in paused, and for staff throughout ----------
    response = _switch_to(client, admin_username, admin_password, "admin re-login to pause run 1")
    _expect_status(response, 200, "admin re-login to pause run 1")
    response = client.post(f"/api/v1/runs/{run1_id}/transition", json={"action": "pause"})
    body = _expect_status(response, 200, "pause run 1")
    assert body["status"] == "paused", f"pause run 1: expected paused, got {body}"

    response = _switch_to(
        client, GAMEADMIN_USERNAME, GAMEADMIN_CHOSEN_PASSWORD, "gameadmin login while run 1 paused"
    )
    _expect_status(response, 200, "gameadmin login while run 1 paused")

    response = _switch_to(
        client, PLAYER_USERNAME, PLAYER_CHOSEN_PASSWORD, "player login while run 1 paused"
    )
    _expect_status(response, 200, "player login while run 1 paused")

    # --- Login keeps working in finished -----------------------------------
    response = _switch_to(client, admin_username, admin_password, "admin re-login to finish run 1")
    _expect_status(response, 200, "admin re-login to finish run 1")
    response = client.post(f"/api/v1/runs/{run1_id}/transition", json={"action": "finish"})
    body = _expect_status(response, 200, "finish run 1")
    assert body["status"] == "finished", f"finish run 1: expected finished, got {body}"

    response = _switch_to(
        client,
        GAMEADMIN_USERNAME,
        GAMEADMIN_CHOSEN_PASSWORD,
        "gameadmin login while run 1 finished",
    )
    _expect_status(response, 200, "gameadmin login while run 1 finished")

    response = _switch_to(
        client, PLAYER_USERNAME, PLAYER_CHOSEN_PASSWORD, "player login while run 1 finished"
    )
    _expect_status(response, 200, "player login while run 1 finished")

    # --- Trap 2: a second run, already `created` since before run 1 even
    # started (set up above, ahead of run 1's own roster, to break the
    # insertion-order coincidence — see the module docstring). A
    # participant whose only run is `created` is refused with the splash
    # state; a participant who already has a readable run and holds a
    # participation in the `created` run too still logs in — §2.6's
    # "current run" skips a `created` run whenever a readable one exists.
    # Both cases asserted, not just one.

    # Trap 3: run_not_started carries `scheduled_start` as an extension
    # member, asserted by name — not just the code. `EventRun.scheduled_start`
    # has no public writer in the current API surface (see the module
    # docstring), so the only shape reachable through this flow's own
    # routes is null; that is the shape asserted here.
    response = _switch_to(
        client, SOLE_RUN2_USERNAME, SOLE_RUN2_USERNAME, "login refused for run-2-only participant"
    )
    body = _expect_status(response, 409, "login refused for run-2-only participant")
    _expect_code(body, "run_not_started", "login refused for run-2-only participant")
    assert "scheduled_start" in body, (
        "login refused for run-2-only participant: expected a scheduled_start "
        f"extension member, got {body}"
    )
    assert body["scheduled_start"] is None, (
        "login refused for run-2-only participant: expected scheduled_start "
        f"null for a run with none, got {body['scheduled_start']!r}"
    )

    response = _switch_to(
        client,
        PLAYER_USERNAME,
        PLAYER_CHOSEN_PASSWORD,
        "login for participant with a readable run 1 and a new created run 2",
    )
    _expect_status(
        response, 200, "login for participant with a readable run 1 and a new created run 2"
    )
