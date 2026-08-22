"""M2-Task-Plan.md Task 8 Step 3: roster freeze and the captain window
(api-surface.md §2.5, §2.17; ADR-0007). Two windows, not one, and that is
the trap this file is written to catch: team creation and member
assignment close at `start`, `PUT /teams/{id}/captain` stays open through
`running` and `finished` and closes only at `destroyed` — an
implementation gating both routes on the same check would pass a suite
that only ever exercised one window. `PATCH /teams/{id}` shares the
captain's wider window, not the roster freeze, because a name keys nothing
(data-model.md §3.11).
"""

import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.db.models.feedback import AuditLog
from gameframework.db.models.identity import Role, User
from gameframework.db.models.identity import Session as SessionModel
from gameframework.db.models.runs import RunStatus, Team
from gameframework.services.passwords import hash_password

from ..conftest import make_event_run, make_participation, make_team, make_user

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


def _login_as(client: TestClient, user: User, password: str) -> None:
    response = client.post(
        "/api/v1/auth/login", json={"username": user.username, "password": password}
    )
    assert response.status_code == 200


def _audit_rows(db_session: Session, team_id: object, action: str) -> list[AuditLog]:
    return list(
        db_session.execute(
            select(AuditLog).where(AuditLog.target_id == team_id, AuditLog.action == action)
        )
        .scalars()
        .all()
    )


def test_team_creation_is_refused_once_the_run_is_running(
    client: TestClient, db_session: Session
) -> None:
    """api-surface.md §2.5: "Only while the run is `created`." The
    negative case for the freeze — every Step 2 test proves the positive
    by creating teams on `created` runs successfully.
    """
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.running)
    alice = make_user(db_session)
    make_participation(db_session, user=alice, run=run)

    response = client.post(
        f"/api/v1/runs/{run.id}/teams",
        json={"name": "Crew", "member_user_ids": [str(alice.id)], "captain_user_id": str(alice.id)},
    )

    assert response.status_code == 409
    assert response.json()["code"] == "roster_frozen"


def test_member_assignment_is_refused_once_the_run_is_running(
    client: TestClient, db_session: Session
) -> None:
    """api-surface.md §2.5: `PUT /teams/{id}/members` shares the roster
    freeze with creation — a team already exists (formed while the run was
    still `created`), and the run is moved to `running` directly on the
    fixture, standing in for `start` (Task 13, not yet built).
    """
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)
    alice = make_user(db_session)
    bob = make_user(db_session)
    alice_participation = make_participation(db_session, user=alice, run=run)
    make_participation(db_session, user=bob, run=run)
    team = make_team(db_session, run=run, captain=alice)
    alice_participation.team_id = team.id
    db_session.commit()

    run.status = RunStatus.running
    db_session.commit()

    response = client.put(
        f"/api/v1/teams/{team.id}/members",
        json={"member_user_ids": [str(alice.id), str(bob.id)]},
    )

    assert response.status_code == 409
    assert response.json()["code"] == "roster_frozen"


def test_members_route_refuses_to_drop_the_captain_without_a_replacement(
    client: TestClient, db_session: Session
) -> None:
    """api-surface.md §2.5: "Refused with 409 when it would remove the
    team's current captain." A one-member team whose sole member is the
    captain, dropped in favour of someone not yet on the team, with no
    replacement named — refused, and nothing changes: neither participation
    moves and no audit row is written, since the whole call rolls back.
    """
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)
    alice = make_user(db_session)
    bob = make_user(db_session)
    alice_participation = make_participation(db_session, user=alice, run=run)
    bob_participation = make_participation(db_session, user=bob, run=run)
    team = make_team(db_session, run=run, captain=alice)
    alice_participation.team_id = team.id
    db_session.commit()

    response = client.put(
        f"/api/v1/teams/{team.id}/members",
        json={"member_user_ids": [str(bob.id)]},
    )

    assert response.status_code == 409
    assert response.json()["code"] == "captain_not_a_member"

    db_session.refresh(alice_participation)
    db_session.refresh(bob_participation)
    assert alice_participation.team_id == team.id
    assert bob_participation.team_id is None
    assert _audit_rows(db_session, team.id, "team_members_changed") == []
    assert _audit_rows(db_session, team.id, "team_captain_changed") == []


def test_members_route_accepts_a_same_request_captain_replacement(
    client: TestClient, db_session: Session
) -> None:
    """The positive half of the pair above, and the case that forces the
    same-request field to exist at all: a one-member team whose sole
    member is the captain, replaced by someone not yet in the team — no
    order of two separate calls can reach this (`PUT .../captain` refuses
    an outsider; `PUT .../members` alone refuses to drop the sitting
    captain). Both facts are audited: the members change and the captain
    swap are two rows, not one.
    """
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)
    alice = make_user(db_session)
    bob = make_user(db_session)
    alice_participation = make_participation(db_session, user=alice, run=run)
    bob_participation = make_participation(db_session, user=bob, run=run)
    team = make_team(db_session, run=run, captain=alice)
    alice_participation.team_id = team.id
    db_session.commit()

    response = client.put(
        f"/api/v1/teams/{team.id}/members",
        json={"member_user_ids": [str(bob.id)], "new_captain_user_id": str(bob.id)},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["captain_user_id"] == str(bob.id)

    db_session.refresh(alice_participation)
    db_session.refresh(bob_participation)
    assert alice_participation.team_id is None
    assert bob_participation.team_id == team.id

    team_row = db_session.get(Team, team.id)
    assert team_row is not None
    assert team_row.captain_user_id == bob.id

    assert len(_audit_rows(db_session, team.id, "team_members_changed")) == 1
    assert len(_audit_rows(db_session, team.id, "team_captain_changed")) == 1


def test_members_route_refuses_a_same_request_captain_not_in_the_new_member_list(
    client: TestClient, db_session: Session
) -> None:
    """api-surface.md §2.5: "When the field is present it must name
    someone in the new member list." Naming a third party who is not among
    the members this same call is about to write is refused, the same
    code as the plain drop-without-replacement case above — deliberately
    the same code here too, since alice (the sitting captain) is *also*
    being dropped in this body: this test alone cannot tell that refusal
    apart from the drop-without-replacement one, which is exactly what the
    isolating test below (captain unchanged, only the replacement is
    invalid) is for.
    """
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)
    alice = make_user(db_session)
    bob = make_user(db_session)
    carol = make_user(db_session)
    alice_participation = make_participation(db_session, user=alice, run=run)
    make_participation(db_session, user=bob, run=run)
    make_participation(db_session, user=carol, run=run)
    team = make_team(db_session, run=run, captain=alice)
    alice_participation.team_id = team.id
    db_session.commit()

    response = client.put(
        f"/api/v1/teams/{team.id}/members",
        json={"member_user_ids": [str(bob.id)], "new_captain_user_id": str(carol.id)},
    )

    assert response.status_code == 409
    assert response.json()["code"] == "captain_not_a_member"

    db_session.refresh(alice_participation)
    assert alice_participation.team_id == team.id


def test_members_route_refuses_an_invalid_captain_replacement_when_the_captain_is_unchanged(
    client: TestClient, db_session: Session
) -> None:
    """The isolating case the test above cannot reach: the sitting
    captain stays in the new member list (nothing about her would be
    dropped), so the *only* thing that can refuse this call is
    `new_captain_user_id` not naming someone in that list. Removing that
    specific check — as opposed to the drop-without-replacement one —
    is what this test alone catches.
    """
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)
    alice = make_user(db_session)
    bob = make_user(db_session)
    carol = make_user(db_session)
    alice_participation = make_participation(db_session, user=alice, run=run)
    bob_participation = make_participation(db_session, user=bob, run=run)
    make_participation(db_session, user=carol, run=run)
    team = make_team(db_session, run=run, captain=alice)
    alice_participation.team_id = team.id
    bob_participation.team_id = team.id
    db_session.commit()

    response = client.put(
        f"/api/v1/teams/{team.id}/members",
        json={
            "member_user_ids": [str(alice.id), str(bob.id)],
            "new_captain_user_id": str(carol.id),
        },
    )

    assert response.status_code == 409
    assert response.json()["code"] == "captain_not_a_member"

    team_row = db_session.get(Team, team.id)
    assert team_row is not None
    assert team_row.captain_user_id == alice.id


def test_members_route_refuses_a_member_naming_no_participation_in_this_run(
    client: TestClient, db_session: Session
) -> None:
    """The `set_members` counterpart to Step 2's mid-transaction test:
    a named member with no participation in this run fails after an
    earlier, valid member's `team_id` may already have been touched,
    proving this route's write rolls back too.
    """
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)
    alice = make_user(db_session)
    alice_participation = make_participation(db_session, user=alice, run=run)
    team = make_team(db_session, run=run, captain=alice)
    alice_participation.team_id = team.id
    db_session.commit()
    nonexistent_user_id = uuid.uuid4()

    response = client.put(
        f"/api/v1/teams/{team.id}/members",
        json={"member_user_ids": [str(alice.id), str(nonexistent_user_id)]},
    )

    assert response.status_code == 422
    assert response.json()["code"] == "participation_not_found"


def test_members_route_refuses_to_move_in_someone_who_captains_another_team(
    client: TestClient, db_session: Session
) -> None:
    """`ensure_captain_not_removed_by_participation_change` protects
    whichever team a moved participation currently captains, not only the
    team named in this request: adding `bob` to team A while he still
    captains team B — his sole member there — would strip team B of its
    captain, and is refused for that reason.
    """
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)
    alice = make_user(db_session)
    bob = make_user(db_session)
    alice_participation = make_participation(db_session, user=alice, run=run)
    bob_participation = make_participation(db_session, user=bob, run=run)
    team_a = make_team(db_session, run=run, captain=alice)
    team_b = make_team(db_session, run=run, captain=bob)
    alice_participation.team_id = team_a.id
    bob_participation.team_id = team_b.id
    db_session.commit()

    response = client.put(
        f"/api/v1/teams/{team_a.id}/members",
        json={"member_user_ids": [str(alice.id), str(bob.id)]},
    )

    assert response.status_code == 409
    assert response.json()["code"] == "captain_not_a_member"

    db_session.refresh(bob_participation)
    assert bob_participation.team_id == team_b.id


def test_captain_swap_is_accepted_while_running(client: TestClient, db_session: Session) -> None:
    """api-surface.md §2.5: "Available from created through finished
    inclusive" — the running case, contrasted with the roster-freeze
    tests above, which refuse creation and member assignment at the same
    status. Same window, different route: this is the pair the freeze
    tests need beside them.
    """
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)
    alice = make_user(db_session)
    bob = make_user(db_session)
    alice_participation = make_participation(db_session, user=alice, run=run)
    bob_participation = make_participation(db_session, user=bob, run=run)
    team = make_team(db_session, run=run, captain=alice)
    alice_participation.team_id = team.id
    bob_participation.team_id = team.id
    db_session.commit()

    run.status = RunStatus.running
    db_session.commit()

    response = client.put(f"/api/v1/teams/{team.id}/captain", json={"captain_user_id": str(bob.id)})

    assert response.status_code == 200
    assert response.json()["captain_user_id"] == str(bob.id)


def test_captain_swap_is_accepted_while_finished(client: TestClient, db_session: Session) -> None:
    """The other named case: `finished` is inside the window rather than
    its edge, because Phase 3's captain-only rating (`POST /ratings`, §2.13)
    runs exactly there.
    """
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)
    alice = make_user(db_session)
    bob = make_user(db_session)
    alice_participation = make_participation(db_session, user=alice, run=run)
    bob_participation = make_participation(db_session, user=bob, run=run)
    team = make_team(db_session, run=run, captain=alice)
    alice_participation.team_id = team.id
    bob_participation.team_id = team.id
    db_session.commit()

    run.status = RunStatus.finished
    db_session.commit()

    response = client.put(f"/api/v1/teams/{team.id}/captain", json={"captain_user_id": str(bob.id)})

    assert response.status_code == 200
    assert response.json()["captain_user_id"] == str(bob.id)


def test_captain_swap_is_refused_once_the_run_is_destroyed(
    client: TestClient, db_session: Session
) -> None:
    """api-surface.md §2.5: "refused from destroyed" — the one status the
    window excludes, distinct from `roster_frozen`'s own gate (which
    excludes everything but `created`)."""
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)
    alice = make_user(db_session)
    bob = make_user(db_session)
    alice_participation = make_participation(db_session, user=alice, run=run)
    bob_participation = make_participation(db_session, user=bob, run=run)
    team = make_team(db_session, run=run, captain=alice)
    alice_participation.team_id = team.id
    bob_participation.team_id = team.id
    db_session.commit()

    run.status = RunStatus.destroyed
    db_session.commit()

    response = client.put(f"/api/v1/teams/{team.id}/captain", json={"captain_user_id": str(bob.id)})

    assert response.status_code == 409
    assert response.json()["code"] == "run_destroyed"


def test_captain_swap_refused_when_replacement_is_not_a_member(
    client: TestClient, db_session: Session
) -> None:
    """api-surface.md §2.5: "the replacement must already be a member of
    this team." An outsider — a real participation of this same run, just
    not on this team — is refused, checked against the live
    `event_participation` row rather than any request-supplied list."""
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.running)
    alice = make_user(db_session)
    outsider = make_user(db_session)
    alice_participation = make_participation(db_session, user=alice, run=run)
    make_participation(db_session, user=outsider, run=run)
    team = make_team(db_session, run=run, captain=alice)
    alice_participation.team_id = team.id
    db_session.commit()

    response = client.put(
        f"/api/v1/teams/{team.id}/captain", json={"captain_user_id": str(outsider.id)}
    )

    assert response.status_code == 409
    assert response.json()["code"] == "captain_not_a_member"


def test_captain_swap_moves_no_participation_and_revokes_no_session(
    client: TestClient, db_session: Session
) -> None:
    """ADR-0007: captaincy is derived from `team.captain_user_id` at
    authorization time rather than carried in the session, so a swap moves
    no `event_participation` row and revokes no session — both negatives,
    both asserted here, since a swap that revoked sessions would look
    correct (the outgoing captain simply logs in again) and be wrong.
    """
    admin = _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.running)
    alice_password = "Alice-Passw0rd!"
    alice = make_user(
        db_session,
        role=Role.player,
        must_change_password=False,
        password_hash=hash_password(alice_password),
    )
    bob = make_user(db_session, role=Role.player)
    alice_participation = make_participation(db_session, user=alice, run=run)
    bob_participation = make_participation(db_session, user=bob, run=run)
    team = make_team(db_session, run=run, captain=alice)
    alice_participation.team_id = team.id
    bob_participation.team_id = team.id
    db_session.commit()

    client.cookies.clear()
    _login_as(client, alice, alice_password)
    alice_sessions_before = (
        db_session.execute(select(SessionModel).where(SessionModel.user_id == alice.id))
        .scalars()
        .all()
    )
    assert len(alice_sessions_before) == 1

    client.cookies.clear()
    _login_as(client, admin, ADMIN_PASSWORD)

    response = client.put(f"/api/v1/teams/{team.id}/captain", json={"captain_user_id": str(bob.id)})
    assert response.status_code == 200

    db_session.refresh(alice_participation)
    db_session.refresh(bob_participation)
    assert alice_participation.team_id == team.id
    assert bob_participation.team_id == team.id

    alice_sessions_after = (
        db_session.execute(select(SessionModel).where(SessionModel.user_id == alice.id))
        .scalars()
        .all()
    )
    assert len(alice_sessions_after) == 1
    assert alice_sessions_after[0].id == alice_sessions_before[0].id


def test_rename_by_the_teams_own_captain_succeeds(client: TestClient, db_session: Session) -> None:
    """api-surface.md §2.17: `PATCH /teams/{id}` scope is `own team` for a
    captain — `captain` is derived from `team.captain_user_id`, resolved
    the same way `POST /auth/otp` resolves it (`resolve_captaincy`,
    Task 4), not a stored role. `running`, not `created` — a participant
    login is refused outright while the run is `created` (api-surface.md
    §2.2), regardless of captaincy.
    """
    run = make_event_run(db_session, status=RunStatus.running)
    alice_password = "Alice-Passw0rd!"
    alice = make_user(
        db_session,
        role=Role.player,
        must_change_password=False,
        password_hash=hash_password(alice_password),
    )
    alice_participation = make_participation(db_session, user=alice, run=run)
    team = make_team(db_session, run=run, captain=alice)
    alice_participation.team_id = team.id
    db_session.commit()

    _login_as(client, alice, alice_password)

    response = client.patch(f"/api/v1/teams/{team.id}", json={"name": "Captained Rename"})

    assert response.status_code == 200
    assert response.json()["name"] == "Captained Rename"


def test_rename_by_a_player_who_captains_no_team_is_role_denied(
    client: TestClient, db_session: Session
) -> None:
    """The role-level denial: a plain player who captains nothing at all
    is refused before any object is even considered — `role_denied`, the
    same code `current_session` uses for a role the route does not list."""
    run = make_event_run(db_session, status=RunStatus.running)
    alice = make_user(db_session)
    alice_participation = make_participation(db_session, user=alice, run=run)
    team = make_team(db_session, run=run, captain=alice)
    alice_participation.team_id = team.id
    db_session.commit()

    bystander_password = "Bystander-Passw0rd!"
    bystander = make_user(
        db_session,
        role=Role.player,
        must_change_password=False,
        password_hash=hash_password(bystander_password),
    )
    make_participation(db_session, user=bystander, run=run)
    db_session.commit()

    _login_as(client, bystander, bystander_password)

    response = client.patch(f"/api/v1/teams/{team.id}", json={"name": "Nope"})

    assert response.status_code == 403
    assert response.json()["code"] == "role_denied"


def test_rename_by_a_captain_of_a_different_team_is_not_found(
    client: TestClient, db_session: Session
) -> None:
    """The object-level denial: a captain may call this route, so a
    mismatched target answers `404 object_not_found` rather than `403` —
    the split api-surface.md §1 draws between a role denial and
    non-disclosure of an object outside the caller's scope."""
    run = make_event_run(db_session, status=RunStatus.running)
    alice = make_user(db_session)
    alice_participation = make_participation(db_session, user=alice, run=run)
    team_a = make_team(db_session, run=run, captain=alice)
    alice_participation.team_id = team_a.id

    bob_password = "Bob-Passw0rd!"
    bob = make_user(
        db_session,
        role=Role.player,
        must_change_password=False,
        password_hash=hash_password(bob_password),
    )
    bob_participation = make_participation(db_session, user=bob, run=run)
    team_b = make_team(db_session, run=run, captain=bob)
    bob_participation.team_id = team_b.id
    db_session.commit()

    _login_as(client, bob, bob_password)

    response = client.patch(f"/api/v1/teams/{team_a.id}", json={"name": "Nope"})

    assert response.status_code == 404
    assert response.json()["code"] == "object_not_found"


def test_team_creation_against_a_nonexistent_run_is_not_found(
    client: TestClient, db_session: Session
) -> None:
    """`_get_run`'s guard, shared by every run-scoped team route."""
    _login_as_admin(client, db_session)

    response = client.post(
        f"/api/v1/runs/{uuid.uuid4()}/teams",
        json={"name": "Crew", "member_user_ids": [], "captain_user_id": str(uuid.uuid4())},
    )

    assert response.status_code == 404
    assert response.json()["code"] == "object_not_found"


def test_rename_of_a_nonexistent_team_is_not_found(client: TestClient, db_session: Session) -> None:
    """`_get_team`'s guard, shared by every team-id-scoped route."""
    _login_as_admin(client, db_session)

    response = client.patch(f"/api/v1/teams/{uuid.uuid4()}", json={"name": "Nope"})

    assert response.status_code == 404
    assert response.json()["code"] == "object_not_found"


def test_rename_stays_open_through_finished(client: TestClient, db_session: Session) -> None:
    """api-surface.md §2.17: rename's lifecycle gate is
    `created`/`running`/`paused`/`finished` — the same window as the
    captain swap, not the roster freeze creation and member assignment
    close at `start`."""
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)
    alice = make_user(db_session)
    alice_participation = make_participation(db_session, user=alice, run=run)
    team = make_team(db_session, run=run, captain=alice)
    alice_participation.team_id = team.id
    db_session.commit()

    run.status = RunStatus.finished
    db_session.commit()

    response = client.patch(f"/api/v1/teams/{team.id}", json={"name": "Renamed Crew"})

    assert response.status_code == 200
    assert response.json()["name"] == "Renamed Crew"


def test_rename_is_refused_once_run_is_destroyed(client: TestClient, db_session: Session) -> None:
    """The negative case the conditional above needs: rename shares the
    captain swap's window, so it is refused at the same one status the
    swap is, `destroyed` — not left ungated entirely."""
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)
    alice = make_user(db_session)
    alice_participation = make_participation(db_session, user=alice, run=run)
    team = make_team(db_session, run=run, captain=alice)
    alice_participation.team_id = team.id
    db_session.commit()

    run.status = RunStatus.destroyed
    db_session.commit()

    response = client.patch(f"/api/v1/teams/{team.id}", json={"name": "Renamed Crew"})

    assert response.status_code == 409
    assert response.json()["code"] == "run_destroyed"


def test_audit_asymmetry_across_team_writes(client: TestClient, db_session: Session) -> None:
    """api-surface.md §2.17: creation, member assignment and the captain
    swap are each audited; the rename is not. Asserted together, in one
    file, so "not audited" and "auditing is broken" cannot read as the
    same result — three presences and one absence, side by side.
    """
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)
    alice = make_user(db_session)
    bob = make_user(db_session)
    make_participation(db_session, user=alice, run=run)
    make_participation(db_session, user=bob, run=run)

    created = client.post(
        f"/api/v1/runs/{run.id}/teams",
        json={"name": "Crew", "member_user_ids": [str(alice.id)], "captain_user_id": str(alice.id)},
    )
    assert created.status_code == 200
    team_id = uuid.UUID(created.json()["id"])
    assert len(_audit_rows(db_session, team_id, "team_created")) == 1

    members = client.put(
        f"/api/v1/teams/{team_id}/members",
        json={"member_user_ids": [str(alice.id), str(bob.id)]},
    )
    assert members.status_code == 200
    assert len(_audit_rows(db_session, team_id, "team_members_changed")) == 1

    swap = client.put(f"/api/v1/teams/{team_id}/captain", json={"captain_user_id": str(bob.id)})
    assert swap.status_code == 200
    assert len(_audit_rows(db_session, team_id, "team_captain_changed")) == 1

    audit_rows_before_rename = list(
        db_session.execute(select(AuditLog).where(AuditLog.target_id == team_id)).scalars().all()
    )

    renamed = client.patch(f"/api/v1/teams/{team_id}", json={"name": "New Name"})
    assert renamed.status_code == 200

    audit_rows_after_rename = list(
        db_session.execute(select(AuditLog).where(AuditLog.target_id == team_id)).scalars().all()
    )
    assert len(audit_rows_after_rename) == len(audit_rows_before_rename)
