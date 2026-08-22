"""M2-Task-Plan.md Task 8 Step 2: atomic team creation (api-surface.md §2.5;
data-model.md §3.11, §6). `services/teams.py` and `api/teams.py` do not exist
yet, so every call below is expected to fail on FastAPI's own routing `404`
at collection/run time rather than on `problem_error_handler` — the same
collection-level red Task 7's `test_import.py` documented for a module not
yet on disk (Working-Agreement "a collection error is not a red proof": the
exception it names is for code already on disk, which this is not).

`data-model.md §3.11`: `team.captain_user_id` is non-nullable and the
captain must hold this run's `event_participation` with `team_id = team.id`
— two facts no sequence of separate writes can satisfy, which is why
`POST /runs/{id}/teams` takes name, members and captain in one transaction
(api-surface.md §2.5). Four things bind this:

- the happy path writes all three (team row, members' `team_id`,
  `captain_user_id`) and audits, in one call;
- a captain not named among the members is refused — checked against the
  live `event_participation` rows via `ensure_captain_is_team_member`
  (Task 1a), after the member writes, not by a second parallel check of
  the same fact;
- the generated handle is run-unique and grammar-matching, mirroring
  Task 7's `mint_handle` proof for participation handles;
- a failure partway through the write — one member resolves, the next
  does not — leaves nothing behind: no team row, no reassigned
  participation (not even the one already flushed), no audit row. The
  captain-refusal case above is a second, independent trigger for the same
  rollback, forced by a different condition (a captain never written
  rather than a member never found).
"""

import re
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.db.models.feedback import AuditLog, AuditScope
from gameframework.db.models.identity import Role, User
from gameframework.db.models.runs import EventParticipation, RunStatus, Team
from gameframework.services.passwords import hash_password

from ..conftest import make_event_run, make_participation, make_user

ADMIN_PASSWORD = "Admin-Passw0rd!"
_HANDLE_RE = re.compile(r"[a-z][a-z0-9-]{1,27}")


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


def _teams_for_run(db_session: Session, run_id: object) -> list[Team]:
    return list(db_session.execute(select(Team).where(Team.event_run_id == run_id)).scalars().all())


def test_team_creation_writes_team_members_and_captain_in_one_call(
    client: TestClient, db_session: Session
) -> None:
    """The happy path: a body naming name, members and captain creates all
    three in one transaction (api-surface.md §2.5) — asserted on the DB
    rows, not only the response, and the `audit_log` row too (§2.17's ✅ for
    team creation).
    """
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)
    alice = make_user(db_session)
    bob = make_user(db_session)
    carol = make_user(db_session)
    for user in (alice, bob, carol):
        make_participation(db_session, user=user, run=run)

    response = client.post(
        f"/api/v1/runs/{run.id}/teams",
        json={
            "name": "Crew",
            "member_user_ids": [str(alice.id), str(bob.id), str(carol.id)],
            "captain_user_id": str(alice.id),
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["name"] == "Crew"
    assert body["captain_user_id"] == str(alice.id)
    assert _HANDLE_RE.fullmatch(body["handle"])

    team = db_session.get(Team, uuid.UUID(body["id"]))
    assert team is not None
    assert team.captain_user_id == alice.id

    participations = (
        db_session.execute(
            select(EventParticipation).where(EventParticipation.event_run_id == run.id)
        )
        .scalars()
        .all()
    )
    assert {p.user_id for p in participations} == {alice.id, bob.id, carol.id}
    assert all(p.team_id == team.id for p in participations)

    audit_rows = list(
        db_session.execute(
            select(AuditLog).where(AuditLog.target_id == team.id, AuditLog.action == "team_created")
        )
        .scalars()
        .all()
    )
    assert len(audit_rows) == 1
    assert audit_rows[0].scope is AuditScope.participant
    assert audit_rows[0].event_run_id == run.id


def test_team_appears_on_the_list_route(client: TestClient, db_session: Session) -> None:
    """`GET /teams` (api-surface.md §2.5): a minimal read proving the route
    exists and reflects what creation wrote, cursor-paginated like
    `GET /users` (api-surface.md §1).
    """
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)
    alice = make_user(db_session)
    make_participation(db_session, user=alice, run=run)

    created = client.post(
        f"/api/v1/runs/{run.id}/teams",
        json={
            "name": "Solo Crew",
            "member_user_ids": [str(alice.id)],
            "captain_user_id": str(alice.id),
        },
    )
    assert created.status_code == 200

    response = client.get("/api/v1/teams")
    assert response.status_code == 200
    names = {row["name"] for row in response.json()["items"]}
    assert "Solo Crew" in names


def test_captain_not_in_member_list_is_refused(client: TestClient, db_session: Session) -> None:
    """api-surface.md §2.5: "The captain must be one of the members named
    in the same body." Asserts the refusal's status and code only — the
    write it happens to trigger a rollback of is `test_mid_transaction_
    failure_leaves_nothing_behind`'s claim, not this one's. A test naming
    the captain rule that also asserted "no team row" would go red under a
    transaction-shape mutation (an early commit that lets the team row
    outlive the rollback) for a reason that has nothing to do with the
    captain rule — the two claims need two tests, each failing only for
    its own reason.
    """
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)
    alice = make_user(db_session)
    bob = make_user(db_session)
    make_participation(db_session, user=alice, run=run)
    make_participation(db_session, user=bob, run=run)

    response = client.post(
        f"/api/v1/runs/{run.id}/teams",
        json={
            "name": "Crew",
            "member_user_ids": [str(bob.id)],
            "captain_user_id": str(alice.id),
        },
    )

    assert response.status_code == 409
    assert response.json()["code"] == "captain_not_a_member"


def test_mid_transaction_failure_leaves_nothing_behind(
    client: TestClient, db_session: Session
) -> None:
    """A member naming no participation in this run fails the write after
    an earlier, valid member's `team_id` has already been set — proving
    the whole call rolls back rather than leaving that earlier write
    standing. `alice` is listed first deliberately, so her participation is
    flushed before the second, nonexistent member is reached.
    """
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)
    alice = make_user(db_session)
    alice_participation = make_participation(db_session, user=alice, run=run)
    nonexistent_user_id = uuid.uuid4()

    response = client.post(
        f"/api/v1/runs/{run.id}/teams",
        json={
            "name": "Crew",
            "member_user_ids": [str(alice.id), str(nonexistent_user_id)],
            "captain_user_id": str(alice.id),
        },
    )

    assert response.status_code == 422
    assert response.json()["code"] == "participation_not_found"

    assert _teams_for_run(db_session, run.id) == []
    db_session.refresh(alice_participation)
    assert alice_participation.team_id is None
    audit_rows = list(
        db_session.execute(
            select(AuditLog).where(
                AuditLog.event_run_id == run.id, AuditLog.action == "team_created"
            )
        )
        .scalars()
        .all()
    )
    assert audit_rows == []


def test_two_teams_in_one_run_get_distinct_run_unique_handles(
    client: TestClient, db_session: Session
) -> None:
    """data-model.md §3.11: `team.handle` matches `^[a-z][a-z0-9-]{1,27}$`
    and is unique per run — asserted across two teams created in the same
    run, mirroring Task 7's handle-uniqueness proof for participations.
    """
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)
    alice = make_user(db_session)
    bob = make_user(db_session)
    make_participation(db_session, user=alice, run=run)
    make_participation(db_session, user=bob, run=run)

    first = client.post(
        f"/api/v1/runs/{run.id}/teams",
        json={
            "name": "Team A",
            "member_user_ids": [str(alice.id)],
            "captain_user_id": str(alice.id),
        },
    )
    second = client.post(
        f"/api/v1/runs/{run.id}/teams",
        json={
            "name": "Team B",
            "member_user_ids": [str(bob.id)],
            "captain_user_id": str(bob.id),
        },
    )

    assert first.status_code == 200
    assert second.status_code == 200
    handle_a = first.json()["handle"]
    handle_b = second.json()["handle"]
    assert handle_a != handle_b
    for handle in (handle_a, handle_b):
        assert _HANDLE_RE.fullmatch(handle)


def test_mint_handle_retries_on_a_collision_within_one_run(monkeypatch: pytest.MonkeyPatch) -> None:
    """`mint_handle(prefix, existing) -> str` (data-model.md §3.10/§3.11):
    a within-run collision must be retried rather than minted twice —
    proven here with the random suffix source controlled, since an actual
    HTTP-level collision is not practical to force. Relocated from Task 7's
    `test_import.py` (Task 8 Step 4): `mint_handle` moved to
    `services/teams.py`, which `services/participants.py` now imports
    rather than defines.
    """
    from gameframework.services import teams as teams_module

    suffixes = iter(["aaaaaa", "aaaaaa", "bbbbbb"])

    def _fake_token_hex(n: int) -> str:
        return next(suffixes)

    monkeypatch.setattr(teams_module.secrets, "token_hex", _fake_token_hex)

    handle = teams_module.mint_handle("p", {"p-aaaaaa"})

    assert handle == "p-bbbbbb"
    assert _HANDLE_RE.fullmatch(handle)
