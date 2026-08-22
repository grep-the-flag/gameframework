"""Role administration (M2-Task-Plan.md Task 6 Step 4; api-surface.md §2.17
"Role administration"). Three rules bound `POST /users`'/`PATCH /users/{id}`'s
Roles columns, and a fourth mechanism makes the first of them actually hold:

(1) `role` changes are admin-only and audited; (2) a gameadmin's writes reach
participant accounts only — a staff target answers `404`, never `403`,
because a `403` on that object would confirm it exists; (3) no session
changes its own `role`; and a role change deletes every `sid` row the target
holds, because `sid` is the only claim authorization reads (ADR-0007,
Working-Agreement "State as of this handover") — a claim-trusting
implementation would leave a downgraded gameadmin's existing token good for
up to 12 hours.

`client` carries CSRF for every mutating call (Task 3 Step 6); no test here
needs `raw_client` or a hand-minted token — every identity below authenticates
through a real `POST /auth/login`. `client.cookies.clear()` drops one
identity's session before a second login on the same client, the same fix
Step 2/3's own "own password" test needed: a live session's CSRF token binds
to that session's `sid` rather than to a fresh pre-session id, so a second
login on an already-authenticated client is refused `403 csrf_token_invalid`
for a reason that has nothing to do with the account under test.
"""

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.db.models.feedback import AuditLog, AuditScope
from gameframework.db.models.identity import Role, User
from gameframework.db.models.identity import Session as SessionModel
from gameframework.services.passwords import hash_password

from ..conftest import make_user

SESSION_COOKIE = "__Secure-gf_session"


def _login(client: TestClient, username: str, password: str) -> None:
    response = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200


def _make_staff(db_session: Session, role: Role, password: str) -> User:
    return make_user(
        db_session,
        role=role,
        must_change_password=False,
        password_hash=hash_password(password),
    )


def test_gameadmin_cannot_change_a_role(client: TestClient, db_session: Session) -> None:
    """api-surface.md §2.17 role administration (1): `role` changes are
    admin-only — "for a gameadmin the field is simply not writable." The
    target here is a participant, a scope the route otherwise lets a
    gameadmin reach — isolating this refusal from the staff-target `404`
    tested below in the same file, so the two denials are shown to answer
    differently rather than the same code standing in for both.
    """
    gameadmin = _make_staff(db_session, Role.gameadmin, "Gameadmin-Passw0rd!")
    _login(client, gameadmin.username, "Gameadmin-Passw0rd!")
    target = make_user(db_session, role=Role.player)

    response = client.patch(f"/api/v1/users/{target.id}", json={"role": "player"})

    assert response.status_code == 403
    assert response.json()["code"] == "role_denied"


def test_admin_changes_someone_elses_role_and_it_is_audited(
    client: TestClient, db_session: Session
) -> None:
    """The positive half of "no session changes its own role" (tested
    below): without this, that negative would be consistent with an admin
    simply unable to change *any* role, staff or otherwise, rather than
    specifically their own — bound by narrowing to the self case, not by a
    blanket refusal.
    """
    admin = _make_staff(db_session, Role.admin, "Admin-Passw0rd!")
    _login(client, admin.username, "Admin-Passw0rd!")
    target = _make_staff(db_session, Role.gameadmin, "Target-Passw0rd!")

    response = client.patch(f"/api/v1/users/{target.id}", json={"role": "player"})

    assert response.status_code == 200
    db_session.expire_all()
    db_session.refresh(target)
    assert target.role is Role.player

    entry = db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "user_role_changed", AuditLog.target_id == target.id
        )
    ).scalar_one()
    assert entry.actor_user_id == admin.id
    assert entry.scope is AuditScope.installation


def test_no_session_changes_its_own_role(client: TestClient, db_session: Session) -> None:
    """api-surface.md §2.17 role administration (3). Paired with the test
    above in the same file: without that positive, this test alone would be
    indistinguishable from an admin who simply cannot change any role.
    """
    admin = _make_staff(db_session, Role.admin, "Self-Admin-Passw0rd!")
    _login(client, admin.username, "Self-Admin-Passw0rd!")

    response = client.patch(f"/api/v1/users/{admin.id}", json={"role": "gameadmin"})

    assert response.status_code == 403
    assert response.json()["code"] == "self_role_change_denied"
    db_session.expire_all()
    db_session.refresh(admin)
    assert admin.role is Role.admin


def test_gameadmin_write_against_a_staff_target_is_404(
    client: TestClient, db_session: Session
) -> None:
    """api-surface.md §2.17 role administration (2), and the other half of
    the 403/404 split this task runs twice in opposite directions: an
    admin-only *route* denies a gameadmin by role (`403`, tested above and
    in test_erasure_export.py); a staff *object* a gameadmin's otherwise-
    reachable route may not confirm exists answers `404`. No `role` field in
    this request — the object-scope check must not depend on which field
    the request happens to touch.
    """
    gameadmin = _make_staff(db_session, Role.gameadmin, "Gameadmin-Passw0rd!")
    _login(client, gameadmin.username, "Gameadmin-Passw0rd!")
    staff_target = _make_staff(db_session, Role.admin, "Hidden-Admin-Passw0rd!")

    response = client.patch(f"/api/v1/users/{staff_target.id}", json={"display_name": "Nope"})

    assert response.status_code == 404
    assert response.json()["code"] == "object_not_found"


def test_role_change_deletes_sid_rows_and_the_old_token_is_refused(
    client: TestClient, db_session: Session
) -> None:
    """ADR-0007: `sid` is the only claim authorization reads. Two
    assertions bind this, not one: the row count is a pre/post pair — a
    deletion-rule test needs a pre-assertion, since "zero rows" and "never
    created" are otherwise indistinguishable — and the old token's own next
    request is what shows the deletion is actually load-bearing: a
    claim-trusting implementation could delete every row here and still
    honour that token for up to 12 hours, which the row-count assertion
    alone would never catch.
    """
    target_password = "Target-Passw0rd!"
    target = _make_staff(db_session, Role.gameadmin, target_password)
    _login(client, target.username, target_password)
    old_token = client.cookies.get(SESSION_COOKIE)
    assert old_token is not None

    sessions_before = (
        db_session.execute(select(SessionModel).where(SessionModel.user_id == target.id))
        .scalars()
        .all()
    )
    assert len(sessions_before) == 1

    client.cookies.clear()
    admin = _make_staff(db_session, Role.admin, "Admin-Passw0rd!")
    _login(client, admin.username, "Admin-Passw0rd!")

    response = client.patch(f"/api/v1/users/{target.id}", json={"role": "player"})
    assert response.status_code == 200

    sessions_after = (
        db_session.execute(select(SessionModel).where(SessionModel.user_id == target.id))
        .scalars()
        .all()
    )
    assert len(sessions_after) == 0

    client.cookies.clear()
    client.cookies.set(SESSION_COOKIE, old_token)
    refused = client.get("/api/v1/auth/session")

    assert refused.status_code == 401
    assert refused.json()["code"] == "session_invalid"
