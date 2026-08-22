"""Erasure and export (M2-Task-Plan.md Task 6 Step 5; api-surface.md §2.4,
§2.17; data-model.md §3.1, §4).

**The 403/404 split runs through this task twice, in opposite directions.**
Step 4's `test_role_administration.py::test_gameadmin_write_against_a_staff_
target_is_404` already bound the non-disclosure half: a gameadmin's
otherwise-reachable `PATCH /users/{id}` against a staff target must not
confirm that object exists, so it answers `404 object_not_found`. The two
tests below are that test's opposite pair, in this file rather than that
one because they sit on routes that are admin-only *at the role level* —
`GET /users/{id}/export` and `DELETE /users/{id}` — so a gameadmin is
refused before the route body, let alone an object, is ever reached:
`403 role_denied`. Both assert `code`, not status alone, exactly as the
404 test does — a test that only ever sees one direction of this split
passes against an implementation that answers the same thing everywhere.

`client` carries CSRF for every mutating call; no test here needs
`raw_client` or a hand-minted token.
"""

from datetime import UTC, datetime, timedelta

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


def test_delete_is_admin_only_gameadmin_refused(client: TestClient, db_session: Session) -> None:
    """api-surface.md §2.4/§2.17: `DELETE /users/{id}` is admin-only, "not
    gameadmin." The target is an ordinary participant — a scope a
    gameadmin's other writes may reach — isolating this from the
    staff-target `404` (test_role_administration.py): the refusal here is
    about the *route*, not about what the target happens to be.
    """
    gameadmin = _make_staff(db_session, Role.gameadmin, "Gameadmin-Passw0rd!")
    _login(client, gameadmin.username, "Gameadmin-Passw0rd!")
    target = make_user(db_session, role=Role.player)

    response = client.delete(f"/api/v1/users/{target.id}")

    assert response.status_code == 403
    assert response.json()["code"] == "role_denied"


def test_export_is_admin_only_gameadmin_refused(client: TestClient, db_session: Session) -> None:
    """The other half of the same pair, same reasoning as the delete test
    above: `GET /users/{id}/export` is the one route serving chat/ticket/
    gamemaster content to staff (api-surface.md §2.4), so it is admin-only
    at the role level rather than gated by which account it targets.
    """
    gameadmin = _make_staff(db_session, Role.gameadmin, "Gameadmin-Export!")
    _login(client, gameadmin.username, "Gameadmin-Export!")
    target = make_user(db_session, role=Role.player)

    response = client.get(f"/api/v1/users/{target.id}/export")

    assert response.status_code == 403
    assert response.json()["code"] == "role_denied"


def test_export_succeeds_for_admin_and_is_audited(client: TestClient, db_session: Session) -> None:
    """The one ceiling opening (api-surface.md §2.17): admin-only, and
    audited on every call — asserted as its own row, not inferred from the
    200 the response also carries.
    """
    admin = _make_staff(db_session, Role.admin, "Admin-Export-Passw0rd!")
    _login(client, admin.username, "Admin-Export-Passw0rd!")
    target = make_user(db_session, role=Role.player, display_name="Exportee", email="e@example.com")

    response = client.get(f"/api/v1/users/{target.id}/export")

    assert response.status_code == 200
    body = response.json()
    assert body["user_id"] == str(target.id)
    assert body["username"] == target.username
    assert body["display_name"] == "Exportee"
    assert body["email"] == "e@example.com"

    entry = db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "user_data_exported", AuditLog.target_id == target.id
        )
    ).scalar_one()
    assert entry.actor_user_id == admin.id
    assert entry.scope is AuditScope.installation


def test_delete_tombstones_in_place_and_the_account_never_authenticates_again(
    client: TestClient, db_session: Session
) -> None:
    """data-model.md §3.1: in-place erasure, not row removal. The
    pre-assertion is what makes "nulled" and "never set" two different
    claims — without recording that `display_name`/`email`/the OTP columns
    held real values first, a fixture that never set them would pass the
    same post-assertions. And the tombstoned account is shown to fail a
    real login attempt, not merely to be missing from a list: `is_active`
    and the tombstoned `username` together are what "never authenticates
    again" actually rests on.
    """
    admin = _make_staff(db_session, Role.admin, "Admin-Delete-Passw0rd!")
    target_password = "Target-Delete-Passw0rd!"
    target = make_user(
        db_session,
        role=Role.player,
        display_name="Before Name",
        email="before@example.com",
        password_hash=hash_password(target_password),
        otp_hash=hash_password("SOMECODE"),
        otp_expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    target_id = target.id
    target_username = target.username

    # Pre-assertions: the row and its fields held real values before the
    # delete, and the account had at least one live session.
    assert target.display_name == "Before Name"
    assert target.email == "before@example.com"
    assert target.is_active is True
    assert target.deleted_at is None
    assert target.otp_hash is not None
    assert target.otp_expires_at is not None

    _login(client, target_username, target_password)
    sessions_before = (
        db_session.execute(select(SessionModel).where(SessionModel.user_id == target_id))
        .scalars()
        .all()
    )
    assert len(sessions_before) == 1

    client.cookies.clear()
    _login(client, admin.username, "Admin-Delete-Passw0rd!")

    response = client.delete(f"/api/v1/users/{target_id}")
    assert response.status_code == 200

    db_session.expire_all()
    tombstoned = db_session.get(User, target_id)
    assert tombstoned is not None
    assert tombstoned.username == f"deleted-{target_id}"
    assert tombstoned.display_name is None
    assert tombstoned.email is None
    assert tombstoned.is_active is False
    assert tombstoned.deleted_at is not None
    assert tombstoned.otp_hash is None
    assert tombstoned.otp_expires_at is None
    assert tombstoned.otp_consumed_at is None

    sessions_after = (
        db_session.execute(select(SessionModel).where(SessionModel.user_id == target_id))
        .scalars()
        .all()
    )
    assert len(sessions_after) == 0

    client.cookies.clear()
    login_response = client.post(
        "/api/v1/auth/login",
        json={"username": target_username, "password": target_password},
    )
    assert login_response.status_code == 401
    assert login_response.json()["code"] == "invalid_credentials"


def test_put_me_language_writes_only_the_callers_own_row(
    client: TestClient, db_session: Session
) -> None:
    """api-surface.md §2.17: `self` scope. The negative is what binds it —
    without a second user's row checked unchanged, this would be
    consistent with a route that updates every account's language.
    """
    password = "Language-Passw0rd!"
    caller = make_user(
        db_session,
        role=Role.player,
        must_change_password=False,
        password_hash=hash_password(password),
        preferred_language="en",
    )
    other = make_user(db_session, role=Role.player, preferred_language="en")
    _login(client, caller.username, password)

    response = client.put("/api/v1/me/language", json={"preferred_language": "fr"})

    assert response.status_code == 200
    db_session.expire_all()
    db_session.refresh(caller)
    db_session.refresh(other)
    assert caller.preferred_language == "fr"
    assert other.preferred_language == "en"
