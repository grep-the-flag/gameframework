"""Staff creation and the basic reads/edits (M2-Task-Plan.md Task 6 Step 2;
api-surface.md §2.4).

`POST /users` and its siblings do not exist yet — every assertion below is
expected to fail on FastAPI's own routing `404`, not on
`problem_error_handler`, exactly as test_login.py's Step 3 did for
`POST /auth/login`. `uv run pytest tests/users -x` must show that.

The acting admin below authenticates through a real login (`client` already
carries CSRF for free, Task 3 Step 6) rather than a hand-minted session —
no test in this task needs `raw_client`, and none fetches a token by hand.
"""

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.db.models.identity import Role, User
from gameframework.db.models.identity import Session as SessionModel
from gameframework.services.bootstrap import INITIAL_ADMIN_USERNAME
from gameframework.services.passwords import hash_password

from ..conftest import make_user

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


def test_creating_staff_without_initial_password_is_refused(
    client: TestClient, db_session: Session
) -> None:
    """api-surface.md §2.4: "an initial password in the request" — required,
    not optional. A body omitting `initial_password` is `422`, FastAPI's own
    validation rather than a business rule this route writes itself.
    """
    _login_as_admin(client, db_session)

    response = client.post("/api/v1/users", json={"username": "new-gameadmin", "role": "gameadmin"})

    assert response.status_code == 422


def test_creating_staff_sets_forced_change_and_its_own_password(
    client: TestClient, db_session: Session
) -> None:
    """The created account carries `must_change_password` (ADR-0007) and
    authenticates on the password the creating admin chose, never on its
    own username — proven behaviourally, by attempting the
    username-as-password login a participant would use and watching it
    fail, rather than only inspecting `password_hash`.
    """
    _login_as_admin(client, db_session)
    username = "new-gameadmin"

    response = client.post(
        "/api/v1/users",
        json={"username": username, "initial_password": "Chosen-Passw0rd!", "role": "gameadmin"},
    )

    assert response.status_code == 200
    created = db_session.execute(select(User).where(User.username == username)).scalar_one()
    assert created.role is Role.gameadmin
    assert created.must_change_password is True

    # The admin's own session is still live in this client's cookie jar;
    # left in place, `POST /auth/login`'s CSRF token would bind to that
    # session's `sid` instead of a fresh pre-session id, and the call would
    # be refused `403 csrf_token_invalid` before password verification ever
    # ran — a fact about this client, not about the account under test.
    client.cookies.clear()
    login_response = client.post(
        "/api/v1/auth/login", json={"username": username, "password": username}
    )
    assert login_response.status_code == 401
    assert login_response.json()["code"] == "invalid_credentials"


def test_creating_participant_via_post_users_is_422(
    client: TestClient, db_session: Session
) -> None:
    """api-surface.md §2.4: "A participant is refused here (422)" —
    participants exist only as members of a run's roster, minted by
    `POST /runs/{id}/users/import`/`POST /runs/{id}/users` (Task 7), never
    by this route.
    """
    _login_as_admin(client, db_session)

    response = client.post(
        "/api/v1/users",
        json={"username": "sneaky-participant", "initial_password": "irrelevant", "role": "player"},
    )

    assert response.status_code == 422


def test_unauthenticated_post_users_is_refused_in_factory_state(
    client: TestClient, db_session: Session
) -> None:
    """api-surface.md §2.1: "There is no setup endpoint" — no call in this
    document creates an admin account without an authenticated admin behind
    it, in any state of the installation. `client`'s own fixture setup
    already ran the ASGI lifespan, which mints the framework's initial admin
    for this test's isolated `db_session` (Task 5).

    The pre-assertion is what binds this test to *factory* state rather
    than to "no session cookie" in general, which `current_session` refuses
    identically no matter how many accounts exist: without checking that
    the table holds only the framework-minted admin at the moment of the
    call, "in factory state" and "in any state" would be the same assertion
    — indistinguishable the same way a deletion-rule test's "zero rows" and
    "never created" are without a pre-assertion of its own.
    """
    users = db_session.execute(select(User)).scalars().all()
    assert len(users) == 1
    assert users[0].username == INITIAL_ADMIN_USERNAME
    assert users[0].role is Role.admin

    response = client.post(
        "/api/v1/users",
        json={"username": "uninvited-admin", "initial_password": "irrelevant", "role": "admin"},
    )

    assert response.status_code == 401
    assert response.json()["code"] == "session_required"


def test_get_single_user_returns_expected_fields(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)
    target = make_user(
        db_session, role=Role.player, display_name="Target", email="target@example.com"
    )

    response = client.get(f"/api/v1/users/{target.id}")

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == str(target.id)
    assert body["display_name"] == "Target"
    assert body["email"] == "target@example.com"


def test_list_users_includes_created_staff(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)
    username = "listed-gameadmin"
    client.post(
        "/api/v1/users",
        json={"username": username, "initial_password": "Chosen-Passw0rd!", "role": "gameadmin"},
    )

    response = client.get("/api/v1/users")

    assert response.status_code == 200
    usernames = [item["username"] for item in response.json()["items"]]
    assert username in usernames


def test_patch_updates_a_basic_field(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)
    target = make_user(db_session, role=Role.player, display_name="Old Name")

    response = client.patch(f"/api/v1/users/{target.id}", json={"display_name": "New Name"})

    assert response.status_code == 200
    db_session.expire_all()
    db_session.refresh(target)
    assert target.display_name == "New Name"


def test_deactivate_sets_is_active_false(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)
    target = make_user(db_session, role=Role.player, is_active=True)

    response = client.post(f"/api/v1/users/{target.id}/deactivate")

    assert response.status_code == 200
    db_session.expire_all()
    db_session.refresh(target)
    assert target.is_active is False


def test_deactivated_account_is_refused_login_with_account_deactivated(
    client: TestClient, db_session: Session
) -> None:
    """api-surface.md §2.2 codes table / data-model.md §3.1 `is_active`:
    deactivation must refuse the account's *next* login, or the switch
    stops nothing — the same account would otherwise sign straight back in
    a second later. Pre-asserted with a real, successful login before the
    deactivation: without it, "refused because deactivated" and "never
    able to log in at all" would be the same assertion. Also checks the
    other half of the same promise: an already-live session is revoked at
    deactivation, not merely refused on its next login — a pre/post pair
    on the `sid` row, since `current_session` never reads `is_active`
    itself and would otherwise keep honouring a session minted before the
    switch flipped.
    """
    password = "Target-Deactivate-Passw0rd!"
    target = make_user(
        db_session,
        role=Role.player,
        must_change_password=False,
        password_hash=hash_password(password),
    )

    pre_login = client.post(
        "/api/v1/auth/login", json={"username": target.username, "password": password}
    )
    assert pre_login.status_code == 200
    sessions_before = (
        db_session.execute(select(SessionModel).where(SessionModel.user_id == target.id))
        .scalars()
        .all()
    )
    assert len(sessions_before) == 1

    client.cookies.clear()
    _login_as_admin(client, db_session)
    deactivate_response = client.post(f"/api/v1/users/{target.id}/deactivate")
    assert deactivate_response.status_code == 200
    sessions_after = (
        db_session.execute(select(SessionModel).where(SessionModel.user_id == target.id))
        .scalars()
        .all()
    )
    assert len(sessions_after) == 0

    client.cookies.clear()
    post_login = client.post(
        "/api/v1/auth/login", json={"username": target.username, "password": password}
    )

    assert post_login.status_code == 409
    assert post_login.json()["code"] == "account_deactivated"
