"""Backlog "Before Task 7": `username` is normalized nowhere today, though
data-model.md §3.1 requires NFKC + casefold + trim **at write and at
lookup**, "so `Anna` and `anna` are one account." Task 7 is the gate: it is
the first task to write usernames in bulk, and until it runs the only real
row is the minted `admin`, already normalized — so the fix needs no
migration if it lands first (Backlog.md "Before Task 7").

Both tests here exercise write sites that already exist and are already
merged (`create_staff_user`, Task 6; the `auth.py` lookup, Task 3) — the fix
does not depend on this task's own import to be observable, and isolating
it here keeps the import's own suite (`test_import.py`) about the import.

Bound by mutation, per the backlog entry: normalizing writes but not
lookups, and lookups but not writes, must each redden a test below. Neither
test below uses a login string that is already in casefolded form (a
literal lowercase `anna`) as the *only* case tested — see
`test_account_created_in_mixed_case_authenticates_from_a_different_case`'s
docstring for why that distinction matters.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from gameframework.db.models.identity import Role, User
from gameframework.services.passwords import hash_password
from gameframework.services.users import create_staff_user

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


def test_account_created_in_mixed_case_authenticates_from_a_different_case(
    client: TestClient, db_session: Session
) -> None:
    """Created as `Anna` via `POST /users` (`create_staff_user`, Task 6),
    found by a login as `ANNA` (`auth.py`'s `User.username ==` lookup,
    Task 3) — deliberately not `anna`: `casefold("Anna")` is already
    `"anna"`, so a literal-lowercase login would match a normalize-at-write
    -only implementation's raw-compared lookup by coincidence, proving
    nothing about the lookup half. `ANNA` does not coincide with either
    input, so it requires both halves to be correct:

    - writes normalized, lookup raw: stored `"anna"`, lookup compares raw
      `"ANNA"` against it — mismatch, red.
    - writes raw, lookup normalized: stored `"Anna"`, lookup normalizes
      `"ANNA"` to `"anna"` and compares against the raw `"Anna"` — mismatch,
      red.
    - both normalized: stored `"anna"`, lookup normalizes `"ANNA"` to
      `"anna"` — match, green.

    Today, with neither half fixed, this is red for the same reason as the
    first case above (stored `"Anna"` raw, compared against raw `"ANNA"`).
    """
    _login_as_admin(client, db_session)
    password = "Chosen-Passw0rd!"

    create_response = client.post(
        "/api/v1/users",
        json={"username": "Anna", "initial_password": password, "role": "gameadmin"},
    )
    assert create_response.status_code == 200

    client.cookies.clear()
    login_response = client.post(
        "/api/v1/auth/login", json={"username": "ANNA", "password": password}
    )

    assert login_response.status_code == 200


def test_second_staff_creation_with_case_variant_username_collides(db_session: Session) -> None:
    """A second creation as `ANNA` collides with the first, created as
    `Anna`, rather than making a second account — proof that
    `create_staff_user`'s write normalizes before the insert, so both target
    the same entry in `user_username_key` (data-model.md §3.1/§6). Asserted
    against the specific constraint name (Working-Agreement "Assert the
    specific constraint name"), not a bare `IntegrityError` — a test that
    only checked that would also pass if the row tripped some other
    constraint first.

    Exercises the write side only: normalizing the lookup without the write
    leaves `"Anna"` and `"ANNA"` stored as distinct raw strings, so this
    stays red under that half-fix too — the two creates would not collide.
    Today, with neither half fixed, it is red for the same reason.
    """
    create_staff_user(
        db_session, username="Anna", initial_password="First-Passw0rd!", role=Role.gameadmin
    )

    with pytest.raises(IntegrityError) as exc_info:
        create_staff_user(
            db_session, username="ANNA", initial_password="Second-Passw0rd!", role=Role.gameadmin
        )
    actual_constraint = exc_info.value.orig.diag.constraint_name  # type: ignore[union-attr]
    assert actual_constraint == "user_username_key"
    db_session.rollback()

    accounts = db_session.execute(select(User).where(User.role == Role.gameadmin)).scalars().all()
    assert len(accounts) == 1
