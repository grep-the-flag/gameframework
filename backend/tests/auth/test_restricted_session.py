"""The restricted session (M2-Task-Plan.md Task 3 Step 5; ADR-0007
"Onboarding, initial password and OTP"): while `must_change_password`
holds, the issued session reaches exactly `GET /auth/session`,
`GET /auth/csrf` and `POST /auth/password`, "so it can complete the
change and do nothing else." `_check_restricted_allowlist` in
`api/deps.py` is still the no-op Step 5 leaves it as (Step 6 fills it
in), and neither `GET /auth/csrf` nor `POST /auth/password` exist in
`api/auth.py` yet — every test below that touches one of those two is
expected to fail for one of those two reasons, not a fixture. The one
exception is `test_restricted_session_reaches_get_session`, already true
today because nothing has ever gated that route on `restricted` —
included anyway because it is part of the allowlist's own claim, not
because it is currently red.

api-surface.md §2.17 (Task 18, not yet written) is what api-surface.md
itself names as the source that generates authorization tests row by
table row, and it says outright that the restricted session's three
routes are deliberately **not** rows there: "what governs them is the
session's `restricted` flag, and their access rule is stated at §2.2" —
so this hand-written file, not a generated one, is where that rule is
proven, and it stays hand-written even once Task 18 lands.
`POST /auth/logout` is the one route that exists today and sits outside
the allowlist; it stands in for "nothing else" until later tasks add
more of them.

The denial code for a restricted session reaching a non-allowlisted
route is not named in api-surface.md or ADR-0007 — neither document
defines one. This file asserts `403 session_restricted`: 403 because the
session is valid and the denial is about what it may reach rather than
who it is (matching `role_denied`'s status, api-surface.md §1), and
`session_restricted` to sit beside this codebase's other three
session-state codes (`session_required`, `session_invalid`,
`session_cookie_ambiguous`, all in `api/deps.py`/
`test_session_lifecycle.py`) rather than inventing an unrelated shape —
this file's own choice, not a documented contract.

Every CSRF token below comes from `_fetch_csrf_token`, `test_csrf.py`'s
own helper duplicated here rather than imported — a test module
importing from another lets an unrelated suite's change break this one
(conftest.py's stated reason for the same choice, restated in
`test_session_lifecycle.py`).
"""

import uuid
from datetime import UTC, datetime, timedelta

import jwt
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from gameframework.config import get_settings
from gameframework.db.models.identity import Role, User
from gameframework.db.models.identity import Session as SessionModel
from gameframework.services.passwords import hash_password
from gameframework.services.secrets import ensure_signing_key

from ..conftest import make_user

SESSION_COOKIE = "__Secure-gf_session"
_ALGORITHM = "HS256"


def _authenticate(client: TestClient, db_session: Session, user: User) -> SessionModel:
    """Same helper as `test_csrf.py`, duplicated rather than imported
    (see this file's own docstring)."""
    key = ensure_signing_key(get_settings())
    session_row = SessionModel(
        user_id=user.id,
        restricted=user.must_change_password,
        expires_at=datetime.now(UTC) + timedelta(hours=12),
    )
    db_session.add(session_row)
    db_session.commit()
    claims = {
        "sub": str(user.id),
        "role": user.role.value,
        "sid": str(session_row.id),
        "iat": int(datetime.now(UTC).timestamp()),
        "exp": int(session_row.expires_at.timestamp()),
    }
    token = jwt.encode(claims, key, algorithm=_ALGORITHM)
    client.cookies.set(SESSION_COOKIE, token)
    return session_row


def _fetch_csrf_token(client: TestClient) -> str:
    """Same helper as `test_csrf.py`, duplicated rather than imported
    (see this file's own docstring). Response shape (`{"csrf_token":
    ...}`) is the same assumption `test_csrf.py` makes, stated once
    there.
    """
    response = client.get("/api/v1/auth/csrf")
    assert response.status_code == 200, response.text
    token = response.json()["csrf_token"]
    assert isinstance(token, str)
    return token


def _restricted_user(db_session: Session, *, password: str) -> User:
    return make_user(
        db_session,
        role=Role.admin,
        must_change_password=True,
        password_hash=hash_password(password),
    )


def test_restricted_session_reaches_get_session(client: TestClient, db_session: Session) -> None:
    """Already true today: nothing has ever gated `GET /auth/session` on
    `restricted`, and it must stay that way once Step 6 adds the gate for
    the routes that are not on the allowlist.
    """
    user = _restricted_user(db_session, password="Staff-Passw0rd!")
    _authenticate(client, db_session, user)

    response = client.get("/api/v1/auth/session")

    assert response.status_code == 200
    assert response.json()["must_change_password"] is True


def test_restricted_session_reaches_get_csrf(client: TestClient, db_session: Session) -> None:
    """`GET /auth/csrf` is on the allowlist specifically so the forced
    change can obtain the token `POST /auth/password` requires (ADR-0007
    Onboarding) — this only proves the route answers a restricted caller,
    not that the token it returns then works there (the next test).
    """
    user = _restricted_user(db_session, password="Staff-Passw0rd!")
    _authenticate(client, db_session, user)

    response = client.get("/api/v1/auth/csrf")

    assert response.status_code == 200
    assert isinstance(response.json()["csrf_token"], str)


def test_completing_password_change_deletes_restricted_row_and_issues_full_session(
    client: TestClient, db_session: Session
) -> None:
    """Task 3 Step 5: "completing POST /auth/password deletes the
    restricted row and a full session is issued." Field names
    (`old_password`/`new_password`) match the ones
    `test_session_lifecycle.py`'s own `test_password_change_deletes_
    session_row` already uses against this same route.
    """
    old_password = "Old-Passw0rd!"
    user = _restricted_user(db_session, password=old_password)
    session_row = _authenticate(client, db_session, user)
    token = _fetch_csrf_token(client)

    response = client.post(
        "/api/v1/auth/password",
        headers={"X-CSRF-Token": token},
        json={"old_password": old_password, "new_password": "New-Passw0rd!"},
    )

    assert response.status_code == 200
    db_session.expire_all()
    assert db_session.get(SessionModel, session_row.id) is None

    new_cookie = response.cookies.get(SESSION_COOKIE)
    assert new_cookie is not None
    key = ensure_signing_key(get_settings())
    new_claims = jwt.decode(new_cookie, key, algorithms=[_ALGORITHM])
    new_session_row = db_session.get(SessionModel, uuid.UUID(str(new_claims["sid"])))
    assert new_session_row is not None
    assert new_session_row.restricted is False


def test_restricted_session_is_refused_on_post_logout(
    client: TestClient, db_session: Session
) -> None:
    """`POST /auth/logout` is the one non-allowlist route that exists
    today — the "nothing else" case, standing in until later tasks add
    more of them (this file's own docstring). A valid CSRF token is
    included even though `require_csrf` runs after the allowlist check in
    `current_session`'s ordering (ADR-0007/Task 3): without one, a bug
    that checked CSRF first would still answer 403, and this test would
    not tell the two failure modes apart.
    """
    user = _restricted_user(db_session, password="Staff-Passw0rd!")
    _authenticate(client, db_session, user)
    token = _fetch_csrf_token(client)

    response = client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": token})

    assert response.status_code == 403
    assert response.json()["code"] == "session_restricted"
