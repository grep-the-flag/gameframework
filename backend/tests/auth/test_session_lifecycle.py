"""Session lifecycle from ADR-0007's "Session model" (M2-Task-Plan.md Task 3
Step 3): revocation checked on reads, sliding renewal, deletion on password
change, and the duplicate-cookie refusal. `current_session` does not exist
yet (Task 3 Step 4), so every request below drives `GET /api/v1/auth/session`
or `POST /api/v1/auth/password` — routes that do not exist either — and each
test is expected to fail on that missing route (`404`), not on a broken
fixture. `uv run pytest tests/auth -x` must show that.

Tokens are minted directly with PyJWT under the bytes `ensure_signing_key`
returns, the same approach `test_signing_key.py` uses for the same reason:
`issue_session` is Task 3 Step 4's, not this step's. The app's own lifespan
(`main.py`) already calls `ensure_signing_key` before serving, so the
`client` fixture's `TestClient` has written the key file by the time a test
body runs; `ensure_signing_key` is idempotent, so reading it again here
returns the identical bytes.

The `client` fixture is Task 1a's HTTPS client at
`https://app.event.example.com` — required because the session cookie is
`Secure` with `Domain=.event.example.com` (api-surface.md §2.2), which no
compliant client stores over plain HTTP.

The duplicate-cookie test uses a raw `Cookie:` header, which suppresses
httpx's cookie jar entirely rather than merely adding to it (conftest.py's
`client` fixture docstring). Since `GET /auth/session` needs no CSRF token,
the session cookie pair is the only cookie the route needs, so nothing else
has to be spelled out here — unlike a mutating route, where every cookie
the route needs would have to be listed explicitly.

The duplicate-cookie assertion is bounded exactly as ADR-0007 states it:
the response is `401`, twice in a row for a client that keeps sending both
values — never a claim about the cookie jar being left clean, which the
server cannot promise for a duplicate planted on another `Path`.
"""

import secrets
from datetime import UTC, datetime, timedelta

import httpx
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


def _mint_token(user: User, session_row: SessionModel) -> str:
    """All five ADR-0007 claims: `sub`, `role`, `sid`, `iat`, `exp`. Once
    Step 4's `current_session` checks the route's role requirement, a
    token missing `role` fails these tests for a reason unrelated to what
    each one tests.
    """
    key = ensure_signing_key(get_settings())
    claims = {
        "sub": str(user.id),
        "role": user.role.value,
        "sid": str(session_row.id),
        "iat": int(datetime.now(UTC).timestamp()),
        "exp": int(session_row.expires_at.timestamp()),
    }
    return jwt.encode(claims, key, algorithm=_ALGORITHM)


def _find_set_cookie(response: httpx.Response, cookie_name: str) -> str:
    """Same helper as `test_login.py`, duplicated rather than imported —
    a test module importing from another lets an unrelated suite's change
    break this one (conftest.py's own stated reason for the same choice).
    """
    headers = response.headers.get_list("set-cookie")
    for header in headers:
        if header.startswith(f"{cookie_name}="):
            return header
    raise AssertionError(f"no Set-Cookie header for {cookie_name!r} among {headers!r}")


def _cookie_attribute(header: str, name: str) -> str | bool | None:
    """The exact value of one `Set-Cookie` attribute — see `test_login.py`."""
    for part in header.split(";"):
        key, sep, value = part.strip().partition("=")
        if key.strip().lower() == name.lower():
            return value if sep else True
    return None


def test_no_session_cookie_at_all_is_refused_with_session_required(
    client: TestClient,
) -> None:
    """api-surface.md §2.2: `401` `session_required` — distinct from
    `session_cookie_ambiguous` (more than one) and from `session_invalid`
    (one present but unusable). A status-only assertion would leave all
    three free to drift into each other.
    """
    response = client.get("/api/v1/auth/session")

    assert response.status_code == 401
    assert response.json()["code"] == "session_required"


def test_session_cookie_with_broken_signature_is_refused_with_session_invalid(
    client: TestClient, db_session: Session
) -> None:
    """api-surface.md §2.2: `session_invalid` covers a bad signature, an
    expired `exp`, an unknown `sid` and an unknown `sub` alike — one code
    for all four, deliberately (telling them apart is information for an
    attacker, not the client). This is the bad-signature case: a
    correctly-shaped token signed under a key that is not
    `ensure_signing_key`'s.
    """
    user = make_user(db_session, role=Role.admin, must_change_password=False)
    session_row = SessionModel(
        user_id=user.id, restricted=False, expires_at=datetime.now(UTC) + timedelta(hours=12)
    )
    db_session.add(session_row)
    db_session.commit()
    wrong_key = secrets.token_bytes(32)
    claims = {
        "sub": str(user.id),
        "role": user.role.value,
        "sid": str(session_row.id),
        "iat": int(datetime.now(UTC).timestamp()),
        "exp": int(session_row.expires_at.timestamp()),
    }
    token = jwt.encode(claims, wrong_key, algorithm=_ALGORITHM)
    client.cookies.set(SESSION_COOKIE, token)

    response = client.get("/api/v1/auth/session")

    assert response.status_code == 401
    assert response.json()["code"] == "session_invalid"


def test_revoked_sid_refused_on_next_read_request(
    client: TestClient, db_session: Session
) -> None:
    """ADR-0007: "`sid` is a row in a server-side session table, checked on
    every authenticated request — reads included." `GET /auth/session` is
    the read under test; nothing here writes anything.
    """
    user = make_user(db_session, role=Role.admin, must_change_password=False)
    session_row = SessionModel(
        user_id=user.id, restricted=False, expires_at=datetime.now(UTC) + timedelta(hours=12)
    )
    db_session.add(session_row)
    db_session.commit()
    token = _mint_token(user, session_row)
    client.cookies.set(SESSION_COOKIE, token)

    db_session.delete(session_row)
    db_session.commit()

    response = client.get("/api/v1/auth/session")

    assert response.status_code == 401
    assert response.json()["code"] == "session_invalid"


def test_expired_session_token_is_refused_with_session_invalid(
    client: TestClient, db_session: Session
) -> None:
    """A distinct path through `decode_token` from the bad-signature case
    above: PyJWT raises `ExpiredSignatureError`, not `InvalidSignatureError`,
    when the signature is correct and only `exp` is in the past.
    """
    user = make_user(db_session, role=Role.admin, must_change_password=False)
    session_row = SessionModel(
        user_id=user.id, restricted=False, expires_at=datetime.now(UTC) - timedelta(hours=1)
    )
    db_session.add(session_row)
    db_session.commit()
    token = _mint_token(user, session_row)
    client.cookies.set(SESSION_COOKIE, token)

    response = client.get("/api/v1/auth/session")

    assert response.status_code == 401
    assert response.json()["code"] == "session_invalid"


def test_sliding_renewal_reissues_same_sid_under_two_hours_remaining(
    client: TestClient, db_session: Session
) -> None:
    """ADR-0007: "any authenticated request made with less than 2 hours of
    validity left is answered with a re-issued cookie carrying the same
    `sid` and a fresh `exp`."
    """
    user = make_user(db_session, role=Role.admin, must_change_password=False)
    near_expiry = datetime.now(UTC) + timedelta(hours=1)
    session_row = SessionModel(user_id=user.id, restricted=False, expires_at=near_expiry)
    db_session.add(session_row)
    db_session.commit()
    token = _mint_token(user, session_row)
    client.cookies.set(SESSION_COOKIE, token)

    response = client.get("/api/v1/auth/session")

    assert response.status_code == 200
    renewed_cookie = response.cookies.get(SESSION_COOKIE)
    assert renewed_cookie is not None
    key = ensure_signing_key(get_settings())
    renewed_claims = jwt.decode(renewed_cookie, key, algorithms=[_ALGORITHM])
    assert renewed_claims["sid"] == str(session_row.id)
    assert renewed_claims["exp"] > int(near_expiry.timestamp())


def test_no_renewal_when_more_than_two_hours_remain(
    client: TestClient, db_session: Session
) -> None:
    """The negative side of the assertion above: renewal is conditional on
    the 2h threshold, not issued on every request. Without this case, an
    implementation that always re-issues the cookie also passes the
    positive test, and "under 2 h" is never actually exercised.
    """
    user = make_user(db_session, role=Role.admin, must_change_password=False)
    far_expiry = datetime.now(UTC) + timedelta(hours=11)
    session_row = SessionModel(user_id=user.id, restricted=False, expires_at=far_expiry)
    db_session.add(session_row)
    db_session.commit()
    token = _mint_token(user, session_row)
    client.cookies.set(SESSION_COOKIE, token)

    response = client.get("/api/v1/auth/session")

    assert response.status_code == 200
    assert SESSION_COOKIE not in response.cookies


def test_password_change_deletes_session_row(client: TestClient, db_session: Session) -> None:
    """ADR-0007: "Logout, user deactivation, single-user deletion, password
    change and a change of `user.role` delete the row."
    """
    old_password = "Old-Passw0rd!"
    user = make_user(
        db_session,
        role=Role.admin,
        must_change_password=False,
        password_hash=hash_password(old_password),
    )
    session_row = SessionModel(
        user_id=user.id, restricted=False, expires_at=datetime.now(UTC) + timedelta(hours=12)
    )
    db_session.add(session_row)
    db_session.commit()
    assert db_session.get(SessionModel, session_row.id) is not None
    token = _mint_token(user, session_row)
    client.cookies.set(SESSION_COOKIE, token)

    response = client.post(
        "/api/v1/auth/password",
        json={"old_password": old_password, "new_password": "New-Passw0rd!"},
    )

    assert response.status_code == 200
    db_session.expire_all()
    assert db_session.get(SessionModel, session_row.id) is None


def test_duplicate_session_cookie_answered_401_and_stays_401(client: TestClient) -> None:
    header = {"Cookie": f"{SESSION_COOKIE}=aaa; {SESSION_COOKIE}=bbb"}

    first = client.get("/api/v1/auth/session", headers=header)
    second = client.get("/api/v1/auth/session", headers=header)

    assert first.status_code == 401
    assert first.json()["code"] == "session_cookie_ambiguous"
    assert second.status_code == 401
    assert second.json()["code"] == "session_cookie_ambiguous"


def test_logout_expires_the_session_cookie(client: TestClient, db_session: Session) -> None:
    """`POST /auth/logout` deletes the `sid` row (covered above) and also
    clears the cookie client-side, through the same `expire_session_cookie`
    every other clearing emission uses — not a second, independently
    written `Domain`/attribute set that could silently drift from it.
    """
    user = make_user(db_session, role=Role.admin, must_change_password=False)
    session_row = SessionModel(
        user_id=user.id, restricted=False, expires_at=datetime.now(UTC) + timedelta(hours=12)
    )
    db_session.add(session_row)
    db_session.commit()
    token = _mint_token(user, session_row)
    client.cookies.set(SESSION_COOKIE, token)

    response = client.post("/api/v1/auth/logout")

    assert response.status_code == 200
    header = _find_set_cookie(response, SESSION_COOKIE).lower()
    assert _cookie_attribute(header, "max-age") == "0"
    assert _cookie_attribute(header, "domain") == ".event.example.com"
