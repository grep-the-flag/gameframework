"""CSRF (M2-Task-Plan.md Task 3 Step 5): a keyed MAC bound to the session
(or, before login, to the pre-session `__Host-` cookie), valid 2 hours,
checked on every mutating request (ADR-0007 "Session model" — CSRF;
api-surface.md §1, §2.2). `require_csrf` is still the no-op `api/deps.py`
leaves it as through Step 5 (Step 6 fills it in), and neither
`GET /auth/csrf` nor `POST /auth/password` exist in `api/auth.py` yet —
every test below is expected to fail for one of those two reasons, not a
fixture. `uv run pytest tests/auth -x` must show that.

Two Step 6 primitives are referenced directly rather than worked around:
`mint_csrf_token(binding, expires_at, settings)` in `services/sessions.py`
and `csrf_key(signing_key)` in `services/secrets.py` — both now specified
in M2-Task-Plan.md Task 3, not only here. Neither exists yet, so
importing either is this file's own red for the two tests that need one
— the same shape `test_passwords.py` took against a wholly missing
module before Step 3 landed it, scoped here to a local import inside just
the test that needs it, so the tests that need no hand-minted token still
fail on `require_csrf`/the missing route rather than an unrelated
collection error for the whole file. `mint_csrf_token` takes the expiry
as a parameter instead of computing `now + 2h` itself: that is what lets
a test mint an already-past token with no clock to move, and it makes
"two hours" the route's choice rather than the primitive's — a choice
`test_csrf_token_expiry_is_about_two_hours_ahead` checks directly, since
every other test here would also pass a route that chose 200 hours. The
token is an HS256 JWT under that key, the mechanism `services/sessions.py`
already uses for the session cookie — and the task plan is explicit that
the verifier pins `algorithms=["HS256"]` and never reads the algorithm
out of the token, as the session side already does; every `jwt.decode`
call below does the same.

`GET /auth/csrf`'s response body is assumed to carry the token as
`{"csrf_token": "..."}` — api-surface.md leaves body schemas out of scope
by design (§1) — decided once in `_fetch_csrf_token` below and used
everywhere a token is needed, rather than re-fetched inline per test:
Step 6 turning `require_csrf` on is also what makes Step 3's eighteen
login tests start posting without a token, and the fix belongs in one
place, not eighteen.

Sessions are minted directly under the real signing key (`_authenticate`),
the same shortcut `test_session_lifecycle.py` uses (`_mint_token`) and for
the same reason: routing every fixture through `POST /auth/login` would
run it through the very CSRF gate several of these tests exist to prove,
before that gate is shown to work.
"""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from gameframework.config import get_settings
from gameframework.db.models.identity import Role, User
from gameframework.db.models.identity import Session as SessionModel
from gameframework.db.session import get_session
from gameframework.main import create_app
from gameframework.services.passwords import hash_password
from gameframework.services.secrets import ensure_signing_key

from ..conftest import make_user

SESSION_COOKIE = "__Secure-gf_session"
_ALGORITHM = "HS256"


def _authenticate(client: TestClient, db_session: Session, user: User) -> SessionModel:
    """Mints a session directly under the real signing key and attaches
    it to `client`'s cookie jar — the same shortcut
    `test_session_lifecycle.py` uses (`_mint_token`), for the same
    reason: `POST /auth/login` is itself CSRF-gated once Step 6 lands, so
    a test that needs an established session in place cannot get there
    through login without first assuming the very thing some of these
    tests exist to prove.
    """
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
    """The one place every test below obtains a token: once Step 6 turns
    `require_csrf` on, Step 3's eighteen login tests start posting
    without one, and this is the single seam that then has to change
    rather than eighteen call sites.

    Response shape (`{"csrf_token": ...}`) is this file's own assumption
    — `GET /auth/csrf` does not exist yet, and api-surface.md documents
    the route's purpose, not its body schema (§1).
    """
    response = client.get("/api/v1/auth/csrf")
    assert response.status_code == 200, response.text
    token = response.json()["csrf_token"]
    assert isinstance(token, str)
    return token


def test_mutating_request_without_csrf_token_is_refused_with_csrf_token_invalid(
    client: TestClient, db_session: Session
) -> None:
    """api-surface.md §1's cookie table: missing or invalid alike answer
    `403 csrf_token_invalid`. `POST /auth/logout` is the only
    authenticated mutating route that exists today; no `X-CSRF-Token`
    header is sent.
    """
    user = make_user(db_session, role=Role.admin, must_change_password=False)
    _authenticate(client, db_session, user)

    response = client.post("/api/v1/auth/logout")

    assert response.status_code == 403
    assert response.json()["code"] == "csrf_token_invalid"


def test_login_without_csrf_token_or_presession_cookie_is_refused(
    client: TestClient, db_session: Session
) -> None:
    """Task 3 Step 5: "a mutating request without a token is 403...
    including POST /auth/login." Login is public and mutating with no
    `sid` yet to bind to, so it needs its own pre-session token rather
    than inheriting the general case for free (api-surface.md §1).
    """
    password = "Staff-Passw0rd!"
    user = make_user(
        db_session,
        role=Role.admin,
        must_change_password=False,
        password_hash=hash_password(password),
    )

    response = client.post(
        "/api/v1/auth/login", json={"username": user.username, "password": password}
    )

    assert response.status_code == 403
    assert response.json()["code"] == "csrf_token_invalid"


def test_login_succeeds_with_a_valid_presession_csrf_token(
    client: TestClient, db_session: Session
) -> None:
    """The positive half of the case above: "both cases or neither"
    (Task 3 Step 5, stated there for the sid-binding assertion) applies
    here too — a login that is always refused would also pass a
    token-absent-only test. `GET /auth/csrf` with no session yet sets the
    `__Host-` pre-session cookie in the same response (api-surface.md
    §1/§2.2); httpx's jar carries it into the login call that follows,
    since neither request uses a raw `Cookie:` header.
    """
    password = "Staff-Passw0rd!"
    user = make_user(
        db_session,
        role=Role.admin,
        must_change_password=False,
        password_hash=hash_password(password),
    )
    token = _fetch_csrf_token(client)

    response = client.post(
        "/api/v1/auth/login",
        headers={"X-CSRF-Token": token},
        json={"username": user.username, "password": password},
    )

    assert response.status_code == 200


def test_csrf_token_minted_for_one_sid_is_refused_for_another_and_accepted_for_its_own(
    client: TestClient, db_session: Session
) -> None:
    """Task 3 Step 5: "a token minted for one sid is refused for another —
    and accepted for its own. The negative alone does not bind it; both
    cases or neither." Two real sessions, two real tokens, one `client`
    whose session cookie is swapped between them — never a hand-minted
    token here, so this exercises only the binding check itself, not
    `mint_csrf_token`'s own correctness (the expiry tests below do that).
    """
    user_a = make_user(db_session, role=Role.admin, must_change_password=False)
    user_b = make_user(db_session, role=Role.admin, must_change_password=False)

    _authenticate(client, db_session, user_a)
    token_for_a = _fetch_csrf_token(client)

    _authenticate(client, db_session, user_b)
    refused = client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": token_for_a})

    assert refused.status_code == 403
    assert refused.json()["code"] == "csrf_token_invalid"

    token_for_b = _fetch_csrf_token(client)
    accepted = client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": token_for_b})

    assert accepted.status_code == 200


def test_expired_csrf_token_is_refused_then_refetching_succeeds(
    client: TestClient, db_session: Session
) -> None:
    """A token past its two hours is refused, and re-fetching from
    `GET /auth/csrf` succeeds (Task 3 Step 5). No clock to move: this
    mints its own token directly under `mint_csrf_token`, exactly as
    `test_session_lifecycle.py` mints its own session JWTs directly under
    `ensure_signing_key()` rather than calling `issue_session()`.
    `mint_csrf_token` does not exist until Step 6 — the resulting
    `ImportError` is this test's red, the same shape `test_passwords.py`
    took before `services/passwords.py` existed.
    """
    from gameframework.services.sessions import mint_csrf_token

    user = make_user(db_session, role=Role.admin, must_change_password=False)
    session_row = _authenticate(client, db_session, user)
    past_token = mint_csrf_token(
        str(session_row.id), datetime.now(UTC) - timedelta(seconds=1), get_settings()
    )

    refused = client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": past_token})

    assert refused.status_code == 403
    assert refused.json()["code"] == "csrf_token_invalid"

    fresh_token = _fetch_csrf_token(client)
    retried = client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": fresh_token})

    assert retried.status_code == 200


def test_csrf_token_expiry_is_about_two_hours_ahead(
    client: TestClient, db_session: Session
) -> None:
    """The two-hour promise has two separate claims, and this is the
    second: the test above proves the verifier checks expiry at all; this
    one proves the route chose two hours specifically, not merely a value
    the verifier happens to accept — a route that set 200 hours would
    pass every other test in this file. A window, not an exact
    comparison, and bounded on both sides: real time passes between the
    request and this assertion, and an unbounded `>=` would also pass a
    route that never expires anything. Decoding the real token needs
    `csrf_key()` directly, and assumes the token is a JWT under that key —
    the same mechanism `services/sessions.py` already uses for the
    session cookie.
    """
    from gameframework.services.secrets import csrf_key

    user = make_user(db_session, role=Role.admin, must_change_password=False)
    _authenticate(client, db_session, user)
    requested_at = datetime.now(UTC)

    token = _fetch_csrf_token(client)

    key = csrf_key(ensure_signing_key(get_settings()))
    claims = jwt.decode(token, key, algorithms=[_ALGORITHM])
    expiry = datetime.fromtimestamp(claims["exp"], tz=UTC)
    window = timedelta(minutes=5)

    assert requested_at + timedelta(hours=2) - window <= expiry
    assert expiry <= requested_at + timedelta(hours=2) + window


def test_get_csrf_unreadable_cross_origin_for_a_non_frontend_event_subdomain(
    client: TestClient,
) -> None:
    """An absence assertion alone passes against a route that emits no
    CORS headers at all, so this is paired with the positive case right
    below it rather than left to stand alone. The origin is a sibling
    `*.event.example.com` host, not an unrelated domain — same-site with
    the framework, so `SameSite=Lax` restrains nothing between them,
    which is exactly the case the cross-origin policy exists for
    (ADR-0007, api-surface.md §1).

    `status_code == 200` is asserted alongside the header check: CORS is
    enforced by the browser reading the header, not by the server
    refusing the request, so a correct implementation answers this
    request in full and only omits the header a script on that origin
    would need to read it.
    """
    response = client.get("/api/v1/auth/csrf", headers={"Origin": "https://evil.event.example.com"})

    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


def test_get_csrf_readable_for_the_configured_frontend_origin(client: TestClient) -> None:
    """The positive counterpart the test above needs: read from
    `Settings` rather than hardcoded, since `get_settings().
    frontend_origin` is the same source `CORSMiddleware` is configured
    from in `main.py` — not a copy of the literal this test's own
    environment happens to set, which the next test drives a second
    value through.
    """
    origin = get_settings().frontend_origin

    response = client.get("/api/v1/auth/csrf", headers={"Origin": origin})

    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == origin


def test_cors_allowance_follows_a_different_configured_frontend_origin(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Asserting the allowed origin against the same literal the test
    environment already sets (`GF_FRONTEND_ORIGIN=https://app.event.
    example.com`, CI's own env block) would pass just as well against a
    hardcoded `CORSMiddleware(allow_origins=["https://app.event.example.
    com"])`. Driving a second value through the setting and checking the
    allowance follows it is what tells the two apart — the same
    principle `test_login.py`'s `test_login_response_session_cookie_
    domain_follows_the_settings` already applies to `cookie_domain`,
    there via `app.dependency_overrides[get_settings]`.

    That override does not reach this setting: `CORSMiddleware` reads
    `settings.frontend_origin` once, inside `create_app()`, when the
    middleware is constructed — never through `Depends(get_settings)` at
    request time — so overriding the dependency on the shared `app`
    changes nothing here. This test instead builds its own app from a
    changed environment, and clears `get_settings`'s cache twice: once to
    let the new value in, once more before the environment reverts
    (`monkeypatch`'s own teardown), so the next test's `get_settings()`
    does not inherit this one's cached object — the cache is process-wide,
    not per test.
    """
    other_origin = "https://other-frontend.example.net"
    monkeypatch.setenv("GF_FRONTEND_ORIGIN", other_origin)
    get_settings.cache_clear()
    try:
        fresh_app = create_app()

        def _override_get_session() -> Iterator[Session]:
            yield db_session

        fresh_app.dependency_overrides[get_session] = _override_get_session
        try:
            with TestClient(fresh_app, base_url="https://app.event.example.com") as fresh_client:
                response = fresh_client.get("/api/v1/auth/csrf", headers={"Origin": other_origin})
        finally:
            fresh_app.dependency_overrides.pop(get_session, None)
    finally:
        get_settings.cache_clear()

    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == other_origin
