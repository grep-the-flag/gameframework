"""Source-address blocking (M2-Task-Plan.md Task 4; ADR-0007 "Failed
authentication is answered per source address, not per account";
data-model.md §3.3; api-surface.md §2.16). Tests written in Step 4,
implementation (`services/blocking.py`, wired into `POST /auth/login` and
the OTP submission on `POST /auth/password`) in Step 5.

**Why every test here builds its own client.** `conftest.py`'s `client`
fixture — and `test_otp.py`'s own `_authenticate` helper — are pinned to
Starlette's default `TestClient` socket peer, `("testclient", 50000)`: a
fixed, non-IP string, identical across every default-constructed instance.
The whole point of this suite is telling sources apart, which that peer
cannot do and which `normalize_source` (an `ipaddress` parse) could not
accept even if it could. `TestClient(app, ..., client=(ip, port))` lets a
test pin a real, parseable peer per instance (Starlette's own
`_TestClientTransport` writes it straight into the ASGI scope), so
`_source_client` below builds one per source under test rather than
reusing the shared fixture — the same "duplicate rather than share"
reasoning `conftest.py` and every other file in this suite already give
for their own helpers.

**Every source below is a documentation/test-only range** (RFC 5737
`TEST-NET-1/2/3`, `192.0.2.0/24` / `198.51.100.0/24` / `203.0.113.0/24`,
and RFC 3849 `2001:db8::/32`), never a real one.

**The blocked refusal is `429 source_blocked` with `Retry-After`**
(api-surface.md §2.2 codes table, added after the Step 4 report flagged
its absence). `_assert_blocked` is the one place that shape is checked —
a code of its own rather than Task 2's `rate_limited`, because the two
remedies diverge: the per-source token bucket throttle §1 also describes
lapses in seconds, this block runs for `block_window_minutes` or an
admin's release, and the `code` is what a client branches on to tell them
apart.
"""

from collections.abc import Generator, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import httpx
import jwt
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.config import get_settings
from gameframework.db.models.identity import BlockedAddress, Role, User
from gameframework.db.models.identity import Session as SessionModel
from gameframework.db.models.runs import RunStatus
from gameframework.db.session import get_session
from gameframework.main import app
from gameframework.services.passwords import hash_password
from gameframework.services.secrets import ensure_signing_key

from ..conftest import make_event_run, make_participation, make_team, make_user

SESSION_COOKIE = "__Secure-gf_session"
_ALGORITHM = "HS256"


class _SourceCsrfClient(TestClient):
    """`conftest.py`'s `_CsrfInjectingTestClient`, duplicated (this file's
    own docstring) rather than imported — a private class, and every
    mutating call below needs a live token bound to whatever cookie jar
    this specific source's client instance is carrying.
    """

    _MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

    def request(self, method: str, url: object, **kwargs: object) -> object:
        if method.upper() in self._MUTATING_METHODS:
            headers = httpx.Headers(kwargs.get("headers"))  # type: ignore[arg-type]
            if "x-csrf-token" not in headers:
                token_response = self.get("/api/v1/auth/csrf")
                assert token_response.status_code == 200, token_response.text
                headers["X-CSRF-Token"] = token_response.json()["csrf_token"]
                kwargs["headers"] = headers
        return super().request(method, url, **kwargs)  # type: ignore[arg-type]


@contextmanager
def _source_client(db_session: Session, peer: str) -> Generator[TestClient]:
    """A CSRF-injecting client whose socket peer is `peer` — real, so
    `normalize_source` can parse it, and pinned, so a scenario needing five
    consecutive attempts from *one* source gets the same one every call.

    Restores whatever `app.dependency_overrides[get_session]` held before
    this call, rather than clearing it outright, so nesting one
    `_source_client` inside another (`test_admin_releases_a_block_early`'s
    attacker-plus-admin scenario) leaves the outer one's override intact
    once the inner one exits — an unconditional pop here breaks the outer
    client silently, falling back to a real, unrelated database
    connection instead of erroring.
    """

    def override_get_session() -> Iterator[Session]:
        yield db_session

    previous = app.dependency_overrides.get(get_session)
    app.dependency_overrides[get_session] = override_get_session
    try:
        with _SourceCsrfClient(
            app, base_url="https://app.event.example.com", client=(peer, 51000)
        ) as test_client:
            yield test_client
    finally:
        if previous is not None:
            app.dependency_overrides[get_session] = previous
        else:
            app.dependency_overrides.pop(get_session, None)


def _authenticate(client: TestClient, db_session: Session, user: User) -> SessionModel:
    """Mints a session directly, bypassing `POST /auth/login` — same
    helper as `test_otp.py`'s own, duplicated for the same reason. Used
    here so an admin's own action (release, or reading an established
    session) is never itself subject to the block under test, which gates
    `POST /auth/login` and OTP submission only (data-model.md §3.3) but
    there is no reason to route an unrelated action through it either.
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


def _fail_login(client: TestClient, username: str) -> None:
    response = client.post(
        "/api/v1/auth/login", json={"username": username, "password": "wrong-password"}
    )
    assert response.status_code == 401


def _assert_blocked(response: httpx.Response) -> None:
    """api-surface.md §2.2 codes table: a blocked source is `429
    source_blocked` with `Retry-After` — the one `429` shape §1 fixes for
    the whole surface, but a `code` of its own, distinct from Task 2's
    `rate_limited`, because the two remedies diverge (the throttle lapses
    in seconds, this block runs for `block_window_minutes` or an admin's
    release).
    """
    assert response.status_code == 429
    assert response.json()["code"] == "source_blocked"
    assert "Retry-After" in response.headers


def test_five_failures_block_the_source_and_the_account_still_works_from_another_source(
    db_session: Session,
) -> None:
    """ADR-0007: five consecutive failures from one source block that
    address; a sixth attempt from it is refused even with the correct
    password, because the block is on the address, not the account
    (data-model.md §3.3) — proven here by the same account succeeding
    immediately from a different source.
    """
    username = "admin-under-attack"
    password = "Correct-Passw0rd!"
    make_user(
        db_session,
        username=username,
        role=Role.admin,
        must_change_password=False,
        password_hash=hash_password(password),
    )

    with _source_client(db_session, "192.0.2.10") as attacker:
        for _ in range(5):
            _fail_login(attacker, username)

        sixth = attacker.post(
            "/api/v1/auth/login", json={"username": username, "password": password}
        )
        _assert_blocked(sixth)

    with _source_client(db_session, "192.0.2.20") as legitimate:
        response = legitimate.post(
            "/api/v1/auth/login", json={"username": username, "password": password}
        )
        assert response.status_code == 200
        assert SESSION_COOKIE in response.cookies


def test_block_lapses_after_the_configured_window(db_session: Session) -> None:
    """data-model.md §3.3 `expires_at`: "the block lapses by itself." No
    literal wait: the stored row's `expires_at` is pushed into the past —
    the same technique `test_session_lifecycle.py` uses for an expired
    session token — and a login that would otherwise still be blocked
    succeeds.
    """
    username = "admin-window-lapses"
    password = "Correct-Passw0rd!"
    make_user(
        db_session,
        username=username,
        role=Role.admin,
        must_change_password=False,
        password_hash=hash_password(password),
    )

    with _source_client(db_session, "192.0.2.30") as attacker:
        for _ in range(5):
            _fail_login(attacker, username)

        blocked_row = db_session.execute(
            select(BlockedAddress).where(BlockedAddress.failed_attempts >= 5)
        ).scalar_one()
        blocked_row.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        db_session.add(blocked_row)
        db_session.commit()

        response = attacker.post(
            "/api/v1/auth/login", json={"username": username, "password": password}
        )
        assert response.status_code == 200
        assert SESSION_COOKIE in response.cookies


def test_admin_releases_a_block_early(db_session: Session) -> None:
    """api-surface.md §2.16 `DELETE /security/blocked-addresses/{id}`:
    "Release a block early, before it lapses on its own." No time
    manipulation here, unlike the lapse test above — the release itself is
    what has to take effect immediately.
    """
    username = "admin-released-early"
    password = "Correct-Passw0rd!"
    make_user(
        db_session,
        username=username,
        role=Role.admin,
        must_change_password=False,
        password_hash=hash_password(password),
    )
    releasing_admin = make_user(
        db_session,
        role=Role.admin,
        must_change_password=False,
        password_hash=hash_password("Releaser-Passw0rd!"),
    )

    with _source_client(db_session, "192.0.2.40") as attacker:
        for _ in range(5):
            _fail_login(attacker, username)

        blocked_row = db_session.execute(
            select(BlockedAddress).where(BlockedAddress.failed_attempts >= 5)
        ).scalar_one()

        with _source_client(db_session, "192.0.2.41") as admin_client:
            _authenticate(admin_client, db_session, releasing_admin)
            release_response = admin_client.delete(
                f"/api/v1/security/blocked-addresses/{blocked_row.id}"
            )
            assert release_response.status_code // 100 == 2

        response = attacker.post(
            "/api/v1/auth/login", json={"username": username, "password": password}
        )
        assert response.status_code == 200
        assert SESSION_COOKIE in response.cookies


def test_established_session_from_a_blocked_source_keeps_working(db_session: Session) -> None:
    """api-surface.md §2.16: "the block gates authentication only —
    established sessions keep working." A session minted on the same
    client that then earns the block must still read `GET /auth/session`
    afterward, from the same now-blocked peer.

    Already green today, like `test_restricted_session_reaches_get_session`
    in `test_restricted_session.py` (Task 3) was before its allowlist
    existed: with no blocking implemented at all yet, nothing can over-block
    established sessions either, so this passes vacuously rather than being
    observably red. Included anyway because it is the negative case that
    binds the block to authentication only — without it, an implementation
    that also refused ordinary requests from a blocked source would pass
    every other test in this file undetected. Bound by mutation once Step 5
    lands: narrowing the block to cover every route, not only login and OTP
    submission, must turn this one red.
    """
    admin = make_user(
        db_session,
        role=Role.admin,
        must_change_password=False,
        password_hash=hash_password("Admin-Passw0rd!"),
    )
    other_username = "admin-being-guessed"
    make_user(
        db_session,
        username=other_username,
        role=Role.admin,
        must_change_password=False,
        password_hash=hash_password("Other-Passw0rd!"),
    )

    with _source_client(db_session, "192.0.2.45") as blocked_source:
        _authenticate(blocked_source, db_session, admin)
        # `GET /auth/csrf` binds to the live session once one exists
        # (Task 3 "session-optional resolver"), which is right for a
        # mutating call on that session but wrong for the public,
        # pre-session `POST /auth/login` calls below — so the session
        # cookie is set aside for the five failed attempts and restored
        # only for the final read, exactly as an attacker's fresh guesses
        # would carry no session cookie of their own.
        session_cookie = blocked_source.cookies.get(SESSION_COOKIE)
        blocked_source.cookies.clear()

        for _ in range(5):
            _fail_login(blocked_source, other_username)

        blocked_source.cookies.set(SESSION_COOKIE, session_cookie)
        response = blocked_source.get("/api/v1/auth/session")
        assert response.status_code == 200
        assert response.json()["user_id"] == str(admin.id)


def test_forged_forwarded_for_neither_evades_nor_plants_a_block(db_session: Session) -> None:
    """ADR-0007 rule 2: "walked from the rightmost... skipping every entry
    that is itself a trusted proxy address; the first entry that is not is
    the client." The socket peer is a configured trusted proxy; each of
    the five attempts prepends a *different* forged address to the left
    (a fresh one per attempt, the exact evasion rule 1 names) while the
    real attacker's address stays rightmost and constant. A test that
    skips `trusted_proxies` proves nothing here (this file's own
    docstring): with none configured the header is ignored outright, so a
    left-to-right implementation would pass too.
    """
    username = "admin-behind-forged-header"
    password = "Correct-Passw0rd!"
    make_user(
        db_session,
        username=username,
        role=Role.admin,
        must_change_password=False,
        password_hash=hash_password(password),
    )
    real_attacker = "198.51.100.7"
    forged_left_values = [
        "10.0.0.1",
        "10.0.0.2",
        "10.0.0.3",
        "10.0.0.4",
        "10.0.0.5",
    ]

    with _source_client(db_session, "192.0.2.1") as proxy_client:
        settings = get_settings().model_copy(update={"trusted_proxies": ["192.0.2.1/32"]})
        app.dependency_overrides[get_settings] = lambda: settings
        try:
            for forged in forged_left_values:
                response = proxy_client.post(
                    "/api/v1/auth/login",
                    json={"username": username, "password": "wrong-password"},
                    headers={"X-Forwarded-For": f"{forged}, {real_attacker}"},
                )
                assert response.status_code == 401

            sixth = proxy_client.post(
                "/api/v1/auth/login",
                json={"username": username, "password": password},
                headers={"X-Forwarded-For": f"9.9.9.9, {real_attacker}"},
            )
            _assert_blocked(sixth)
        finally:
            app.dependency_overrides.pop(get_settings, None)

    # `BlockedAddress.address` reads back as an `ipaddress` object
    # (`IPv4Address`/`IPv6Interface`), not the plain `str` the model
    # annotates — SQLAlchemy's postgresql `INET` type, confirmed here
    # rather than assumed; `str()` gets back to a substring-checkable form.
    blocked_addresses = {
        str(row.address) for row in db_session.execute(select(BlockedAddress)).scalars().all()
    }
    assert not any(forged in addr for addr in blocked_addresses for forged in forged_left_values)
    assert any(real_attacker in addr for addr in blocked_addresses)


def test_ipv6_slash_64_prefix_blocks_together_and_a_different_prefix_is_unaffected(
    db_session: Session,
) -> None:
    """data-model.md §3.3: "a single IPv6 address is not a source... the
    /64 prefix" is what is counted and stored. Five failures from one
    host in `2001:db8:1:2::/64` block a *different* host in the same /64,
    while a host in a different /64 (`2001:db8:1:3::/64`) is unaffected —
    and the stored row carries the prefix itself, not the exact address
    that earned it.
    """
    username = "admin-ipv6-target"
    password = "Correct-Passw0rd!"
    make_user(
        db_session,
        username=username,
        role=Role.admin,
        must_change_password=False,
        password_hash=hash_password(password),
    )

    with _source_client(db_session, "2001:db8:1:2::a") as attacker:
        for _ in range(5):
            _fail_login(attacker, username)

    with _source_client(db_session, "2001:db8:1:2::b") as same_prefix:
        response = same_prefix.post(
            "/api/v1/auth/login", json={"username": username, "password": password}
        )
        _assert_blocked(response)

    with _source_client(db_session, "2001:db8:1:3::a") as different_prefix:
        response = different_prefix.post(
            "/api/v1/auth/login", json={"username": username, "password": password}
        )
        assert response.status_code == 200
        assert SESSION_COOKIE in response.cookies

    stored = db_session.execute(select(BlockedAddress)).scalars().all()
    assert len(stored) == 1
    # `str()` for the same reason as the forged-header test above:
    # `.address` reads back as an `ipaddress.IPv6Interface`, not `str`.
    assert str(stored[0].address) == "2001:db8:1:2::/64"


def test_restricted_session_login_does_not_reset_the_failure_counter(db_session: Session) -> None:
    """data-model.md §3.3: "A login that merely opens a restricted session
    ... does not reset the counter." Three failures, then a restricted
    (captain, first-login-on-username) success, then two more failures —
    five in total — must still block: if the restricted success had reset
    it, only two consecutive failures would stand and the sixth attempt
    below would succeed.
    """
    username = "admin-around-restricted-login"
    password = "Correct-Passw0rd!"
    make_user(
        db_session,
        username=username,
        role=Role.admin,
        must_change_password=False,
        password_hash=hash_password(password),
    )
    run = make_event_run(db_session, status=RunStatus.running)
    captain_username = "captain-first-login-mid-attack"
    captain = make_user(
        db_session,
        username=captain_username,
        role=Role.player,
        must_change_password=True,
        password_hash=hash_password(captain_username),
    )
    team = make_team(db_session, run=run, captain=captain)
    make_participation(db_session, user=captain, run=run, team_id=team.id)

    with _source_client(db_session, "192.0.2.50") as source:
        for _ in range(3):
            _fail_login(source, username)

        restricted_login = source.post(
            "/api/v1/auth/login",
            json={"username": captain_username, "password": captain_username},
        )
        assert restricted_login.status_code == 200
        # The success set a session cookie, which shifts `GET /auth/csrf`
        # from presession- to session-binding (Task 3) — wrong for the
        # public login attempts below. Cleared here for the same reason
        # as the established-session test above.
        source.cookies.clear()

        for _ in range(2):
            _fail_login(source, username)

        sixth = source.post("/api/v1/auth/login", json={"username": username, "password": password})
        _assert_blocked(sixth)


def test_full_login_success_resets_the_failure_counter(db_session: Session) -> None:
    """The positive half of the test above: an *unrestricted* login
    success does reset the counter (data-model.md §3.3 — "reset only by a
    full success"). Three failures, then a correct-password success, then
    four more failures — seven historical failures in total, but only four
    consecutive since the reset — must still let a further correct login
    through.

    Already green today, for the same reason as the established-session
    test above: with no blocking implemented, nothing ever blocks the
    final login regardless of whether a reset would matter. Bound by
    mutation once Step 5 lands: an implementation that counts all seven
    failures instead of resetting at the success would cross five before
    the second login and must turn this one red — verified there, not
    here, since there is nothing yet to mutate.
    """
    username = "admin-full-login-resets"
    password = "Correct-Passw0rd!"
    make_user(
        db_session,
        username=username,
        role=Role.admin,
        must_change_password=False,
        password_hash=hash_password(password),
    )

    with _source_client(db_session, "192.0.2.60") as source:
        for _ in range(3):
            _fail_login(source, username)

        first_success = source.post(
            "/api/v1/auth/login", json={"username": username, "password": password}
        )
        assert first_success.status_code == 200
        # Same reason as the two tests above: clear the session cookie the
        # success just set, so `GET /auth/csrf` binds to a fresh
        # presession cookie again for the public login attempts below.
        source.cookies.clear()

        for _ in range(4):
            _fail_login(source, username)

        second_success = source.post(
            "/api/v1/auth/login", json={"username": username, "password": password}
        )
        assert second_success.status_code == 200
        assert SESSION_COOKIE in second_success.cookies


def test_password_change_resets_the_failure_counter(db_session: Session) -> None:
    """data-model.md §3.3 line 166 / ADR-0007 line 115: both name "a login
    that issues an unrestricted session, **or a completed activation or
    password change**" as the full success that resets the counter —
    deliberately, not an oversight: several players activating in
    sequence on one shared PC (ADR-0007 "Activation is granted per
    request... a group playing together on one shared PC") would
    otherwise accumulate mistyped OTPs with no reset between them, and
    the fifth would block the machine for everyone still to activate.
    Four failures, then a completed change from the same source, then one
    more failure — only one consecutive failure since the reset — must
    still let a further correct login through.
    """
    changer_username = "admin-changes-own-password"
    changer_password = "Changer-Passw0rd!"
    guessed_username = "admin-guessed-around-the-change"
    changer = make_user(
        db_session,
        username=changer_username,
        role=Role.admin,
        must_change_password=False,
        password_hash=hash_password(changer_password),
    )
    make_user(
        db_session,
        username=guessed_username,
        role=Role.admin,
        must_change_password=False,
        password_hash=hash_password("Guessed-Passw0rd!"),
    )

    with _source_client(db_session, "192.0.2.80") as source:
        for _ in range(4):
            _fail_login(source, guessed_username)

        _authenticate(source, db_session, changer)
        change_response = source.post(
            "/api/v1/auth/password",
            json={"old_password": changer_password, "new_password": "New-Passw0rd!"},
        )
        assert change_response.status_code == 200
        # The change set a session cookie, which shifts `GET /auth/csrf`
        # from presession- to session-binding (Task 3) — wrong for the
        # public login attempts below.
        source.cookies.clear()

        after_reset_failure = source.post(
            "/api/v1/auth/login",
            json={"username": guessed_username, "password": "wrong-password"},
        )
        assert after_reset_failure.status_code == 401

        response = source.post(
            "/api/v1/auth/login",
            json={"username": guessed_username, "password": "Guessed-Passw0rd!"},
        )
        assert response.status_code == 200
        assert SESSION_COOKIE in response.cookies
