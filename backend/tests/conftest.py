"""Shared test fixtures — the only test-isolation mechanism for this milestone
(M2 Task 1a; see AGENTS.md and M2-Task-Plan.md Task 1a). Every later task's
suite uses these rather than building its own session, client or database.

The data factories below live here for the same reason: Tasks 3 through 19
all need minimal valid rows to build fixtures on top of, and a test module
importing helpers from another test module (rather than from conftest.py)
would let an unrelated suite's change break this one. One mechanism, one
place.

Not used by tests/db/test_migrations.py: `alembic upgrade head`/`downgrade
base` are DDL over a whole database and cannot run inside a wrapping
transaction, so that suite gets a database of its own per test, independently
of the template database built here.
"""

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import Connection, create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.orm import Session

from gameframework.config import get_settings
from gameframework.db.models.authoring import (
    Challenge,
    DefinitionStatus,
    EventDefinition,
    RewardDefinition,
    RewardType,
    ScoringMode,
    UnlockMode,
)
from gameframework.db.models.identity import BlockedAddress, Role, User
from gameframework.db.models.infrastructure import ArtifactType, InstalledArtifact, Job, JobState
from gameframework.db.models.runs import EventParticipation, EventRun, ExportState, RunStatus, Team
from gameframework.db.models.runtime import (
    InstanceHealth,
    MinigameInstance,
    MinigamePort,
    PortSource,
    SolveMode,
)
from gameframework.db.session import get_session
from gameframework.main import app

BACKEND_DIR = Path(__file__).resolve().parents[1]
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"


def _alembic_config(url: URL) -> Config:
    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("sqlalchemy.url", url.render_as_string(hide_password=False))
    return cfg


def _terminate_backends(admin_connection: Connection, db_name: str) -> None:
    """Postgres refuses CREATE/DROP DATABASE while another session holds a
    connection to it. Every fixture here closes its own connections at
    teardown, but this is cheap insurance against a leaked one (a stray
    manual psql session, a not-yet-garbage-collected engine) rather than
    something the normal flow relies on — the same defensive call
    tests/db/test_migrations.py already makes before its own DROP DATABASE.
    """
    admin_connection.execute(
        text(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            "WHERE datname = :db AND pid <> pg_backend_pid()"
        ),
        {"db": db_name},
    )


@pytest.fixture(scope="session")
def template_db_url() -> Iterator[URL]:
    """A database migrated to head exactly once for the whole test session.
    `db_session` opens its own connection to it per test; `fresh_install_db`
    clones it wholesale via CREATE DATABASE ... TEMPLATE. Session-scoped
    because migrating it is the expensive part and nothing here mutates it
    afterwards — every consumer either wraps a rolled-back transaction
    around its own connection or clones the whole database instead of
    writing to this one directly.
    """
    base_url = make_url(get_settings().database_url)
    db_name = f"test_template_{uuid.uuid4().hex}"
    admin_engine = create_engine(base_url, isolation_level="AUTOCOMMIT")
    try:
        with admin_engine.connect() as conn:
            conn.execute(text(f'CREATE DATABASE "{db_name}"'))
        template_url = base_url.set(database=db_name)
        command.upgrade(_alembic_config(template_url), "head")
        yield template_url
    finally:
        with admin_engine.connect() as conn:
            _terminate_backends(conn, db_name)
            conn.execute(text(f'DROP DATABASE IF EXISTS "{db_name}"'))
        admin_engine.dispose()


@pytest.fixture()
def db_session(template_db_url: URL) -> Iterator[Session]:
    """One connection per test, wrapped in an outer transaction that is
    always rolled back at teardown — nothing a test does here is ever visible
    to another test or another connection.

    The session joins that transaction with `join_transaction_mode=
    "create_savepoint"`: SQLAlchemy issues a SAVEPOINT under the outer
    transaction and re-issues a fresh one on the next statement after a
    rollback, rather than leaving the connection's transaction aborted the
    way a bare `IntegrityError` would. This is the mechanism the constraint
    suite (Task 1a Step 3) exists to exercise: every test there triggers an
    `IntegrityError`, calls `.rollback()`, and keeps going in the same test
    on the same connection. Verified directly against Postgres before
    relying on it — see the Step 2 report.
    """
    engine = create_engine(template_db_url)
    try:
        connection = engine.connect()
        outer_transaction = connection.begin()
        session = Session(bind=connection, join_transaction_mode="create_savepoint")
        try:
            yield session
        finally:
            session.close()
            outer_transaction.rollback()
            connection.close()
    finally:
        engine.dispose()


@pytest.fixture()
def fresh_install_db(template_db_url: URL) -> Iterator[Session]:
    """A brand-new database cloned from the migrated template, wholly its
    own — not wrapped in a rollback transaction like `db_session`. Bootstrap
    tests (Task 5) need this because "a fresh installation has exactly one
    admin" and "two fresh installs differ" describe a database nothing else
    has ever written to, which a shared schema rolled back per test cannot
    express. Cloning (CREATE DATABASE ... TEMPLATE) copies the whole
    migrated database at the filesystem level, so nothing here re-runs
    Alembic. Paid for only by the tests that ask for it.
    """
    base_url = make_url(get_settings().database_url)
    db_name = f"test_fresh_{uuid.uuid4().hex}"
    admin_engine = create_engine(base_url, isolation_level="AUTOCOMMIT")
    try:
        with admin_engine.connect() as conn:
            # Postgres refuses to clone a template that has other sessions
            # connected to it — belt-and-suspenders alongside db_session's
            # own per-test engine disposal (see the Step 2 report for the
            # verification against a deliberately-held-open connection).
            _terminate_backends(conn, template_db_url.database or "")
            conn.execute(text(f'CREATE DATABASE "{db_name}" TEMPLATE "{template_db_url.database}"'))
        fresh_url = base_url.set(database=db_name)
        fresh_engine = create_engine(fresh_url)
        try:
            with Session(fresh_engine) as session:
                yield session
        finally:
            fresh_engine.dispose()
    finally:
        with admin_engine.connect() as conn:
            _terminate_backends(conn, db_name)
            conn.execute(text(f'DROP DATABASE IF EXISTS "{db_name}"'))
        admin_engine.dispose()


class _CsrfInjectingTestClient(TestClient):
    """`client`'s own class (M2-Task-Plan.md Task 3 Step 6): every
    mutating request gets a live `X-CSRF-Token` for free, fetched from
    `GET /auth/csrf` on this same client — sharing its cookie jar, so the
    token binds to whatever `sid` or pre-session cookie the jar already
    holds — unless the caller already set the header. The fix belongs
    here, in the fixture, rather than at each of the login matrix's and
    the lifecycle suite's own call sites: a helper each author has to
    remember to call would let a forgotten one read as a bug in the
    route instead of a missing test-fixture call.
    """

    _MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

    def request(self, method: str, url: Any, **kwargs: Any) -> Any:
        if method.upper() in self._MUTATING_METHODS:
            headers = httpx.Headers(kwargs.get("headers"))
            if "x-csrf-token" not in headers:
                token_response = self.get("/api/v1/auth/csrf")
                if token_response.status_code != 200:
                    raise AssertionError(
                        "client fixture: GET /auth/csrf returned "
                        f"{token_response.status_code}, expected 200 — "
                        f"body: {token_response.text}"
                    )
                token = token_response.json()["csrf_token"]
                headers["X-CSRF-Token"] = token
                kwargs["headers"] = headers
        return super().request(method, url, **kwargs)


def _test_client(db_session: Session, client_cls: type[TestClient]) -> Iterator[TestClient]:
    """The HTTPS API client every route test drives, at
    `https://app.event.example.com` — matching ADR-0007's domain-wide cookie
    (`Domain=.event.example.com`) and the `__Host-`-prefixed pre-session
    cookie, neither of which a compliant client stores over plain
    `http://testserver`. Runs the ASGI lifespan (`with TestClient(...) as
    ...`) so Task 3/5's startup hooks (signing key, initial admin) run per
    test once they exist.

    `app.dependency_overrides[get_session]` is bound to this fixture's own
    `db_session`, not a new one, so a route's writes and the test's own
    assertions read one transaction. Task 1a ships no route to prove that
    with; verified instead with a temporary diagnostic route added directly
    to `app` — see the Step 2 report for the method and result.
    """

    def override_get_session() -> Iterator[Session]:
        yield db_session

    app.dependency_overrides[get_session] = override_get_session
    try:
        with client_cls(app, base_url="https://app.event.example.com") as test_client:
            yield test_client
    finally:
        app.dependency_overrides.pop(get_session, None)


@pytest.fixture()
def raw_client(db_session: Session) -> Iterator[TestClient]:
    """The plain client, with no CSRF injection — what `test_csrf.py` and
    `test_restricted_session.py` drive instead of `client`: every test in
    those two files asserts something about a token being absent, wrong
    or hand-minted, so an injecting client would destroy every one of
    them (Task 3 Step 6).

    Raw duplicate cookies (Task 3's duplicate-session-cookie rejection):
    pass `headers={"Cookie": "a=1; a=2"}` on that one call. httpx never
    overwrites an explicit `Cookie` header with the jar's — but the
    suppression is total, not per-name: `http.cookiejar.CookieJar.
    add_cookie_header` only contributes a `Cookie` header when the request
    doesn't already carry one, so a request with an explicit header gets
    *none* of the jar's cookies, not just a deduplicated version of it. A
    raw-header call must therefore spell out every cookie the route needs —
    session cookie(s) *and* CSRF — or it fails for a reason that has nothing
    to do with the thing under test (a missing CSRF cookie reads as a CSRF
    bug, not the duplicate-cookie behaviour being exercised). Every other
    test uses `client.cookies`, the normal jar, which does not have this
    problem because it never sets a literal header itself.
    """
    yield from _test_client(db_session, TestClient)


@pytest.fixture()
def client(db_session: Session) -> Iterator[TestClient]:
    """The injecting client (`_CsrfInjectingTestClient` above) every
    non-CSRF-specific route test drives: a mutating call gets a live
    token for free, so the login matrix and the session-lifecycle suite
    need not fetch or attach one themselves.
    """
    yield from _test_client(db_session, _CsrfInjectingTestClient)


# --------------------------------------------------------------------------
# data factories — minimal valid rows, every NOT NULL column filled; callers
# override only the column(s) they care about. Every factory commits (not
# just flushes): a durable checkpoint, so a later rollback for an expected
# violation elsewhere in the same test can't also undo a prerequisite row —
# see the Step 3 report for the empirical case that motivated this.
# --------------------------------------------------------------------------


def make_user(db_session: Session, **overrides: object) -> User:
    defaults: dict[str, Any] = dict(
        username=f"user-{uuid.uuid4().hex}",
        password_hash="hash",
        role=Role.player,
        is_active=True,
        must_change_password=False,
        preferred_language="en",
    )
    defaults.update(overrides)
    user = User(**defaults)  # type: ignore[arg-type]
    db_session.add(user)
    db_session.commit()
    return user


def make_event_definition(db_session: Session, **overrides: object) -> EventDefinition:
    defaults: dict[str, Any] = dict(
        slug="demo",
        source_version="1.0.0",
        name={"en": "Demo"},
        story={"en": "Story"},
        status=DefinitionStatus.draft,
        revision=1,
        unlock_mode=UnlockMode.manual,
        scoring_mode=ScoringMode.casual,
        language_default="en",
        contract_version="1.0",
        gamemaster_enabled=False,
        privacy_notice_md="notice",
    )
    defaults.update(overrides)
    definition = EventDefinition(**defaults)  # type: ignore[arg-type]
    db_session.add(definition)
    db_session.commit()
    return definition


def make_challenge(
    db_session: Session, definition: EventDefinition | None = None, **overrides: object
) -> Challenge:
    definition = definition or make_event_definition(db_session)
    defaults: dict[str, Any] = dict(
        event_definition_id=definition.id,
        slug=f"chal-{uuid.uuid4().hex[:8]}",
        order_num=1,
        title={"en": "Title"},
        text={"en": "Text"},
        minigame_id="demo-minigame",
        minigame_version_range=">=1.0.0",
        minigame_version="1.0.0",
        minigame_image_digest="sha256:" + "0" * 64,
        minigame_host_label=f"host-{uuid.uuid4().hex[:8]}",
        points=10,
        hint_cost=1,
    )
    defaults.update(overrides)
    challenge = Challenge(**defaults)  # type: ignore[arg-type]
    db_session.add(challenge)
    db_session.commit()
    return challenge


def make_event_run(
    db_session: Session, definition: EventDefinition | None = None, **overrides: object
) -> EventRun:
    definition = definition or make_event_definition(db_session)
    defaults: dict[str, Any] = dict(
        event_definition_id=definition.id,
        definition_revision=1,
        status=RunStatus.created,
        unlock_mode=UnlockMode.manual,
        scoring_mode=ScoringMode.casual,
        participation_mode="teams",
        gamemaster_enabled=False,
        language_default="en",
        grace_period_days=7,
        export_state=ExportState.pending,
    )
    defaults.update(overrides)
    run = EventRun(**defaults)  # type: ignore[arg-type]
    db_session.add(run)
    db_session.commit()
    return run


def make_team(db_session: Session, run: EventRun | None = None, **overrides: object) -> Team:
    run = run or make_event_run(db_session)
    captain = overrides.pop("captain", None) or make_user(db_session)
    defaults: dict[str, Any] = dict(
        event_run_id=run.id,
        name="Team",
        handle=f"team-{uuid.uuid4().hex[:8]}",
        captain_user_id=captain.id,  # type: ignore[union-attr]
    )
    defaults.update(overrides)
    team = Team(**defaults)  # type: ignore[arg-type]
    db_session.add(team)
    db_session.commit()
    return team


def make_participation(
    db_session: Session, user: User | None = None, run: EventRun | None = None, **overrides: object
) -> EventParticipation:
    user = user or make_user(db_session)
    run = run or make_event_run(db_session)
    defaults: dict[str, Any] = dict(
        user_id=user.id,
        event_run_id=run.id,
        handle=f"p-{uuid.uuid4().hex[:8]}",
    )
    defaults.update(overrides)
    participation = EventParticipation(**defaults)  # type: ignore[arg-type]
    db_session.add(participation)
    db_session.commit()
    return participation


def make_minigame_instance(
    db_session: Session, run: EventRun | None = None, **overrides: object
) -> MinigameInstance:
    run = run or make_event_run(db_session)
    defaults: dict[str, Any] = dict(
        event_run_id=run.id,
        minigame_id=f"minigame-{uuid.uuid4().hex[:8]}",
        solve_mode=SolveMode.flag,
        image_ref="registry/demo:1.0.0",
        image_digest="sha256:" + "1" * 64,
        health=InstanceHealth.unknown,
    )
    defaults.update(overrides)
    instance = MinigameInstance(**defaults)  # type: ignore[arg-type]
    db_session.add(instance)
    db_session.commit()
    return instance


def make_minigame_port(
    db_session: Session, instance: MinigameInstance, **overrides: object
) -> MinigamePort:
    defaults: dict[str, Any] = dict(
        minigame_instance_id=instance.id,
        container_port=22,
        host_port=9000,
        source=PortSource.allocated,
    )
    defaults.update(overrides)
    port = MinigamePort(**defaults)  # type: ignore[arg-type]
    db_session.add(port)
    db_session.commit()
    return port


def make_reward_definition(
    db_session: Session, challenge: Challenge | None = None, **overrides: object
) -> RewardDefinition:
    challenge = challenge or make_challenge(db_session)
    defaults: dict[str, Any] = dict(
        producer_challenge_id=challenge.id,
        name="Reward",
        type=RewardType.token,
    )
    defaults.update(overrides)
    reward = RewardDefinition(**defaults)  # type: ignore[arg-type]
    db_session.add(reward)
    db_session.commit()
    return reward


def make_installed_artifact(db_session: Session, **overrides: object) -> InstalledArtifact:
    defaults: dict[str, Any] = dict(
        type=ArtifactType.minigame,
        artifact_id=f"artifact-{uuid.uuid4().hex[:8]}",
        version="1.0.0",
        manifest={},
        verified=False,
    )
    defaults.update(overrides)
    artifact = InstalledArtifact(**defaults)  # type: ignore[arg-type]
    db_session.add(artifact)
    db_session.commit()
    return artifact


def make_job(db_session: Session, **overrides: object) -> Job:
    defaults: dict[str, Any] = dict(
        job_type="provision",
        business_key=f"key-{uuid.uuid4().hex[:8]}",
        payload={},
        state=JobState.pending,
        next_attempt_at=datetime.now(UTC),
    )
    defaults.update(overrides)
    job = Job(**defaults)  # type: ignore[arg-type]
    db_session.add(job)
    db_session.commit()
    return job


def make_blocked_address(db_session: Session, **overrides: object) -> BlockedAddress:
    defaults: dict[str, Any] = dict(
        address=f"10.0.{uuid.uuid4().int % 256}.{uuid.uuid4().int % 256}/32",
        last_attempt_at=datetime.now(UTC),
    )
    defaults.update(overrides)
    blocked = BlockedAddress(**defaults)  # type: ignore[arg-type]
    db_session.add(blocked)
    db_session.commit()
    return blocked
