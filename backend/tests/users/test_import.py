"""M2-Task-Plan.md Task 7: bulk import and single creation of participants
(api-surface.md §2.4, §2.17; data-model.md §3.10). Runs are inserted as
fixtures — the run routes arrive in Task 12.

`services/participants.py` and `api/participants.py` do not exist yet, so
every call below is expected to fail on FastAPI's own routing `404`, not on
`problem_error_handler` — the same collection-level red `test_staff_creation
.py` documented for `POST /users` in Task 6, and `test_mint_handle_...`
below fails to import its module entirely, which is the expected red for a
module that does not exist yet (Working-Agreement "a collection error is
not a red proof" — the exception it names is for code already on disk,
which this is not).

Four things bind by mutation rather than by redness alone once the
implementation lands, named where each test's docstring explains it:
reuse vs. refusal are one code path apart; the handle is run-unique and
grammar-matching; the `created`-only gate needs its negative; a login
lands in a *restricted* session, not merely a `200`. A fifth was added by
review rather than by the task plan: the import is transactional — one
refused row refuses the whole call and writes nothing (api-surface.md
§2.4, the paragraph after the endpoint table).
"""

import re

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.db.models.feedback import AuditLog, AuditScope
from gameframework.db.models.identity import Role, User
from gameframework.db.models.identity import Session as SessionModel
from gameframework.db.models.runs import EventParticipation, RunStatus
from gameframework.services.otp import issue_otp
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


def _run_audit_rows(db_session: Session, run_id: object) -> list[AuditLog]:
    return list(
        db_session.execute(select(AuditLog).where(AuditLog.event_run_id == run_id)).scalars().all()
    )


def test_csv_import_creates_participants_and_audits_in_one_transaction(
    client: TestClient, db_session: Session
) -> None:
    """CSV body (Concept §1: username, name, email — email optional),
    uploaded as `multipart/form-data` (python-multipart). Asserts the
    `audit_log` row, not only the `200` (Task 2's `write_audit`,
    api-surface.md §2.17's ✅ column) — a route that returns `200` without
    writing one would still pass a test that stopped at the status code.
    """
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)
    csv_body = "username,name,email\r\nalice,Alice,alice@example.com\r\nbob,Bob,\r\n"

    response = client.post(
        f"/api/v1/runs/{run.id}/users/import",
        files={"file": ("roster.csv", csv_body, "text/csv")},
    )

    assert response.status_code == 200
    usernames = {row["username"] for row in response.json()["participants"]}
    assert usernames == {"alice", "bob"}

    alice = db_session.execute(select(User).where(User.username == "alice")).scalar_one()
    assert alice.display_name == "Alice"
    assert alice.email == "alice@example.com"
    bob = db_session.execute(select(User).where(User.username == "bob")).scalar_one()
    assert bob.email is None

    participations = (
        db_session.execute(
            select(EventParticipation).where(EventParticipation.event_run_id == run.id)
        )
        .scalars()
        .all()
    )
    assert len(participations) == 2

    audit_rows = _run_audit_rows(db_session, run.id)
    assert len(audit_rows) == 1
    assert audit_rows[0].scope is AuditScope.participant


def test_json_import_creates_participants(client: TestClient, db_session: Session) -> None:
    """The same route, `application/json` instead of a CSV upload — the
    other half of "CSV and JSON bodies import" (Task 7 Step 2)."""
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)

    response = client.post(
        f"/api/v1/runs/{run.id}/users/import",
        json=[{"username": "carol", "name": "Carol", "email": None}],
    )

    assert response.status_code == 200
    body = response.json()
    assert body["participants"][0]["username"] == "carol"
    carol = db_session.execute(select(User).where(User.username == "carol")).scalar_one()
    assert carol.display_name == "Carol"


def test_reusing_an_existing_username_in_a_new_run_keeps_the_previous_participation(
    client: TestClient, db_session: Session
) -> None:
    """api-surface.md §2.4: "an existing username's account is reused" —
    identity is separate from participation (data-model.md §3.10). Importing
    the same username into a *second* run adds a participation there without
    touching the first: asserted by re-fetching the first run's participation
    row by id after the second import, not merely by counting — a
    reuse that silently recreated the row would still show one participation
    per run and pass a count-only assertion. Reuse and "duplicate in the same
    run is refused" (test_duplicate_participation...) are one code path
    apart, so both are covered — a test that only covered one would pass
    against an implementation that always reuses or always refuses.
    """
    _login_as_admin(client, db_session)
    run_a = make_event_run(db_session, status=RunStatus.created)
    run_b = make_event_run(db_session, status=RunStatus.created)

    first = client.post(
        f"/api/v1/runs/{run_a.id}/users/import",
        json=[{"username": "dana", "name": "Dana", "email": None}],
    )
    assert first.status_code == 200
    dana = db_session.execute(select(User).where(User.username == "dana")).scalar_one()
    participation_a = db_session.execute(
        select(EventParticipation).where(
            EventParticipation.user_id == dana.id, EventParticipation.event_run_id == run_a.id
        )
    ).scalar_one()

    second = client.post(
        f"/api/v1/runs/{run_b.id}/users/import",
        json=[{"username": "dana", "name": "Dana", "email": None}],
    )
    assert second.status_code == 200
    assert second.json()["participants"][0]["reused"] is True

    users_named_dana = (
        db_session.execute(select(User).where(User.username == "dana")).scalars().all()
    )
    assert len(users_named_dana) == 1

    still_there = db_session.get(EventParticipation, participation_a.id)
    assert still_there is not None
    assert still_there.event_run_id == run_a.id

    participation_b = db_session.execute(
        select(EventParticipation).where(
            EventParticipation.user_id == dana.id, EventParticipation.event_run_id == run_b.id
        )
    ).scalar_one()
    assert participation_b.id != participation_a.id


def test_single_creation_route_creates_one_participant(
    client: TestClient, db_session: Session
) -> None:
    """The single-account form's own success path (api-surface.md §2.4:
    "the single-account form of the import, for the person added while the
    roster is still in preparation") — found while checking coverage: every
    other test driving `POST /runs/{id}/users` in this file exercises its
    duplicate-refusal branch, none its `200`.
    """
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)

    response = client.post(
        f"/api/v1/runs/{run.id}/users", json={"username": "karl", "name": "Karl", "email": None}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["username"] == "karl"
    assert _HANDLE_RE.fullmatch(body["handle"])

    karl = db_session.execute(select(User).where(User.username == "karl")).scalar_one()
    participation = db_session.execute(
        select(EventParticipation).where(
            EventParticipation.user_id == karl.id, EventParticipation.event_run_id == run.id
        )
    ).scalar_one()
    assert participation.handle == body["handle"]

    audit_rows = _run_audit_rows(db_session, run.id)
    assert len(audit_rows) == 1


def test_duplicate_participation_in_the_same_run_is_refused(
    client: TestClient, db_session: Session
) -> None:
    """The other half of the reuse/refusal pair: the single-account form
    (`POST /runs/{id}/users`), where the whole call is exactly the one row
    under test — unlike the bulk route, there is no "which row" ambiguity
    to add to the response.
    """
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)
    user = make_user(db_session, username="erin")
    make_participation(db_session, user=user, run=run)

    response = client.post(
        f"/api/v1/runs/{run.id}/users", json={"username": "erin", "name": "Erin", "email": None}
    )

    assert response.status_code == 409
    assert response.json()["code"] == "duplicate_participation"


def test_bulk_import_with_one_duplicate_row_writes_nothing(
    client: TestClient, db_session: Session
) -> None:
    """api-surface.md §2.4 (added by review): "a bulk import applies wholly
    or not at all" — one refused row refuses the call and writes nothing,
    named in the report rather than partially applied. Asserts the user and
    participation counts are unchanged, not only the status: a status-only
    assertion passes just as well against an implementation that writes the
    valid row and reports the refused one.

    Bound by mutation: an implementation that applies "grace" (the valid
    row) and reports "frank" (the duplicate) as refused reddens this test on
    the count assertions even though it would answer the same `409` — that
    is the implementation Daniel's review named directly, and this is what
    catches it.
    """
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)
    existing = make_user(db_session, username="frank")
    make_participation(db_session, user=existing, run=run)

    users_before = db_session.execute(select(User)).scalars().all()
    participations_before = (
        db_session.execute(
            select(EventParticipation).where(EventParticipation.event_run_id == run.id)
        )
        .scalars()
        .all()
    )

    response = client.post(
        f"/api/v1/runs/{run.id}/users/import",
        json=[
            {"username": "grace", "name": "Grace", "email": None},
            {"username": "frank", "name": "Frank", "email": None},
        ],
    )

    assert response.status_code == 409
    body = response.json()
    assert body["code"] == "duplicate_participation"
    assert body["username"] == "frank"

    users_after = db_session.execute(select(User)).scalars().all()
    assert len(users_after) == len(users_before)
    assert (
        db_session.execute(select(User).where(User.username == "grace")).scalar_one_or_none()
        is None
    )

    participations_after = (
        db_session.execute(
            select(EventParticipation).where(EventParticipation.event_run_id == run.id)
        )
        .scalars()
        .all()
    )
    assert len(participations_after) == len(participations_before)

    assert _run_audit_rows(db_session, run.id) == []


def test_import_is_refused_once_the_run_has_left_created(
    client: TestClient, db_session: Session
) -> None:
    """The `created`-only gate's negative case (Working-Agreement: "any
    conditional rule needs its negative case"). The positive case is proven
    by every other test in this file, all of which import into a `created`
    run and succeed.
    """
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.running)

    response = client.post(
        f"/api/v1/runs/{run.id}/users/import",
        json=[{"username": "henry", "name": "Henry", "email": None}],
    )

    assert response.status_code == 409
    assert response.json()["code"] == "roster_frozen"
    assert (
        db_session.execute(select(User).where(User.username == "henry")).scalar_one_or_none()
        is None
    )


def test_a_second_import_into_the_same_run_does_not_collide_with_the_first(
    client: TestClient, db_session: Session
) -> None:
    """data-model.md §3.10: run-unique, not merely unique within one call.
    `test_handles_from_one_import_are_distinct_and_match_the_grammar` below
    checks distinctness within one import; `test_mint_handle_retries_on_a_
    collision_within_one_run` checks `mint_handle` against an `existing` set
    handed to it directly. Neither imports twice into the same run, which is
    what "run-unique" actually promises against a `mint_handle` seeded from
    the current call's rows rather than from the run's whole roster.
    """
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)

    first = client.post(
        f"/api/v1/runs/{run.id}/users/import",
        json=[
            {"username": "mia", "name": "Mia", "email": None},
            {"username": "noah", "name": "Noah", "email": None},
        ],
    )
    assert first.status_code == 200
    second = client.post(
        f"/api/v1/runs/{run.id}/users/import",
        json=[
            {"username": "olive", "name": "Olive", "email": None},
            {"username": "paul", "name": "Paul", "email": None},
        ],
    )
    assert second.status_code == 200

    handles = [row["handle"] for row in first.json()["participants"]] + [
        row["handle"] for row in second.json()["participants"]
    ]
    assert len(set(handles)) == 4


def test_handles_from_one_import_are_distinct_and_match_the_grammar(
    client: TestClient, db_session: Session
) -> None:
    """data-model.md §3.10: `^[a-z][a-z0-9-]{1,27}$`. A test asserting only
    "not null" passes against a counter that repeats across runs — this
    asserts the grammar on every handle from one call and that the two
    differ. The collision-retry itself (two mints that would otherwise
    produce the same value) is proven directly against `mint_handle` below,
    where the randomness is controlled — forcing an actual collision through
    HTTP would mean enumerating the suffix space.
    """
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)

    response = client.post(
        f"/api/v1/runs/{run.id}/users/import",
        json=[
            {"username": "iris", "name": "Iris", "email": None},
            {"username": "ivy", "name": "Ivy", "email": None},
        ],
    )

    assert response.status_code == 200
    handles = [row["handle"] for row in response.json()["participants"]]
    assert len(set(handles)) == 2
    for handle in handles:
        assert _HANDLE_RE.fullmatch(handle)


# test_mint_handle_retries_on_a_collision_within_one_run moved to
# tests/teams/test_atomic_creation.py (Task 8 Step 4): `mint_handle` now
# lives in services/teams.py, which services/participants.py imports
# rather than defines.


def test_imported_participant_authenticates_into_a_restricted_session(
    client: TestClient, db_session: Session
) -> None:
    """ADR-0007 / api-surface.md §2.4: "each imported account's initial
    password is its own username, with the forced change at first login" —
    wiring Task 3's flow to real imported data. Asserted on the `Session`
    row's `restricted` column directly, not merely on the login's `200`: a
    full, unrestricted session would satisfy a status-only assertion just as
    well.

    Imports only into a `created` run (the roster-freeze gate), but a
    participant's login is itself refused while the run is still `created`
    (api-surface.md §2.2, `run_not_started`) — so the run is moved to
    `running` directly on the fixture after the import, standing in for
    Task 12's `start` transition, which does not exist yet. And a plain
    player — Task 7 forms no team, so nobody imported here is a captain —
    is refused login outright with no OTP outstanding (Task 4,
    `activation_required`); this is Task 4's already-correct gate, not
    something Task 7 changes, so the test issues one directly via Task 4's
    own `issue_otp` rather than through a route this task does not own.
    """
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)

    import_response = client.post(
        f"/api/v1/runs/{run.id}/users/import",
        json=[{"username": "jill", "name": "Jill", "email": None}],
    )
    assert import_response.status_code == 200

    jill = db_session.execute(select(User).where(User.username == "jill")).scalar_one()
    run.status = RunStatus.running
    issue_otp(db_session, jill, run)

    client.cookies.clear()
    login_response = client.post(
        "/api/v1/auth/login", json={"username": "jill", "password": "jill"}
    )
    assert login_response.status_code == 200

    session_row = db_session.execute(
        select(SessionModel).where(SessionModel.user_id == jill.id)
    ).scalar_one()
    assert session_row.restricted is True


def test_reusing_an_existing_username_that_differs_only_in_case(
    client: TestClient, db_session: Session
) -> None:
    """The seam between normalization and reuse: the reuse lookup itself has
    to compare normalized values, not raw ones, or a roster row whose case
    differs from how the account was first created — the likeliest real
    case, since a directory export rarely matches the case an account was
    made in — creates a second account instead of reusing the first.
    Neither `test_username_normalization.py` (which never imports) nor
    `test_reusing_an_existing_username_in_a_new_run_...` above (which never
    varies case) reaches this.
    """
    _login_as_admin(client, db_session)
    run_a = make_event_run(db_session, status=RunStatus.created)
    run_b = make_event_run(db_session, status=RunStatus.created)

    first = client.post(
        f"/api/v1/runs/{run_a.id}/users/import",
        json=[{"username": "Karl", "name": "Karl", "email": None}],
    )
    assert first.status_code == 200
    karl = db_session.execute(select(User).where(User.username == "karl")).scalar_one()

    second = client.post(
        f"/api/v1/runs/{run_b.id}/users/import",
        json=[{"username": "KARL", "name": "Karl", "email": None}],
    )
    assert second.status_code == 200
    assert second.json()["participants"][0]["reused"] is True

    users_named_karl = (
        db_session.execute(select(User).where(User.username == "karl")).scalars().all()
    )
    assert len(users_named_karl) == 1

    participation_b = db_session.execute(
        select(EventParticipation).where(EventParticipation.event_run_id == run_b.id)
    ).scalar_one()
    assert participation_b.user_id == karl.id


def test_duplicate_participation_detection_is_case_insensitive(
    client: TestClient, db_session: Session
) -> None:
    """The same normalize-before-compare seam as reuse above governs the
    duplicate check too: a row differing only in case from an account that
    already holds a participation in this run is `duplicate_participation`,
    not a second participant. Not already implied by
    `test_duplicate_participation_in_the_same_run_is_refused` — that test's
    row and the existing account match in raw case, so it cannot tell a
    normalized comparison from a raw one; this one can, because "louis" and
    "LOUIS" are equal only after normalization.
    """
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.created)
    user = make_user(db_session, username="louis")
    make_participation(db_session, user=user, run=run)

    response = client.post(
        f"/api/v1/runs/{run.id}/users", json={"username": "LOUIS", "name": "Louis", "email": None}
    )

    assert response.status_code == 409
    assert response.json()["code"] == "duplicate_participation"
