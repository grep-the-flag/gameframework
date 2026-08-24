"""M2-Task-Plan.md Task 14 Step 2: `pause`/`resume`/`finish` on
`POST /runs/{id}/transition` (api-surface.md §2.6, §1; data-model.md §3.9,
§2.17).

`start`'s admin-only 403 is already proven in
`tests/runs/test_start.py::test_gameadmin_start_is_403` and is not
duplicated here — this file's role-split coverage is for the three
transitions this task adds.
"""

import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.db.models.feedback import AuditLog
from gameframework.db.models.identity import Role, User
from gameframework.db.models.runs import EventRun, RunStatus
from gameframework.services.passwords import hash_password

from ..conftest import make_event_run, make_user

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


def _login_as_gameadmin(client: TestClient, db_session: Session) -> User:
    gameadmin = make_user(
        db_session,
        role=Role.gameadmin,
        must_change_password=False,
        password_hash=hash_password(ADMIN_PASSWORD),
    )
    response = client.post(
        "/api/v1/auth/login", json={"username": gameadmin.username, "password": ADMIN_PASSWORD}
    )
    assert response.status_code == 200
    return gameadmin


def _transition(client: TestClient, run_id: uuid.UUID, action: str) -> httpx.Response:
    return client.post(f"/api/v1/runs/{run_id}/transition", json={"action": action})


def _audit_rows(db_session: Session, run_id: uuid.UUID, action: str) -> list[AuditLog]:
    return list(
        db_session.execute(
            select(AuditLog).where(AuditLog.target_id == run_id, AuditLog.action == action)
        )
        .scalars()
        .all()
    )


# ---------------------------------------------------------------------------
# legal state machine, and only it
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "status",
    [RunStatus.created, RunStatus.paused, RunStatus.finished, RunStatus.destroyed],
)
def test_pause_refused_outside_running(
    client: TestClient, db_session: Session, status: RunStatus
) -> None:
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=status)

    response = _transition(client, run.id, "pause")

    assert response.status_code == 409
    assert response.json()["code"] == "invalid_status_transition"


@pytest.mark.parametrize(
    "status",
    [RunStatus.created, RunStatus.running, RunStatus.finished, RunStatus.destroyed],
)
def test_resume_refused_outside_paused(
    client: TestClient, db_session: Session, status: RunStatus
) -> None:
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=status)

    response = _transition(client, run.id, "resume")

    assert response.status_code == 409
    assert response.json()["code"] == "invalid_status_transition"


@pytest.mark.parametrize("status", [RunStatus.created, RunStatus.finished, RunStatus.destroyed])
def test_finish_refused_outside_running_or_paused(
    client: TestClient, db_session: Session, status: RunStatus
) -> None:
    _login_as_admin(client, db_session)
    run = make_event_run(db_session, status=status)

    response = _transition(client, run.id, "finish")

    assert response.status_code == 409
    assert response.json()["code"] == "invalid_status_transition"


def test_pause_accepted_from_running(client: TestClient, db_session: Session) -> None:
    gameadmin = _login_as_gameadmin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.running)

    response = _transition(client, run.id, "pause")

    assert response.status_code == 200, response.text
    db_run = db_session.get(EventRun, run.id)
    assert db_run is not None
    assert db_run.status == RunStatus.paused
    assert db_run.paused_at is not None

    rows = _audit_rows(db_session, run.id, "event_run_paused")
    assert len(rows) == 1
    assert rows[0].actor_user_id == gameadmin.id


def test_resume_accepted_from_paused(client: TestClient, db_session: Session) -> None:
    gameadmin = _login_as_gameadmin(client, db_session)
    paused_at = datetime.now(UTC) - timedelta(minutes=5)
    run = make_event_run(db_session, status=RunStatus.paused, paused_at=paused_at)

    response = _transition(client, run.id, "resume")

    assert response.status_code == 200, response.text
    db_run = db_session.get(EventRun, run.id)
    assert db_run is not None
    assert db_run.status == RunStatus.running
    assert db_run.paused_at is None

    rows = _audit_rows(db_session, run.id, "event_run_resumed")
    assert len(rows) == 1
    assert rows[0].actor_user_id == gameadmin.id


def test_resume_pushes_scheduled_end_back_by_paused_duration(
    client: TestClient, db_session: Session
) -> None:
    """data-model.md §3.9 defines `paused_at` literally as "the moment
    `scheduled_end` is pushed back by" — pure arithmetic, independent of
    the M3 scheduled job that later acts on `scheduled_end` (a resumed run
    that still ends at its original time is wrong the moment anyone reads
    it, not only once a scheduler runs). The implementation's own `now` is
    not observable from the test, so it is bracketed between two Python
    timestamps taken immediately before and after the request — a tight
    window, not a loose tolerance, because `paused_at` is a known, Python-
    set value and the push-back must fall within `[before, after]` minus
    it.
    """
    _login_as_gameadmin(client, db_session)
    paused_at = datetime.now(UTC) - timedelta(minutes=47)
    original_scheduled_end = datetime.now(UTC) + timedelta(hours=2)
    run = make_event_run(
        db_session,
        status=RunStatus.paused,
        paused_at=paused_at,
        scheduled_end=original_scheduled_end,
    )

    before = datetime.now(UTC)
    response = _transition(client, run.id, "resume")
    after = datetime.now(UTC)

    assert response.status_code == 200, response.text
    db_run = db_session.get(EventRun, run.id)
    assert db_run is not None
    assert db_run.scheduled_end is not None
    assert original_scheduled_end + (before - paused_at) <= db_run.scheduled_end
    assert db_run.scheduled_end <= original_scheduled_end + (after - paused_at)


def test_resume_leaves_null_scheduled_end_untouched(
    client: TestClient, db_session: Session
) -> None:
    """The null case: a run with no `scheduled_end` has nothing to push
    back, and `resume` must not invent one."""
    _login_as_gameadmin(client, db_session)
    paused_at = datetime.now(UTC) - timedelta(minutes=5)
    run = make_event_run(
        db_session, status=RunStatus.paused, paused_at=paused_at, scheduled_end=None
    )

    response = _transition(client, run.id, "resume")

    assert response.status_code == 200, response.text
    db_run = db_session.get(EventRun, run.id)
    assert db_run is not None
    assert db_run.scheduled_end is None


def test_finish_accepted_from_running(client: TestClient, db_session: Session) -> None:
    gameadmin = _login_as_gameadmin(client, db_session)
    run = make_event_run(db_session, status=RunStatus.running)

    response = _transition(client, run.id, "finish")

    assert response.status_code == 200, response.text
    db_run = db_session.get(EventRun, run.id)
    assert db_run is not None
    assert db_run.status == RunStatus.finished

    rows = _audit_rows(db_session, run.id, "event_run_finished")
    assert len(rows) == 1
    assert rows[0].actor_user_id == gameadmin.id


# ---------------------------------------------------------------------------
# paused_at: null whenever status != paused, bound on every transition that
# leaves `paused` — not only `resume` (data-model.md §3.9)
# ---------------------------------------------------------------------------


def test_finish_from_paused_clears_paused_at_and_derives_grace_columns(
    client: TestClient, db_session: Session
) -> None:
    """An implementation that only clears `paused_at` inside `resume_run`
    passes every test that only tries `resume` — this is the case that
    catches it: `finish` reached directly from `paused`, never passing
    through `running` first.

    Also binds `finished_at`/`grace_deadline_at`/`hard_deadline_at`'s
    derivation (§3.9) against the run's own snapshotted
    `grace_period_days` (11, a value distinctive enough that a wrong
    constant cannot coincidentally satisfy the assertion), and ADR-0019's
    fixed 30-day maximum-retention extension — not a setting, so the test
    hardcodes it too.
    """
    admin = _login_as_admin(client, db_session)
    paused_at = datetime.now(UTC) - timedelta(minutes=5)
    run = make_event_run(
        db_session, status=RunStatus.paused, paused_at=paused_at, grace_period_days=11
    )

    response = _transition(client, run.id, "finish")

    assert response.status_code == 200, response.text
    db_run = db_session.get(EventRun, run.id)
    assert db_run is not None
    assert db_run.status == RunStatus.finished
    assert db_run.paused_at is None
    assert db_run.finished_at is not None
    assert db_run.grace_deadline_at == db_run.finished_at + timedelta(days=11)
    assert db_run.grace_deadline_at is not None
    assert db_run.hard_deadline_at == db_run.grace_deadline_at + timedelta(days=30)

    rows = _audit_rows(db_session, run.id, "event_run_finished")
    assert len(rows) == 1
    assert rows[0].actor_user_id == admin.id


# ---------------------------------------------------------------------------
# 404 on an unknown run — the same non-disclosure convention every other
# run route uses (already proven generically in test_start.py; one case
# here for completeness of this file's own routes)
# ---------------------------------------------------------------------------


def test_pause_on_unknown_run_is_404(client: TestClient, db_session: Session) -> None:
    _login_as_admin(client, db_session)

    response = _transition(client, uuid.uuid4(), "pause")

    assert response.status_code == 404
    assert response.json()["code"] == "object_not_found"
