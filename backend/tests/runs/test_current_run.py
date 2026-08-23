"""M2-Task-Plan.md Task 12 Step 2: api-surface.md §2.6's "current run"
resolution — both readers. `resolve_current_run` is exercised directly
against the service (services/runs.py); the staff branch's wiring through
`GET /event` is proven separately in test_run_creation.py's
definition_revision test, and its user-less variant (`GET
/privacy-notice`, public) is proven here through the route.
"""

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from gameframework.db.models.authoring import DefinitionStatus
from gameframework.db.models.identity import Role
from gameframework.db.models.runs import RunStatus
from gameframework.services.runs import resolve_current_run

from ..conftest import make_event_definition, make_event_run, make_participation, make_user

# `event_participation.created_at` is `server_default=func.now()`, and
# Postgres's `now()` is frozen for the lifetime of a transaction — the
# whole test runs inside one (db_session's outer transaction plus
# savepoints), so two factory calls in the same test would otherwise get
# the *identical* timestamp and "most recent" would be an unspecified tie-
# break rather than the thing under test. Explicit, Python-computed
# timestamps make the ordering a fact rather than a coincidence of
# insertion order.
_EARLIER = datetime.now(UTC) - timedelta(hours=1)
_LATER = datetime.now(UTC)

# ---------------------------------------------------------------------------
# staff resolution
# ---------------------------------------------------------------------------


def test_staff_resolution_prefers_active_run_over_most_recent_created(db_session: Session) -> None:
    admin = make_user(db_session, role=Role.admin)
    make_event_run(db_session, status=RunStatus.created)  # older, not active
    active = make_event_run(db_session, status=RunStatus.running)
    make_event_run(db_session, status=RunStatus.created)  # newer than `active`, but not active

    result = resolve_current_run(db_session, admin)

    assert result is not None
    assert result.id == active.id


def test_staff_resolution_falls_back_to_most_recently_created_non_destroyed_run(
    db_session: Session,
) -> None:
    """Negative case for the "not destroyed" half: a *more recent*
    destroyed run must be skipped in favour of an older run that is still
    standing, proving the fallback filters on status rather than only
    ordering by recency. Explicit, distinct timestamps make "more recent"
    a fact rather than a tie the `status` filter alone happens to settle.
    """
    gameadmin = make_user(db_session, role=Role.gameadmin)
    older_standing = make_event_run(db_session, status=RunStatus.finished, created_at=_EARLIER)
    make_event_run(db_session, status=RunStatus.destroyed, created_at=_LATER)  # newer, destroyed

    result = resolve_current_run(db_session, gameadmin)

    assert result is not None
    assert result.id == older_standing.id


# ---------------------------------------------------------------------------
# participant resolution
# ---------------------------------------------------------------------------


def test_participant_resolution_prefers_own_active_run(db_session: Session) -> None:
    player = make_user(db_session, role=Role.player)
    make_participation(
        db_session, user=player, run=make_event_run(db_session, status=RunStatus.finished)
    )
    active_run = make_event_run(db_session, status=RunStatus.running)
    make_participation(db_session, user=player, run=active_run)

    result = resolve_current_run(db_session, player)

    assert result is not None
    assert result.id == active_run.id


def test_participant_resolution_skips_created_run_when_readable_run_exists(
    db_session: Session,
) -> None:
    """The subtle rule api-surface.md §2.6 exists for: a participant still
    rating a finished run must not be flipped onto a freshly-imported next
    run merely because its roster landed more recently. The `created`-run
    participation below is given the *later* `created_at` explicitly, so
    the finished run winning is provably the skip rule and not a
    coincidence of insertion order.
    """
    player = make_user(db_session, role=Role.player)
    finished_run = make_event_run(db_session, status=RunStatus.finished)
    make_participation(db_session, user=player, run=finished_run, created_at=_EARLIER)
    next_run = make_event_run(db_session, status=RunStatus.created)
    make_participation(db_session, user=player, run=next_run, created_at=_LATER)

    result = resolve_current_run(db_session, player)

    assert result is not None
    assert result.id == finished_run.id


def test_participant_resolution_falls_back_to_most_recent_participation_with_no_readable_run(
    db_session: Session,
) -> None:
    player = make_user(db_session, role=Role.player)
    make_participation(
        db_session,
        user=player,
        run=make_event_run(db_session, status=RunStatus.created),
        created_at=_EARLIER,
    )
    latest_run = make_event_run(db_session, status=RunStatus.created)
    make_participation(db_session, user=player, run=latest_run, created_at=_LATER)

    result = resolve_current_run(db_session, player)

    assert result is not None
    assert result.id == latest_run.id


def test_participant_resolution_returns_none_with_no_participations(db_session: Session) -> None:
    player = make_user(db_session, role=Role.player)

    assert resolve_current_run(db_session, player) is None


# ---------------------------------------------------------------------------
# GET /privacy-notice — public, the staff branch with no user at all
# ---------------------------------------------------------------------------


def test_privacy_notice_serves_the_running_runs_definition_not_the_newest(
    client: TestClient, db_session: Session
) -> None:
    running_definition = make_event_definition(
        db_session, status=DefinitionStatus.published, privacy_notice_md="Running notice"
    )
    make_event_run(db_session, definition=running_definition, status=RunStatus.running)

    newer_definition = make_event_definition(
        db_session, status=DefinitionStatus.published, privacy_notice_md="Newer notice"
    )
    make_event_run(db_session, definition=newer_definition, status=RunStatus.created)

    response = client.get("/api/v1/privacy-notice")

    assert response.status_code == 200, response.text
    assert response.json() == {"privacy_notice_md": "Running notice"}


def test_privacy_notice_404_with_no_run(client: TestClient) -> None:
    response = client.get("/api/v1/privacy-notice")

    assert response.status_code == 404
    assert response.json()["code"] == "object_not_found"


def test_privacy_notice_404_when_definitions_notice_is_empty(
    client: TestClient, db_session: Session
) -> None:
    definition = make_event_definition(
        db_session, status=DefinitionStatus.published, privacy_notice_md=""
    )
    make_event_run(db_session, definition=definition, status=RunStatus.running)

    response = client.get("/api/v1/privacy-notice")

    assert response.status_code == 404
    assert response.json()["code"] == "object_not_found"
