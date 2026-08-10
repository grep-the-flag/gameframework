"""The application-enforced half of data-model.md §6 that is testable
without routes (Task 1a Step 4): run/definition coherence, and the
captain-membership invariant. These two tests define the minimal service
helpers Step 5 implements — the signatures here are a contract later tasks
call, not an implementation detail. They fail first because the helpers do
not exist yet.

Deliberately not here: any "current run" resolution across a user's
multiple participations. That's Task 12's, named as its own owner in the
plan. Run/definition coherence is a narrower thing — a challenge resolved
through a specific, already-known run's `event_definition_id`, never
trusted bare from a request.
"""

from datetime import UTC, datetime, timedelta

import pytest

from gameframework.db.models.runs import RunStatus
from gameframework.services.invariants import (
    ensure_captain_is_team_member,
    ensure_captain_not_removed_by_participation_change,
    resolve_challenge_for_definition,
)

from ..conftest import (
    make_challenge,
    make_event_definition,
    make_event_run,
    make_participation,
    make_team,
    make_user,
)


def test_challenge_resolution_is_scoped_to_the_runs_definition(db_session) -> None:  # type: ignore[no-untyped-def]
    """§6, application-enforced: run/definition coherence. With two
    coexisting runs — a finished run in its grace period beside a created
    one — a challenge must resolve only through the querying run's own
    `event_definition_id`; a bare `challenge_id` from a request must not be
    trusted across that boundary even though both rows exist right now.
    """
    finished_definition = make_event_definition(db_session)
    make_event_run(
        db_session,
        definition=finished_definition,
        status=RunStatus.finished,
        finished_at=datetime.now(UTC),
        grace_deadline_at=datetime.now(UTC) + timedelta(days=7),
    )
    finished_challenge = make_challenge(db_session, definition=finished_definition)

    created_definition = make_event_definition(db_session)
    created_run = make_event_run(
        db_session, definition=created_definition, status=RunStatus.created
    )
    created_challenge = make_challenge(db_session, definition=created_definition)

    resolved = resolve_challenge_for_definition(
        db_session, created_run.event_definition_id, created_challenge.id
    )
    assert resolved.id == created_challenge.id

    with pytest.raises(ValueError):
        resolve_challenge_for_definition(
            db_session, created_run.event_definition_id, finished_challenge.id
        )


def test_captain_must_be_a_team_member(db_session) -> None:  # type: ignore[no-untyped-def]
    """§6, application-enforced: the captain belongs to the team —
    `team.captain_user_id` must name a user holding *this* team's
    `event_participation` (`team_id = team.id`), not merely any
    participation in the same run.
    """
    run = make_event_run(db_session)
    captain = make_user(db_session)
    team = make_team(db_session, run=run, captain=captain)
    make_participation(db_session, user=captain, run=run, team_id=team.id)

    ensure_captain_is_team_member(db_session, team, captain.id)

    other_team = make_team(db_session, run=run)
    outsider = make_user(db_session)
    make_participation(db_session, user=outsider, run=run, team_id=other_team.id)

    with pytest.raises(ValueError):
        ensure_captain_is_team_member(db_session, team, outsider.id)


def test_captain_removal_via_participation_change_is_refused(db_session) -> None:  # type: ignore[no-untyped-def]
    """§6, application-enforced: the captain invariant's other write path —
    "a later member write that would take the current captain out of the
    team is refused rather than left to violate the invariant." Checked
    before a participation's `team_id` is moved or cleared, not just at
    captain assignment.
    """
    run = make_event_run(db_session)
    captain = make_user(db_session)
    team = make_team(db_session, run=run, captain=captain)
    captain_participation = make_participation(db_session, user=captain, run=run, team_id=team.id)
    other_team = make_team(db_session, run=run)

    with pytest.raises(ValueError):
        ensure_captain_not_removed_by_participation_change(
            db_session, captain_participation, other_team.id
        )
    with pytest.raises(ValueError):
        ensure_captain_not_removed_by_participation_change(db_session, captain_participation, None)

    # An ordinary member is free to move — only the captain's own
    # participation is protected.
    member = make_user(db_session)
    member_participation = make_participation(db_session, user=member, run=run, team_id=team.id)
    ensure_captain_not_removed_by_participation_change(
        db_session, member_participation, other_team.id
    )
