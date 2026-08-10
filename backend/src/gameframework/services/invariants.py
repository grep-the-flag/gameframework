"""The application-enforced half of data-model.md §6 that Task 1a proves
without routes: run/definition coherence, and both write-path directions of
the captain-membership invariant. Minimal by design — exactly what
tests/db/test_transactional_invariants.py requires; later tasks (Task 8's
team and participation write paths) call these rather than reimplementing
the checks, and extend them if a new call site needs more.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.db.models.authoring import Challenge
from gameframework.db.models.runs import EventParticipation, Team


def resolve_challenge_for_definition(
    db: Session, event_definition_id: uuid.UUID, challenge_id: uuid.UUID
) -> Challenge:
    """Run/definition coherence (§6): a challenge is always resolved through
    the run's own `event_definition_id`, never trusted bare from a request.
    """
    challenge = db.execute(
        select(Challenge).where(
            Challenge.id == challenge_id,
            Challenge.event_definition_id == event_definition_id,
        )
    ).scalar_one_or_none()
    if challenge is None:
        raise ValueError(
            f"challenge {challenge_id} does not belong to event_definition {event_definition_id}"
        )
    return challenge


def ensure_captain_is_team_member(db: Session, team: Team, captain_user_id: uuid.UUID) -> None:
    """The captain belongs to the team (§6): `captain_user_id` must name a
    user holding *this* team's own `event_participation`
    (`team_id = team.id`).
    """
    participation = db.execute(
        select(EventParticipation).where(
            EventParticipation.user_id == captain_user_id,
            EventParticipation.team_id == team.id,
        )
    ).scalar_one_or_none()
    if participation is None:
        raise ValueError(f"user {captain_user_id} does not hold a participation on team {team.id}")


def ensure_captain_not_removed_by_participation_change(
    db: Session, participation: EventParticipation, new_team_id: uuid.UUID | None
) -> None:
    """The write-path counterpart to `ensure_captain_is_team_member` (§6): a
    member write that would take the current captain out of their team is
    refused rather than left to violate the invariant.
    """
    if participation.team_id is None or participation.team_id == new_team_id:
        return
    # participation.team_id is FK-guaranteed (composite FK to team(id,
    # event_run_id)) to reference a real row — scalar_one() trusts that
    # rather than defending against a case the database already rules out.
    team = db.execute(select(Team).where(Team.id == participation.team_id)).scalar_one()
    if team.captain_user_id == participation.user_id:
        raise ValueError(
            f"cannot move participation {participation.id}: user "
            f"{participation.user_id} is the captain of team {team.id}"
        )
