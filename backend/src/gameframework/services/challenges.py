"""Challenge reads and the `start` state machine's M2 half
(M2-Task-Plan.md Task 15; api-surface.md §2.7, §2.17; data-model.md §3.12,
§3.24, §6).

The three refusal codes below — `run_not_running`, `team_occupied`,
`challenge_not_offered` — and their extension members are normative in
api-surface.md §2.7 ("`start` refuses in three named ways, and the three
are ordered"), not invented here; the checks below run in that same order,
outermost first, so the first one to refuse is the one answered.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.db.models.authoring import Challenge, ChallengeDependency, UnlockMode
from gameframework.db.models.identity import User
from gameframework.db.models.infrastructure import Job, JobState
from gameframework.db.models.play import TeamChallenge, TeamChallengeState
from gameframework.db.models.runs import EventParticipation, EventRun, RunStatus, Team

# data-model.md §6: at most one team_challenge row per team in these three
# states occupies the team — `provisioning`/`active` behind the partial
# unique index of §3.12, `provision_failed` behind nothing but this check.
_OCCUPYING_STATES = (
    TeamChallengeState.provisioning,
    TeamChallengeState.active,
    TeamChallengeState.provision_failed,
)
# A repeat start of the exact row already occupying the team is a replay,
# not a conflict — this is the idempotent case the job's business key is
# meant to cover (api-surface.md §1). `provision_failed` is excluded
# deliberately: retrying a failed provision is §2.8's manual-retry route,
# not this one, and no worker exists in M2 to ever produce the state this
# route would need to replay against.
_REPLAY_STATES = (TeamChallengeState.provisioning, TeamChallengeState.active)
# A row not in one of these two states is not a start candidate at all —
# already solved, or already occupying (caught above first).
_CANDIDATE_STATES = (TeamChallengeState.locked, TeamChallengeState.startable)


class RunNotRunningError(Exception):
    """api-surface.md §2.7 refusal 1: the lifecycle gate — legal only
    while the run is `running`. `created`, `paused` and `finished` all
    reach here (a participant's current-run resolution can fall back to a
    `created` run when they hold no readable one, api-surface.md §2.6);
    the caller reads the extension member off its own `run`, so nothing
    is carried on this exception.
    """


class TeamOccupiedError(Exception):
    """api-surface.md §2.7 refusal 2: "server enforces max 1 active", with
    `provision_failed` occupying the team the same way. The
    `provisioning`/`active` half is also backed by data-model.md §3.12's
    partial unique index; `provision_failed` has nothing behind it but
    this check. Carries the occupying row's `challenge_id` and `state` —
    the extension members §2.7 names (`challenge_id`, `challenge_state`).
    """

    def __init__(self, challenge_id: uuid.UUID, state: TeamChallengeState) -> None:
        super().__init__()
        self.challenge_id = challenge_id
        self.state = state


class ChallengeNotOfferedError(Exception):
    """api-surface.md §2.7 refusal 3: the requested challenge is not
    currently offered to this team — already solved, a dependency
    (explicit or reward-derived) is not yet solved, or — guided mode only
    — eligible but not the eligible challenge with the lowest `order`.
    Carries no discriminator: which of the three holds is a fact about
    the challenge graph, and the graph is precisely what the hidden
    titles of ADR-0004 withhold (api-surface.md §2.7).
    """


def _eligible_challenge_ids(
    db: Session, row_by_challenge_id: dict[uuid.UUID, TeamChallenge]
) -> set[uuid.UUID]:
    """data-model.md §6: "guided-mode 'lowest eligible order' selection
    reads dependencies and states in one snapshot" — every team_challenge
    state was already read once by the caller, into `row_by_challenge_id`,
    and this function reads it no further; only the (static, never
    team-scoped) dependency edges are read here. A challenge's own
    `state` label (`locked` vs `startable`) is not trusted for
    eligibility — nothing in M2 moves it forward as dependencies solve —
    so eligibility is recomputed from the dependency graph and the
    current states every call.
    """
    dependencies = (
        db.execute(
            select(ChallengeDependency).where(
                ChallengeDependency.challenge_id.in_(row_by_challenge_id)
            )
        )
        .scalars()
        .all()
    )
    deps_by_challenge: dict[uuid.UUID, list[uuid.UUID]] = {}
    for dep in dependencies:
        deps_by_challenge.setdefault(dep.challenge_id, []).append(dep.depends_on_id)

    eligible: set[uuid.UUID] = set()
    for challenge_id, row in row_by_challenge_id.items():
        if row.state not in _CANDIDATE_STATES:
            continue
        deps = deps_by_challenge.get(challenge_id, ())
        if all(row_by_challenge_id[dep_id].state == TeamChallengeState.solved for dep_id in deps):
            eligible.add(challenge_id)
    return eligible


def start_challenge(db: Session, run: EventRun, user: User, challenge: Challenge) -> TeamChallenge:
    """`POST /challenges/{id}/start` (api-surface.md §2.7, §2.17): captain
    or player, own team from the session. `run` is the caller's own
    current run, resolved by the caller; `challenge` is the target of the
    path id, already scoped to that run's definition by the caller.
    `user`'s own team is resolved here, not by the caller — only once the
    lifecycle gate below has passed, since a participant's current-run
    resolution can land on a `created` run whose roster is still being
    built, where a participation's `team_id` may still be null.

    Writes `provisioning` and the `provision` job row in the same
    transaction (data-model.md §3.24) — no worker consumes it in M2, so a
    started challenge stays `provisioning` for the rest of the milestone,
    which is what makes the occupancy rule testable here at all.
    """
    if run.status is not RunStatus.running:
        raise RunNotRunningError()

    participation = db.execute(
        select(EventParticipation).where(
            EventParticipation.user_id == user.id,
            EventParticipation.event_run_id == run.id,
        )
    ).scalar_one()
    # data-model.md §6: team composition is frozen from `start`, and no
    # participation reaches a started run without a team — so a
    # participant whose current run is `running` (guaranteed by the check
    # above) is already teamed.
    assert participation.team_id is not None
    team = db.get(Team, participation.team_id)
    assert team is not None

    joined = db.execute(
        select(TeamChallenge, Challenge)
        .join(Challenge, TeamChallenge.challenge_id == Challenge.id)
        .where(TeamChallenge.team_id == team.id)
    ).all()
    row_by_challenge_id = {tc.challenge_id: tc for tc, _ in joined}
    challenge_by_id = {c.id: c for _, c in joined}

    row = row_by_challenge_id.get(challenge.id)
    # data-model.md §6: every team existing when `start` ran holds one
    # team_challenge row per challenge of the run's definition, and
    # neither a new team nor a new challenge joins afterward (roster and
    # structure freeze) — a challenge the caller already scoped to this
    # run's definition always has a row here.
    assert row is not None

    occupying = next(
        (tc for tc, _ in joined if tc.state in _OCCUPYING_STATES),
        None,
    )
    if occupying is not None:
        if occupying.challenge_id == challenge.id and occupying.state in _REPLAY_STATES:
            return occupying
        raise TeamOccupiedError(occupying.challenge_id, occupying.state)

    eligible_ids = _eligible_challenge_ids(db, row_by_challenge_id)
    if challenge.id not in eligible_ids:
        raise ChallengeNotOfferedError()

    if run.unlock_mode is UnlockMode.guided:
        lowest = min((challenge_by_id[cid] for cid in eligible_ids), key=lambda c: c.order_num)
        if lowest.id != challenge.id:
            raise ChallengeNotOfferedError()

    row.state = TeamChallengeState.provisioning
    row.started_at = datetime.now(UTC)
    db.add(
        Job(
            job_type="provision",
            business_key=f"{challenge.minigame_id}:{team.id}",
            payload={
                "event_run_id": str(run.id),
                "team_id": str(team.id),
                "challenge_id": str(challenge.id),
            },
            state=JobState.pending,
            next_attempt_at=datetime.now(UTC),
        )
    )
    db.commit()
    return row
