"""Event runs — creation with the §3.9 config snapshot, the "current run"
resolution of api-surface.md §2.6 (M2-Task-Plan.md Task 12), and the
`start` transition (M2-Task-Plan.md Task 13; data-model.md §3.12, §6).
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.config import Settings
from gameframework.db.models.authoring import (
    Challenge,
    ChallengeDependency,
    DefinitionStatus,
    EventDefinition,
)
from gameframework.db.models.identity import Role, User
from gameframework.db.models.play import TeamChallenge, TeamChallengeState
from gameframework.db.models.runs import EventParticipation, EventRun, ExportState, RunStatus, Team
from gameframework.services.preflight import RunNotCreatedError, compute_config_hash

_ACTIVE_STATUSES = (RunStatus.running, RunStatus.paused)
_READABLE_STATUSES = (RunStatus.running, RunStatus.paused, RunStatus.finished)

# data-model.md §3.9: the run's own default, mirrored here rather than
# left to the column default so the "starts fresh, never copied" claim is
# visible at the one call site that could otherwise be tempted to read it
# off something else.
_DEFAULT_OTP_LIFETIME_MINUTES = 5


class DefinitionNotPublishedError(Exception):
    """`POST /event-definitions/{id}/runs` (api-surface.md §2.6): a run may
    only be created from a `published` definition — structure is frozen
    there, which is what makes a snapshot of it meaningful."""


class ActiveRunExistsError(Exception):
    """api-surface.md §2.6: "409 while another run is running/paused"
    (data-model.md §3.9's partial unique index). Checked here, before any
    insert, so the refusal is always a clean one — the caller never sees
    an `IntegrityError`, and one code (`run_active`) covers this and Task
    10's archive guard alike: both name a live run standing in the way of
    the caller's action, and the remedy for either is identical — end the
    active run first.
    """


class PreflightNotCurrentError(Exception):
    """`start` (api-surface.md §2.6): refused without a "current successful
    preflight — passed, hash still matching". Both halves of that phrase —
    never having passed, and having passed but gone stale — answer the
    same code, `preflight_not_current`: data-model.md §3.9 states them as
    one combined precondition (`preflight_passed_at` non-null **and** a
    matching `preflight_config_hash`), not two, and a client's remedy is
    identical either way — run the preflight again.
    """


def create_run(db: Session, definition: EventDefinition) -> EventRun:
    """api-surface.md §2.6, data-model.md §3.9: snapshots the run-affecting
    definition config (`unlock_mode`, `scoring_mode`, `participation_mode`,
    `theme_ref`, `gamemaster_enabled`, `language_default`,
    `grace_period_days`) onto the new row. `gamemaster_provider`,
    `gamemaster_endpoint` and `otp_lifetime_minutes` are deliberately
    **not** read from anywhere — `event_definition` carries no matching
    columns at all, because they are the operator's own infrastructure and
    security knobs, never part of a shareable game design (§3.9) — so
    every run starts them at their defaults regardless of what any other
    run, past or present, holds. Not audited: creating a run writes no
    participant data, §2.17's own criterion for the audited roster/team
    rows.
    """
    if definition.status is not DefinitionStatus.published:
        raise DefinitionNotPublishedError()

    active_exists = (
        db.execute(select(EventRun.id).where(EventRun.status.in_(_ACTIVE_STATUSES)).limit(1))
        .scalars()
        .first()
        is not None
    )
    if active_exists:
        raise ActiveRunExistsError()

    run = EventRun(
        event_definition_id=definition.id,
        definition_revision=definition.revision,
        status=RunStatus.created,
        unlock_mode=definition.unlock_mode,
        scoring_mode=definition.scoring_mode,
        participation_mode=definition.participation_mode,
        theme_ref=definition.theme_ref,
        gamemaster_enabled=definition.gamemaster_enabled,
        gamemaster_provider=None,
        gamemaster_endpoint=None,
        language_default=definition.language_default,
        grace_period_days=definition.grace_period_days,
        otp_lifetime_minutes=_DEFAULT_OTP_LIFETIME_MINUTES,
        export_state=ExportState.pending,
    )
    db.add(run)
    db.commit()
    return run


def start_run(db: Session, run: EventRun, settings: Settings) -> None:
    """`POST /runs/{id}/transition` `start` (api-surface.md §2.6): admin-
    only at the route (checked there, not here — a role gate belongs
    beside the session, not the domain logic); `created`-only, refused
    against a second concurrent run, and gated on a current successful
    preflight — passed, hash still matching (`compute_config_hash` re-run
    fresh and compared against the stored one, never trusted stale).

    data-model.md §6: "the start transition materializes progress: one
    team_challenge row per team and per challenge of the run's
    definition, written in the same transaction as the status change" —
    `startable` where the challenge carries no dependency row (explicit or
    reward-derived, data-model.md §3.12), `locked` otherwise. One
    `db.commit()` covers both the inserts and the status write.
    """
    if run.status is not RunStatus.created:
        raise RunNotCreatedError()

    active_exists = (
        db.execute(select(EventRun.id).where(EventRun.status.in_(_ACTIVE_STATUSES)).limit(1))
        .scalars()
        .first()
        is not None
    )
    if active_exists:
        raise ActiveRunExistsError()

    current_hash = compute_config_hash(db, run, settings)
    if run.preflight_passed_at is None or run.preflight_config_hash != current_hash:
        raise PreflightNotCurrentError()

    teams = db.execute(select(Team).where(Team.event_run_id == run.id)).scalars().all()
    challenges = (
        db.execute(
            select(Challenge).where(Challenge.event_definition_id == run.event_definition_id)
        )
        .scalars()
        .all()
    )
    challenge_ids = [c.id for c in challenges]
    dependent_ids = set(
        db.execute(
            select(ChallengeDependency.challenge_id).where(
                ChallengeDependency.challenge_id.in_(challenge_ids)
            )
        )
        .scalars()
        .all()
    )

    for team in teams:
        for challenge in challenges:
            state = (
                TeamChallengeState.locked
                if challenge.id in dependent_ids
                else TeamChallengeState.startable
            )
            db.add(
                TeamChallenge(
                    team_id=team.id,
                    challenge_id=challenge.id,
                    state=state,
                    provision_attempts=0,
                )
            )

    run.status = RunStatus.running
    db.commit()


def resolve_current_run(db: Session, user: User | None) -> EventRun | None:
    """api-surface.md §2.6's "current run", resolved for both readers —
    and for no reader at all.

    Staff (`admin`/`gameadmin`) and `user=None` share one branch,
    installation-wide and needing no user to scope by: the run in
    `running`/`paused` when one exists, otherwise the most recently
    created run that is not `destroyed`. `user=None` is that branch with
    no session to have taken it from — `GET /privacy-notice` is public
    (api-surface.md §2.1) — not a special case of it.

    Participant (everyone else — `captain` is derived, so a captain's
    stored role is `player` and takes this branch too): the run in
    `running`/`paused` among their own participations, otherwise their
    most recent participation in a *readable* run (`running`, `paused` or
    `finished`), with a `created` run skipped whenever a readable one
    exists. Three strict priority tiers, not one "most recent among a
    merged set": a participant's readable run always outranks a more-
    recently-imported `created` one, which is the whole reason this
    resolution exists — a fresh roster import must not sever a
    participant's access to a run they are still rating.
    """
    if user is None or user.role in (Role.admin, Role.gameadmin):
        active = db.execute(
            select(EventRun).where(EventRun.status.in_(_ACTIVE_STATUSES))
        ).scalar_one_or_none()
        if active is not None:
            return active
        return db.execute(
            select(EventRun)
            .where(EventRun.status != RunStatus.destroyed)
            .order_by(EventRun.created_at.desc(), EventRun.id.desc())
            .limit(1)
        ).scalar_one_or_none()

    rows = db.execute(
        select(EventParticipation, EventRun)
        .join(EventRun, EventParticipation.event_run_id == EventRun.id)
        .where(EventParticipation.user_id == user.id)
        .order_by(EventParticipation.created_at.desc(), EventParticipation.id.desc())
    ).all()

    for _, run in rows:
        if run.status in _ACTIVE_STATUSES:
            return run
    for _, run in rows:
        if run.status in _READABLE_STATUSES:
            return run
    for _, run in rows:
        return run
    return None
