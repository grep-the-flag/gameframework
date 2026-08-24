"""Event runs — creation with the §3.9 config snapshot, the "current run"
resolution of api-surface.md §2.6 (M2-Task-Plan.md Task 12), the `start`
transition (M2-Task-Plan.md Task 13; data-model.md §3.12, §6), and
`pause`/`resume`/`finish` plus the operational `PATCH` (M2-Task-Plan.md
Task 14; data-model.md §3.9, §2.17).
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.config import Settings
from gameframework.db.models.authoring import (
    Challenge,
    ChallengeDependency,
    DefinitionStatus,
    EventDefinition,
)
from gameframework.db.models.feedback import AuditScope
from gameframework.db.models.identity import Role, User
from gameframework.db.models.play import TeamChallenge, TeamChallengeState
from gameframework.db.models.runs import EventParticipation, EventRun, ExportState, RunStatus, Team
from gameframework.services.audit import write_audit
from gameframework.services.preflight import RunNotCreatedError, compute_config_hash

# ADR-0019's maximum retention window: 30 days past the grace deadline,
# fixed rather than a setting — like fetch.py's caps, no installation has
# asked to configure it.
_HARD_DEADLINE_EXTRA_DAYS = 30

# api-surface.md §2.6's run-operational whitelist, `grace_period_days`
# included: the field-level admin-only gate on that one field is the
# route's to enforce (api-surface.md §1 — "some fields on an otherwise-
# reachable route are narrower than the route itself"), not a second
# whitelist here.
PATCH_WHITELIST_FIELDS = (
    "scheduled_end",
    "theme_ref",
    "gamemaster_enabled",
    "gamemaster_provider",
    "gamemaster_endpoint",
    "otp_lifetime_minutes",
    "grace_period_days",
)

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


class InvalidTransitionError(Exception):
    """`pause`/`resume`/`finish` (api-surface.md §2.6): the run is not in
    the status (or, for `finish`, one of the two statuses) that transition
    requires — pause needs `running`, resume needs `paused`, finish needs
    `running` or `paused`. Answered as `invalid_status_transition`, the
    same code `RunNotCreatedError` answers for the preflight and `start`
    (Task 12/13's "one code where the remedy is one"): a caller's next
    step is always "read the run's current status", never a second name
    for the same fact.
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


def start_run(db: Session, run: EventRun, settings: Settings, actor_user_id: UUID) -> None:
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
    reward-derived, data-model.md §3.12), `locked` otherwise. `_audit_run`'s
    own commit is what covers the inserts, the status write and the audit
    row together (Task 14 Step 2 correction — Task 13 built this transition
    and left it unaudited, even though api-surface.md §2.17's run-lifecycle
    row is marked audited and names `start` by name: "start is admin's,
    like the preflight that gates it"). The contrast is deliberate, not an
    oversight to mirror here: the *preflight* row directly above it in the
    same table is marked `—` — the check stays unaudited, only the
    transition it gates is.
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
    _audit_run(db, run, actor_user_id, "event_run_started")


def _audit_run(db: Session, run: EventRun, actor_user_id: UUID, action: str) -> None:
    """The `write_audit`/status-change ordering that lands both in one
    transaction: it is called last, after every column mutation, so its
    own `db.commit()` is the one that finalizes them together (the same
    pattern `services/teams.py`'s `create_team` uses) — data-model.md §6.
    """
    write_audit(
        db,
        actor_user_id=actor_user_id,
        scope=AuditScope.participant,
        event_run_id=run.id,
        action=action,
        target_type="event_run",
        target_id=run.id,
        details={},
    )


def pause_run(db: Session, run: EventRun, actor_user_id: UUID) -> None:
    """`POST /runs/{id}/transition` `pause` (api-surface.md §2.6): legal
    from `running` only. Sets `paused_at` (data-model.md §3.9)."""
    if run.status is not RunStatus.running:
        raise InvalidTransitionError()
    run.status = RunStatus.paused
    run.paused_at = datetime.now(UTC)
    _audit_run(db, run, actor_user_id, "event_run_paused")


def resume_run(db: Session, run: EventRun, actor_user_id: UUID) -> None:
    """`POST /runs/{id}/transition` `resume` (api-surface.md §2.6): legal
    from `paused` only. Clears `paused_at` — one of the two transitions
    that must (data-model.md §3.9's "null whenever status != paused").

    Also pushes `scheduled_end` back by the paused duration: §3.9 defines
    `paused_at` literally as "the moment scheduled_end is pushed back by",
    so the column's documented purpose is this arithmetic, not the M3
    scheduled job that later *acts* on `scheduled_end` — a value can be
    wrong long before anything reads it on a schedule. `run.paused_at` is
    still the pre-clear value here since it is read before being set to
    `None` below; a run with no `scheduled_end` is left untouched, since
    there is nothing to push.
    """
    if run.status is not RunStatus.paused:
        raise InvalidTransitionError()
    assert run.paused_at is not None  # invariant: status == paused implies paused_at is set
    paused_duration = datetime.now(UTC) - run.paused_at
    if run.scheduled_end is not None:
        run.scheduled_end = run.scheduled_end + paused_duration
    run.status = RunStatus.running
    run.paused_at = None
    _audit_run(db, run, actor_user_id, "event_run_resumed")


def finish_run(db: Session, run: EventRun, actor_user_id: UUID) -> None:
    """`POST /runs/{id}/transition` `finish` (api-surface.md §2.6): legal
    from `running` or `paused` — always available in either, never
    conditioned on how the run got there. Clears `paused_at` (data-model.md
    §3.9's coupling reaches this transition too, not only `resume`) and
    derives `finished_at`/`grace_deadline_at`/`hard_deadline_at` from the
    run's own snapshotted `grace_period_days` and ADR-0019's fixed 30-day
    maximum-retention extension. `datetime.now(UTC)` is read once into
    `now` and every derived column is built from that one value, so the
    three columns cannot observe three different instants.
    """
    if run.status not in (RunStatus.running, RunStatus.paused):
        raise InvalidTransitionError()
    now = datetime.now(UTC)
    grace_deadline_at = now + timedelta(days=run.grace_period_days)
    run.status = RunStatus.finished
    run.paused_at = None
    run.finished_at = now
    run.grace_deadline_at = grace_deadline_at
    run.hard_deadline_at = grace_deadline_at + timedelta(days=_HARD_DEADLINE_EXTRA_DAYS)
    _audit_run(db, run, actor_user_id, "event_run_finished")


def patch_run(db: Session, run: EventRun, actor_user_id: UUID, fields: dict[str, object]) -> None:
    """`PATCH /runs/{id}` (api-surface.md §2.6): the run-operational
    whitelist. The `grace_period_days` admin-only gate is resolved from
    the live session before this is ever called (api/runs.py) — this
    function assumes a caller who may write every key in `fields`.

    None of `PATCH_WHITELIST_FIELDS` is an input to `compute_config_hash`
    (`services/preflight.py`, M2-Task-Plan.md Task 13): a preflight
    validates none of them in M2, so writing any of them must never stale
    a passed one — the same principle that lets a post-publication content
    fix skip a re-preflight (data-model.md §3.9).
    """
    for key, value in fields.items():
        setattr(run, key, value)
    _audit_run(db, run, actor_user_id, "event_run_patched")


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
