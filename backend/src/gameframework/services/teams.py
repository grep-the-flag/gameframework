"""Teams — atomic creation, corrections, freeze, solo (M2-Task-Plan.md
Task 8; api-surface.md §2.5, §2.17; data-model.md §3.11, §6).

`team.captain_user_id` is non-nullable and the captain must hold this run's
`event_participation` with `team_id = team.id` (data-model.md §3.11/§6) —
two facts no sequence of separate writes can satisfy, which is why
`create_team` writes the team row, every named member's `team_id` and the
captain in one call, committing once, at the very end, through
`write_audit`. Anything that fails before that point — a captain not named
among the members, a member naming no participation in this run — rolls
back everything this call has flushed so far, not only the field that
failed: the `try`/`except`/`rollback` around the whole body is what makes
"one transaction" true of a failure partway through, not only of the happy
path.

`ensure_roster_open` and `RosterFrozenError` live here rather than in
`services/participants.py`, and `mint_handle` moved here with them —
solo-mode import (Task 8 Step 4) calls `create_team` from
`services/participants.py`, so that module now imports from this one; this
one must therefore import nothing back from it, and the roster-freeze
check Task 7 built for itself is exactly the one these routes need too
(this task's own Produces line: "the roster-freeze write-path checks used
by these routes and by Task 7's importer"). `services/participants.py` and
`api/participants.py` are updated to import these three names from here
instead of defining or importing a private copy — no behavioural change,
proven by Task 7's own suite staying green.
"""

import secrets
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.db.models.feedback import AuditScope
from gameframework.db.models.runs import EventParticipation, EventRun, RunStatus, Team
from gameframework.services.audit import write_audit
from gameframework.services.invariants import (
    ensure_captain_is_team_member,
    ensure_captain_not_removed_by_participation_change,
)

# 3 bytes = 6 hex chars: "team-abcdef" is 11 characters, comfortably inside
# data-model.md §3.10/§3.11's shared ^[a-z][a-z0-9-]{1,27}$ body limit.
_HANDLE_SUFFIX_BYTES = 3


class RosterFrozenError(Exception):
    """api-surface.md §2.4/§2.5: a roster write once the run has left
    `created` — the roster freezes at `start`."""


class CaptainNotAMemberError(Exception):
    """The named captain does not hold a participation on this team — at
    creation (not among the named members), at the members route's
    optional same-request swap, or at the dedicated captain-swap route
    (api-surface.md §2.5)."""

    def __init__(self, user_id: uuid.UUID) -> None:
        super().__init__(str(user_id))
        self.user_id = user_id


class ParticipationNotFoundError(Exception):
    """A named member does not hold a participation in this run
    (api-surface.md §2.5)."""

    def __init__(self, user_id: uuid.UUID) -> None:
        super().__init__(str(user_id))
        self.user_id = user_id


class RunDestroyedError(Exception):
    """The captain-swap and rename window (api-surface.md §2.5's
    authorization matrix, §2.17): open from `created` through `finished`
    inclusive, refused only once the run is `destroyed` — a materially
    different gate from `RosterFrozenError`, which closes at `start` and
    governs creation and member assignment instead."""


def mint_handle(prefix: str, existing: set[str]) -> str:
    """data-model.md §3.10/§3.11: `^[a-z][a-z0-9-]{1,27}$`, unique **per
    run** — `existing` is the caller's set of handles already taken in the
    run being minted into. Shared between participation handles
    (`services/participants.py`, prefix `p`) and team handles (this module,
    prefix `team`) — one mechanism, not two copies of the same grammar and
    retry loop.
    """
    while True:
        candidate = f"{prefix}-{secrets.token_hex(_HANDLE_SUFFIX_BYTES)}"
        if candidate not in existing:
            return candidate


def ensure_roster_open(run: EventRun) -> None:
    if run.status is not RunStatus.created:
        raise RosterFrozenError()


def ensure_run_not_destroyed(run: EventRun) -> None:
    if run.status is RunStatus.destroyed:
        raise RunDestroyedError()


def _existing_team_handles(db: Session, run: EventRun) -> set[str]:
    return set(db.execute(select(Team.handle).where(Team.event_run_id == run.id)).scalars().all())


def _get_participation(db: Session, run: EventRun, user_id: uuid.UUID) -> EventParticipation | None:
    return db.execute(
        select(EventParticipation).where(
            EventParticipation.user_id == user_id,
            EventParticipation.event_run_id == run.id,
        )
    ).scalar_one_or_none()


def create_team(
    db: Session,
    run: EventRun,
    *,
    name: str,
    member_ids: list[uuid.UUID],
    captain_id: uuid.UUID,
    actor_user_id: uuid.UUID,
) -> Team:
    """api-surface.md §2.5: "The body carries the name, the member list and
    the captain together, and the three land in one transaction." The
    whole write is wrapped in `try`/`except`/`rollback`: a member naming no
    participation in this run, or a captain never named among the members,
    can each fail after zero or more earlier members' `team_id` have
    already been flushed, and the rollback is what makes that failure leave
    nothing behind rather than a partially-applied team. The
    captain-membership check happens after the member writes rather than
    as a request-shape pre-check, so it goes through the one place this
    invariant is checked (`ensure_captain_is_team_member`,
    `services/invariants.py`, Task 1a) rather than a second, parallel test
    of the same fact. `created`-only — the roster freeze that closes at
    `start` (api-surface.md §2.5), a different gate from the captain
    swap's wider window.
    """
    ensure_roster_open(run)

    team = Team(
        event_run_id=run.id,
        name=name,
        handle=mint_handle("team", _existing_team_handles(db, run)),
        captain_user_id=captain_id,
    )
    try:
        db.add(team)
        db.flush()

        for member_id in member_ids:
            participation = _get_participation(db, run, member_id)
            if participation is None:
                raise ParticipationNotFoundError(member_id)
            participation.team_id = team.id
            db.flush()

        try:
            ensure_captain_is_team_member(db, team, captain_id)
        except ValueError as exc:
            raise CaptainNotAMemberError(captain_id) from exc

        write_audit(
            db,
            actor_user_id=actor_user_id,
            scope=AuditScope.participant,
            event_run_id=run.id,
            action="team_created",
            target_type="team",
            target_id=team.id,
            details={"member_count": len(member_ids)},
        )
    except Exception:
        db.rollback()
        raise

    return team


def rename_team(db: Session, team: Team, run: EventRun, *, name: str) -> Team:
    """`PATCH /teams/{id}` (api-surface.md §2.5, §2.17): the one team field
    that stays writable through the event, on the same window as the
    captain swap (`created` through `finished`, refused at `destroyed`) —
    a name keys nothing, so it follows that gate rather than the roster
    freeze. Deliberately **not** audited, unlike the other three team
    writes — the matrix's asymmetry, not an omission.
    """
    ensure_run_not_destroyed(run)
    team.name = name
    db.commit()
    return team


def set_members(
    db: Session,
    team: Team,
    run: EventRun,
    *,
    member_user_ids: list[uuid.UUID],
    new_captain_user_id: uuid.UUID | None,
    actor_user_id: uuid.UUID,
) -> Team:
    """`PUT /teams/{id}/members` (api-surface.md §2.5): writes
    `event_participation.team_id` for the run's participations, `created`-
    only like creation. Refused when the new set would drop the current
    captain, unless `new_captain_user_id` names their replacement — the
    only way to reach a team whose sole member is its captain, replaced by
    someone not yet a member, since no order of two separate calls can
    (`PUT .../captain` refuses an outsider; this route alone refuses to
    drop the sitting captain). The swap, when present, is applied **first**
    — before the membership invariant is checked against any dropped
    participation — so `ensure_captain_not_removed_by_participation_change`
    reads the *new* captain and the drop is no longer a violation; it
    writes its own audit row beside the member-assignment one, because two
    facts happened.
    """
    ensure_roster_open(run)

    try:
        if new_captain_user_id is not None and new_captain_user_id != team.captain_user_id:
            if new_captain_user_id not in member_user_ids:
                raise CaptainNotAMemberError(new_captain_user_id)
            team.captain_user_id = new_captain_user_id
            write_audit(
                db,
                actor_user_id=actor_user_id,
                scope=AuditScope.participant,
                event_run_id=run.id,
                action="team_captain_changed",
                target_type="team",
                target_id=team.id,
                details={"new_captain_user_id": str(new_captain_user_id)},
            )

        run_participations = {
            p.user_id: p
            for p in db.execute(
                select(EventParticipation).where(EventParticipation.event_run_id == run.id)
            )
            .scalars()
            .all()
        }
        new_member_set = set(member_user_ids)

        for participation in run_participations.values():
            if participation.team_id == team.id and participation.user_id not in new_member_set:
                try:
                    ensure_captain_not_removed_by_participation_change(db, participation, None)
                except ValueError as exc:
                    raise CaptainNotAMemberError(participation.user_id) from exc
                participation.team_id = None
                db.flush()

        for user_id in member_user_ids:
            participation = run_participations.get(user_id)
            if participation is None:
                raise ParticipationNotFoundError(user_id)
            if participation.team_id != team.id:
                try:
                    ensure_captain_not_removed_by_participation_change(db, participation, team.id)
                except ValueError as exc:
                    raise CaptainNotAMemberError(participation.user_id) from exc
                participation.team_id = team.id
                db.flush()

        write_audit(
            db,
            actor_user_id=actor_user_id,
            scope=AuditScope.participant,
            event_run_id=run.id,
            action="team_members_changed",
            target_type="team",
            target_id=team.id,
            details={"member_count": len(member_user_ids)},
        )
    except Exception:
        db.rollback()
        raise

    return team


def set_captain(
    db: Session, team: Team, run: EventRun, *, captain_user_id: uuid.UUID, actor_user_id: uuid.UUID
) -> Team:
    """`PUT /teams/{id}/captain` (api-surface.md §2.5, §2.17): open from
    `created` through `finished`, refused only from `destroyed` — Phase 3's
    rating is captain-only and runs in `finished`, which is why that
    status is inside the window rather than its edge. The replacement must
    already be a member of this team — checked against the live
    `event_participation` row via `ensure_captain_is_team_member`, since
    there is no member list in this request to check against. Moves no
    participation and revokes no session (captaincy is derived at
    authorization time, ADR-0007) — only `team.captain_user_id` changes,
    and that write is audited.
    """
    ensure_run_not_destroyed(run)

    try:
        ensure_captain_is_team_member(db, team, captain_user_id)
    except ValueError as exc:
        raise CaptainNotAMemberError(captain_user_id) from exc

    team.captain_user_id = captain_user_id
    write_audit(
        db,
        actor_user_id=actor_user_id,
        scope=AuditScope.participant,
        event_run_id=run.id,
        action="team_captain_changed",
        target_type="team",
        target_id=team.id,
        details={"new_captain_user_id": str(captain_user_id)},
    )
    return team
