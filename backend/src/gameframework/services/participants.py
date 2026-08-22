"""Participant import and single creation (M2-Task-Plan.md Task 7;
api-surface.md §2.4, §2.17; data-model.md §3.10). Solo-mode team creation
(Task 8 Step 4) lives here too, since it is the import's own behaviour in
a `solo` run rather than a separate call (api-surface.md §2.4/§2.5) — but
it writes no team-creation logic of its own: `create_team` in
`services/teams.py` is the one place a team is ever written, and this
module calls it once per participant rather than growing a second path.

`RosterFrozenError`, `ensure_roster_open` and `mint_handle` moved to
`services/teams.py` in the same step, because this module now depends on
that one for `create_team` — a dependency that must not run in the other
direction, which is what "one mechanism" for the roster freeze and the
handle grammar actually requires once two modules need both. Re-exported
here so `api/participants.py`'s existing import keeps working unchanged.
"""

import uuid
from collections.abc import Iterable
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.db.models.authoring import ParticipationMode
from gameframework.db.models.feedback import AuditScope
from gameframework.db.models.identity import Role, User
from gameframework.db.models.runs import EventParticipation, EventRun
from gameframework.services.audit import write_audit
from gameframework.services.passwords import hash_password
from gameframework.services.teams import (
    RosterFrozenError,
    create_team,
    ensure_roster_open,
    mint_handle,
)
from gameframework.services.users import normalize_username

__all__ = [
    "RosterFrozenError",
    "DuplicateParticipationError",
    "ParticipantRow",
    "ImportedParticipant",
    "ImportReport",
    "mint_handle",
    "import_participants",
    "create_participant",
]


@dataclass
class ParticipantRow:
    """One row of an import, or the single-creation route's one row —
    already resolved from CSV, JSON or the request body by the API layer,
    so this module never parses transport formats itself."""

    username: str
    name: str
    email: str | None = None


@dataclass
class ImportedParticipant:
    user_id: uuid.UUID
    username: str
    handle: str
    reused: bool


@dataclass
class ImportReport:
    participants: list[ImportedParticipant]


class DuplicateParticipationError(Exception):
    """A row naming an account that already holds a participation in this
    run — distinct from reuse, where the account exists elsewhere and gains
    a participation here (api-surface.md §2.4)."""

    def __init__(self, username: str) -> None:
        super().__init__(username)
        self.username = username


def import_participants(
    db: Session,
    run: EventRun,
    rows: Iterable[ParticipantRow],
    *,
    actor_user_id: uuid.UUID,
    action: str = "participants_imported",
) -> ImportReport:
    """api-surface.md §2.4 (added by review): applies **wholly or not at
    all**. Every row is validated — against the run's existing roster and
    against every other row in this same call — before anything is
    written, so one refused row (`DuplicateParticipationError`) refuses the
    whole call rather than leaving a partial roster behind, at exactly the
    point Task 13's preflight would start naming participations with no
    team.

    The `audit_log` row is written by `write_audit`'s own `commit` — after
    every user and participation this call creates is only `add`ed, never
    committed on its own — so one transaction carries the whole set, and
    describes it as one coherent set rather than whichever prefix survived.

    In a `solo` run, each participant's own team is formed immediately
    after their participation is written, via `create_team` — "the one
    place a team is formed without §2.5" (api-surface.md §2.4). Each call
    commits on its own (`create_team`'s own `write_audit`), so a solo
    import's atomicity is per-participant from that point on rather than
    whole-batch: every row was already validated above, before any user,
    participation or team was written, so the only way a later
    participant's `create_team` call could fail is a condition this
    function's own construction rules out — the captain is always that
    same participant, already a member of the one-person team by
    construction, and their own participation was just written in this
    same call.
    """
    ensure_roster_open(run)

    existing_participations = (
        db.execute(select(EventParticipation).where(EventParticipation.event_run_id == run.id))
        .scalars()
        .all()
    )
    existing_user_ids = {p.user_id for p in existing_participations}
    existing_handles = {p.handle for p in existing_participations}

    validated: list[tuple[str, ParticipantRow, User | None]] = []
    seen_in_batch: set[str] = set()
    for row in rows:
        normalized = normalize_username(row.username)
        existing_user = db.execute(
            select(User).where(User.username == normalized)
        ).scalar_one_or_none()
        already_in_run = existing_user is not None and existing_user.id in existing_user_ids
        if already_in_run or normalized in seen_in_batch:
            raise DuplicateParticipationError(normalized)
        seen_in_batch.add(normalized)
        validated.append((normalized, row, existing_user))

    results: list[ImportedParticipant] = []
    for normalized, row, user in validated:
        reused = user is not None
        if user is None:
            user = User(
                username=normalized,
                password_hash=hash_password(normalized),
                role=Role.player,
                is_active=True,
                must_change_password=True,
                display_name=row.name,
                email=row.email,
                preferred_language=run.language_default,
            )
            db.add(user)
            db.flush()

        handle = mint_handle("p", existing_handles)
        existing_handles.add(handle)
        db.add(EventParticipation(user_id=user.id, event_run_id=run.id, handle=handle))
        db.flush()

        if run.participation_mode is ParticipationMode.solo:
            create_team(
                db,
                run,
                name=row.name,
                member_ids=[user.id],
                captain_id=user.id,
                actor_user_id=actor_user_id,
            )

        results.append(
            ImportedParticipant(
                user_id=user.id, username=user.username, handle=handle, reused=reused
            )
        )

    write_audit(
        db,
        actor_user_id=actor_user_id,
        scope=AuditScope.participant,
        event_run_id=run.id,
        action=action,
        target_type="event_run",
        target_id=run.id,
        details={"count": len(results)},
    )

    return ImportReport(participants=results)


def create_participant(
    db: Session, run: EventRun, row: ParticipantRow, *, actor_user_id: uuid.UUID
) -> ImportedParticipant:
    """The single-account form of the import (api-surface.md §2.4): same
    rules, one row — implemented as `import_participants` called with a
    batch of one, rather than a parallel code path, which is what keeps
    reuse and refusal one code path apart for this route too.
    """
    report = import_participants(
        db, run, [row], actor_user_id=actor_user_id, action="participant_created"
    )
    return report.participants[0]
