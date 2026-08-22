"""Participant import and single creation (M2-Task-Plan.md Task 7;
api-surface.md §2.4, §2.17; data-model.md §3.10). Solo-mode team creation is
Task 8's, which owns the team machinery it needs — this module writes
`event_participation` rows only, never `team`.
"""

import secrets
import uuid
from collections.abc import Iterable
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.db.models.feedback import AuditScope
from gameframework.db.models.identity import Role, User
from gameframework.db.models.runs import EventParticipation, EventRun, RunStatus
from gameframework.services.audit import write_audit
from gameframework.services.passwords import hash_password
from gameframework.services.users import normalize_username

# 3 bytes = 6 hex chars: "p-abcdef" is 8 characters, comfortably inside
# data-model.md §3.10's ^[a-z][a-z0-9-]{1,27}$ body limit.
_HANDLE_SUFFIX_BYTES = 3


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


class RosterFrozenError(Exception):
    """api-surface.md §2.4: a roster write once the run has left `created`
    — the roster freezes at `start` (§2.5)."""


class DuplicateParticipationError(Exception):
    """A row naming an account that already holds a participation in this
    run — distinct from reuse, where the account exists elsewhere and gains
    a participation here (api-surface.md §2.4)."""

    def __init__(self, username: str) -> None:
        super().__init__(username)
        self.username = username


def mint_handle(prefix: str, existing: set[str]) -> str:
    """data-model.md §3.10: `^[a-z][a-z0-9-]{1,27}$`, unique **per run** —
    `existing` is the caller's set of handles already taken in the run being
    minted into, so a collision within that one run is retried rather than
    minted twice. Not globally unique: the same value may recur in a
    different run, which the composite `(event_run_id, handle)` index
    (data-model.md §6) allows and this function has no reason to prevent.
    """
    while True:
        candidate = f"{prefix}-{secrets.token_hex(_HANDLE_SUFFIX_BYTES)}"
        if candidate not in existing:
            return candidate


def _ensure_roster_open(run: EventRun) -> None:
    if run.status is not RunStatus.created:
        raise RosterFrozenError()


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
    """
    _ensure_roster_open(run)

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
