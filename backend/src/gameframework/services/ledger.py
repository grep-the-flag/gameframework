"""The append-only score ledger (M2-Task-Plan.md Task 16; data-model.md
§3.14, §6; api-surface.md §2.12). Service-level only: `GET /leaderboard`
and the adjustment routes ship in M5; `append_entry`'s only callers are the
solve transaction (M3) and the hint/adjustment writers (M5).

`append_entry` does not commit. §6: "the solve transaction is atomic —
marking `team_challenge` solved, ... writing the `challenge_award` score
entry, ... and the audit row commit together or not at all." A function
that commits its own transaction cannot be composed into that one, so this
flushes only — the caller owns the commit, exactly as it owns the rest of
the transaction this entry is one step of.

Replay is check-then-act, not catch-and-requery: a retried caller supplies
the same `idempotency_key` and finds its entry already present. A
genuinely concurrent caller instead loses to `score_entry`'s unique index
at flush — that IntegrityError is the index doing the job it exists for,
not a case this service defends against itself.

`leaderboard()` is over the run's teams, not the ledger's rows: it starts
from `team` and LEFT JOINs `score_entry`, so a team with no entries yet
still appears, at 0 — which is not a floor, since a team whose corrections
net negative must appear at its true negative total too. `TeamStanding`
carries `paid_hints`, the tiebreak input §3.14 says is "derived from this
ledger" — a COUNT of `hint_charge` entries, not reduced by a later
`hint_refund` (the refund is its own positive entry, never a rollback).
No ordering or comparator is implemented here: the full tiebreak also
needs `team_challenge.solved_at`, which this service does not own: ranking
belongs to `GET /leaderboard` in M5.
"""

import uuid
from dataclasses import dataclass

from sqlalchemy import Case, case, func, select
from sqlalchemy.orm import Session

from gameframework.db.models.authoring import Challenge
from gameframework.db.models.identity import User
from gameframework.db.models.play import ScoreEntry, ScoreEntrySource, ScoreEntryType
from gameframework.db.models.runs import EventRun, Team
from gameframework.services.invariants import resolve_challenge_for_definition

# §3.14: "set for `challenge_award`, `hint_charge`, `hint_refund`; null for
# entries with no challenge context" — mandatory for these three.
_CHALLENGE_REQUIRED_TYPES = (
    ScoreEntryType.challenge_award,
    ScoreEntryType.hint_charge,
    ScoreEntryType.hint_refund,
)
# §3.14: `reason` is "mandatory for `admin_adjustment` and `penalty`, null for
# system entries". Keyed on `entry_type`, not on `source`: a `challenge_award`
# carries no reason regardless of who caused it, because §3.12 puts the
# earned-vs-force-solved distinction in `audit_log` rather than in this row.
# Whether a force-solved award is written with `source = admin` is M3's to decide;
# nothing here depends on the answer.
_REASON_REQUIRED_TYPES = (
    ScoreEntryType.admin_adjustment,
    ScoreEntryType.penalty,
)


class ReasonRequiredError(Exception):
    """§3.14: `reason` is mandatory for `admin_adjustment` and `penalty`."""


class ReasonNotAllowedError(Exception):
    """§3.14: `reason` is null for system entries. Read prohibitively, unlike
    `challenge_id`'s parallel "null for entries with no challenge context"
    (kept permissive): `reason` is PII, free text that "may name individuals
    or describe their conduct", and a system entry has no accountable human
    behind it — forbidding it keeps unattributable free text about a person
    out of the ledger. `challenge_id` carries no such risk.
    """


class ChallengeRequiredError(Exception):
    """§3.14: `challenge_id` is set for `challenge_award`, `hint_charge`
    and `hint_refund` — these have no "no challenge context" case.
    """


class TeamRunMismatchError(Exception):
    """§6 run/definition coherence, the team half: every row joining a
    team with a challenge joins a team of run R — `resolve_challenge_for_
    definition` covers the challenge half only.
    """


@dataclass(frozen=True)
class TeamStanding:
    team_id: uuid.UUID
    points: int
    paid_hints: int


def append_entry(
    db: Session,
    *,
    run: EventRun,
    team: Team,
    entry_type: ScoreEntryType,
    points_delta: int,
    challenge: Challenge | None = None,
    reason: str | None = None,
    source: ScoreEntrySource,
    actor: User | None = None,
    idempotency_key: str | None = None,
) -> ScoreEntry:
    """Replay-safe via `idempotency_key`; does not commit (see module
    docstring). `points_delta` is stored exactly as given and never
    re-derived — that is the whole of §3.14's snapshot guarantee, since a
    later `PATCH` raising `challenge.points` has nothing left here to
    reach.
    """
    if idempotency_key is not None:
        existing = db.execute(
            select(ScoreEntry).where(ScoreEntry.idempotency_key == idempotency_key)
        ).scalar_one_or_none()
        if existing is not None:
            return existing

    if team.event_run_id != run.id:
        raise TeamRunMismatchError(
            f"team {team.id} belongs to run {team.event_run_id}, not {run.id}"
        )

    if challenge is not None:
        resolve_challenge_for_definition(db, run.event_definition_id, challenge.id)
    elif entry_type in _CHALLENGE_REQUIRED_TYPES:
        raise ChallengeRequiredError(f"{entry_type} requires a challenge")

    if entry_type in _REASON_REQUIRED_TYPES:
        if not reason:
            raise ReasonRequiredError(f"{entry_type} requires a reason")
    elif reason is not None:
        raise ReasonNotAllowedError(f"{entry_type} entries carry no reason")

    entry = ScoreEntry(
        event_run_id=run.id,
        team_id=team.id,
        challenge_id=challenge.id if challenge is not None else None,
        entry_type=entry_type,
        points_delta=points_delta,
        reason=reason,
        source=source,
        actor_user_id=actor.id if actor is not None else None,
        idempotency_key=idempotency_key,
    )
    db.add(entry)
    db.flush()
    return entry


def leaderboard(db: Session, run: EventRun) -> list[TeamStanding]:
    """`SUM(points_delta)` per team, negative allowed, over every team of
    the run — not just the ones with entries — plus the paid-hints
    tiebreak input. No ordering: ranking is `GET /leaderboard`'s job in M5.
    """
    hint_charge_case: Case[int] = case((ScoreEntry.entry_type == ScoreEntryType.hint_charge, 1))
    rows = db.execute(
        select(
            Team.id,
            func.coalesce(func.sum(ScoreEntry.points_delta), 0),
            func.count(hint_charge_case),
        )
        .select_from(Team)
        .outerjoin(ScoreEntry, ScoreEntry.team_id == Team.id)
        .where(Team.event_run_id == run.id)
        .group_by(Team.id)
    ).all()
    return [
        TeamStanding(team_id=team_id, points=points, paid_hints=paid_hints)
        for team_id, points, paid_hints in rows
    ]
