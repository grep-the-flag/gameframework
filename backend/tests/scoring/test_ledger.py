"""M2-Task-Plan.md Task 16: the append-only score ledger (data-model.md
§3.14, §6; api-surface.md §2.12). Service-level only — `GET /leaderboard`
and the adjustment routes ship in M5; the solve transaction (M3) and the
hint/adjustment writers (M5) are `append_entry`'s only callers. Every test
here drives `services/ledger.py` directly against `db_session`, the same
level `tests/db/test_transactional_invariants.py` uses for the rest of §6.

Two scope decisions settled before this suite was written, both binding:

- `TeamStanding` carries `paid_hints` — a COUNT of `hint_charge` entries,
  not reduced by a later `hint_refund` (§3.14's literal wording: the
  refund is "a positive `hint_refund` entry, not a rollback"). No
  ordering/comparator is implemented here — the full tiebreak also needs
  `team_challenge.solved_at`, which this service does not own; ranking is
  `GET /leaderboard`'s job in M5.
- `leaderboard()` is over the run's teams, not the ledger's rows: it
  starts from `team WHERE event_run_id = run.id` and LEFT JOINs
  `score_entry`, so a team with no entries yet still appears, at 0 — not
  a floor, since a net-negative team must appear at its true negative
  total too.

`append_entry` does not commit. §6: "the solve transaction is atomic —
... writing the `challenge_award` score entry ... commit together or not
at all" — a function that commits cannot be composed into that
transaction, so it flushes only and the caller owns the commit. The
`db_session` fixture's savepoint-per-test isolation does not distinguish
flush from commit for most assertions (both make a row visible to later
queries in the same test), so this is bound by its own test:
`test_append_entry_does_not_commit` calls `append_entry` and then rolls
back the *test's own* session — a wrong implementation that commits
internally would have already released that row past the rollback.
"""

import inspect

import pytest
from sqlalchemy import func, select

from gameframework.db.models.identity import Role
from gameframework.db.models.play import ScoreEntry, ScoreEntrySource, ScoreEntryType
from gameframework.db.models.runs import RunStatus
from gameframework.services import ledger
from gameframework.services.ledger import (
    ChallengeRequiredError,
    ReasonNotAllowedError,
    ReasonRequiredError,
    TeamRunMismatchError,
    append_entry,
    leaderboard,
)

from ..conftest import (
    make_challenge,
    make_event_definition,
    make_event_run,
    make_team,
    make_user,
)

# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------


def test_award_snapshots_points_given_not_recomputed_from_challenge(db_session) -> None:  # type: ignore[no-untyped-def]
    """§3.14: an award entry stores the points it was given. Raising
    `challenge.points` between two awards must leave the first entry
    unchanged, and the second must carry exactly what it was given — bound
    against a fresh read from the database, not the in-memory object, and
    against a value that never coincides with the live `challenge.points`
    at either call, so a service that reads the column live (at write time
    or at read time) cannot pass by coincidence the way it would if the
    caller's `points_delta` always happened to match the current value.
    """
    definition = make_event_definition(db_session)
    run = make_event_run(db_session, definition=definition, status=RunStatus.running)
    challenge = make_challenge(db_session, definition=definition, points=10)
    team_a = make_team(db_session, run=run)
    team_b = make_team(db_session, run=run)

    award_a = append_entry(
        db_session,
        run=run,
        team=team_a,
        entry_type=ScoreEntryType.challenge_award,
        points_delta=10,
        challenge=challenge,
        source=ScoreEntrySource.system,
        idempotency_key=f"award:{team_a.id}:{challenge.id}",
    )

    # Raised well past what award_b will be given below, so award_b's
    # expected value never coincides with the live column either — a
    # write-time substitution bug and a read-time recompute bug would
    # otherwise both slip past a test that only ever passes the current
    # challenge.points as points_delta.
    challenge.points = 999
    db_session.flush()

    award_b = append_entry(
        db_session,
        run=run,
        team=team_b,
        entry_type=ScoreEntryType.challenge_award,
        points_delta=15,
        challenge=challenge,
        source=ScoreEntrySource.system,
        idempotency_key=f"award:{team_b.id}:{challenge.id}",
    )

    db_session.expire_all()
    reloaded_a = db_session.execute(
        select(ScoreEntry).where(ScoreEntry.id == award_a.id)
    ).scalar_one()
    reloaded_b = db_session.execute(
        select(ScoreEntry).where(ScoreEntry.id == award_b.id)
    ).scalar_one()
    assert reloaded_a.points_delta == 10
    assert reloaded_b.points_delta == 15


# ---------------------------------------------------------------------------
# reason: mandatory for admin_adjustment/penalty, forbidden for system types
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("entry_type", [ScoreEntryType.admin_adjustment, ScoreEntryType.penalty])
def test_reason_required_for_admin_types(db_session, entry_type: ScoreEntryType) -> None:  # type: ignore[no-untyped-def]
    run = make_event_run(db_session, status=RunStatus.running)
    team = make_team(db_session, run=run)

    with pytest.raises(ReasonRequiredError):
        append_entry(
            db_session,
            run=run,
            team=team,
            entry_type=entry_type,
            points_delta=-5,
            source=ScoreEntrySource.admin,
        )


@pytest.mark.parametrize(
    ("entry_type", "points_delta"),
    [
        (ScoreEntryType.challenge_award, 10),
        (ScoreEntryType.hint_charge, -1),
        (ScoreEntryType.hint_refund, 1),
    ],
)
def test_reason_not_allowed_for_system_types(
    db_session,  # type: ignore[no-untyped-def]
    entry_type: ScoreEntryType,
    points_delta: int,
) -> None:
    definition = make_event_definition(db_session)
    run = make_event_run(db_session, definition=definition, status=RunStatus.running)
    team = make_team(db_session, run=run)
    challenge = make_challenge(db_session, definition=definition)

    with pytest.raises(ReasonNotAllowedError):
        append_entry(
            db_session,
            run=run,
            team=team,
            entry_type=entry_type,
            points_delta=points_delta,
            challenge=challenge,
            reason="should not be allowed",
            source=ScoreEntrySource.system,
        )


def test_reason_persisted_for_admin_adjustment(db_session) -> None:  # type: ignore[no-untyped-def]
    run = make_event_run(db_session, status=RunStatus.running)
    team = make_team(db_session, run=run)

    entry = append_entry(
        db_session,
        run=run,
        team=team,
        entry_type=ScoreEntryType.admin_adjustment,
        points_delta=5,
        reason="compensation for outage",
        source=ScoreEntrySource.admin,
    )

    assert entry.reason == "compensation for outage"


# ---------------------------------------------------------------------------
# source = admin, actor_user_id = null is legitimate (deleted admin), and
# stays distinguishable from a live actor
# ---------------------------------------------------------------------------


def test_source_admin_with_null_actor_is_legitimate_and_distinguishable(db_session) -> None:  # type: ignore[no-untyped-def]
    run = make_event_run(db_session, status=RunStatus.running)
    team = make_team(db_session, run=run)
    admin = make_user(db_session, role=Role.admin)

    deleted_admin_entry = append_entry(
        db_session,
        run=run,
        team=team,
        entry_type=ScoreEntryType.penalty,
        points_delta=-5,
        reason="rule violation, actor since deleted",
        source=ScoreEntrySource.admin,
        actor=None,
    )
    live_admin_entry = append_entry(
        db_session,
        run=run,
        team=team,
        entry_type=ScoreEntryType.penalty,
        points_delta=-3,
        reason="second violation",
        source=ScoreEntrySource.admin,
        actor=admin,
    )

    assert deleted_admin_entry.source == ScoreEntrySource.admin
    assert deleted_admin_entry.actor_user_id is None
    assert live_admin_entry.source == ScoreEntrySource.admin
    assert live_admin_entry.actor_user_id == admin.id


# ---------------------------------------------------------------------------
# Replay: award:<team_id>:<challenge_id> is one key for all routes to a
# solve; a replay finds the entry already present and inserts nothing
# ---------------------------------------------------------------------------


def test_replay_returns_existing_entry_without_inserting(db_session) -> None:  # type: ignore[no-untyped-def]
    definition = make_event_definition(db_session)
    run = make_event_run(db_session, definition=definition, status=RunStatus.running)
    team = make_team(db_session, run=run)
    challenge = make_challenge(db_session, definition=definition)
    key = f"award:{team.id}:{challenge.id}"

    first = append_entry(
        db_session,
        run=run,
        team=team,
        entry_type=ScoreEntryType.challenge_award,
        points_delta=10,
        challenge=challenge,
        source=ScoreEntrySource.system,
        idempotency_key=key,
    )
    second = append_entry(
        db_session,
        run=run,
        team=team,
        entry_type=ScoreEntryType.challenge_award,
        points_delta=10,
        challenge=challenge,
        source=ScoreEntrySource.system,
        idempotency_key=key,
    )

    assert second.id == first.id
    count = db_session.execute(
        select(func.count()).select_from(ScoreEntry).where(ScoreEntry.idempotency_key == key)
    ).scalar_one()
    assert count == 1


# ---------------------------------------------------------------------------
# §6 run/definition coherence, both axes: team must belong to the given
# run; a challenge must resolve through the run's own event_definition_id
# ---------------------------------------------------------------------------


def test_team_must_belong_to_the_given_run(db_session) -> None:  # type: ignore[no-untyped-def]
    # Only one run may be `running` at a time (uq_event_run_single_active);
    # run_b's own lifecycle status is irrelevant to this test.
    run_a = make_event_run(db_session, status=RunStatus.running)
    run_b = make_event_run(db_session, status=RunStatus.created)
    team_of_run_b = make_team(db_session, run=run_b)

    with pytest.raises(TeamRunMismatchError):
        append_entry(
            db_session,
            run=run_a,
            team=team_of_run_b,
            entry_type=ScoreEntryType.penalty,
            points_delta=-1,
            reason="wrong run",
            source=ScoreEntrySource.admin,
        )


def test_challenge_must_belong_to_the_runs_definition(db_session) -> None:  # type: ignore[no-untyped-def]
    """Mirrors `test_transactional_invariants.py`'s own coherence test:
    two coexisting runs on different definitions, and a challenge from the
    wrong one must not resolve even though both rows exist right now.
    """
    other_definition = make_event_definition(db_session)
    make_event_run(db_session, definition=other_definition, status=RunStatus.created)
    other_challenge = make_challenge(db_session, definition=other_definition)

    definition = make_event_definition(db_session)
    run = make_event_run(db_session, definition=definition, status=RunStatus.running)
    team = make_team(db_session, run=run)

    with pytest.raises(ValueError):
        append_entry(
            db_session,
            run=run,
            team=team,
            entry_type=ScoreEntryType.hint_charge,
            points_delta=-1,
            challenge=other_challenge,
            source=ScoreEntrySource.system,
        )


# ---------------------------------------------------------------------------
# challenge_id: mandatory for challenge_award/hint_charge/hint_refund,
# permitted (not forbidden) for admin_adjustment/penalty
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("entry_type", "points_delta"),
    [
        (ScoreEntryType.challenge_award, 10),
        (ScoreEntryType.hint_charge, -1),
        (ScoreEntryType.hint_refund, 1),
    ],
)
def test_challenge_required_for_system_types(
    db_session,  # type: ignore[no-untyped-def]
    entry_type: ScoreEntryType,
    points_delta: int,
) -> None:
    run = make_event_run(db_session, status=RunStatus.running)
    team = make_team(db_session, run=run)

    with pytest.raises(ChallengeRequiredError):
        append_entry(
            db_session,
            run=run,
            team=team,
            entry_type=entry_type,
            points_delta=points_delta,
            source=ScoreEntrySource.system,
        )


def test_challenge_optional_for_admin_adjustment_without_one(db_session) -> None:  # type: ignore[no-untyped-def]
    run = make_event_run(db_session, status=RunStatus.running)
    team = make_team(db_session, run=run)

    entry = append_entry(
        db_session,
        run=run,
        team=team,
        entry_type=ScoreEntryType.admin_adjustment,
        points_delta=5,
        reason="no challenge context",
        source=ScoreEntrySource.admin,
    )

    assert entry.challenge_id is None


def test_challenge_permitted_for_admin_adjustment_with_one(db_session) -> None:  # type: ignore[no-untyped-def]
    """§2.12: an adjustment can be 'compensation for a failed game' — a
    challenge context is a legitimate case, not one to reject.
    """
    definition = make_event_definition(db_session)
    run = make_event_run(db_session, definition=definition, status=RunStatus.running)
    team = make_team(db_session, run=run)
    challenge = make_challenge(db_session, definition=definition)

    entry = append_entry(
        db_session,
        run=run,
        team=team,
        entry_type=ScoreEntryType.admin_adjustment,
        points_delta=5,
        challenge=challenge,
        reason="compensation for a failed game",
        source=ScoreEntrySource.admin,
    )

    assert entry.challenge_id == challenge.id


# ---------------------------------------------------------------------------
# Append-only: no update or delete path exists. Bound by the absence of a
# path, not by a successful insert.
# ---------------------------------------------------------------------------


def test_ledger_module_exposes_no_update_or_delete_path() -> None:
    public_functions = {
        name
        for name, obj in vars(ledger).items()
        if inspect.isfunction(obj) and inspect.getmodule(obj) is ledger and not name.startswith("_")
    }
    assert public_functions == {"append_entry", "leaderboard"}


# ---------------------------------------------------------------------------
# append_entry does not commit — §6, the solve transaction's atomicity
# ---------------------------------------------------------------------------


def test_append_entry_does_not_commit(db_session) -> None:  # type: ignore[no-untyped-def]
    run = make_event_run(db_session, status=RunStatus.running)
    team = make_team(db_session, run=run)

    entry = append_entry(
        db_session,
        run=run,
        team=team,
        entry_type=ScoreEntryType.penalty,
        points_delta=-5,
        reason="test",
        source=ScoreEntrySource.admin,
    )
    entry_id = entry.id

    db_session.rollback()

    assert db_session.get(ScoreEntry, entry_id) is None


# ---------------------------------------------------------------------------
# leaderboard(): the plain sum, negative allowed; every team of the run
# appears, whether by absence or by cancellation; paid_hints is a count of
# hint_charge entries, unaffected by a later hint_refund; scoped to the run
# ---------------------------------------------------------------------------


def test_leaderboard_sums_points_and_counts_paid_hints_per_team(db_session) -> None:  # type: ignore[no-untyped-def]
    definition = make_event_definition(db_session)
    run = make_event_run(db_session, definition=definition, status=RunStatus.running)
    team = make_team(db_session, run=run)
    challenge = make_challenge(db_session, definition=definition, points=10)

    append_entry(
        db_session,
        run=run,
        team=team,
        entry_type=ScoreEntryType.challenge_award,
        points_delta=10,
        challenge=challenge,
        source=ScoreEntrySource.system,
        idempotency_key=f"award:{team.id}:{challenge.id}",
    )
    append_entry(
        db_session,
        run=run,
        team=team,
        entry_type=ScoreEntryType.hint_charge,
        points_delta=-1,
        challenge=challenge,
        source=ScoreEntrySource.system,
        idempotency_key="msg-1",
    )
    append_entry(
        db_session,
        run=run,
        team=team,
        entry_type=ScoreEntryType.hint_charge,
        points_delta=-1,
        challenge=challenge,
        source=ScoreEntrySource.system,
        idempotency_key="msg-2",
    )
    append_entry(
        db_session,
        run=run,
        team=team,
        entry_type=ScoreEntryType.hint_refund,
        points_delta=1,
        challenge=challenge,
        source=ScoreEntrySource.system,
        idempotency_key="refund-1",
    )
    append_entry(
        db_session,
        run=run,
        team=team,
        entry_type=ScoreEntryType.admin_adjustment,
        points_delta=-3,
        reason="adjustment",
        source=ScoreEntrySource.admin,
    )

    standings = {s.team_id: s for s in leaderboard(db_session, run)}

    assert standings[team.id].points == 6  # 10 - 1 - 1 + 1 - 3
    assert standings[team.id].paid_hints == 2  # the refund does not reduce it


def test_leaderboard_includes_zero_and_negative_teams_scoped_to_run(db_session) -> None:  # type: ignore[no-untyped-def]
    run = make_event_run(db_session, status=RunStatus.running)
    untouched_team = make_team(db_session, run=run)  # zero by absence
    cancelled_team = make_team(db_session, run=run)  # zero by cancellation
    negative_team = make_team(db_session, run=run)

    append_entry(
        db_session,
        run=run,
        team=cancelled_team,
        entry_type=ScoreEntryType.admin_adjustment,
        points_delta=10,
        reason="award",
        source=ScoreEntrySource.admin,
    )
    append_entry(
        db_session,
        run=run,
        team=cancelled_team,
        entry_type=ScoreEntryType.penalty,
        points_delta=-10,
        reason="reversed",
        source=ScoreEntrySource.admin,
    )
    append_entry(
        db_session,
        run=run,
        team=negative_team,
        entry_type=ScoreEntryType.penalty,
        points_delta=-7,
        reason="misconduct",
        source=ScoreEntrySource.admin,
    )

    # Only one run may be `running` at a time (uq_event_run_single_active);
    # this run's own lifecycle status is irrelevant to the scoping claim.
    other_run = make_event_run(db_session, status=RunStatus.created)
    other_team = make_team(db_session, run=other_run)
    append_entry(
        db_session,
        run=other_run,
        team=other_team,
        entry_type=ScoreEntryType.admin_adjustment,
        points_delta=99,
        reason="a different run entirely",
        source=ScoreEntrySource.admin,
    )

    standings = {s.team_id: s for s in leaderboard(db_session, run)}

    assert set(standings) == {untouched_team.id, cancelled_team.id, negative_team.id}
    assert standings[untouched_team.id].points == 0
    assert standings[untouched_team.id].paid_hints == 0
    assert standings[cancelled_team.id].points == 0
    assert standings[negative_team.id].points == -7


def test_leaderboard_empty_run_has_no_standings(db_session) -> None:  # type: ignore[no-untyped-def]
    run = make_event_run(db_session, status=RunStatus.created)
    assert leaderboard(db_session, run) == []
