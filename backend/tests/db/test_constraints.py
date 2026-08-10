"""One test per entry in data-model.md §6's database-enforced list (40
entries — see the Step 3 report for how they were counted). Each test names
the exact constraint it expects to violate via `psycopg`'s `diag
.constraint_name`, because "some IntegrityError occurred" would also pass
against the wrong constraint. Partial indexes additionally prove the
negative case: a row that violates the naive (non-partial) reading must be
*accepted*. Deletion rules are FK behaviours, not constraints, and are
proven by deleting the parent and inspecting the child, not by
`IntegrityError`.

Every violation here forces `db_session` to roll back to its SAVEPOINT and
keep going — this suite is the fixtures' proof, not a separate concern.

The data factories (make_user, make_team, ...) live in conftest.py, shared
with every other suite that needs a minimal valid row — see its module
docstring.
"""

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from gameframework.db.models.communication import (
    AiConversation,
    AiMessage,
    AiMessageRole,
    ChatMessage,
    Ticket,
    TicketMessage,
    TicketStatus,
)
from gameframework.db.models.feedback import AuditLog, AuditScope, Rating
from gameframework.db.models.identity import BlockedAddress, Role, User
from gameframework.db.models.infrastructure import JobState
from gameframework.db.models.play import (
    ScoreEntry,
    ScoreEntrySource,
    ScoreEntryType,
    TeamChallenge,
    TeamChallengeState,
    VaultEntry,
)
from gameframework.db.models.runs import EventParticipation, RunStatus
from gameframework.db.models.runtime import MinigamePort, PortSource

from ..conftest import (
    make_blocked_address,
    make_challenge,
    make_event_definition,
    make_event_run,
    make_installed_artifact,
    make_job,
    make_minigame_instance,
    make_minigame_port,
    make_participation,
    make_reward_definition,
    make_team,
    make_user,
)

# --------------------------------------------------------------------------
# assertion helper
# --------------------------------------------------------------------------


def _assert_violates(exc_info: pytest.ExceptionInfo[IntegrityError], constraint_name: str) -> None:
    """The whole point of naming a constraint: a test that only checked
    `IntegrityError` would also pass if the row tripped some other
    constraint first, silently proving nothing about the one it names.
    """
    actual = exc_info.value.orig.diag.constraint_name  # type: ignore[union-attr]
    assert actual == constraint_name, (
        f"expected a violation of {constraint_name!r}, got {actual!r}: {exc_info.value.orig}"
    )


# --------------------------------------------------------------------------
# identity and access — §6 lines 881-883
# --------------------------------------------------------------------------


def test_user_password_hash_not_null(db_session: Session) -> None:
    """§6 line 881."""
    user = User(
        username=f"user-{uuid.uuid4().hex}",
        password_hash=None,  # type: ignore[arg-type]
        role=Role.player,
        is_active=True,
        must_change_password=False,
        preferred_language="en",
    )
    db_session.add(user)
    with pytest.raises(IntegrityError) as exc_info:
        db_session.flush()
    assert exc_info.value.orig.diag.constraint_name is None  # type: ignore[union-attr]
    assert "password_hash" in str(exc_info.value.orig)
    assert exc_info.value.orig.sqlstate == "23502"  # type: ignore[union-attr]  # not_null_violation
    db_session.rollback()


def test_user_username_unique(db_session: Session) -> None:
    """§6 line 882."""
    make_user(db_session, username="dupe-handle")

    with pytest.raises(IntegrityError) as exc_info:
        make_user(db_session, username="dupe-handle")
    _assert_violates(exc_info, "user_username_key")
    db_session.rollback()


def test_blocked_address_address_unique(db_session: Session) -> None:
    """§6 line 892."""
    make_blocked_address(db_session, address="203.0.113.5/32")

    with pytest.raises(IntegrityError) as exc_info:
        make_blocked_address(db_session, address="203.0.113.5/32")
    _assert_violates(exc_info, "blocked_address_address_key")
    db_session.rollback()


# --------------------------------------------------------------------------
# runs, participation and teams — §6 lines 883-884, 886, 891
# --------------------------------------------------------------------------


def test_event_participation_user_run_unique(db_session: Session) -> None:
    """§6 line 883."""
    user = make_user(db_session)
    run = make_event_run(db_session)
    make_participation(db_session, user=user, run=run)

    with pytest.raises(IntegrityError) as exc_info:
        make_participation(db_session, user=user, run=run)
    _assert_violates(exc_info, "event_participation_user_id_event_run_id_key")
    db_session.rollback()


def test_event_participation_team_run_composite_fk(db_session: Session) -> None:
    """§6 line 884: a team from a DIFFERENT run must be unrepresentable,
    not merely "some invalid team_id" — using a team that genuinely exists
    (just under the wrong run) is what actually exercises the composite FK
    rather than a plain single-column one.
    """
    run_a = make_event_run(db_session)
    run_b = make_event_run(db_session)
    team_in_run_a = make_team(db_session, run=run_a)
    user = make_user(db_session)

    participation = EventParticipation(
        user_id=user.id,
        event_run_id=run_b.id,
        team_id=team_in_run_a.id,
        handle="p-cross-run",
    )
    db_session.add(participation)
    with pytest.raises(IntegrityError) as exc_info:
        db_session.flush()
    _assert_violates(exc_info, "fk_event_participation_team")
    db_session.rollback()


def test_event_run_single_running_or_paused_partial_unique(db_session: Session) -> None:
    """§6 line 886. Negative case: two runs *outside* the predicate (both
    `created`) must be accepted — proving this is a partial index scoped to
    running/paused, not a blanket "one run ever" rule.
    """
    make_event_run(db_session, status=RunStatus.running)

    with pytest.raises(IntegrityError) as exc_info:
        make_event_run(db_session, status=RunStatus.paused)
    _assert_violates(exc_info, "uq_event_run_single_active")
    db_session.rollback()

    make_event_run(db_session, status=RunStatus.created)
    make_event_run(db_session, status=RunStatus.created)


def test_team_handle_unique_per_run(db_session: Session) -> None:
    """§6 line 891."""
    run = make_event_run(db_session)
    make_team(db_session, run=run, handle="dupe-handle")

    with pytest.raises(IntegrityError) as exc_info:
        make_team(db_session, run=run, handle="dupe-handle")
    _assert_violates(exc_info, "team_event_run_id_handle_key")
    db_session.rollback()


def test_event_participation_handle_unique_per_run(db_session: Session) -> None:
    """§6 line 891."""
    run = make_event_run(db_session)
    make_participation(db_session, run=run, handle="dupe-handle")

    with pytest.raises(IntegrityError) as exc_info:
        make_participation(db_session, run=run, handle="dupe-handle")
    _assert_violates(exc_info, "event_participation_event_run_id_handle_key")
    db_session.rollback()


# --------------------------------------------------------------------------
# event authoring — §6 line 890
# --------------------------------------------------------------------------


def test_challenge_order_num_unique_per_definition(db_session: Session) -> None:
    """§6 line 890."""
    definition = make_event_definition(db_session)
    make_challenge(db_session, definition=definition, order_num=1)

    with pytest.raises(IntegrityError) as exc_info:
        make_challenge(db_session, definition=definition, order_num=1)
    _assert_violates(exc_info, "challenge_event_definition_id_order_num_key")
    db_session.rollback()


def test_challenge_slug_unique_per_definition(db_session: Session) -> None:
    """§6 line 890."""
    definition = make_event_definition(db_session)
    make_challenge(db_session, definition=definition, slug="dupe-slug", order_num=1)

    with pytest.raises(IntegrityError) as exc_info:
        make_challenge(db_session, definition=definition, slug="dupe-slug", order_num=2)
    _assert_violates(exc_info, "challenge_event_definition_id_slug_key")
    db_session.rollback()


def test_challenge_minigame_host_label_unique_per_definition(db_session: Session) -> None:
    """§6 line 890."""
    definition = make_event_definition(db_session)
    make_challenge(db_session, definition=definition, minigame_host_label="dupe-label", order_num=1)

    with pytest.raises(IntegrityError) as exc_info:
        make_challenge(
            db_session, definition=definition, minigame_host_label="dupe-label", order_num=2
        )
    _assert_violates(exc_info, "challenge_event_definition_id_minigame_host_label_key")
    db_session.rollback()


# --------------------------------------------------------------------------
# play state — §6 lines 885, 887-889, 896 (idempotency_key half)
# --------------------------------------------------------------------------


def test_team_challenge_active_or_provisioning_partial_unique(db_session: Session) -> None:
    """§6 line 885. Negative case: a second row for the same team *outside*
    the predicate (`locked`) must be accepted — a plain `UNIQUE(team_id)`
    index would wrongly reject it too.
    """
    team = make_team(db_session)
    challenge_a = make_challenge(db_session, order_num=1)
    challenge_b = make_challenge(db_session, order_num=2)
    challenge_c = make_challenge(db_session, order_num=3)
    db_session.add(
        TeamChallenge(
            team_id=team.id,
            challenge_id=challenge_a.id,
            state=TeamChallengeState.provisioning,
            provision_attempts=0,
        )
    )
    db_session.flush()

    db_session.add(
        TeamChallenge(
            team_id=team.id,
            challenge_id=challenge_b.id,
            state=TeamChallengeState.active,
            provision_attempts=0,
        )
    )
    with pytest.raises(IntegrityError) as exc_info:
        db_session.flush()
    _assert_violates(exc_info, "uq_team_challenge_active_per_team")
    db_session.rollback()

    db_session.add(
        TeamChallenge(
            team_id=team.id,
            challenge_id=challenge_c.id,
            state=TeamChallengeState.locked,
            provision_attempts=0,
        )
    )
    db_session.flush()


def test_vault_entry_team_reward_unique(db_session: Session) -> None:
    """§6 line 887."""
    run = make_event_run(db_session)
    team = make_team(db_session, run=run)
    reward = make_reward_definition(db_session)
    db_session.add(
        VaultEntry(
            event_run_id=run.id,
            team_id=team.id,
            reward_definition_id=reward.id,
            encrypted_value=b"x",
        )
    )
    db_session.flush()

    db_session.add(
        VaultEntry(
            event_run_id=run.id,
            team_id=team.id,
            reward_definition_id=reward.id,
            encrypted_value=b"y",
        )
    )
    with pytest.raises(IntegrityError) as exc_info:
        db_session.flush()
    _assert_violates(exc_info, "vault_entry_team_id_reward_definition_id_key")
    db_session.rollback()


def test_ai_conversation_team_challenge_unique(db_session: Session) -> None:
    """§6 line 888."""
    team = make_team(db_session)
    challenge = make_challenge(db_session)
    db_session.add(AiConversation(team_id=team.id, challenge_id=challenge.id))
    db_session.flush()

    db_session.add(AiConversation(team_id=team.id, challenge_id=challenge.id))
    with pytest.raises(IntegrityError) as exc_info:
        db_session.flush()
    _assert_violates(exc_info, "ai_conversation_team_id_challenge_id_key")
    db_session.rollback()


def test_rating_run_minigame_team_unique(db_session: Session) -> None:
    """§6 line 889."""
    run = make_event_run(db_session)
    team = make_team(db_session, run=run)
    db_session.add(Rating(event_run_id=run.id, minigame_id="demo", team_id=team.id, stars=5))
    db_session.flush()

    db_session.add(Rating(event_run_id=run.id, minigame_id="demo", team_id=team.id, stars=3))
    with pytest.raises(IntegrityError) as exc_info:
        db_session.flush()
    _assert_violates(exc_info, "rating_event_run_id_minigame_id_team_id_key")
    db_session.rollback()


def test_score_entry_idempotency_key_unique_when_set(db_session: Session) -> None:
    """§6 line 896 (first half). Negative case: two rows with no
    idempotency key at all must both be accepted — standard SQL NULL
    semantics, not a partial index, is what "unique when set" relies on.
    """
    run = make_event_run(db_session)
    team = make_team(db_session, run=run)
    db_session.add(
        ScoreEntry(
            event_run_id=run.id,
            team_id=team.id,
            entry_type=ScoreEntryType.hint_charge,
            points_delta=-1,
            source=ScoreEntrySource.system,
            idempotency_key="dupe-key",
        )
    )
    db_session.flush()

    db_session.add(
        ScoreEntry(
            event_run_id=run.id,
            team_id=team.id,
            entry_type=ScoreEntryType.hint_charge,
            points_delta=-1,
            source=ScoreEntrySource.system,
            idempotency_key="dupe-key",
        )
    )
    with pytest.raises(IntegrityError) as exc_info:
        db_session.flush()
    _assert_violates(exc_info, "score_entry_idempotency_key_key")
    db_session.rollback()

    db_session.add(
        ScoreEntry(
            event_run_id=run.id,
            team_id=team.id,
            entry_type=ScoreEntryType.challenge_award,
            points_delta=10,
            source=ScoreEntrySource.system,
            idempotency_key=None,
        )
    )
    db_session.add(
        ScoreEntry(
            event_run_id=run.id,
            team_id=team.id,
            entry_type=ScoreEntryType.challenge_award,
            points_delta=10,
            source=ScoreEntrySource.system,
            idempotency_key=None,
        )
    )
    db_session.flush()


def test_score_entry_points_delta_nonzero_check(db_session: Session) -> None:
    """§6 line 895: `ck_score_entry_points_delta_nonzero` — a zero-delta
    entry would be a ledger row that moves nothing. Added in this task's own
    migration (747148e09c2b), on top of Task 1's merged one.
    """
    run = make_event_run(db_session)
    team = make_team(db_session, run=run)

    db_session.add(
        ScoreEntry(
            event_run_id=run.id,
            team_id=team.id,
            entry_type=ScoreEntryType.admin_adjustment,
            points_delta=0,
            source=ScoreEntrySource.admin,
            reason="typo correction attempt",
        )
    )
    with pytest.raises(IntegrityError) as exc_info:
        db_session.flush()
    _assert_violates(exc_info, "ck_score_entry_points_delta_nonzero")
    db_session.rollback()


# --------------------------------------------------------------------------
# minigame runtime — §6 lines 896 (job half), 897-901
# --------------------------------------------------------------------------


def test_job_business_key_unique_for_non_terminal_partial_unique(db_session: Session) -> None:
    """§6 line 896 (second half). Negative case: a *terminal* job with the
    same key must be accepted — a `dead` job must not block re-enqueuing
    its business key (data-model.md §3.24).
    """
    make_job(db_session, job_type="provision", business_key="dupe-key", state=JobState.pending)

    with pytest.raises(IntegrityError) as exc_info:
        make_job(db_session, job_type="provision", business_key="dupe-key", state=JobState.leased)
    _assert_violates(exc_info, "uq_job_business_key_non_terminal")
    db_session.rollback()

    make_job(db_session, job_type="provision", business_key="dupe-key", state=JobState.dead)


def test_minigame_instance_run_minigame_id_unique(db_session: Session) -> None:
    """§6 line 897. hostname left null on both sides (nullable, no collision
    risk) to isolate the minigame_id dimension specifically.
    """
    run = make_event_run(db_session)
    make_minigame_instance(db_session, run=run, minigame_id="dupe-id")

    with pytest.raises(IntegrityError) as exc_info:
        make_minigame_instance(db_session, run=run, minigame_id="dupe-id")
    _assert_violates(exc_info, "minigame_instance_event_run_id_minigame_id_key")
    db_session.rollback()


def test_minigame_instance_run_hostname_unique(db_session: Session) -> None:
    """§6 line 897. minigame_id varies between the two rows so only the
    hostname dimension is under test.
    """
    run = make_event_run(db_session)
    make_minigame_instance(db_session, run=run, hostname="dupe.event.example.com")

    with pytest.raises(IntegrityError) as exc_info:
        make_minigame_instance(db_session, run=run, hostname="dupe.event.example.com")
    _assert_violates(exc_info, "minigame_instance_event_run_id_hostname_key")
    db_session.rollback()


def test_minigame_port_host_port_live_partial_unique(db_session: Session) -> None:
    """§6 line 898. Installation-wide, not per-instance: uses two different
    instances with two different container_ports (so the OTHER unique
    constraint on this table can't also fire) and the same host_port.
    Negative case: a *released* port with the same host_port is accepted.
    """
    instance_a = make_minigame_instance(db_session)
    instance_b = make_minigame_instance(db_session)
    make_minigame_port(db_session, instance_a, container_port=10, host_port=9000)

    with pytest.raises(IntegrityError) as exc_info:
        make_minigame_port(db_session, instance_b, container_port=20, host_port=9000)
    _assert_violates(exc_info, "uq_minigame_port_live_host_port")
    db_session.rollback()

    instance_a = make_minigame_instance(db_session)
    instance_b = make_minigame_instance(db_session)
    make_minigame_port(db_session, instance_a, container_port=10, host_port=9001)
    make_minigame_port(
        db_session,
        instance_b,
        container_port=20,
        host_port=9001,
        released_at=datetime.now(UTC),
    )


def test_minigame_port_instance_container_port_unique(db_session: Session) -> None:
    """§6 line 899. host_port varies between the two rows so only the
    (instance, container_port) dimension is under test.
    """
    instance = make_minigame_instance(db_session)
    make_minigame_port(db_session, instance, container_port=22, host_port=9000)

    with pytest.raises(IntegrityError) as exc_info:
        make_minigame_port(db_session, instance, container_port=22, host_port=9001)
    _assert_violates(exc_info, "minigame_port_minigame_instance_id_container_port_key")
    db_session.rollback()


def test_minigame_port_override_reason_check(db_session: Session) -> None:
    """§6 line 900: `(source = 'override') = (override_reason IS NOT NULL)`
    is a biconditional — both accepted combinations and both violating ones
    are exercised.
    """
    instance = make_minigame_instance(db_session)

    make_minigame_port(
        db_session,
        instance,
        container_port=1,
        host_port=9101,
        source=PortSource.override,
        override_reason="operator correction",
    )
    make_minigame_port(
        db_session,
        instance,
        container_port=2,
        host_port=9102,
        source=PortSource.allocated,
        override_reason=None,
    )

    with pytest.raises(IntegrityError) as exc_info:
        make_minigame_port(
            db_session,
            instance,
            container_port=3,
            host_port=9103,
            source=PortSource.override,
            override_reason=None,
        )
    _assert_violates(exc_info, "ck_minigame_port_override_reason")
    db_session.rollback()

    with pytest.raises(IntegrityError) as exc_info:
        make_minigame_port(
            db_session,
            instance,
            container_port=4,
            host_port=9104,
            source=PortSource.allocated,
            override_reason="reason given anyway",
        )
    _assert_violates(exc_info, "ck_minigame_port_override_reason")
    db_session.rollback()


def test_minigame_port_container_port_range_check(db_session: Session) -> None:
    """§6 line 901."""
    instance = make_minigame_instance(db_session)

    with pytest.raises(IntegrityError) as exc_info:
        make_minigame_port(db_session, instance, container_port=0, host_port=9200)
    _assert_violates(exc_info, "ck_minigame_port_container_port_range")
    db_session.rollback()

    with pytest.raises(IntegrityError) as exc_info:
        make_minigame_port(db_session, instance, container_port=65536, host_port=9201)
    _assert_violates(exc_info, "ck_minigame_port_container_port_range")
    db_session.rollback()


def test_minigame_port_host_port_range_check(db_session: Session) -> None:
    """§6 line 901."""
    instance = make_minigame_instance(db_session)

    with pytest.raises(IntegrityError) as exc_info:
        make_minigame_port(db_session, instance, container_port=30, host_port=0)
    _assert_violates(exc_info, "ck_minigame_port_host_port_range")
    db_session.rollback()

    with pytest.raises(IntegrityError) as exc_info:
        make_minigame_port(db_session, instance, container_port=31, host_port=65536)
    _assert_violates(exc_info, "ck_minigame_port_host_port_range")
    db_session.rollback()


def test_rating_stars_range_check(db_session: Session) -> None:
    """§6 line 901."""
    run = make_event_run(db_session)
    team = make_team(db_session, run=run)

    db_session.add(Rating(event_run_id=run.id, minigame_id="demo", team_id=team.id, stars=0))
    with pytest.raises(IntegrityError) as exc_info:
        db_session.flush()
    _assert_violates(exc_info, "ck_rating_stars_range")
    db_session.rollback()

    db_session.add(Rating(event_run_id=run.id, minigame_id="demo", team_id=team.id, stars=6))
    with pytest.raises(IntegrityError) as exc_info:
        db_session.flush()
    _assert_violates(exc_info, "ck_rating_stars_range")
    db_session.rollback()


# --------------------------------------------------------------------------
# infrastructure — §6 line 893
# --------------------------------------------------------------------------


def test_installed_artifact_type_id_version_unique(db_session: Session) -> None:
    """§6 line 893."""
    make_installed_artifact(db_session, artifact_id="dupe", version="1.0.0")

    with pytest.raises(IntegrityError) as exc_info:
        make_installed_artifact(db_session, artifact_id="dupe", version="1.0.0")
    _assert_violates(exc_info, "installed_artifact_type_artifact_id_version_key")
    db_session.rollback()


# --------------------------------------------------------------------------
# feedback and audit — §6 line 894
# --------------------------------------------------------------------------


def test_audit_log_scope_participant_requires_event_run_id(db_session: Session) -> None:
    """§6 line 894: `scope = 'participant' <=> event_run_id IS NOT NULL` is
    a biconditional — both accepted combinations and both violating ones
    are exercised.
    """
    run = make_event_run(db_session)

    db_session.add(
        AuditLog(
            scope=AuditScope.participant,
            event_run_id=run.id,
            action="a",
            target_type="t",
            target_id=uuid.uuid4(),
            details={},
        )
    )
    db_session.flush()
    db_session.add(
        AuditLog(
            scope=AuditScope.installation,
            event_run_id=None,
            action="a",
            target_type="t",
            target_id=uuid.uuid4(),
            details={},
        )
    )
    db_session.flush()

    db_session.add(
        AuditLog(
            scope=AuditScope.participant,
            event_run_id=None,
            action="a",
            target_type="t",
            target_id=uuid.uuid4(),
            details={},
        )
    )
    with pytest.raises(IntegrityError) as exc_info:
        db_session.flush()
    _assert_violates(exc_info, "ck_audit_log_scope_event_run")
    db_session.rollback()

    db_session.add(
        AuditLog(
            scope=AuditScope.installation,
            event_run_id=run.id,
            action="a",
            target_type="t",
            target_id=uuid.uuid4(),
            details={},
        )
    )
    with pytest.raises(IntegrityError) as exc_info:
        db_session.flush()
    _assert_violates(exc_info, "ck_audit_log_scope_event_run")
    db_session.rollback()


# --------------------------------------------------------------------------
# deletion rules — §6 line 902 (FK behaviours, not IntegrityError shapes)
# --------------------------------------------------------------------------


def test_chat_message_author_set_null_when_user_deleted(db_session: Session) -> None:
    """§6 line 902: chat_message.author_user_id ON DELETE SET NULL."""
    team = make_team(db_session)
    author = make_user(db_session)
    message = ChatMessage(team_id=team.id, author_user_id=author.id, body="hi")
    db_session.add(message)
    db_session.flush()
    message_id = message.id

    # Prove the "before" state, not just the "after": a child row that never
    # existed, or never actually referenced this parent, would also show
    # `author_user_id is None` once queried post-delete.
    pre_delete = db_session.execute(
        select(ChatMessage).where(ChatMessage.id == message_id)
    ).scalar_one()
    assert pre_delete.author_user_id == author.id

    db_session.delete(author)
    db_session.flush()
    # The SET NULL happened server-side, inside Postgres's own FK action —
    # nothing here told SQLAlchemy's identity map about it, so the child
    # object (if already loaded, as it is here) would otherwise still show
    # its pre-delete, now-stale value on the next access.
    db_session.expire_all()

    reloaded = db_session.execute(
        select(ChatMessage).where(ChatMessage.id == message_id)
    ).scalar_one()
    assert reloaded.author_user_id is None


def test_ticket_opened_by_set_null_when_user_deleted(db_session: Session) -> None:
    """§6 line 902: ticket.opened_by_user_id ON DELETE SET NULL."""
    team = make_team(db_session)
    opener = make_user(db_session)
    ticket = Ticket(
        team_id=team.id, opened_by_user_id=opener.id, title="t", status=TicketStatus.open
    )
    db_session.add(ticket)
    db_session.flush()
    ticket_id = ticket.id

    pre_delete = db_session.execute(select(Ticket).where(Ticket.id == ticket_id)).scalar_one()
    assert pre_delete.opened_by_user_id == opener.id

    db_session.delete(opener)
    db_session.flush()
    # The SET NULL happened server-side, inside Postgres's own FK action —
    # nothing here told SQLAlchemy's identity map about it, so the child
    # object (if already loaded, as it is here) would otherwise still show
    # its pre-delete, now-stale value on the next access.
    db_session.expire_all()

    reloaded = db_session.execute(select(Ticket).where(Ticket.id == ticket_id)).scalar_one()
    assert reloaded.opened_by_user_id is None


def test_ticket_assigned_to_set_null_when_user_deleted(db_session: Session) -> None:
    """§6 line 902: ticket.assigned_to_user_id ON DELETE SET NULL."""
    team = make_team(db_session)
    assignee = make_user(db_session)
    ticket = Ticket(
        team_id=team.id, assigned_to_user_id=assignee.id, title="t", status=TicketStatus.open
    )
    db_session.add(ticket)
    db_session.flush()
    ticket_id = ticket.id

    pre_delete = db_session.execute(select(Ticket).where(Ticket.id == ticket_id)).scalar_one()
    assert pre_delete.assigned_to_user_id == assignee.id

    db_session.delete(assignee)
    db_session.flush()
    # The SET NULL happened server-side, inside Postgres's own FK action —
    # nothing here told SQLAlchemy's identity map about it, so the child
    # object (if already loaded, as it is here) would otherwise still show
    # its pre-delete, now-stale value on the next access.
    db_session.expire_all()

    reloaded = db_session.execute(select(Ticket).where(Ticket.id == ticket_id)).scalar_one()
    assert reloaded.assigned_to_user_id is None


def test_ticket_message_author_set_null_when_user_deleted(db_session: Session) -> None:
    """§6 line 902: ticket_message.author_user_id ON DELETE SET NULL."""
    team = make_team(db_session)
    ticket = Ticket(team_id=team.id, title="t", status=TicketStatus.open)
    db_session.add(ticket)
    db_session.flush()
    author = make_user(db_session)
    message = TicketMessage(ticket_id=ticket.id, author_user_id=author.id, body="hi")
    db_session.add(message)
    db_session.flush()
    message_id = message.id

    pre_delete = db_session.execute(
        select(TicketMessage).where(TicketMessage.id == message_id)
    ).scalar_one()
    assert pre_delete.author_user_id == author.id

    db_session.delete(author)
    db_session.flush()
    # The SET NULL happened server-side, inside Postgres's own FK action —
    # nothing here told SQLAlchemy's identity map about it, so the child
    # object (if already loaded, as it is here) would otherwise still show
    # its pre-delete, now-stale value on the next access.
    db_session.expire_all()

    reloaded = db_session.execute(
        select(TicketMessage).where(TicketMessage.id == message_id)
    ).scalar_one()
    assert reloaded.author_user_id is None


def test_ai_message_author_set_null_when_user_deleted(db_session: Session) -> None:
    """§6 line 902: ai_message.author_user_id ON DELETE SET NULL."""
    team = make_team(db_session)
    challenge = make_challenge(db_session)
    conversation = AiConversation(team_id=team.id, challenge_id=challenge.id)
    db_session.add(conversation)
    db_session.flush()
    author = make_user(db_session)
    message = AiMessage(
        conversation_id=conversation.id,
        role=AiMessageRole.user,
        content="hi",
        hint_cost_charged=0,
        author_user_id=author.id,
    )
    db_session.add(message)
    db_session.flush()
    message_id = message.id

    pre_delete = db_session.execute(
        select(AiMessage).where(AiMessage.id == message_id)
    ).scalar_one()
    assert pre_delete.author_user_id == author.id

    db_session.delete(author)
    db_session.flush()
    # The SET NULL happened server-side, inside Postgres's own FK action —
    # nothing here told SQLAlchemy's identity map about it, so the child
    # object (if already loaded, as it is here) would otherwise still show
    # its pre-delete, now-stale value on the next access.
    db_session.expire_all()

    reloaded = db_session.execute(select(AiMessage).where(AiMessage.id == message_id)).scalar_one()
    assert reloaded.author_user_id is None


def test_audit_log_actor_set_null_when_user_deleted(db_session: Session) -> None:
    """§6 line 902: audit_log.actor_user_id ON DELETE SET NULL."""
    actor = make_user(db_session)
    entry = AuditLog(
        actor_user_id=actor.id,
        scope=AuditScope.installation,
        event_run_id=None,
        action="a",
        target_type="t",
        target_id=uuid.uuid4(),
        details={},
    )
    db_session.add(entry)
    db_session.flush()
    entry_id = entry.id

    pre_delete = db_session.execute(select(AuditLog).where(AuditLog.id == entry_id)).scalar_one()
    assert pre_delete.actor_user_id == actor.id

    db_session.delete(actor)
    db_session.flush()
    # The SET NULL happened server-side, inside Postgres's own FK action —
    # nothing here told SQLAlchemy's identity map about it, so the child
    # object (if already loaded, as it is here) would otherwise still show
    # its pre-delete, now-stale value on the next access.
    db_session.expire_all()

    reloaded = db_session.execute(select(AuditLog).where(AuditLog.id == entry_id)).scalar_one()
    assert reloaded.actor_user_id is None


def test_score_entry_actor_set_null_when_user_deleted(db_session: Session) -> None:
    """§6 line 902: score_entry.actor_user_id ON DELETE SET NULL."""
    run = make_event_run(db_session)
    team = make_team(db_session, run=run)
    actor = make_user(db_session)
    entry = ScoreEntry(
        event_run_id=run.id,
        team_id=team.id,
        entry_type=ScoreEntryType.admin_adjustment,
        points_delta=5,
        source=ScoreEntrySource.admin,
        actor_user_id=actor.id,
    )
    db_session.add(entry)
    db_session.flush()
    entry_id = entry.id

    pre_delete = db_session.execute(
        select(ScoreEntry).where(ScoreEntry.id == entry_id)
    ).scalar_one()
    assert pre_delete.actor_user_id == actor.id

    db_session.delete(actor)
    db_session.flush()
    # The SET NULL happened server-side, inside Postgres's own FK action —
    # nothing here told SQLAlchemy's identity map about it, so the child
    # object (if already loaded, as it is here) would otherwise still show
    # its pre-delete, now-stale value on the next access.
    db_session.expire_all()

    reloaded = db_session.execute(select(ScoreEntry).where(ScoreEntry.id == entry_id)).scalar_one()
    assert reloaded.actor_user_id is None


def test_team_challenge_solved_by_set_null_when_user_deleted(db_session: Session) -> None:
    """§6 line 902: team_challenge.solved_by_user_id ON DELETE SET NULL."""
    team = make_team(db_session)
    challenge = make_challenge(db_session)
    solver = make_user(db_session)
    db_session.add(
        TeamChallenge(
            team_id=team.id,
            challenge_id=challenge.id,
            state=TeamChallengeState.solved,
            solved_by_user_id=solver.id,
            provision_attempts=0,
        )
    )
    db_session.flush()

    pre_delete = db_session.execute(
        select(TeamChallenge).where(
            TeamChallenge.team_id == team.id, TeamChallenge.challenge_id == challenge.id
        )
    ).scalar_one()
    assert pre_delete.solved_by_user_id == solver.id

    db_session.delete(solver)
    db_session.flush()
    # The SET NULL happened server-side, inside Postgres's own FK action —
    # nothing here told SQLAlchemy's identity map about it, so the child
    # object (if already loaded, as it is here) would otherwise still show
    # its pre-delete, now-stale value on the next access.
    db_session.expire_all()

    reloaded = db_session.execute(
        select(TeamChallenge).where(
            TeamChallenge.team_id == team.id, TeamChallenge.challenge_id == challenge.id
        )
    ).scalar_one()
    assert reloaded.solved_by_user_id is None


def test_blocked_address_released_by_set_null_when_user_deleted(db_session: Session) -> None:
    """§6 line 902: blocked_address.released_by_user_id ON DELETE SET NULL."""
    releaser = make_user(db_session)
    blocked = make_blocked_address(db_session, released_by_user_id=releaser.id)
    blocked_id = blocked.id

    pre_delete = db_session.execute(
        select(BlockedAddress).where(BlockedAddress.id == blocked_id)
    ).scalar_one()
    assert pre_delete.released_by_user_id == releaser.id

    db_session.delete(releaser)
    db_session.flush()
    # The SET NULL happened server-side, inside Postgres's own FK action —
    # nothing here told SQLAlchemy's identity map about it, so the child
    # object (if already loaded, as it is here) would otherwise still show
    # its pre-delete, now-stale value on the next access.
    db_session.expire_all()

    reloaded = db_session.execute(
        select(BlockedAddress).where(BlockedAddress.id == blocked_id)
    ).scalar_one()
    assert reloaded.released_by_user_id is None


def test_event_participation_deleted_when_user_deleted(db_session: Session) -> None:
    """§6 line 902: event_participation.user_id ON DELETE CASCADE — reached
    only by a factory reset, since individual erasure tombstones the user
    row in place (§3.1) rather than deleting it. `user_id` is NOT NULL, so a
    SET NULL misconfiguration here would itself raise on delete rather than
    silently leaving a nulled row — this assertion only holds under CASCADE.
    """
    user = make_user(db_session)
    run = make_event_run(db_session)
    participation = make_participation(db_session, user=user, run=run)
    participation_id = participation.id

    pre_delete = db_session.execute(
        select(EventParticipation).where(EventParticipation.id == participation_id)
    ).scalar_one()
    assert pre_delete.user_id == user.id

    db_session.delete(user)
    db_session.flush()

    remaining = db_session.execute(
        select(EventParticipation).where(EventParticipation.id == participation_id)
    ).scalar_one_or_none()
    assert remaining is None


def test_minigame_port_deleted_when_minigame_instance_deleted(db_session: Session) -> None:
    """§6 line 902: minigame_port.minigame_instance_id ON DELETE CASCADE —
    the one exception among the run-scoped tables that cascades via a real
    FK rather than the destruction job.
    """
    instance = make_minigame_instance(db_session)
    port = make_minigame_port(db_session, instance, host_port=9300)
    port_id = port.id

    pre_delete = db_session.execute(
        select(MinigamePort).where(MinigamePort.id == port_id)
    ).scalar_one()
    assert pre_delete.minigame_instance_id == instance.id

    db_session.delete(instance)
    db_session.flush()

    remaining = db_session.execute(
        select(MinigamePort).where(MinigamePort.id == port_id)
    ).scalar_one_or_none()
    assert remaining is None


def test_event_definition_delete_restricted_while_run_exists(db_session: Session) -> None:
    """§6 line 902: event_run.event_definition_id ON DELETE RESTRICT — a
    definition with runs cannot be deleted."""
    definition = make_event_definition(db_session)
    make_event_run(db_session, definition=definition)

    db_session.delete(definition)
    with pytest.raises(IntegrityError) as exc_info:
        db_session.flush()
    _assert_violates(exc_info, "event_run_event_definition_id_fkey")
    db_session.rollback()
