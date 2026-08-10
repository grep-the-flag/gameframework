import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import CheckConstraint, Enum, ForeignKey, Index, UniqueConstraint, func, text
from sqlalchemy.orm import Mapped, mapped_column

from gameframework.db.base import Base


class TeamChallengeState(StrEnum):
    locked = "locked"
    startable = "startable"
    provisioning = "provisioning"
    active = "active"
    solved = "solved"
    provision_failed = "provision_failed"


class ScoreEntryType(StrEnum):
    challenge_award = "challenge_award"
    hint_charge = "hint_charge"
    hint_refund = "hint_refund"
    admin_adjustment = "admin_adjustment"
    penalty = "penalty"


class ScoreEntrySource(StrEnum):
    system = "system"
    admin = "admin"


class TeamChallenge(Base):
    """§3.12"""

    __tablename__ = "team_challenge"
    __table_args__ = (
        Index(
            "uq_team_challenge_active_per_team",
            "team_id",
            unique=True,
            postgresql_where=text("state IN ('provisioning', 'active')"),
        ),
    )

    team_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("team.id"), primary_key=True)
    challenge_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("challenge.id"), primary_key=True)
    state: Mapped[TeamChallengeState] = mapped_column(
        Enum(TeamChallengeState, name="team_challenge_state")
    )
    started_at: Mapped[datetime | None]
    solved_at: Mapped[datetime | None]
    solved_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("user.id", ondelete="SET NULL")
    )
    provision_attempts: Mapped[int]


class VaultEntry(Base):
    """§3.13"""

    __tablename__ = "vault_entry"
    __table_args__ = (UniqueConstraint("team_id", "reward_definition_id"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    event_run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("event_run.id"))
    team_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("team.id"))
    reward_definition_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("reward_definition.id"))
    encrypted_value: Mapped[bytes]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class ScoreEntry(Base):
    """§3.14"""

    __tablename__ = "score_entry"
    __table_args__ = (
        CheckConstraint("points_delta != 0", name="ck_score_entry_points_delta_nonzero"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    event_run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("event_run.id"))
    team_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("team.id"))
    challenge_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("challenge.id"))
    entry_type: Mapped[ScoreEntryType] = mapped_column(
        Enum(ScoreEntryType, name="score_entry_type")
    )
    points_delta: Mapped[int]
    reason: Mapped[str | None]
    source: Mapped[ScoreEntrySource] = mapped_column(
        Enum(ScoreEntrySource, name="score_entry_source")
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("user.id", ondelete="SET NULL")
    )
    idempotency_key: Mapped[str | None] = mapped_column(unique=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
