import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import Enum, ForeignKey, ForeignKeyConstraint, Index, UniqueConstraint, func, text
from sqlalchemy.orm import Mapped, mapped_column

from gameframework.db.base import Base
from gameframework.db.models.authoring import ParticipationMode, ScoringMode, UnlockMode


class RunStatus(StrEnum):
    created = "created"
    running = "running"
    paused = "paused"
    finished = "finished"
    destroyed = "destroyed"


class ExportState(StrEnum):
    pending = "pending"
    succeeded = "succeeded"
    failed_retrying = "failed_retrying"
    skipped = "skipped"


class EventRun(Base):
    """§3.9"""

    __tablename__ = "event_run"
    __table_args__ = (
        Index(
            "uq_event_run_single_active",
            text("(true)"),
            unique=True,
            postgresql_where=text("status IN ('running', 'paused')"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    event_definition_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("event_definition.id", ondelete="RESTRICT")
    )
    definition_revision: Mapped[int]
    preflight_passed_at: Mapped[datetime | None]
    preflight_config_hash: Mapped[str | None]
    status: Mapped[RunStatus] = mapped_column(Enum(RunStatus, name="event_run_status"))
    scheduled_start: Mapped[datetime | None]
    scheduled_end: Mapped[datetime | None]
    paused_at: Mapped[datetime | None]
    unlock_mode: Mapped[UnlockMode] = mapped_column(Enum(UnlockMode, name="unlock_mode"))
    scoring_mode: Mapped[ScoringMode] = mapped_column(Enum(ScoringMode, name="scoring_mode"))
    participation_mode: Mapped[ParticipationMode] = mapped_column(
        Enum(ParticipationMode, name="participation_mode")
    )
    theme_ref: Mapped[str | None]
    gamemaster_enabled: Mapped[bool]
    gamemaster_provider: Mapped[str | None]
    gamemaster_endpoint: Mapped[str | None]
    language_default: Mapped[str]
    grace_period_days: Mapped[int]
    otp_lifetime_minutes: Mapped[int] = mapped_column(default=5, server_default="5")
    finished_at: Mapped[datetime | None]
    grace_deadline_at: Mapped[datetime | None]
    export_state: Mapped[ExportState] = mapped_column(
        Enum(ExportState, name="event_run_export_state")
    )
    export_attempts: Mapped[int] = mapped_column(default=0, server_default="0")
    hard_deadline_at: Mapped[datetime | None]
    legal_hold: Mapped[bool] = mapped_column(default=False, server_default="false")
    legal_hold_reason: Mapped[str | None]
    destroyed_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class EventParticipation(Base):
    """§3.10"""

    __tablename__ = "event_participation"
    __table_args__ = (
        UniqueConstraint("user_id", "event_run_id"),
        UniqueConstraint("event_run_id", "handle"),
        ForeignKeyConstraint(
            ["team_id", "event_run_id"],
            ["team.id", "team.event_run_id"],
            name="fk_event_participation_team",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("user.id", ondelete="CASCADE"))
    event_run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("event_run.id"))
    team_id: Mapped[uuid.UUID | None] = mapped_column()
    handle: Mapped[str]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class Team(Base):
    """§3.11"""

    __tablename__ = "team"
    __table_args__ = (
        UniqueConstraint("id", "event_run_id", name="uq_team_id_event_run_id"),
        UniqueConstraint("event_run_id", "handle"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    event_run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("event_run.id"))
    name: Mapped[str]
    handle: Mapped[str]
    captain_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("user.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
