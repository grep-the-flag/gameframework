import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import CheckConstraint, Enum, ForeignKey, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from gameframework.db.base import Base


class AuditScope(StrEnum):
    participant = "participant"
    installation = "installation"


class Rating(Base):
    """§3.22"""

    __tablename__ = "rating"
    __table_args__ = (
        UniqueConstraint("event_run_id", "minigame_id", "team_id"),
        CheckConstraint("stars BETWEEN 1 AND 5", name="ck_rating_stars_range"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    event_run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("event_run.id"))
    minigame_id: Mapped[str]
    team_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("team.id"))
    stars: Mapped[int]
    comment: Mapped[str | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class AuditLog(Base):
    """§3.23"""

    __tablename__ = "audit_log"
    __table_args__ = (
        CheckConstraint(
            "(scope = 'participant') = (event_run_id IS NOT NULL)",
            name="ck_audit_log_scope_event_run",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("user.id", ondelete="SET NULL")
    )
    scope: Mapped[AuditScope] = mapped_column(Enum(AuditScope, name="audit_log_scope"))
    event_run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("event_run.id"))
    action: Mapped[str]
    target_type: Mapped[str]
    target_id: Mapped[uuid.UUID]
    details: Mapped[dict[str, Any]]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
