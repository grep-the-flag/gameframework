import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import BigInteger, Enum, Index, UniqueConstraint, func, text
from sqlalchemy.orm import Mapped, mapped_column

from gameframework.db.base import Base


class JobState(StrEnum):
    pending = "pending"
    leased = "leased"
    succeeded = "succeeded"
    failed = "failed"
    dead = "dead"


class ArtifactType(StrEnum):
    minigame = "minigame"
    event = "event"
    theme = "theme"
    language = "language"


class Job(Base):
    """§3.24"""

    __tablename__ = "job"
    __table_args__ = (
        Index(
            "uq_job_business_key_non_terminal",
            "job_type",
            "business_key",
            unique=True,
            postgresql_where=text("state IN ('pending', 'leased')"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    job_type: Mapped[str]
    business_key: Mapped[str]
    payload: Mapped[dict[str, Any]]
    state: Mapped[JobState] = mapped_column(Enum(JobState, name="job_state"))
    attempts: Mapped[int] = mapped_column(default=0, server_default="0")
    next_attempt_at: Mapped[datetime]
    lease_owner: Mapped[str | None]
    lease_expires_at: Mapped[datetime | None]
    last_error: Mapped[str | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class OutboxEvent(Base):
    """§3.25"""

    __tablename__ = "outbox_event"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    topic: Mapped[str]
    event_type: Mapped[str]
    payload: Mapped[dict[str, Any]]
    published_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class InstalledArtifact(Base):
    """§3.26"""

    __tablename__ = "installed_artifact"
    __table_args__ = (UniqueConstraint("type", "artifact_id", "version"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    type: Mapped[ArtifactType] = mapped_column(Enum(ArtifactType, name="installed_artifact_type"))
    artifact_id: Mapped[str]
    version: Mapped[str]
    manifest: Mapped[dict[str, Any]]
    image_digest: Mapped[str | None]
    verified: Mapped[bool]
    source: Mapped[str | None]
    installed_at: Mapped[datetime] = mapped_column(server_default=func.now())
