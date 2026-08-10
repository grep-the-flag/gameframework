import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import CheckConstraint, Enum, ForeignKey, Index, UniqueConstraint, func, text
from sqlalchemy.orm import Mapped, mapped_column

from gameframework.db.base import Base


class SolveMode(StrEnum):
    flag = "flag"
    callback = "callback"


class InstanceHealth(StrEnum):
    unknown = "unknown"
    healthy = "healthy"
    unhealthy = "unhealthy"


class PortSource(StrEnum):
    allocated = "allocated"
    override = "override"


class MinigameInstance(Base):
    """§3.15"""

    __tablename__ = "minigame_instance"
    __table_args__ = (
        UniqueConstraint("event_run_id", "minigame_id"),
        UniqueConstraint("event_run_id", "hostname"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    event_run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("event_run.id"))
    minigame_id: Mapped[str]
    hostname: Mapped[str | None]
    solve_mode: Mapped[SolveMode] = mapped_column(
        Enum(SolveMode, name="minigame_instance_solve_mode")
    )
    image_ref: Mapped[str]
    image_digest: Mapped[str]
    resources_override: Mapped[dict[str, Any] | None]
    container_ref: Mapped[str | None]
    health: Mapped[InstanceHealth] = mapped_column(
        Enum(InstanceHealth, name="minigame_instance_health")
    )
    last_health_at: Mapped[datetime | None]


class MinigamePort(Base):
    """§3.16"""

    __tablename__ = "minigame_port"
    __table_args__ = (
        UniqueConstraint("minigame_instance_id", "container_port"),
        Index(
            "uq_minigame_port_live_host_port",
            "host_port",
            unique=True,
            postgresql_where=text("released_at IS NULL"),
        ),
        CheckConstraint(
            "(source = 'override') = (override_reason IS NOT NULL)",
            name="ck_minigame_port_override_reason",
        ),
        CheckConstraint(
            "container_port BETWEEN 1 AND 65535",
            name="ck_minigame_port_container_port_range",
        ),
        CheckConstraint(
            "host_port BETWEEN 1 AND 65535",
            name="ck_minigame_port_host_port_range",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    minigame_instance_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("minigame_instance.id", ondelete="CASCADE")
    )
    container_port: Mapped[int]
    host_port: Mapped[int]
    source: Mapped[PortSource] = mapped_column(Enum(PortSource, name="minigame_port_source"))
    override_reason: Mapped[str | None]
    released_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
