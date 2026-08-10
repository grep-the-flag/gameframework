import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import Enum, ForeignKey, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from gameframework.db.base import Base


class DefinitionStatus(StrEnum):
    draft = "draft"
    published = "published"
    archived = "archived"


class UnlockMode(StrEnum):
    manual = "manual"
    guided = "guided"


class ScoringMode(StrEnum):
    casual = "casual"
    challenge = "challenge"


class ParticipationMode(StrEnum):
    teams = "teams"
    solo = "solo"


class DependencySource(StrEnum):
    explicit = "explicit"
    reward = "reward"


class RewardType(StrEnum):
    ssh_keypair = "ssh_keypair"
    password = "password"
    token = "token"
    ssl_cert = "ssl_cert"


class EventDefinition(Base):
    """§3.4"""

    __tablename__ = "event_definition"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    slug: Mapped[str]
    source_version: Mapped[str]
    name: Mapped[dict[str, Any]]
    story: Mapped[dict[str, Any]]
    status: Mapped[DefinitionStatus] = mapped_column(
        Enum(DefinitionStatus, name="event_definition_status")
    )
    revision: Mapped[int]
    unlock_mode: Mapped[UnlockMode] = mapped_column(Enum(UnlockMode, name="unlock_mode"))
    scoring_mode: Mapped[ScoringMode] = mapped_column(Enum(ScoringMode, name="scoring_mode"))
    participation_mode: Mapped[ParticipationMode] = mapped_column(
        Enum(ParticipationMode, name="participation_mode"),
        default=ParticipationMode.teams,
        server_default=ParticipationMode.teams.value,
    )
    grace_period_days: Mapped[int] = mapped_column(default=7, server_default="7")
    theme_ref: Mapped[str | None]
    language_default: Mapped[str]
    contract_version: Mapped[str]
    source: Mapped[str | None]
    gamemaster_enabled: Mapped[bool]
    privacy_notice_md: Mapped[str]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class Challenge(Base):
    """§3.5"""

    __tablename__ = "challenge"
    __table_args__ = (
        UniqueConstraint("event_definition_id", "slug"),
        UniqueConstraint("event_definition_id", "order_num"),
        UniqueConstraint("event_definition_id", "minigame_host_label"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    event_definition_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("event_definition.id"))
    slug: Mapped[str]
    order_num: Mapped[int]
    title: Mapped[dict[str, Any]]
    text: Mapped[dict[str, Any]]
    minigame_id: Mapped[str]
    minigame_version_range: Mapped[str]
    minigame_version: Mapped[str]
    minigame_image_digest: Mapped[str]
    minigame_host_label: Mapped[str]
    points: Mapped[int]
    hint_cost: Mapped[int]
    hint_cap: Mapped[int | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class ChallengeDependency(Base):
    """§3.6"""

    __tablename__ = "challenge_dependency"

    challenge_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("challenge.id"), primary_key=True)
    depends_on_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("challenge.id"), primary_key=True)
    source: Mapped[DependencySource] = mapped_column(
        Enum(DependencySource, name="challenge_dependency_source")
    )


class RewardDefinition(Base):
    """§3.7"""

    __tablename__ = "reward_definition"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    producer_challenge_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("challenge.id"))
    name: Mapped[str]
    type: Mapped[RewardType] = mapped_column(Enum(RewardType, name="reward_definition_type"))


class RewardConsumption(Base):
    """§3.8"""

    __tablename__ = "reward_consumption"

    reward_definition_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("reward_definition.id"), primary_key=True
    )
    consumer_challenge_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("challenge.id"), primary_key=True
    )
