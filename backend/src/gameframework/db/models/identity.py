import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import Enum, ForeignKey, func
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import Mapped, mapped_column

from gameframework.db.base import Base


class Role(StrEnum):
    admin = "admin"
    gameadmin = "gameadmin"
    player = "player"


class User(Base):
    """§3.1"""

    __tablename__ = "user"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(unique=True)
    display_name: Mapped[str | None]
    email: Mapped[str | None]
    password_hash: Mapped[str]
    role: Mapped[Role] = mapped_column(Enum(Role, name="user_role"))
    is_active: Mapped[bool]
    deleted_at: Mapped[datetime | None]
    must_change_password: Mapped[bool]
    otp_hash: Mapped[str | None]
    otp_expires_at: Mapped[datetime | None]
    otp_consumed_at: Mapped[datetime | None]
    preferred_language: Mapped[str]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class Session(Base):
    """§3.2"""

    __tablename__ = "session"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("user.id"))
    restricted: Mapped[bool]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    expires_at: Mapped[datetime]


class BlockedAddress(Base):
    """§3.3"""

    __tablename__ = "blocked_address"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    address: Mapped[str] = mapped_column(INET, unique=True)
    failed_attempts: Mapped[int] = mapped_column(default=0, server_default="0")
    blocked_at: Mapped[datetime | None]
    expires_at: Mapped[datetime | None]
    released_at: Mapped[datetime | None]
    released_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("user.id", ondelete="SET NULL")
    )
    last_attempt_at: Mapped[datetime]
