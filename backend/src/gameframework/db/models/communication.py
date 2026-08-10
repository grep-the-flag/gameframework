import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import Enum, ForeignKey, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from gameframework.db.base import Base


class TicketStatus(StrEnum):
    open = "open"
    in_progress = "in_progress"
    closed = "closed"


class AiMessageRole(StrEnum):
    user = "user"
    assistant = "assistant"


class ChatMessage(Base):
    """§3.17"""

    __tablename__ = "chat_message"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    team_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("team.id"))
    author_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("user.id", ondelete="SET NULL")
    )
    body: Mapped[str]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class Ticket(Base):
    """§3.18"""

    __tablename__ = "ticket"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    team_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("team.id"))
    opened_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("user.id", ondelete="SET NULL")
    )
    title: Mapped[str]
    status: Mapped[TicketStatus] = mapped_column(Enum(TicketStatus, name="ticket_status"))
    assigned_to_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("user.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class TicketMessage(Base):
    """§3.19"""

    __tablename__ = "ticket_message"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    ticket_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("ticket.id"))
    author_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("user.id", ondelete="SET NULL")
    )
    body: Mapped[str]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class AiConversation(Base):
    """§3.20"""

    __tablename__ = "ai_conversation"
    __table_args__ = (UniqueConstraint("team_id", "challenge_id"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    team_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("team.id"))
    challenge_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("challenge.id"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class AiMessage(Base):
    """§3.21"""

    __tablename__ = "ai_message"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    conversation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("ai_conversation.id"))
    role: Mapped[AiMessageRole] = mapped_column(Enum(AiMessageRole, name="ai_message_role"))
    content: Mapped[str]
    hint_cost_charged: Mapped[int]
    author_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("user.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
