"""`POST /auth/otp` (api-surface.md §2.2, §2.17; M2-Task-Plan.md Task 4 Step
3) and `GET /security/blocked-addresses` / `DELETE
/security/blocked-addresses/{id}` (api-surface.md §2.16, Step 5). One
router, no prefix — the two resource areas share nothing else, so full
paths are spelled per route rather than splitting into two `APIRouter`
instances for a single file.
"""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from gameframework.api.deps import current_session, resolve_captaincy
from gameframework.api.errors import forbidden, not_found
from gameframework.db.models.feedback import AuditScope
from gameframework.db.models.identity import BlockedAddress, Role, User
from gameframework.db.models.runs import EventParticipation, EventRun
from gameframework.db.session import get_session
from gameframework.services.audit import write_audit
from gameframework.services.otp import issue_otp
from gameframework.services.sessions import AuthContext

router = APIRouter(tags=["security"])

_STAFF_ROLES = (Role.admin, Role.gameadmin)


class IssueOtpRequest(BaseModel):
    user_id: uuid.UUID


@router.post("/auth/otp")
def issue_otp_route(
    body: IssueOtpRequest,
    auth: AuthContext = Depends(current_session(Role.player, Role.admin, Role.gameadmin)),
    db: DbSession = Depends(get_session),
) -> dict[str, str]:
    """api-surface.md §2.17: `captain / admin, gameadmin` for role, `players
    of own team / any` for scope. `captain` is not a stored role (data-
    model.md §3.1/§3.11), so a `Role.player` caller who captains no team is
    denied at the role level — `role_denied` — exactly as `current_session`
    denies a role the route does not list at all; a captain who captains
    the wrong team for this target is denied at the object level —
    `object_not_found` — because the route itself is one they may call.
    """
    captains_team = None
    if auth.user.role is Role.player:
        captains_team = resolve_captaincy(db, auth.user)
        if captains_team is None:
            forbidden("role_denied")

    target = db.get(User, body.user_id)
    if target is None or target.role is not Role.player:
        not_found("object_not_found")

    if captains_team is not None:
        # api-surface.md §2.17 "players of own team": scoped to the
        # captain's own team directly. A target who also holds a
        # participation in another run must not have that other
        # participation's row decide this refusal — an unscoped lookup
        # picking whichever participation the query returns first would
        # let it.
        target_participation = (
            db.execute(
                select(EventParticipation).where(
                    EventParticipation.user_id == target.id,
                    EventParticipation.team_id == captains_team.id,
                )
            )
            .scalars()
            .first()
        )
    else:
        target_participation = (
            db.execute(select(EventParticipation).where(EventParticipation.user_id == target.id))
            .scalars()
            .first()
        )
    if target_participation is None:
        not_found("object_not_found")

    run = db.get(EventRun, target_participation.event_run_id)
    if run is None:
        not_found("object_not_found")

    raw_otp = issue_otp(db, target, run)

    write_audit(
        db,
        actor_user_id=auth.user.id,
        scope=AuditScope.participant,
        event_run_id=run.id,
        action="otp_issued",
        target_type="user",
        target_id=target.id,
        details={},
    )

    return {"otp": raw_otp}


@router.get("/security/blocked-addresses")
def list_blocked_addresses(
    auth: AuthContext = Depends(current_session(*_STAFF_ROLES)),
    db: DbSession = Depends(get_session),
) -> dict[str, object]:
    """api-surface.md §2.16: currently-blocked source addresses, with
    their failure count and expiry. Not the release route's actor —
    §2.17 marks only the release ✅, this route unaudited, being a read.
    """
    now = datetime.now(UTC)
    rows = (
        db.execute(
            select(BlockedAddress).where(
                BlockedAddress.blocked_at.is_not(None),
                BlockedAddress.released_at.is_(None),
                BlockedAddress.expires_at > now,
            )
        )
        .scalars()
        .all()
    )
    return {
        "items": [
            {
                "id": str(row.id),
                "address": row.address,
                "failed_attempts": row.failed_attempts,
                "blocked_at": row.blocked_at.isoformat() if row.blocked_at else None,
                "expires_at": row.expires_at.isoformat() if row.expires_at else None,
            }
            for row in rows
        ]
    }


@router.delete("/security/blocked-addresses/{blocked_id}")
def release_blocked_address(
    blocked_id: uuid.UUID,
    auth: AuthContext = Depends(current_session(*_STAFF_ROLES)),
    db: DbSession = Depends(get_session),
) -> dict[str, object]:
    """api-surface.md §2.16: "Release a block early, before it lapses on
    its own." §2.17 marks this route's release ✅ — audited, installation-
    scoped, because `blocked_address` carries no run key of its own
    (data-model.md §3.3/§6 — the one installation-scoped table in the
    actor-FK list).
    """
    row = db.get(BlockedAddress, blocked_id)
    if row is None:
        not_found("object_not_found")

    row.released_at = datetime.now(UTC)
    row.released_by_user_id = auth.user.id
    db.commit()

    write_audit(
        db,
        actor_user_id=auth.user.id,
        scope=AuditScope.installation,
        event_run_id=None,
        action="blocked_address_released",
        target_type="blocked_address",
        target_id=row.id,
        details={},
    )

    return {}
