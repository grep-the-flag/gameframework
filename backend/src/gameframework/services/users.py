"""Staff creation and the erasure/export mechanics of user administration
(M2-Task-Plan.md Task 6; api-surface.md §2.4; data-model.md §3.1, §4). The
role-administration authorization rules (the gameadmin-target rule, the
role-field gate, the self-role-change refusal) stay in `api/users.py` and
`api/deps.py` — they need `AuthContext` and raise `ProblemError`, so they
belong with the routes rather than here, the same split `api/security.py`
keeps with `resolve_captaincy`.
"""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.db.models.identity import Role, User
from gameframework.db.models.identity import Session as SessionModel
from gameframework.services.passwords import hash_password


def create_staff_user(db: Session, *, username: str, initial_password: str, role: Role) -> User:
    """api-surface.md §2.4: an admin or gameadmin account, its initial
    password set by the creating admin and handed over out of band, never
    derived from the username (ADR-0007) — `must_change_password` is what
    forces the holder to choose their own before anything else.
    """
    user = User(
        username=username,
        password_hash=hash_password(initial_password),
        role=role,
        is_active=True,
        must_change_password=True,
        preferred_language="en",
    )
    db.add(user)
    db.commit()
    return user


def revoke_sessions(db: Session, user: User) -> None:
    """Every `sid` row this user holds — the mechanism a role change
    (M2-Task-Plan.md Task 6 Step 4) and an erasure (Step 5) both need: a
    token minted under a role or identity no longer current must not be
    honoured on its next request, and `sid` is the only claim authorization
    reads (ADR-0007, Working-Agreement "State as of this handover").
    """
    rows = db.execute(select(SessionModel).where(SessionModel.user_id == user.id)).scalars().all()
    for row in rows:
        db.delete(row)


def tombstone_user(db: Session, user: User) -> None:
    """In-place GDPR erasure (data-model.md §3.1, api-surface.md §2.4):
    `username` becomes the tombstone `deleted-<uuid>` — the row's own `id`,
    unique by the primary key rather than merely probable — `display_name`
    and `email` are nulled, the OTP columns are cleared, `deleted_at` is set
    with `is_active = False`, and every session is deleted. The row itself
    stays: `team.captain_user_id` is non-nullable and the roster freeze
    rules out removing a participation mid-run, so this must work without
    removing anything a foreign key still points at.
    """
    user.username = f"deleted-{user.id}"
    user.display_name = None
    user.email = None
    user.is_active = False
    user.deleted_at = datetime.now(UTC)
    user.otp_hash = None
    user.otp_expires_at = None
    user.otp_consumed_at = None
    revoke_sessions(db, user)
    db.commit()


def export_user_inventory(user: User) -> dict[str, Any]:
    """The per-user GDPR export artifact (api-surface.md §2.4, data-model.md
    §4) — the `user`-table slice of the personal-data inventory: exactly
    the three columns §4 lists for the `user` entity (`username`,
    `display_name`, `email`), plus `user_id` as the identifier saying whose
    export this is. Nothing beyond what §4 names — a field that ships now
    becomes the de-facto contract before M6, which owns column-by-column
    completeness, asks the question. Exhaustive coverage of §4's other
    entities (chat/ticket/gamemaster bodies the ceiling otherwise withholds
    from staff) is M6's criterion; M2 owns the route and its admin-only
    authorization, not the artifact's completeness.
    """
    return {
        "user_id": str(user.id),
        "username": user.username,
        "display_name": user.display_name,
        "email": user.email,
    }
