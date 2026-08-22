"""`GET/POST /users`, `GET/PATCH/DELETE /users/{id}`,
`POST /users/{id}/deactivate`, `GET /users/{id}/export`, `PUT /me/language`
(api-surface.md §2.4, §2.17; data-model.md §3.1, §4; M2-Task-Plan.md Task 6).
"""

import uuid
from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from gameframework.api.deps import current_session, require_role, resolve_staff_write_target
from gameframework.api.errors import forbidden, not_found
from gameframework.api.pagination import paginate
from gameframework.db.models.feedback import AuditScope
from gameframework.db.models.identity import Role, User
from gameframework.db.session import get_session
from gameframework.services.audit import write_audit
from gameframework.services.sessions import AuthContext
from gameframework.services.users import (
    create_staff_user,
    export_user_inventory,
    revoke_sessions,
    tombstone_user,
)

router = APIRouter(tags=["users"])

_STAFF_ROLES = (Role.admin, Role.gameadmin)
_ANY_ROLE = (Role.admin, Role.gameadmin, Role.player)


def _user_out(user: User) -> dict[str, object]:
    return {
        "id": str(user.id),
        "username": user.username,
        "display_name": user.display_name,
        "email": user.email,
        "role": user.role.value,
        "is_active": user.is_active,
        "must_change_password": user.must_change_password,
        "preferred_language": user.preferred_language,
        "deleted_at": user.deleted_at.isoformat() if user.deleted_at is not None else None,
    }


@router.get("/users")
def list_users(
    cursor: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    auth: AuthContext = Depends(current_session(*_STAFF_ROLES)),
    db: DbSession = Depends(get_session),
) -> dict[str, object]:
    """api-surface.md §1: cursor-paginated, never an unbounded list."""
    page = paginate(db, select(User), cursor=cursor, limit=limit)
    return {"items": [_user_out(user) for user in page.items], "next_cursor": page.next_cursor}


class CreateStaffRequest(BaseModel):
    username: str
    initial_password: str
    role: Literal[Role.admin, Role.gameadmin]


@router.post("/users")
def create_user(
    body: CreateStaffRequest,
    auth: AuthContext = Depends(current_session(Role.admin)),
    db: DbSession = Depends(get_session),
) -> dict[str, object]:
    """Admin-only (api-surface.md §2.4): creating a staff account assigns a
    role, and role changes are admin-only and audited (§2.17 role
    administration (1)) — staff creation included. A participant is
    refused `422` by `CreateStaffRequest.role`'s `Literal` alone: it does
    not name `Role.player`, so pydantic itself rejects that value before
    this body runs.
    """
    user = create_staff_user(
        db, username=body.username, initial_password=body.initial_password, role=Role(body.role)
    )
    write_audit(
        db,
        actor_user_id=auth.user.id,
        scope=AuditScope.installation,
        event_run_id=None,
        action="staff_account_created",
        target_type="user",
        target_id=user.id,
        details={"role": user.role.value},
    )
    return _user_out(user)


@router.get("/users/{user_id}")
def get_user(
    user_id: uuid.UUID,
    auth: AuthContext = Depends(current_session(*_STAFF_ROLES)),
    db: DbSession = Depends(get_session),
) -> dict[str, object]:
    """A read, not a write: the gameadmin-target rule (§2.17 role
    administration (2)) names `PATCH`, deactivate, `DELETE` and OTP issue —
    reads are unrestricted for both staff roles, same as `GET /users`.
    """
    user = db.get(User, user_id)
    if user is None:
        not_found("object_not_found")
    return _user_out(user)


class PatchUserRequest(BaseModel):
    display_name: str | None = None
    email: str | None = None
    role: Role | None = None


@router.patch("/users/{user_id}")
def patch_user(
    user_id: uuid.UUID,
    body: PatchUserRequest,
    auth: AuthContext = Depends(current_session(*_STAFF_ROLES)),
    db: DbSession = Depends(get_session),
) -> dict[str, object]:
    """api-surface.md §2.17 role administration: (2) a gameadmin's writes
    reach participant accounts only — `resolve_staff_write_target` answers
    `404` for a staff target before any field is even inspected, so that
    check never depends on which fields the request happens to touch. (1)
    `role` is admin-only — `require_role` denies a gameadmin's attempt with
    `403 role_denied`, the same code `current_session` uses for a role that
    may not reach a route at all, since this is that same shape one field
    down. (3) no session changes its own `role` — checked once `require_role`
    has already established the caller is an admin, so this is reachable
    only by an admin targeting themselves. A role change deletes every
    `sid` row this user holds (Task 6 Step 4): `sid` is the only claim
    authorization reads (ADR-0007, Working-Agreement), so a session minted
    under the old role must not survive the grant that ended it.
    """
    target = resolve_staff_write_target(db, auth, user_id)

    if body.role is not None:
        require_role(auth, Role.admin)
        if target.id == auth.user.id:
            forbidden("self_role_change_denied")
        if body.role != target.role:
            target.role = body.role
            revoke_sessions(db, target)
            write_audit(
                db,
                actor_user_id=auth.user.id,
                scope=AuditScope.installation,
                event_run_id=None,
                action="user_role_changed",
                target_type="user",
                target_id=target.id,
                details={"new_role": body.role.value},
            )

    if body.display_name is not None:
        target.display_name = body.display_name
    if body.email is not None:
        target.email = body.email

    db.commit()
    return _user_out(target)


@router.post("/users/{user_id}/deactivate")
def deactivate_user(
    user_id: uuid.UUID,
    auth: AuthContext = Depends(current_session(*_STAFF_ROLES)),
    db: DbSession = Depends(get_session),
) -> dict[str, object]:
    """The gameadmin-target rule applies here too — deactivation is a
    write (§2.17 role administration (2)). data-model.md §3.1 `is_active`:
    deactivating revokes every session the account holds, not only its
    next login — otherwise a holder already signed in keeps working on
    the session `current_session` never reads `is_active` from.
    """
    target = resolve_staff_write_target(db, auth, user_id)
    target.is_active = False
    revoke_sessions(db, target)
    db.commit()
    return {}


@router.delete("/users/{user_id}")
def delete_user(
    user_id: uuid.UUID,
    auth: AuthContext = Depends(current_session(Role.admin)),
    db: DbSession = Depends(get_session),
) -> dict[str, object]:
    """Admin-only, not gameadmin (api-surface.md §2.4/§2.17): a role denial
    a gameadmin gets before this body ever runs, via `current_session`'s
    own role check — the object scope is `any` here, so a missing target
    is the only `404` this route answers on its own. In-place GDPR erasure
    (data-model.md §3.1): the row stays, tombstoned, because `team.
    captain_user_id` is non-nullable and the roster freeze rules out
    removing a mid-run participation.
    """
    target = db.get(User, user_id)
    if target is None:
        not_found("object_not_found")
    tombstone_user(db, target)
    write_audit(
        db,
        actor_user_id=auth.user.id,
        scope=AuditScope.installation,
        event_run_id=None,
        action="user_erased",
        target_type="user",
        target_id=target.id,
        details={},
    )
    return {}


@router.get("/users/{user_id}/export")
def export_user(
    user_id: uuid.UUID,
    auth: AuthContext = Depends(current_session(Role.admin)),
    db: DbSession = Depends(get_session),
) -> dict[str, object]:
    """Admin-only, not gameadmin (api-surface.md §2.4/§2.17): the one
    audited exception to the staff-visibility ceiling, so it sits with the
    role accountable for the installation rather than the role that runs
    the afternoon. A gameadmin is refused `403 role_denied` by
    `current_session` before this body runs — a role denial, never the
    `404` that would have to pretend not to know a participant they can
    already list on `GET /users`.
    """
    target = db.get(User, user_id)
    if target is None:
        not_found("object_not_found")
    payload = export_user_inventory(target)
    write_audit(
        db,
        actor_user_id=auth.user.id,
        scope=AuditScope.installation,
        event_run_id=None,
        action="user_data_exported",
        target_type="user",
        target_id=target.id,
        details={},
    )
    return payload


class LanguageRequest(BaseModel):
    preferred_language: str


@router.put("/me/language")
def set_my_language(
    body: LanguageRequest,
    auth: AuthContext = Depends(current_session(*_ANY_ROLE)),
    db: DbSession = Depends(get_session),
) -> dict[str, object]:
    """api-surface.md §2.17: `self` scope, derived from the live session —
    never a path id, so there is no other user's row this route could
    reach even in error."""
    auth.user.preferred_language = body.preferred_language
    db.commit()
    return {"preferred_language": auth.user.preferred_language}
