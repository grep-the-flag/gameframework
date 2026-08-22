"""`GET /teams`, `POST /runs/{id}/teams`, `PATCH /teams/{id}`,
`PUT /teams/{id}/members`, `PUT /teams/{id}/captain` (api-surface.md §2.5,
§2.17; data-model.md §3.11; M2-Task-Plan.md Task 8).
"""

import uuid

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from gameframework.api.deps import current_session, resolve_captaincy
from gameframework.api.errors import ProblemError, forbidden, not_found
from gameframework.api.pagination import paginate
from gameframework.db.models.identity import Role
from gameframework.db.models.runs import EventRun, Team
from gameframework.db.session import get_session
from gameframework.services.sessions import AuthContext
from gameframework.services.teams import (
    CaptainNotAMemberError,
    ParticipationNotFoundError,
    RosterFrozenError,
    RunDestroyedError,
    create_team,
    rename_team,
    set_captain,
    set_members,
)

router = APIRouter(tags=["teams"])

_STAFF_ROLES = (Role.admin, Role.gameadmin)
_STAFF_AND_PLAYER_ROLES = (Role.player, Role.admin, Role.gameadmin)


def _team_out(team: Team) -> dict[str, object]:
    return {
        "id": str(team.id),
        "event_run_id": str(team.event_run_id),
        "name": team.name,
        "handle": team.handle,
        "captain_user_id": str(team.captain_user_id),
    }


def _get_run(db: DbSession, run_id: uuid.UUID) -> EventRun:
    run = db.get(EventRun, run_id)
    if run is None:
        not_found("object_not_found")
    return run


def _get_team(db: DbSession, team_id: uuid.UUID) -> Team:
    team = db.get(Team, team_id)
    if team is None:
        not_found("object_not_found")
    return team


def _ensure_own_team_or_staff(db: DbSession, auth: AuthContext, team: Team) -> None:
    """`PATCH /teams/{id}` (api-surface.md §2.17): `own team` / `any` — a
    `Role.player` caller who captains no team is denied at the role level
    (`captain` is derived, not stored); a captain of the *wrong* team is
    denied at the object level, `object_not_found`, because the route
    itself is one they may call. Mirrors `POST /auth/otp`'s own-team check
    (`api/security.py`, Task 4) — the same pattern, ahead of Task 18's
    generic object-scope resolution.
    """
    if auth.user.role is not Role.player:
        return
    captains_team = resolve_captaincy(db, auth.user)
    if captains_team is None:
        forbidden("role_denied")
    if captains_team.id != team.id:
        not_found("object_not_found")


@router.get("/teams")
def list_teams(
    cursor: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    auth: AuthContext = Depends(current_session(*_STAFF_ROLES)),
    db: DbSession = Depends(get_session),
) -> dict[str, object]:
    """api-surface.md §1: cursor-paginated, never an unbounded list."""
    page = paginate(db, select(Team), cursor=cursor, limit=limit)
    return {"items": [_team_out(team) for team in page.items], "next_cursor": page.next_cursor}


class CreateTeamRequest(BaseModel):
    name: str
    member_user_ids: list[uuid.UUID]
    captain_user_id: uuid.UUID


@router.post("/runs/{run_id}/teams")
def create_team_route(
    run_id: uuid.UUID,
    body: CreateTeamRequest,
    auth: AuthContext = Depends(current_session(*_STAFF_ROLES)),
    db: DbSession = Depends(get_session),
) -> dict[str, object]:
    """api-surface.md §2.5: name, members and captain in one transaction."""
    run = _get_run(db, run_id)

    try:
        team = create_team(
            db,
            run,
            name=body.name,
            member_ids=body.member_user_ids,
            captain_id=body.captain_user_id,
            actor_user_id=auth.user.id,
        )
    except RosterFrozenError as exc:
        raise ProblemError(409, "roster_frozen") from exc
    except CaptainNotAMemberError as exc:
        raise ProblemError(409, "captain_not_a_member") from exc
    except ParticipationNotFoundError as exc:
        raise ProblemError(422, "participation_not_found") from exc

    return _team_out(team)


class RenameTeamRequest(BaseModel):
    name: str


@router.patch("/teams/{team_id}")
def rename_team_route(
    team_id: uuid.UUID,
    body: RenameTeamRequest,
    auth: AuthContext = Depends(current_session(*_STAFF_AND_PLAYER_ROLES)),
    db: DbSession = Depends(get_session),
) -> dict[str, object]:
    """api-surface.md §2.5, §2.17: `own team` / `any`, open through
    `finished`, refused only at `destroyed` — not audited."""
    team = _get_team(db, team_id)
    _ensure_own_team_or_staff(db, auth, team)
    run = _get_run(db, team.event_run_id)

    try:
        rename_team(db, team, run, name=body.name)
    except RunDestroyedError as exc:
        raise ProblemError(409, "run_destroyed") from exc

    return _team_out(team)


class SetMembersRequest(BaseModel):
    member_user_ids: list[uuid.UUID]
    new_captain_user_id: uuid.UUID | None = None


@router.put("/teams/{team_id}/members")
def set_members_route(
    team_id: uuid.UUID,
    body: SetMembersRequest,
    auth: AuthContext = Depends(current_session(*_STAFF_ROLES)),
    db: DbSession = Depends(get_session),
) -> dict[str, object]:
    """api-surface.md §2.5: correct the member set, `created`-only; an
    optional same-request captain replacement when the new set would drop
    the sitting captain."""
    team = _get_team(db, team_id)
    run = _get_run(db, team.event_run_id)

    try:
        set_members(
            db,
            team,
            run,
            member_user_ids=body.member_user_ids,
            new_captain_user_id=body.new_captain_user_id,
            actor_user_id=auth.user.id,
        )
    except RosterFrozenError as exc:
        raise ProblemError(409, "roster_frozen") from exc
    except CaptainNotAMemberError as exc:
        raise ProblemError(409, "captain_not_a_member") from exc
    except ParticipationNotFoundError as exc:
        raise ProblemError(422, "participation_not_found") from exc

    return _team_out(team)


class SetCaptainRequest(BaseModel):
    captain_user_id: uuid.UUID


@router.put("/teams/{team_id}/captain")
def set_captain_route(
    team_id: uuid.UUID,
    body: SetCaptainRequest,
    auth: AuthContext = Depends(current_session(*_STAFF_ROLES)),
    db: DbSession = Depends(get_session),
) -> dict[str, object]:
    """api-surface.md §2.5: open through `finished`, refused only at
    `destroyed`; the replacement must already be a member."""
    team = _get_team(db, team_id)
    run = _get_run(db, team.event_run_id)

    try:
        set_captain(db, team, run, captain_user_id=body.captain_user_id, actor_user_id=auth.user.id)
    except RunDestroyedError as exc:
        raise ProblemError(409, "run_destroyed") from exc
    except CaptainNotAMemberError as exc:
        raise ProblemError(409, "captain_not_a_member") from exc

    return _team_out(team)
