"""`GET /challenges`, `GET /challenges/{id}`, `POST /challenges/{id}/start`
(api-surface.md §2.7, §2.17, §3.2; M2-Task-Plan.md Task 15).
"""

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from gameframework.api.deps import current_session
from gameframework.api.errors import ProblemError, idempotency_key, not_found
from gameframework.db.models.authoring import Challenge
from gameframework.db.models.identity import Role
from gameframework.db.session import get_session
from gameframework.services.challenges import (
    ChallengeNotOfferedError,
    RunNotRunningError,
    TeamOccupiedError,
    start_challenge,
)
from gameframework.services.runs import resolve_current_run
from gameframework.services.sessions import AuthContext

router = APIRouter(tags=["challenges"])

_ALL_ROLES = (Role.admin, Role.gameadmin, Role.player)


def _challenge_out(challenge: Challenge) -> dict[str, object]:
    """Authored `title`/`text` maps served unchanged — placeholders stay
    unresolved (substitution lands with the port map in M3) and no
    visibility rule hides anything yet (the full suite is M5,
    api-surface.md §3.2)."""
    return {
        "id": str(challenge.id),
        "slug": challenge.slug,
        "order": challenge.order_num,
        "title": challenge.title,
        "text": challenge.text,
        "points": challenge.points,
        "hint_cost": challenge.hint_cost,
        "hint_cap": challenge.hint_cap,
    }


def _get_challenge_for_run(
    db: DbSession, challenge_id: uuid.UUID, definition_id: uuid.UUID
) -> Challenge:
    challenge = db.get(Challenge, challenge_id)
    if challenge is None or challenge.event_definition_id != definition_id:
        not_found("object_not_found")
    return challenge


@router.get("/challenges")
def list_challenges(
    auth: AuthContext = Depends(current_session(*_ALL_ROLES)),
    db: DbSession = Depends(get_session),
) -> dict[str, object]:
    run = resolve_current_run(db, auth.user)
    if run is None:
        not_found("object_not_found")
    challenges = (
        db.execute(
            select(Challenge)
            .where(Challenge.event_definition_id == run.event_definition_id)
            .order_by(Challenge.order_num)
        )
        .scalars()
        .all()
    )
    return {"items": [_challenge_out(c) for c in challenges]}


@router.get("/challenges/{challenge_id}")
def get_challenge(
    challenge_id: uuid.UUID,
    auth: AuthContext = Depends(current_session(*_ALL_ROLES)),
    db: DbSession = Depends(get_session),
) -> dict[str, object]:
    run = resolve_current_run(db, auth.user)
    if run is None:
        not_found("object_not_found")
    challenge = _get_challenge_for_run(db, challenge_id, run.event_definition_id)
    return _challenge_out(challenge)


@router.post("/challenges/{challenge_id}/start")
def start_challenge_route(
    challenge_id: uuid.UUID,
    auth: AuthContext = Depends(current_session(Role.player)),
    db: DbSession = Depends(get_session),
    idempotency_key_header: str | None = Depends(idempotency_key),
) -> dict[str, object]:
    """api-surface.md §2.7, §2.17: captain or player, own team from the
    session (never a path id), run `running`. `own team` is resolved
    inside `services.challenges.start_challenge` from the caller's live
    participation in their own current run — `resolve_current_run`
    derives the run here, exactly as `GET /event` does; nothing here
    re-derives it.

    `idempotency_key_header` is validated (format/length, api-surface.md
    §1) and otherwise unused: replay safety comes from the `provision`
    job's own business key (`services/challenges.py`), never from the
    header's value — the route is idempotent whether or not a client
    sends one at all.
    """
    run = resolve_current_run(db, auth.user)
    if run is None:
        not_found("object_not_found")
    challenge = _get_challenge_for_run(db, challenge_id, run.event_definition_id)

    try:
        row = start_challenge(db, run, auth.user, challenge)
    except RunNotRunningError as exc:
        raise ProblemError(
            409, "run_not_running", extensions={"run_status": run.status.value}
        ) from exc
    except TeamOccupiedError as exc:
        raise ProblemError(
            409,
            "team_occupied",
            extensions={
                "challenge_id": str(exc.challenge_id),
                "challenge_state": exc.state.value,
            },
        ) from exc
    except ChallengeNotOfferedError as exc:
        raise ProblemError(409, "challenge_not_offered") from exc

    return {
        "challenge_id": str(row.challenge_id),
        "team_id": str(row.team_id),
        "state": row.state.value,
    }
