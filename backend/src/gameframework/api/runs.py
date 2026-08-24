"""`POST /event-definitions/{id}/runs` (api-surface.md §2.6, §2.17;
data-model.md §3.9; M2-Task-Plan.md Task 12).
"""

import uuid
from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session as DbSession

from gameframework.api.deps import current_session, require_role
from gameframework.api.errors import ProblemError, not_found
from gameframework.config import Settings, get_settings
from gameframework.db.models.authoring import EventDefinition
from gameframework.db.models.identity import Role
from gameframework.db.models.runs import EventRun
from gameframework.db.session import get_session
from gameframework.services.preflight import RunNotCreatedError, run_preflight
from gameframework.services.runs import (
    ActiveRunExistsError,
    DefinitionNotPublishedError,
    PreflightNotCurrentError,
    create_run,
    start_run,
)
from gameframework.services.sessions import AuthContext

router = APIRouter(tags=["runs"])


def _get_definition(db: DbSession, definition_id: uuid.UUID) -> EventDefinition:
    definition = db.get(EventDefinition, definition_id)
    if definition is None:
        not_found("object_not_found")
    return definition


def _get_run(db: DbSession, run_id: uuid.UUID) -> EventRun:
    run = db.get(EventRun, run_id)
    if run is None:
        not_found("object_not_found")
    return run


def _run_out(run: EventRun) -> dict[str, object]:
    return {
        "id": str(run.id),
        "event_definition_id": str(run.event_definition_id),
        "definition_revision": run.definition_revision,
        "status": run.status.value,
        "unlock_mode": run.unlock_mode.value,
        "scoring_mode": run.scoring_mode.value,
        "participation_mode": run.participation_mode.value,
        "theme_ref": run.theme_ref,
        "gamemaster_enabled": run.gamemaster_enabled,
        "gamemaster_provider": run.gamemaster_provider,
        "gamemaster_endpoint": run.gamemaster_endpoint,
        "language_default": run.language_default,
        "grace_period_days": run.grace_period_days,
        "otp_lifetime_minutes": run.otp_lifetime_minutes,
    }


@router.post("/event-definitions/{definition_id}/runs", status_code=201)
def create_run_route(
    definition_id: uuid.UUID,
    auth: AuthContext = Depends(current_session(Role.admin)),
    db: DbSession = Depends(get_session),
) -> dict[str, object]:
    """api-surface.md §2.6: "Create a run of a published definition
    (snapshots run config); 409 while another run is running/paused"."""
    definition = _get_definition(db, definition_id)
    try:
        run = create_run(db, definition)
    except DefinitionNotPublishedError as exc:
        raise ProblemError(409, "definition_not_published") from exc
    except ActiveRunExistsError as exc:
        raise ProblemError(409, "run_active") from exc
    return _run_out(run)


@router.post("/runs/{run_id}/preflight")
def preflight_route(
    run_id: uuid.UUID,
    auth: AuthContext = Depends(current_session(Role.admin)),
    db: DbSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, object]:
    """api-surface.md §2.6: the run-scoped half of Phase 0 — `created`-
    only, repeatable. Reports `{"passed", "errors"}` at `200` regardless of
    outcome, mirroring `POST /event-definitions/{id}/dry-run`'s own
    report-don't-refuse shape for a static-check result; only a run-status
    mismatch (not `created`) is a `409` before any check runs."""
    run = _get_run(db, run_id)
    try:
        result = run_preflight(db, run, settings)
    except RunNotCreatedError as exc:
        raise ProblemError(409, "invalid_status_transition") from exc
    return {"passed": result.passed, "errors": result.errors}


class TransitionRequest(BaseModel):
    # `pause`/`resume`/`finish` are Task 14's; this Literal narrows to
    # exactly what this task implements rather than accepting values no
    # service function yet handles.
    action: Literal["start"]


@router.post("/runs/{run_id}/transition")
def transition_route(
    run_id: uuid.UUID,
    body: TransitionRequest,
    auth: AuthContext = Depends(current_session(Role.admin, Role.gameadmin)),
    db: DbSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, object]:
    """api-surface.md §2.6: `start\\|pause\\|resume\\|finish` — this task
    implements `start` only. `start` is admin-only (checked here, at the
    action level, beside the route's broader admin+gameadmin reach that
    `pause`/`resume`/`finish` will use), `409`s against a second
    concurrent run, and `409`s without a current successful preflight."""
    run = _get_run(db, run_id)
    require_role(auth, Role.admin)
    try:
        start_run(db, run, settings)
    except RunNotCreatedError as exc:
        raise ProblemError(409, "invalid_status_transition") from exc
    except ActiveRunExistsError as exc:
        raise ProblemError(409, "run_active") from exc
    except PreflightNotCurrentError as exc:
        raise ProblemError(409, "preflight_not_current") from exc
    return _run_out(run)
