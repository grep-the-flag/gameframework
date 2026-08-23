"""`POST /event-definitions/{id}/runs` (api-surface.md §2.6, §2.17;
data-model.md §3.9; M2-Task-Plan.md Task 12).
"""

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session as DbSession

from gameframework.api.deps import current_session
from gameframework.api.errors import ProblemError, not_found
from gameframework.db.models.authoring import EventDefinition
from gameframework.db.models.identity import Role
from gameframework.db.models.runs import EventRun
from gameframework.db.session import get_session
from gameframework.services.runs import (
    ActiveRunExistsError,
    DefinitionNotPublishedError,
    create_run,
)
from gameframework.services.sessions import AuthContext

router = APIRouter(tags=["runs"])


def _get_definition(db: DbSession, definition_id: uuid.UUID) -> EventDefinition:
    definition = db.get(EventDefinition, definition_id)
    if definition is None:
        not_found("object_not_found")
    return definition


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
