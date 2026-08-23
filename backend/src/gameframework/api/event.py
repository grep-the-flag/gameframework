"""`GET /event` and `GET /privacy-notice` (api-surface.md §2.1, §2.6;
M2-Task-Plan.md Task 12).
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session as DbSession

from gameframework.api.deps import current_session
from gameframework.api.errors import not_found
from gameframework.db.models.authoring import EventDefinition
from gameframework.db.models.identity import Role
from gameframework.db.session import get_session
from gameframework.services.runs import resolve_current_run
from gameframework.services.sessions import AuthContext

router = APIRouter(tags=["event"])


def _get_definition(db: DbSession, definition_id: object) -> EventDefinition:
    definition = db.get(EventDefinition, definition_id)
    # ON DELETE RESTRICT (data-model.md §6): a run's own definition can
    # never be gone while the run row is — not a case this route defends
    # against.
    assert definition is not None
    return definition


@router.get("/event")
def get_event(
    auth: AuthContext = Depends(current_session(Role.admin, Role.gameadmin, Role.player)),
    db: DbSession = Depends(get_session),
) -> dict[str, object]:
    """api-surface.md §2.6: definition content plus run state; "404 when
    no run exists". Authored text is served with placeholders
    **unresolved** — substitution lands with the port map in M3 (§2.7) —
    and the full visibility-rule suite (per-role hiding) is M5's; this
    route serves the same content to every authorized role for now.
    """
    run = resolve_current_run(db, auth.user)
    if run is None:
        not_found("object_not_found")
    definition = _get_definition(db, run.event_definition_id)
    return {
        "run": {
            "id": str(run.id),
            "definition_revision": run.definition_revision,
            "status": run.status.value,
            "scheduled_start": run.scheduled_start.isoformat() if run.scheduled_start else None,
            "scheduled_end": run.scheduled_end.isoformat() if run.scheduled_end else None,
            "theme_ref": run.theme_ref,
            "language_default": run.language_default,
            "gamemaster_enabled": run.gamemaster_enabled,
        },
        "definition": {
            "name": definition.name,
            "story": definition.story,
        },
    }


@router.get("/privacy-notice")
def get_privacy_notice(db: DbSession = Depends(get_session)) -> dict[str, object]:
    """api-surface.md §2.1: public, shown at first login — so there is no
    session to resolve a participant's own runs from. Uses the staff
    branch of the §2.6 resolution with `user=None`: the run in
    `running`/`paused` when one exists, otherwise the most recently
    created run that is not `destroyed`, and that run's definition
    supplies the text. No run, or no notice on its definition: `404`. The
    response carries the notice text alone — no slug, no id, no
    definition name — the notice is written to be read before logging in
    and is public by intent; nothing beside it is.
    """
    run = resolve_current_run(db, None)
    if run is None:
        not_found("object_not_found")
    definition = _get_definition(db, run.event_definition_id)
    if not definition.privacy_notice_md:
        not_found("object_not_found")
    return {"privacy_notice_md": definition.privacy_notice_md}
