"""`POST /catalog/refresh` (api-surface.md §2.18, admin; M2 = drop-in only
— the registry half arrives in M7; M2-Task-Plan.md Task 9). Not a row in
the api-surface.md §2.17 authorization matrix (no object scope, no
lifecycle gate, no audit — a re-read of the operator's own filesystem, not
a write to installation state a later reader needs to attribute).
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session as DbSession

from gameframework.api.deps import current_session
from gameframework.config import Settings, get_settings
from gameframework.db.models.identity import Role
from gameframework.db.session import get_session
from gameframework.services.artifacts import refresh_dropin
from gameframework.services.sessions import AuthContext

router = APIRouter(tags=["catalog"])


@router.post("/catalog/refresh")
def refresh_catalog(
    auth: AuthContext = Depends(current_session(Role.admin)),
    db: DbSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, object]:
    report = refresh_dropin(db, settings)
    return {"installed": report.installed, "errors": report.errors}
