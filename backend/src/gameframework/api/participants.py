"""`POST /runs/{id}/users/import`, `POST /runs/{id}/users`
(api-surface.md §2.4, §2.17; data-model.md §3.10; M2-Task-Plan.md Task 7).
Runs are read as plain rows here — the run lifecycle routes arrive in
Task 12, so this module only ever reads `EventRun.status`, never writes it.
"""

import csv
import io
import uuid
from typing import NoReturn

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, TypeAdapter
from sqlalchemy.orm import Session as DbSession
from starlette.datastructures import UploadFile

from gameframework.api.deps import current_session
from gameframework.api.errors import ProblemError, not_found
from gameframework.db.models.identity import Role
from gameframework.db.models.runs import EventRun
from gameframework.db.session import get_session
from gameframework.services.participants import (
    DuplicateParticipationError,
    ImportedParticipant,
    ParticipantRow,
    RosterFrozenError,
    create_participant,
    import_participants,
)
from gameframework.services.sessions import AuthContext

router = APIRouter(tags=["participants"])

_STAFF_ROLES = (Role.admin, Role.gameadmin)


def _participant_out(participant: ImportedParticipant) -> dict[str, object]:
    return {
        "user_id": str(participant.user_id),
        "username": participant.username,
        "handle": participant.handle,
        "reused": participant.reused,
    }


def _get_run(db: DbSession, run_id: uuid.UUID) -> EventRun:
    run = db.get(EventRun, run_id)
    if run is None:
        not_found("object_not_found")
    return run


def _raise_for(exc: RosterFrozenError | DuplicateParticipationError) -> NoReturn:
    if isinstance(exc, DuplicateParticipationError):
        raise ProblemError(
            409, "duplicate_participation", extensions={"username": exc.username}
        ) from exc
    raise ProblemError(409, "roster_frozen") from exc


class _JsonParticipantRow(BaseModel):
    username: str
    name: str
    email: str | None = None


_ROWS_ADAPTER = TypeAdapter(list[_JsonParticipantRow])


def _parse_csv_rows(raw: str) -> list[ParticipantRow]:
    reader = csv.DictReader(io.StringIO(raw))
    validated = _ROWS_ADAPTER.validate_python(list(reader))
    return [
        ParticipantRow(username=row.username, name=row.name, email=(row.email or None))
        for row in validated
    ]


def _parse_json_rows(payload: object) -> list[ParticipantRow]:
    validated = _ROWS_ADAPTER.validate_python(payload)
    return [
        ParticipantRow(username=row.username, name=row.name, email=row.email) for row in validated
    ]


@router.post("/runs/{run_id}/users/import")
async def import_users(
    run_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(current_session(*_STAFF_ROLES)),
    db: DbSession = Depends(get_session),
) -> dict[str, object]:
    """Bulk import — CSV via `multipart/form-data` (python-multipart) or a
    bare JSON list, distinguished by `Content-Type` rather than by two
    routes, since api-surface.md §2.4 names one path for both."""
    run = _get_run(db, run_id)

    content_type = request.headers.get("content-type", "")
    if content_type.startswith("multipart/form-data"):
        form = await request.form()
        upload = form["file"]
        if not isinstance(upload, UploadFile):
            raise ProblemError(422, "csv_file_required")
        raw = (await upload.read()).decode("utf-8")
        rows = _parse_csv_rows(raw)
    else:
        rows = _parse_json_rows(await request.json())

    try:
        report = import_participants(db, run, rows, actor_user_id=auth.user.id)
    except (RosterFrozenError, DuplicateParticipationError) as exc:
        _raise_for(exc)

    return {"participants": [_participant_out(p) for p in report.participants]}


class CreateParticipantRequest(BaseModel):
    username: str
    name: str
    email: str | None = None


@router.post("/runs/{run_id}/users")
def create_user_in_run(
    run_id: uuid.UUID,
    body: CreateParticipantRequest,
    auth: AuthContext = Depends(current_session(*_STAFF_ROLES)),
    db: DbSession = Depends(get_session),
) -> dict[str, object]:
    """The single-account form (api-surface.md §2.4): same rules, one row."""
    run = _get_run(db, run_id)
    row = ParticipantRow(username=body.username, name=body.name, email=body.email)

    try:
        participant = create_participant(db, run, row, actor_user_id=auth.user.id)
    except (RosterFrozenError, DuplicateParticipationError) as exc:
        _raise_for(exc)

    return _participant_out(participant)
