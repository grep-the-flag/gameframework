"""`GET/POST /event-definitions`, `GET/PATCH /event-definitions/{id}`,
`POST /event-definitions/{id}/publish|unpublish|clone|archive|unarchive`
(api-surface.md §2.6, §2.17; data-model.md §3.4-§3.8; M2-Task-Plan.md
Task 10). `unarchive` is not in api-surface.md's original table — added
during this task to close the "reversible to draft/published depending on
prior state" half `archive` alone cannot deliver without a column this task
does not add (see the Step 2 report).
"""

import uuid
from typing import Annotated, Any, cast

import yaml
from fastapi import APIRouter, Depends, Header, Query, Request, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession
from starlette.datastructures import UploadFile

from gameframework.api.deps import current_session
from gameframework.api.errors import ProblemError, not_found
from gameframework.api.pagination import paginate
from gameframework.config import Settings, get_settings
from gameframework.db.models.authoring import (
    EventDefinition,
    ParticipationMode,
    RewardType,
    ScoringMode,
    UnlockMode,
)
from gameframework.db.models.feedback import AuditScope
from gameframework.db.models.identity import Role
from gameframework.db.session import get_session
from gameframework.services.audit import write_audit
from gameframework.services.definitions import (
    DEFAULT_CONTRACT_RANGE,
    DefinitionValidationError,
    RunActiveError,
    RunReferencesDefinitionError,
    StructuralChangeRejectedError,
    apply_patch,
    existing_challenges_document,
)
from gameframework.services.definitions import (
    archive as archive_definition,
)
from gameframework.services.definitions import (
    clone as clone_definition,
)
from gameframework.services.definitions import (
    dry_run as dry_run_definition,
)
from gameframework.services.definitions import (
    publish as publish_definition,
)
from gameframework.services.definitions import (
    unarchive as unarchive_definition,
)
from gameframework.services.definitions import (
    unpublish as unpublish_definition,
)
from gameframework.services.fetch import FetchError, fetch_hardened
from gameframework.services.importer import import_definition, strip_url_userinfo
from gameframework.services.sessions import AuthContext

router = APIRouter(tags=["definitions"])

_STAFF_ROLES = (Role.admin, Role.gameadmin)
DOCUMENT_FIELD_NAMES = (
    "name",
    "story",
    "unlock_mode",
    "scoring",
    "participation_mode",
    "challenges",
)


def _get_definition(db: DbSession, definition_id: uuid.UUID) -> EventDefinition:
    definition = db.get(EventDefinition, definition_id)
    if definition is None:
        not_found("object_not_found")
    return definition


def _definition_out(
    definition: EventDefinition, challenges: list[dict[str, Any]]
) -> dict[str, Any]:
    """A field that comes from the event document keeps the document's own
    name — `scoring`, `unlock_mode`, `participation_mode`, `name`,
    `story`, `challenges` — so a client that reads a definition and
    writes it back (the M5 editor) is not translating between two
    vocabularies on the way out any more than `PATCH` makes it translate
    on the way in. The two exceptions are the document's `id` and
    `version`: they surface as `slug` and `source_version`, because the
    resource's own `id` is already this row's UUID and reusing the name
    for the authoring slug would collide with it.
    """
    return {
        "id": str(definition.id),
        "slug": definition.slug,
        "source_version": definition.source_version,
        "name": definition.name,
        "story": definition.story,
        "status": definition.status.value,
        "revision": definition.revision,
        "unlock_mode": definition.unlock_mode.value,
        "scoring": definition.scoring_mode.value,
        "participation_mode": definition.participation_mode.value,
        "privacy_notice_md": definition.privacy_notice_md,
        "challenges": challenges,
    }


def _definition_summary(definition: EventDefinition) -> dict[str, Any]:
    return {
        "id": str(definition.id),
        "slug": definition.slug,
        "name": definition.name,
        "status": definition.status.value,
        "revision": definition.revision,
    }


@router.get("/event-definitions")
def list_definitions(
    cursor: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    auth: AuthContext = Depends(current_session(*_STAFF_ROLES)),
    db: DbSession = Depends(get_session),
) -> dict[str, object]:
    """api-surface.md §1: cursor-paginated; §2.6: "definitions coexist
    freely" — draft, published and archived rows are listed together."""
    page = paginate(db, select(EventDefinition), cursor=cursor, limit=limit)
    return {
        "items": [_definition_summary(d) for d in page.items],
        "next_cursor": page.next_cursor,
    }


@router.post("/event-definitions", status_code=201)
def create_definition(
    auth: AuthContext = Depends(current_session(Role.admin)),
    db: DbSession = Depends(get_session),
) -> dict[str, object]:
    """api-surface.md §2.6: "Create an empty draft" — no body. Every
    NOT NULL column gets a minimal placeholder; the first `PATCH` is where
    real authoring content arrives. Not audited (§2.17's create/transition
    asymmetry — only publish/unpublish/archive/unarchive are)."""
    definition = EventDefinition(
        slug=f"draft-{uuid.uuid4().hex[:8]}",
        source_version="0.1.0",
        name={"en": "Untitled event"},
        story={"en": "Untitled event"},
        status="draft",
        revision=1,
        unlock_mode=UnlockMode.manual,
        scoring_mode=ScoringMode.casual,
        participation_mode=ParticipationMode.teams,
        language_default="en",
        contract_version=DEFAULT_CONTRACT_RANGE,
        gamemaster_enabled=False,
        privacy_notice_md="",
    )
    db.add(definition)
    db.commit()
    return _definition_out(definition, [])


@router.post("/event-definitions/import", status_code=201)
async def import_definition_route(
    request: Request,
    auth: AuthContext = Depends(current_session(Role.admin)),
    db: DbSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, object]:
    """api-surface.md §2.6: "Import from registry URL, repo link, or
    event.yaml upload" — a `multipart/form-data` `file` field carrying a
    raw `event.yaml`, or a JSON body `{"url": "https://..."}` fetched
    through the hardened pipeline (`fetch_hardened`, Task 11 Step 3), raw
    or archived. Dispatched on `Content-Type` — not on which parser
    happens to find something — because Starlette's multipart parser
    consumes the request stream without buffering it the way `.json()`'s
    cached `.body()` read does: calling both on one request raises
    `RuntimeError: Stream consumed` rather than the second one answering
    empty, so only one parser may ever run. Registered ahead of
    `/event-definitions/{definition_id}` so `import` is never captured as
    a `definition_id` path segment.
    """
    content_type = request.headers.get("content-type", "")
    source: str | None = None
    if content_type.startswith("multipart/form-data"):
        form = await request.form()
        upload = form.get("file")
        if not isinstance(upload, UploadFile):
            raise ProblemError(422, "event_yaml_required")
        raw = await upload.read()
    else:
        try:
            body = await request.json()
        except ValueError as exc:
            raise ProblemError(422, "event_yaml_required") from exc
        url = cast(dict[str, Any], body).get("url") if isinstance(body, dict) else None
        if not isinstance(url, str) or not url:
            raise ProblemError(422, "event_yaml_required")
        try:
            raw = fetch_hardened(url)
        except FetchError as exc:
            raise ProblemError(422, exc.code) from exc
        source = strip_url_userinfo(url)

    try:
        document = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ProblemError(422, "event_yaml_invalid", detail=str(exc)) from exc
    if not isinstance(document, dict):
        raise ProblemError(422, "event_yaml_invalid", detail="event.yaml must be a mapping")
    document = cast(dict[str, Any], document)

    try:
        definition = import_definition(db, document, settings, source=source)
    except DefinitionValidationError as exc:
        raise ProblemError(422, "definition_invalid", extensions={"errors": exc.errors}) from exc

    return _definition_out(definition, existing_challenges_document(db, definition))


@router.get("/event-definitions/{definition_id}")
def get_definition(
    definition_id: uuid.UUID,
    response: Response,
    auth: AuthContext = Depends(current_session(*_STAFF_ROLES)),
    db: DbSession = Depends(get_session),
) -> dict[str, object]:
    """api-surface.md §2.6: "returns the revision as ETag"."""
    definition = _get_definition(db, definition_id)
    response.headers["ETag"] = str(definition.revision)
    challenges = existing_challenges_document(db, definition)
    return _definition_out(definition, challenges)


class MinigameRefIn(BaseModel):
    id: str
    version: str
    host_label: str | None = None


class RewardProduceIn(BaseModel):
    name: str
    type: RewardType


class RewardConsumeIn(BaseModel):
    name: str


class RewardsIn(BaseModel):
    produces: list[RewardProduceIn] = []
    consumes: list[RewardConsumeIn] = []


class ChallengeIn(BaseModel):
    id: str
    order: int
    title: dict[str, str]
    text: dict[str, str]
    minigame: MinigameRefIn
    points: int
    hint_cost: int | None = None
    hint_cap: int | None = None
    depends_on: list[str] = []
    rewards: RewardsIn = RewardsIn()


class PatchDefinitionRequest(BaseModel):
    name: dict[str, str] | None = None
    story: dict[str, str] | None = None
    unlock_mode: UnlockMode | None = None
    scoring: ScoringMode | None = None
    participation_mode: ParticipationMode | None = None
    privacy_notice_md: str | None = None
    challenges: list[ChallengeIn] | None = None


@router.patch("/event-definitions/{definition_id}")
def patch_definition(
    definition_id: uuid.UUID,
    body: PatchDefinitionRequest,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    auth: AuthContext = Depends(current_session(*_STAFF_ROLES)),
    db: DbSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, object]:
    """api-surface.md §1/§2.6: requires a **current** `If-Match`, `412`
    with the current revision otherwise — checked before anything else, so
    a lost race never reaches validation. While `draft`, whole-document
    nested authoring; once `published`, the content whitelist."""
    definition = _get_definition(db, definition_id)
    if if_match != str(definition.revision):
        raise ProblemError(412, "revision_mismatch", extensions={"revision": definition.revision})

    dumped = body.model_dump(exclude_unset=True, exclude_none=True, mode="json")
    document_fields = {k: v for k, v in dumped.items() if k in DOCUMENT_FIELD_NAMES}

    try:
        apply_patch(
            db,
            definition,
            settings,
            document_fields=document_fields,
            privacy_notice_md=dumped.get("privacy_notice_md"),
        )
    except DefinitionValidationError as exc:
        raise ProblemError(422, "definition_invalid", extensions={"errors": exc.errors}) from exc
    except StructuralChangeRejectedError as exc:
        if exc.field == "status":
            raise ProblemError(409, "definition_archived") from exc
        raise ProblemError(
            409,
            "structural_change_rejected",
            detail=f"'{exc.field}' cannot change on a published definition",
        ) from exc

    return _definition_out(definition, existing_challenges_document(db, definition))


def _audit_lifecycle(
    db: DbSession, auth: AuthContext, definition: EventDefinition, action: str
) -> None:
    write_audit(
        db,
        actor_user_id=auth.user.id,
        scope=AuditScope.installation,
        event_run_id=None,
        action=action,
        target_type="event_definition",
        target_id=definition.id,
        details={},
    )


@router.post("/event-definitions/{definition_id}/dry-run")
def dry_run_definition_route(
    definition_id: uuid.UUID,
    auth: AuthContext = Depends(current_session(Role.admin)),
    db: DbSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, object]:
    """api-surface.md §2.6: the definition-scoped half of Phase 0 — static
    validation over the definition's own pins (the local-artifact/image-
    pull half is M3, out of scope here). No write: `dry_run_definition`
    never mutates the row or commits, so this reports the same errors
    `publish`/import would without freezing anything."""
    definition = _get_definition(db, definition_id)
    errors = dry_run_definition(db, definition, settings)
    return {"errors": errors}


@router.post("/event-definitions/{definition_id}/publish")
def publish_definition_route(
    definition_id: uuid.UUID,
    auth: AuthContext = Depends(current_session(Role.admin)),
    db: DbSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> dict[str, object]:
    definition = _get_definition(db, definition_id)
    try:
        publish_definition(db, definition, settings)
    except DefinitionValidationError as exc:
        raise ProblemError(422, "definition_invalid", extensions={"errors": exc.errors}) from exc
    except StructuralChangeRejectedError as exc:
        raise ProblemError(409, "invalid_status_transition") from exc
    _audit_lifecycle(db, auth, definition, "event_definition_published")
    db.commit()
    return _definition_out(definition, existing_challenges_document(db, definition))


@router.post("/event-definitions/{definition_id}/unpublish")
def unpublish_definition_route(
    definition_id: uuid.UUID,
    auth: AuthContext = Depends(current_session(Role.admin)),
    db: DbSession = Depends(get_session),
) -> dict[str, object]:
    definition = _get_definition(db, definition_id)
    try:
        unpublish_definition(db, definition)
    except StructuralChangeRejectedError as exc:
        raise ProblemError(409, "invalid_status_transition") from exc
    except RunReferencesDefinitionError as exc:
        raise ProblemError(409, "run_references_definition") from exc
    _audit_lifecycle(db, auth, definition, "event_definition_unpublished")
    db.commit()
    return _definition_out(definition, existing_challenges_document(db, definition))


@router.post("/event-definitions/{definition_id}/archive")
def archive_definition_route(
    definition_id: uuid.UUID,
    auth: AuthContext = Depends(current_session(Role.admin)),
    db: DbSession = Depends(get_session),
) -> dict[str, object]:
    definition = _get_definition(db, definition_id)
    try:
        archive_definition(db, definition)
    except StructuralChangeRejectedError as exc:
        raise ProblemError(409, "invalid_status_transition") from exc
    except RunActiveError as exc:
        raise ProblemError(409, "run_active") from exc
    _audit_lifecycle(db, auth, definition, "event_definition_archived")
    db.commit()
    return _definition_out(definition, existing_challenges_document(db, definition))


@router.post("/event-definitions/{definition_id}/unarchive")
def unarchive_definition_route(
    definition_id: uuid.UUID,
    auth: AuthContext = Depends(current_session(Role.admin)),
    db: DbSession = Depends(get_session),
) -> dict[str, object]:
    definition = _get_definition(db, definition_id)
    try:
        unarchive_definition(db, definition)
    except StructuralChangeRejectedError as exc:
        raise ProblemError(409, "invalid_status_transition") from exc
    _audit_lifecycle(db, auth, definition, "event_definition_unarchived")
    db.commit()
    return _definition_out(definition, existing_challenges_document(db, definition))


@router.post("/event-definitions/{definition_id}/clone", status_code=201)
def clone_definition_route(
    definition_id: uuid.UUID,
    auth: AuthContext = Depends(current_session(Role.admin)),
    db: DbSession = Depends(get_session),
) -> dict[str, object]:
    """api-surface.md §2.6/§2.17: creates a definition rather than
    transitioning one — not audited, the matrix's asymmetry."""
    source = _get_definition(db, definition_id)
    clone_row = clone_definition(db, source)
    return _definition_out(clone_row, existing_challenges_document(db, clone_row))
