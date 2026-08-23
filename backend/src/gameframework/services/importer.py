"""`POST /event-definitions/import` (api-surface.md §2.6; M2-Task-Plan.md
Task 11): the import's own writer. `import_definition` creates a definition
from an already-parsed `event.yaml` document through `services/definitions.
apply_patch` — the exact mechanism `PATCH` uses while `draft` — so the
import is a second *writer*, never a second *mechanism*: it never calls
`validate_event`, `_persist_challenges` or any resolver directly.

Fetching the document (an upload's raw bytes, or a URL through
`services/fetch.fetch_hardened`) is the route's job; this module only turns
an already-parsed document into a persisted `EventDefinition`.
"""

from typing import Any
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy.orm import Session

from gameframework.config import Settings
from gameframework.db.models.authoring import (
    DefinitionStatus,
    EventDefinition,
    ParticipationMode,
    ScoringMode,
    UnlockMode,
)
from gameframework.services.definitions import (
    DefinitionValidationError,
    apply_patch,
)

__all__ = ["import_definition", "strip_url_userinfo"]


def strip_url_userinfo(url: str) -> str:
    """`event_definition.source` (data-model.md §3.4) is "the fetched URL
    for a URL import" — but a URL of the form `https://user:token@host/...`
    carries a credential in its userinfo component, and this column travels
    into `export-yaml` and the audit trail. The host, path, query and
    fragment identify *where* the document came from; the userinfo answers
    *who was authorized to fetch it*, which is not what this column is for.
    """
    parsed = urlsplit(url)
    netloc = parsed.hostname or ""
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


# The document fields `apply_patch`'s draft branch reads out of `provided`
# (services/definitions.py `_apply_draft_document_fields`) — everything an
# import needs re-validated and persisted through that one mechanism.
_DOCUMENT_FIELD_NAMES = (
    "name",
    "story",
    "unlock_mode",
    "scoring",
    "participation_mode",
    "challenges",
)


def _default_language(name: dict[str, str]) -> str:
    """`event_definition.language_default` (data-model.md §3.4) has no
    `event.yaml` field of its own, so it is derived from the document's
    required `name` map: `en` when the map carries it, otherwise the
    alphabetically first key — alphabetical rather than "first", because a
    YAML mapping's iteration order is typing order, not significance.
    """
    if "en" in name:
        return "en"
    return sorted(name)[0]


def import_definition(
    db: Session, document: dict[str, Any], settings: Settings, *, source: str | None
) -> EventDefinition:
    """Creates a `draft` definition from `document` and immediately runs it
    through `apply_patch`'s draft branch — the same validate-then-persist
    pass a whole-document `PATCH` on a fresh draft would run. Raises
    `DefinitionValidationError` (Task 10's own error, carrying the SDK's
    messages) on a failed pipeline pass, and nothing is persisted then.

    Every `NOT NULL` column is set here, before `apply_patch` ever runs,
    so the row is already valid the moment it is constructed — the
    resolver's own `SELECT` inside `apply_patch`'s validation pass
    autoflushes it safely, which is what gives it a real `id` before
    `_persist_challenges` builds `Challenge` rows against
    `definition.id` (a client-side `default=uuid.uuid4` is only evaluated
    at flush, not at construction). On a validation failure `db.rollback()`
    discards that flush — under the SAVEPOINT-based test session
    (`tests/conftest.py`) this rolls back to the savepoint rather than the
    whole transaction, which is what "nothing persisted" tests rely on.

    `revision` starts at `0` rather than the `1` a `POST /event-
    definitions`-created draft carries: `apply_patch` unconditionally
    bumps it by one on success, so a fresh import still lands on `1` —
    the same value a client that never touched the definition would
    expect from its `ETag`.
    """
    definition = EventDefinition(
        slug=document["id"],
        source_version=document["version"],
        name=document["name"],
        story=document["story"],
        status=DefinitionStatus.draft,
        revision=0,
        unlock_mode=UnlockMode(document["unlock_mode"]),
        scoring_mode=ScoringMode(document["scoring"]),
        participation_mode=ParticipationMode(document.get("participation_mode", "teams")),
        theme_ref=document.get("theme"),
        language_default=_default_language(document["name"]),
        contract_version=document["contract"],
        source=source,
        gamemaster_enabled=False,
        privacy_notice_md="",
    )
    document_fields = {k: document[k] for k in _DOCUMENT_FIELD_NAMES if k in document}

    db.add(definition)
    try:
        apply_patch(
            db,
            definition,
            settings,
            document_fields=document_fields,
            privacy_notice_md=None,
        )
    except DefinitionValidationError:
        db.rollback()
        raise
    return definition
