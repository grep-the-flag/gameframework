"""Event definitions — authoring, lifecycle and the post-publication content
whitelist (M2-Task-Plan.md Task 10; api-surface.md §2.6, §2.17;
data-model.md §3.4-§3.8; sdk-contract-v1.md §3.4).

The "document" this module maps definitions to and from is shaped exactly
like `event.yaml` (sdk-contract-v1.md §3.2): what
`gameframework_sdk.validation.validate_event` needs to run the canonical
pipeline, and what Task 11's import and the M5 export will both read and
write (`event_definition.slug`/`source_version` exist for exactly this
roundtrip — data-model.md §3.4). A definition's scalar identity fields
supply the envelope (`id`/`version`/`contract`/`schema_version`); its
challenge/dependency/reward rows supply `challenges[]`. The document's
`minigame.version` is always the authored **range** — `event.yaml` has no
field for a resolved pin, so `clone` and `_persist_challenges` read
`Challenge` rows directly wherever they need the resolved
`minigame_version`/`minigame_image_digest` pair instead.

Both PATCH branches — the draft's whole-document authoring and the
published whitelist — share `_persist_challenges` and the pin-recording
step: "any write that sets or changes a challenge's minigame reference
resolves it through `StoreResolver`" holds for both, since a text-only
whitelist edit still walks every challenge to rebuild the document that
`PinnedResolver`-backed validation re-checks (SDK contract §3.4 check 13).
"""

import uuid
from dataclasses import dataclass, field
from typing import Any

from gameframework_sdk.validation import validate_event
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from gameframework.config import Settings
from gameframework.db.models.authoring import (
    Challenge,
    ChallengeDependency,
    DefinitionStatus,
    DependencySource,
    EventDefinition,
    ParticipationMode,
    RewardConsumption,
    RewardDefinition,
    RewardType,
    ScoringMode,
    UnlockMode,
)
from gameframework.db.models.runs import EventRun, RunStatus
from gameframework.services.artifacts import PinnedResolver, StoreResolver

# sdk-contract-v1.md §2.1/§3.1's own example manifests: the SDK contract's
# current range while it is pre-1.0 ("the SDK contract range you built
# against"). Distinct from api/info.py's SUPPORTED_CONTRACT_RANGE — that
# docstring names it as the REST API's own contract axis, a different thing
# from the SDK manifest `contract` field this becomes at creation.
DEFAULT_CONTRACT_RANGE = ">=0.1,<1.0"

_SCHEMA_VERSION = 1

_WHITELISTED_TOP_LEVEL_FIELDS = frozenset({"name", "story"})
_WHITELISTED_CHALLENGE_FIELDS = frozenset({"title", "text", "points", "hint_cost", "hint_cap"})


class DefinitionValidationError(Exception):
    """The merged document failed `validate_event` (sdk-contract-v1.md
    §3.4). Carries the SDK's own error strings, which already name the
    offending minigame/placeholder/field — the route surfaces them
    verbatim rather than composing a second message.
    """

    def __init__(self, errors: list[str]) -> None:
        super().__init__("; ".join(errors))
        self.errors = errors


class StructuralChangeRejectedError(Exception):
    """A published definition's `PATCH` tried to change a field outside the
    content whitelist (api-surface.md §2.6): challenge set, `order`,
    `depends_on`, reward wiring, minigame reference, `unlock_mode` or
    `scoring`. Also raised (field `"status"`) by a lifecycle action
    called from a status it does not accept.
    """

    def __init__(self, field: str) -> None:
        super().__init__(field)
        self.field = field


class RunReferencesDefinitionError(Exception):
    """`unpublish` (api-surface.md §2.6): refused while any `event_run`
    still references this definition — reopening structural editing under
    a run would corrupt state the run already depends on."""


class RunActiveError(Exception):
    """`archive` (api-surface.md §2.6): refused while a run of this
    definition is `running` or `paused`. `archived` shares the `status`
    column with `published`, so archiving behind a live run would make
    that run's own definition read as un-published to anything that
    checks status — a data-integrity guard, not a policy one. Content
    fixes stay allowed mid-run (the post-publication whitelist); this
    guards `status` alone.
    """


def default_document_fields(definition: EventDefinition) -> dict[str, Any]:
    """The envelope every document needs (SDK schema-required top-level
    fields not carried by `challenges[]`), read off the definition row.
    """
    return {
        "schema_version": _SCHEMA_VERSION,
        "contract": definition.contract_version,
        "id": definition.slug,
        "version": definition.source_version,
        "name": definition.name,
        "story": definition.story,
        "scoring": definition.scoring_mode.value,
        "unlock_mode": definition.unlock_mode.value,
        "participation_mode": definition.participation_mode.value,
    }


def _load_challenges(db: Session, definition_id: uuid.UUID) -> list[Challenge]:
    return list(
        db.execute(
            select(Challenge)
            .where(Challenge.event_definition_id == definition_id)
            .order_by(Challenge.order_num)
        )
        .scalars()
        .all()
    )


def existing_challenges_document(db: Session, definition: EventDefinition) -> list[dict[str, Any]]:
    """The definition's currently-persisted challenges, in `event.yaml`
    shape — what a whitelist `PATCH` diffs against and re-validates, and
    what a `GET` read serializes. `minigame.version` here is the authored
    range (`minigame_version_range`), not the resolved pin.
    """
    challenges = _load_challenges(db, definition.id)
    if not challenges:
        return []
    challenge_ids = [c.id for c in challenges]
    slug_by_id = {c.id: c.slug for c in challenges}

    depends_on: dict[uuid.UUID, list[str]] = {c.id: [] for c in challenges}
    for dep in (
        db.execute(
            select(ChallengeDependency).where(
                ChallengeDependency.challenge_id.in_(challenge_ids),
                ChallengeDependency.source == DependencySource.explicit,
            )
        )
        .scalars()
        .all()
    ):
        depends_on[dep.challenge_id].append(slug_by_id[dep.depends_on_id])

    produces: dict[uuid.UUID, list[dict[str, Any]]] = {c.id: [] for c in challenges}
    reward_name_by_id: dict[uuid.UUID, str] = {}
    for reward in (
        db.execute(
            select(RewardDefinition).where(
                RewardDefinition.producer_challenge_id.in_(challenge_ids)
            )
        )
        .scalars()
        .all()
    ):
        produces[reward.producer_challenge_id].append(
            {"name": reward.name, "type": reward.type.value}
        )
        reward_name_by_id[reward.id] = reward.name

    consumes: dict[uuid.UUID, list[dict[str, Any]]] = {c.id: [] for c in challenges}
    if reward_name_by_id:
        for consumption in (
            db.execute(
                select(RewardConsumption).where(
                    RewardConsumption.reward_definition_id.in_(reward_name_by_id.keys())
                )
            )
            .scalars()
            .all()
        ):
            consumes[consumption.consumer_challenge_id].append(
                {"name": reward_name_by_id[consumption.reward_definition_id]}
            )

    return [
        {
            "id": c.slug,
            "order": c.order_num,
            "title": c.title,
            "text": c.text,
            "minigame": {
                "id": c.minigame_id,
                "version": c.minigame_version_range,
                "host_label": c.minigame_host_label,
            },
            "points": c.points,
            "hint_cost": c.hint_cost,
            "hint_cap": c.hint_cap,
            "depends_on": depends_on[c.id],
            "rewards": {"produces": produces[c.id], "consumes": consumes[c.id]},
        }
        for c in challenges
    ]


def build_document(definition: EventDefinition, challenges: list[dict[str, Any]]) -> dict[str, Any]:
    """`default_document_fields` plus a given `challenges[]` — kept as a
    parameter rather than always re-reading rows, so the same function
    builds a document over content that has not been persisted yet (the
    pre-write validation pass) and content that has (`GET`, `existing_
    challenges_document`).
    """
    return {**default_document_fields(definition), "challenges": challenges}


@dataclass
class _PinRecordingResolver:
    """Wraps a `StoreResolver`/`PinnedResolver` so a single `validate_event`
    pass also collects every pin it resolves, as a side effect of the
    *same* calls: `validate_event`'s checks 1-4 call `resolver.resolve()`
    exactly once per challenge (sdk-contract-v1.md §3.4), so recording here
    costs nothing extra and leaves no window between "resolved during
    validation" and "resolved again to persist" — there is only one
    resolution, full stop.
    """

    inner: "StoreResolver | PinnedResolver"
    pins: dict[str, tuple[str, str]] = field(default_factory=dict[str, tuple[str, str]])

    def resolve(self, minigame_id: str, version_range: str) -> dict[str, Any] | None:
        row = self.inner.resolve_row(minigame_id, version_range)
        # `image_digest` is nullable at the column level (a theme/language
        # artifact carries none), so an installed *minigame* row missing
        # one is a data-integrity fault this treats as "does not resolve"
        # rather than letting a None reach a NOT NULL challenge column —
        # a clean refusal at validation, never an IntegrityError at write.
        if row is None or row.image_digest is None:
            return None
        self.pins[minigame_id] = (row.version, row.image_digest)
        return row.manifest


def validate_definition(
    document: dict[str, Any], resolver: "StoreResolver | PinnedResolver", settings: Settings
) -> tuple[list[str], dict[str, tuple[str, str]]]:
    """The one canonical pipeline (sdk-contract-v1.md §3.4), never
    reimplemented here — wraps `validate_event` with the installation's
    reserved host labels. Returns `(errors, pins)`: `pins` is
    `minigame_id -> (version, image_digest)` for every minigame reference
    `validate_event` resolved while checking the document (empty on a
    schema failure, since resolution never runs then) — the callers that
    persist new pins (`_apply_draft_document_fields`) use it; the ones
    re-validating against pins that already exist (whitelist, `publish`)
    ignore it.
    """
    recording = _PinRecordingResolver(inner=resolver)
    errors = validate_event(
        document, resolver=recording, reserved_host_labels=settings.reserved_host_labels
    )
    return errors, recording.pins


def pinned_resolver(db: Session, challenge_rows: list[Challenge]) -> PinnedResolver:
    """`PinnedResolver` built from a document's own already-recorded pins
    (sdk-contract-v1.md §3.4, "every later [pass] resolves against what
    that first one pinned") — what a whitelist edit and `publish` both
    re-validate against, never a fresh `StoreResolver` pass that could
    silently adopt an artifact installed since the pins were set.
    """
    pins = {
        row.minigame_id: (row.minigame_version, row.minigame_image_digest) for row in challenge_rows
    }
    return PinnedResolver(db=db, pins=pins)


def _persist_challenges(
    db: Session,
    definition: EventDefinition,
    challenges: list[dict[str, Any]],
    pins: dict[str, tuple[str, str]],
) -> None:
    """Wholesale replace: draft authoring resends the whole graph each
    time (api-surface.md §2.6, "whole-document nested authoring"), and
    while draft no run can reference these rows yet (a run only ever
    targets a *published* definition), so delete-then-reinsert is safe —
    nothing outside this definition holds one of the old challenge ids.
    """
    existing_ids = list(
        db.execute(
            select(Challenge.id).where(Challenge.event_definition_id == definition.id)
        ).scalars()
    )
    if existing_ids:
        db.execute(
            delete(ChallengeDependency).where(ChallengeDependency.challenge_id.in_(existing_ids))
        )
        db.execute(
            delete(ChallengeDependency).where(ChallengeDependency.depends_on_id.in_(existing_ids))
        )
        reward_ids = list(
            db.execute(
                select(RewardDefinition.id).where(
                    RewardDefinition.producer_challenge_id.in_(existing_ids)
                )
            ).scalars()
        )
        if reward_ids:
            db.execute(
                delete(RewardConsumption).where(
                    RewardConsumption.reward_definition_id.in_(reward_ids)
                )
            )
            db.execute(delete(RewardDefinition).where(RewardDefinition.id.in_(reward_ids)))
        db.execute(delete(Challenge).where(Challenge.id.in_(existing_ids)))
        db.flush()

    rows_by_slug: dict[str, Challenge] = {}
    for entry in challenges:
        ref = entry["minigame"]
        # validate_definition's own resolver pass already recorded this
        # pin (data-model.md §3.5) — a KeyError here would mean validate_
        # event reported success without resolving every challenge, which
        # is a defect in that pass, not a case for this one to guard.
        version, image_digest = pins[ref["id"]]
        row = Challenge(
            event_definition_id=definition.id,
            slug=entry["id"],
            order_num=entry["order"],
            title=entry["title"],
            text=entry["text"],
            minigame_id=ref["id"],
            minigame_version_range=ref["version"],
            minigame_version=version,
            minigame_image_digest=image_digest,
            minigame_host_label=ref.get("host_label") or ref["id"],
            points=entry["points"],
            # hint_cost has no event.yaml default (sdk-contract-v1.md §3.2
            # leaves it optional with none stated); 0 is the "no charge
            # unless authored" reading the NOT NULL column needs.
            hint_cost=entry.get("hint_cost") or 0,
            # data-model.md §3.5: "hint_cap ... default = points".
            hint_cap=entry["hint_cap"] if entry.get("hint_cap") is not None else entry["points"],
        )
        db.add(row)
        db.flush()
        rows_by_slug[entry["id"]] = row

    produced_by: dict[str, str] = {}
    reward_rows: dict[tuple[str, str], RewardDefinition] = {}
    for entry in challenges:
        row = rows_by_slug[entry["id"]]
        for produced in entry.get("rewards", {}).get("produces", []):
            reward_row = RewardDefinition(
                producer_challenge_id=row.id,
                name=produced["name"],
                type=RewardType(produced["type"]),
            )
            db.add(reward_row)
            db.flush()
            reward_rows[(entry["id"], produced["name"])] = reward_row
            produced_by[produced["name"]] = entry["id"]

    # A (challenge_id, depends_on_id) pair can arise from both an explicit
    # depends_on entry and a reward-consumption edge on the same producer;
    # the composite PK holds one row per pair, so the first source to name a
    # pair wins and the second is skipped rather than raising — validate_
    # event does not treat the double-statement as an error (§3.4 check 10
    # dedupes it the same way for cycle detection), so persistence should not
    # either.
    seen_pairs: set[tuple[uuid.UUID, uuid.UUID]] = set()

    def _add_dependency(
        consumer_id: uuid.UUID, producer_id: uuid.UUID, source: DependencySource
    ) -> None:
        pair = (consumer_id, producer_id)
        if pair in seen_pairs:
            return
        seen_pairs.add(pair)
        db.add(ChallengeDependency(challenge_id=pair[0], depends_on_id=pair[1], source=source))

    for entry in challenges:
        consumer = rows_by_slug[entry["id"]]
        for dep_slug in entry.get("depends_on", []):
            _add_dependency(consumer.id, rows_by_slug[dep_slug].id, DependencySource.explicit)
        for consumed in entry.get("rewards", {}).get("consumes", []):
            producer_slug = produced_by[consumed["name"]]
            reward_row = reward_rows[(producer_slug, consumed["name"])]
            db.add(
                RewardConsumption(
                    reward_definition_id=reward_row.id, consumer_challenge_id=consumer.id
                )
            )
            _add_dependency(consumer.id, rows_by_slug[producer_slug].id, DependencySource.reward)
    db.flush()


def apply_patch(
    db: Session,
    definition: EventDefinition,
    settings: Settings,
    *,
    document_fields: dict[str, Any],
    privacy_notice_md: str | None,
) -> None:
    """The one `PATCH /event-definitions/{id}` entry point (api-surface.md
    §2.6): dispatches `document_fields` — whatever of `name`/`story`/
    `unlock_mode`/`scoring`/`participation_mode`/`challenges` the
    request actually set — to the draft or whitelist branch by status, and
    applies `privacy_notice_md` beside either one: "operator content, not
    game design... it is no `event.yaml` field" (data-model.md §3.4), so it
    never enters the document `validate_event` checks and stays writable
    regardless of status (except `archived`, alongside everything else).
    One revision bump and one commit cover whichever of the two actually
    wrote something, so a `privacy_notice_md`-only edit still consumes the
    caller's `If-Match` the same as a structural one.
    """
    if definition.status is DefinitionStatus.archived:
        raise StructuralChangeRejectedError("status")

    if privacy_notice_md is not None:
        definition.privacy_notice_md = privacy_notice_md

    if document_fields:
        if definition.status is DefinitionStatus.draft:
            _apply_draft_document_fields(db, definition, settings, document_fields)
        else:
            _apply_whitelist_document_fields(db, definition, settings, document_fields)

    definition.revision += 1
    db.commit()


def _apply_draft_document_fields(
    db: Session, definition: EventDefinition, settings: Settings, provided: dict[str, Any]
) -> None:
    """Draft-only: `provided` is whatever top-level document keys the
    request actually set (challenges included), overlaid on the current
    document and re-validated **whole** through `StoreResolver` — the first
    resolution for any minigame reference this write sets or changes
    (sdk-contract-v1.md §3.4), recording fresh pins on success. Raises
    `DefinitionValidationError` and persists nothing on failure.
    """
    current = build_document(definition, existing_challenges_document(db, definition))
    merged = {**current, **provided}

    resolver = StoreResolver(db=db)
    errors, pins = validate_definition(merged, resolver, settings)
    if errors:
        raise DefinitionValidationError(errors)

    for attr in ("name", "story"):
        if attr in provided:
            setattr(definition, attr, provided[attr])
    if "unlock_mode" in provided:
        definition.unlock_mode = UnlockMode(provided["unlock_mode"])
    if "scoring" in provided:
        definition.scoring_mode = ScoringMode(provided["scoring"])
    if "participation_mode" in provided:
        definition.participation_mode = ParticipationMode(provided["participation_mode"])

    if "challenges" in provided:
        _persist_challenges(db, definition, provided["challenges"], pins)
    db.flush()


def _reward_signature(entries: list[dict[str, Any]]) -> list[tuple[tuple[str, Any], ...]]:
    return sorted(tuple(sorted(entry.items())) for entry in entries)


def _apply_whitelist_document_fields(
    db: Session, definition: EventDefinition, settings: Settings, provided: dict[str, Any]
) -> None:
    """Published-only content whitelist (api-surface.md §2.6): `name`,
    `story` and each challenge's `title`/`text`/`points`/`hint_cost`/
    `hint_cap` may change; everything else in `provided` must equal the
    current document exactly or the whole `PATCH` is refused, naming the
    field, before anything is written. A **text** edit still re-runs the
    canonical pipeline against `PinnedResolver` (SDK contract §3.4 check
    13), which is what catches a mangled access placeholder at the write.
    """
    challenge_rows = _load_challenges(db, definition.id)
    current_challenges = existing_challenges_document(db, definition)
    current = build_document(definition, current_challenges)

    for key, value in provided.items():
        if key in _WHITELISTED_TOP_LEVEL_FIELDS or key == "challenges":
            continue
        if current.get(key) != value:
            raise StructuralChangeRejectedError(key)

    incoming_challenges = provided.get("challenges")
    if incoming_challenges is not None:
        current_by_id = {c["id"]: c for c in current_challenges}
        incoming_ids = [c["id"] for c in incoming_challenges]
        if set(incoming_ids) != current_by_id.keys() or len(incoming_ids) != len(current_by_id):
            raise StructuralChangeRejectedError("challenges")
        for incoming in incoming_challenges:
            cid = incoming["id"]
            existing = current_by_id[cid]
            if incoming["order"] != existing["order"]:
                raise StructuralChangeRejectedError(f"challenges/{cid}/order")
            incoming_minigame = incoming["minigame"]
            effective_host_label = incoming_minigame.get("host_label") or incoming_minigame["id"]
            if (
                incoming_minigame["id"] != existing["minigame"]["id"]
                or incoming_minigame["version"] != existing["minigame"]["version"]
                or effective_host_label != existing["minigame"]["host_label"]
            ):
                raise StructuralChangeRejectedError(f"challenges/{cid}/minigame")
            if sorted(incoming.get("depends_on", [])) != sorted(existing["depends_on"]):
                raise StructuralChangeRejectedError(f"challenges/{cid}/depends_on")
            incoming_rewards = incoming.get("rewards", {})
            if _reward_signature(incoming_rewards.get("produces", [])) != _reward_signature(
                existing["rewards"]["produces"]
            ):
                raise StructuralChangeRejectedError(f"challenges/{cid}/rewards/produces")
            if _reward_signature(incoming_rewards.get("consumes", [])) != _reward_signature(
                existing["rewards"]["consumes"]
            ):
                raise StructuralChangeRejectedError(f"challenges/{cid}/rewards/consumes")

    merged_challenges = (
        incoming_challenges if incoming_challenges is not None else current_challenges
    )
    merged = {**current, **provided, "challenges": merged_challenges}

    resolver = pinned_resolver(db, challenge_rows)
    errors, _ = validate_definition(merged, resolver, settings)
    if errors:
        raise DefinitionValidationError(errors)

    for attr in ("name", "story"):
        if attr in provided:
            setattr(definition, attr, provided[attr])

    if incoming_challenges is not None:
        rows_by_slug = {row.slug: row for row in challenge_rows}
        for incoming in incoming_challenges:
            row = rows_by_slug[incoming["id"]]
            for attr in _WHITELISTED_CHALLENGE_FIELDS:
                if attr in incoming:
                    setattr(row, attr, incoming[attr])
    db.flush()


def publish(db: Session, definition: EventDefinition, settings: Settings) -> None:
    """api-surface.md §2.6: freezes structure; validation must pass —
    against `PinnedResolver`, since every challenge's minigame reference
    was already resolved (through `StoreResolver`) by the draft write that
    set it (sdk-contract-v1.md §3.4, pin-once-resolve-against-pins)."""
    if definition.status is not DefinitionStatus.draft:
        raise StructuralChangeRejectedError("status")
    challenge_rows = _load_challenges(db, definition.id)
    document = build_document(definition, existing_challenges_document(db, definition))
    resolver = pinned_resolver(db, challenge_rows)
    errors, _ = validate_definition(document, resolver, settings)
    if errors:
        raise DefinitionValidationError(errors)
    definition.status = DefinitionStatus.published
    db.commit()


def has_referencing_run(db: Session, definition_id: uuid.UUID) -> bool:
    """Shared by `unpublish` and `unarchive` (api-surface.md §2.6): whether
    any `event_run` still references this definition. `unpublish` refuses
    while true; `unarchive` uses it to decide whether the definition lands
    back on `published` (a run already depends on this exact frozen
    structure) or `draft` (nothing does, so a fresh `publish` must re-run
    the pipeline before it is runnable again — the store may have moved
    while it sat archived).
    """
    return (
        db.execute(
            select(EventRun.id).where(EventRun.event_definition_id == definition_id).limit(1)
        )
        .scalars()
        .first()
        is not None
    )


def unpublish(db: Session, definition: EventDefinition) -> None:
    if definition.status is not DefinitionStatus.published:
        raise StructuralChangeRejectedError("status")
    if has_referencing_run(db, definition.id):
        raise RunReferencesDefinitionError()
    definition.status = DefinitionStatus.draft
    db.commit()


def _has_active_run(db: Session, definition_id: uuid.UUID) -> bool:
    """`archive`'s own guard (api-surface.md §2.6): whether a run of this
    definition is currently `running` or `paused` — narrower than
    `has_referencing_run`, which any lifecycle status derivation uses
    regardless of the run's own state."""
    return (
        db.execute(
            select(EventRun.id)
            .where(
                EventRun.event_definition_id == definition_id,
                EventRun.status.in_((RunStatus.running, RunStatus.paused)),
            )
            .limit(1)
        )
        .scalars()
        .first()
        is not None
    )


def archive(db: Session, definition: EventDefinition) -> None:
    if definition.status is DefinitionStatus.archived:
        raise StructuralChangeRejectedError("status")
    if _has_active_run(db, definition.id):
        raise RunActiveError()
    definition.status = DefinitionStatus.archived
    db.commit()


def unarchive(db: Session, definition: EventDefinition) -> None:
    if definition.status is not DefinitionStatus.archived:
        raise StructuralChangeRejectedError("status")
    definition.status = (
        DefinitionStatus.published
        if has_referencing_run(db, definition.id)
        else DefinitionStatus.draft
    )
    db.commit()


def clone(db: Session, source: EventDefinition) -> EventDefinition:
    """api-surface.md §2.6: "the real clone, no export-delete-import
    dance" — a new, independent draft copying the source's current
    content, structural and otherwise, pins included: the source's pins
    are already-resolved facts about content that passed validation
    before, not a new resolution, so this reads `Challenge` rows directly
    (for `minigame_version`/`minigame_image_digest`) and copies them
    verbatim rather than going through `_persist_challenges`, which always
    re-resolves. Not audited: like `POST /event-definitions`, it creates a
    definition rather than transitioning one (§2.17's asymmetry).
    """
    source_challenges = _load_challenges(db, source.id)

    clone_row = EventDefinition(
        slug=source.slug,
        source_version=source.source_version,
        name=source.name,
        story=source.story,
        status=DefinitionStatus.draft,
        revision=1,
        unlock_mode=source.unlock_mode,
        scoring_mode=source.scoring_mode,
        participation_mode=source.participation_mode,
        grace_period_days=source.grace_period_days,
        theme_ref=source.theme_ref,
        language_default=source.language_default,
        contract_version=source.contract_version,
        source=source.source,
        gamemaster_enabled=source.gamemaster_enabled,
        privacy_notice_md=source.privacy_notice_md,
    )
    db.add(clone_row)
    db.flush()

    rows_by_slug: dict[str, Challenge] = {}
    for source_row in source_challenges:
        row = Challenge(
            event_definition_id=clone_row.id,
            slug=source_row.slug,
            order_num=source_row.order_num,
            title=source_row.title,
            text=source_row.text,
            minigame_id=source_row.minigame_id,
            minigame_version_range=source_row.minigame_version_range,
            minigame_version=source_row.minigame_version,
            minigame_image_digest=source_row.minigame_image_digest,
            minigame_host_label=source_row.minigame_host_label,
            points=source_row.points,
            hint_cost=source_row.hint_cost,
            hint_cap=source_row.hint_cap,
        )
        db.add(row)
        db.flush()
        rows_by_slug[source_row.slug] = row

    source_ids = [row.id for row in source_challenges]
    if source_ids:
        slug_by_id = {row.id: row.slug for row in source_challenges}

        for dep in (
            db.execute(
                select(ChallengeDependency).where(ChallengeDependency.challenge_id.in_(source_ids))
            )
            .scalars()
            .all()
        ):
            db.add(
                ChallengeDependency(
                    challenge_id=rows_by_slug[slug_by_id[dep.challenge_id]].id,
                    depends_on_id=rows_by_slug[slug_by_id[dep.depends_on_id]].id,
                    source=dep.source,
                )
            )

        source_rewards = (
            db.execute(
                select(RewardDefinition).where(
                    RewardDefinition.producer_challenge_id.in_(source_ids)
                )
            )
            .scalars()
            .all()
        )
        clone_reward_by_source_id: dict[uuid.UUID, RewardDefinition] = {}
        for source_reward in source_rewards:
            clone_reward = RewardDefinition(
                producer_challenge_id=rows_by_slug[
                    slug_by_id[source_reward.producer_challenge_id]
                ].id,
                name=source_reward.name,
                type=source_reward.type,
            )
            db.add(clone_reward)
            db.flush()
            clone_reward_by_source_id[source_reward.id] = clone_reward

        if clone_reward_by_source_id:
            for consumption in (
                db.execute(
                    select(RewardConsumption).where(
                        RewardConsumption.reward_definition_id.in_(clone_reward_by_source_id.keys())
                    )
                )
                .scalars()
                .all()
            ):
                db.add(
                    RewardConsumption(
                        reward_definition_id=clone_reward_by_source_id[
                            consumption.reward_definition_id
                        ].id,
                        consumer_challenge_id=rows_by_slug[
                            slug_by_id[consumption.consumer_challenge_id]
                        ].id,
                    )
                )

    db.commit()
    return clone_row
