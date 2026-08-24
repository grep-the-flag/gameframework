"""Run preflight — the database half (M2-Task-Plan.md Task 13;
api-surface.md §2.6; data-model.md §3.9, §3.15, §3.16).

REUSE, DO NOT REBUILD: the reserved-label re-check and the pinned-artifact
presence check are both the SDK's own canonical pipeline
(`services.definitions.validate_definition`), re-run here with the
installation's CURRENT `reserved_host_labels` and a `PinnedResolver` built
from the definition's own already-recorded pins — never a hand-written
label comparison and never a fresh `StoreResolver` resolution.
"""

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.config import Settings
from gameframework.db.models.authoring import Challenge, EventDefinition
from gameframework.db.models.identity import User
from gameframework.db.models.infrastructure import ArtifactType, InstalledArtifact
from gameframework.db.models.runs import EventParticipation, EventRun, RunStatus
from gameframework.db.models.runtime import InstanceHealth, MinigameInstance, SolveMode
from gameframework.services.definitions import (
    build_document,
    existing_challenges_document,
    pinned_resolver,
    validate_definition,
)
from gameframework.services.ports import PortRangeTooSmallError, apply_allocations, plan_allocations


class RunNotCreatedError(Exception):
    """The run is not `created`, so neither the preflight nor `start` may
    act on it. Answered as `invalid_status_transition` (api-surface.md
    §1): the same code `definitions.py` uses for "a lifecycle action
    called from a status it does not accept", reused here beyond its
    literal name — nothing "transitions" at a preflight call, but the
    remedy for a client reading this code is identical either way ("this
    run's current status does not allow what you asked"), and Task 12
    already set the precedent of one code for one remedy across two call
    sites (`run_active`, for both a second concurrent run and the archive
    guard). Do not read the code's name as license to invent a second,
    status-mismatch-specific one — that was considered and rejected here.
    """


@dataclass
class PreflightResult:
    passed: bool
    errors: list[str] = field(default_factory=list[str])


def _load_challenges(db: Session, event_definition_id: uuid.UUID) -> list[Challenge]:
    return list(
        db.execute(
            select(Challenge)
            .where(Challenge.event_definition_id == event_definition_id)
            .order_by(Challenge.order_num)
        )
        .scalars()
        .all()
    )


def compute_config_hash(db: Session, run: EventRun, settings: Settings) -> str:
    """SHA-256 over a canonical serialization of exactly the inputs
    data-model.md §3.9 enumerates for M2's own half of the preflight: the
    run's pinned `definition_revision`, the roster, the operator's
    addressing config (port range, player-facing TCP host, event domain,
    reserved host labels), and the pinned artifact set together with each
    pin's presence in the local store. Canonical, so that two
    implementations cannot disagree about a value `start` compares: build
    a mapping holding exactly those inputs, every collection sorted by a
    stable key (participations by `id`, pins by `(artifact_id, version)`,
    reserved labels lexicographically), then
    `json.dumps(payload, sort_keys=True, separators=(",", ":"),
    ensure_ascii=False)`, UTF-8 encoded, hex digest. An absent optional
    value is serialized as `null` rather than omitted, so "unset" and
    "missing" cannot hash alike.

    Signature note: the plan's own Interfaces line writes this as
    `compute_config_hash(run) -> str`. `db` and `settings` are added here
    because the prescribed inputs are not reachable from `run` alone — no
    ORM relationships exist on this model layer (every sibling service
    function takes an explicit `Session`), and none of the addressing
    config lives on the row. What is prescribed to the byte is the
    serialization below, not the parameter list.

    M2 scope: the gamemaster configuration of a `gamemaster_enabled` run
    is *not* an input here, even though data-model.md §3.9 lists it —
    that sealing exists because "this same preflight checks that
    provider's reachability", and the reachability check is M3's
    (api-surface.md §2.6's M2/M3 split). M3 adds it to this payload
    alongside the check it seals, per "M3 adds checks to it rather than
    replacing it" — not before.

    Each pin's `artifact_id` and `image_digest` are hashed but not
    independently mutation-bound the way `version` is: no live route ever
    varies either one without also moving the `present` lookup they feed
    (it is keyed on all three together), so no real path exercises them
    on their own. Hashing them separately buys nothing observable through
    this codebase's own write paths — this is a deliberately untested
    corner, not an oversight.
    """
    participations = sorted(
        db.execute(select(EventParticipation).where(EventParticipation.event_run_id == run.id))
        .scalars()
        .all(),
        key=lambda p: str(p.id),
    )
    roster = [
        {"id": str(p.id), "team_id": str(p.team_id) if p.team_id is not None else None}
        for p in participations
    ]

    challenges = sorted(
        _load_challenges(db, run.event_definition_id),
        key=lambda c: (c.minigame_id, c.minigame_version),
    )
    pins: list[dict[str, str | bool]] = []
    for challenge in challenges:
        present = (
            db.execute(
                select(InstalledArtifact.id)
                .where(
                    InstalledArtifact.type == ArtifactType.minigame,
                    InstalledArtifact.artifact_id == challenge.minigame_id,
                    InstalledArtifact.version == challenge.minigame_version,
                    InstalledArtifact.image_digest == challenge.minigame_image_digest,
                )
                .limit(1)
            )
            .scalars()
            .first()
            is not None
        )
        pins.append(
            {
                "artifact_id": challenge.minigame_id,
                "version": challenge.minigame_version,
                "image_digest": challenge.minigame_image_digest,
                "present": present,
            }
        )

    payload = {
        "definition_revision": run.definition_revision,
        "roster": roster,
        "port_range": list(settings.tcp_port_range),
        "player_tcp_host": settings.player_tcp_host,
        "event_domain": settings.event_domain,
        "reserved_host_labels": sorted(settings.reserved_host_labels),
        "pins": pins,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _teamless_errors(db: Session, run_id: uuid.UUID) -> list[str]:
    """api-surface.md §2.6: "a participation still carrying `team_id =
    NULL` fails the preflight and is named in the result" — named by the
    account (`user.username`), since that is what the operator building
    the roster recognizes."""
    usernames = (
        db.execute(
            select(User.username)
            .join(EventParticipation, EventParticipation.user_id == User.id)
            .where(EventParticipation.event_run_id == run_id, EventParticipation.team_id.is_(None))
            .order_by(User.username)
        )
        .scalars()
        .all()
    )
    return [f"participant '{username}' has no team" for username in usernames]


def _materialize_instances(
    db: Session,
    run: EventRun,
    challenges: list[Challenge],
    manifest_by_minigame_id: dict[str, dict[str, Any]],
    settings: Settings,
) -> dict[str, MinigameInstance]:
    """data-model.md §3.15: "hostname, solve_mode, image_ref and
    image_digest are resolved out of the manifest here and not at
    deploy". `image_digest` is copied from `challenge.minigame_image_
    digest` (the pin import validated), never re-read off the store row —
    the store's own digest column is only what proves the pin is still
    present (checked before this function is ever reached).
    """
    instances: dict[str, MinigameInstance] = {}
    for challenge in challenges:
        manifest = manifest_by_minigame_id[challenge.minigame_id]
        player_facing: bool = manifest.get("http", {}).get("player_facing", True)
        hostname = (
            f"{challenge.minigame_host_label}.{settings.event_domain}" if player_facing else None
        )
        solve_mode = SolveMode(manifest.get("solve_mode", "flag"))
        image_ref = manifest["image"]

        instance = db.execute(
            select(MinigameInstance).where(
                MinigameInstance.event_run_id == run.id,
                MinigameInstance.minigame_id == challenge.minigame_id,
            )
        ).scalar_one_or_none()
        if instance is None:
            instance = MinigameInstance(
                event_run_id=run.id,
                minigame_id=challenge.minigame_id,
                hostname=hostname,
                solve_mode=solve_mode,
                image_ref=image_ref,
                image_digest=challenge.minigame_image_digest,
                health=InstanceHealth.unknown,
            )
            db.add(instance)
        else:
            instance.hostname = hostname
            instance.solve_mode = solve_mode
            instance.image_ref = image_ref
            instance.image_digest = challenge.minigame_image_digest
        db.flush()
        instances[challenge.minigame_id] = instance
    return instances


def run_preflight(db: Session, run: EventRun, settings: Settings) -> PreflightResult:
    """api-surface.md §2.6, data-model.md §3.15/§3.16: the run-scoped half
    of Phase 0, available while the run is `created` and repeatable.

    M2's four checks: roster complete and teamed; the pinned artifact set
    present in the local store, looked up rather than re-resolved; no
    effective `minigame_host_label` colliding with the CURRENT reserved
    list (both via one re-run of the canonical pipeline,
    `services.definitions.validate_definition`, against a `PinnedResolver`
    built from the definition's own recorded pins — never a hand-written
    label comparison); and port/container capacity, naming the range size
    it would need rather than merely refusing. The gamemaster provider/
    reachability check is M3's (api-surface.md §2.6's M2/M3 split) and is
    deliberately not implemented here.

    Success materializes `minigame_instance` rows and allocates
    `minigame_port` rows. Failure writes nothing at all — in particular it
    never touches `preflight_passed_at`/`preflight_config_hash`, which are
    written by the *last successful* preflight and by nothing else
    (data-model.md §3.9): a failing re-run after an earlier pass leaves
    that pass on record, and what gates `start` from then on is a stale
    hash, not a cleared timestamp.
    """
    if run.status is not RunStatus.created:
        raise RunNotCreatedError()

    errors = _teamless_errors(db, run.id)

    definition = db.get(EventDefinition, run.event_definition_id)
    assert definition is not None  # ON DELETE RESTRICT: a run's definition cannot vanish

    challenges = _load_challenges(db, definition.id)
    resolver = pinned_resolver(db, challenges)
    document = build_document(definition, existing_challenges_document(db, definition))
    pipeline_errors, _ = validate_definition(document, resolver, settings)
    errors += pipeline_errors

    plan: list[tuple[str, int]] | None = None
    manifest_by_minigame_id: dict[str, dict[str, Any]] = {}
    if not pipeline_errors:
        for challenge in challenges:
            row = resolver.resolve_row(challenge.minigame_id, challenge.minigame_version_range)
            assert row is not None  # the pipeline above already confirmed presence
            manifest_by_minigame_id[challenge.minigame_id] = row.manifest
        tcp_ports_by_minigame_id = {
            minigame_id: [port["port"] for port in manifest.get("tcp_ports", [])]
            for minigame_id, manifest in manifest_by_minigame_id.items()
        }
        try:
            plan = plan_allocations(db, run, tcp_ports_by_minigame_id, settings.tcp_port_range)
        except PortRangeTooSmallError as exc:
            errors.append(str(exc))

    if errors:
        return PreflightResult(passed=False, errors=errors)

    assert plan is not None  # pipeline had no errors, so the port check ran and set this
    instances = _materialize_instances(db, run, challenges, manifest_by_minigame_id, settings)
    apply_allocations(db, instances, plan, settings.tcp_port_range)

    run.preflight_passed_at = datetime.now(UTC)
    run.preflight_config_hash = compute_config_hash(db, run, settings)
    db.commit()
    return PreflightResult(passed=True, errors=[])
