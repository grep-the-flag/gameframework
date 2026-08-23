"""The local artifact store: the operator drop-in directory and the two
`gameframework_sdk.validation.MinigameResolver` implementations
(M2-Task-Plan.md Task 9; data-model.md §3.26; sdk-contract-v1.md §3.4;
api-surface.md §2.18).

`refresh_dropin` is the one reader both startup (`main.py`'s lifespan) and
`POST /catalog/refresh` call — "same table, same resolver... the install
route is a second writer, never a second mechanism" (data-model.md §3.26)
holds for the reader too. It processes each drop-in subdirectory
independently: one bad manifest is collected into the report's `errors`
rather than aborting every other artifact in the directory, since an
operator adding one broken drop-in should not block the ones that already
work.

Sequencing decision 3 (M2-Task-Plan.md Global Constraints): a drop-in
minigame's digest comes from its manifest's own `image` field
(`…@sha256:…`/`…@sha512:…`), never a sidecar file — the SDK's own
`ociImageRef` schema already accepts a digest there, so the reader only
has to enforce it is present on the drop-in path and extract it. A bare
tag is rejected naming the artifact.

`StoreResolver` and `PinnedResolver` are the two `MinigameResolver`
implementations sdk-contract-v1.md §3.4 describes: `StoreResolver` is the
first-resolution rule (highest SemVer-satisfying version over a store that
may hold several); `PinnedResolver` is what every later validation pass
reads instead, once a document's pins were recorded — "the resolver it
supplies at every later call site... returns those pinned manifests and
nothing else." Neither implements SemVer as a library dependency: the
contract fixes both grammars (`^\\d+\\.\\d+\\.\\d+(-...)?(\\+...)?$` for a
version, `^>=\\d+\\.\\d+,<\\d+\\.\\d+$` for a range, sdk-contract-v1.md
§2.1) tightly enough that a small hand-rolled comparison is the whole of
it, and pre-release versions never satisfy any range.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from gameframework_sdk.validation import validate_event, validate_minigame
from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.config import Settings
from gameframework.db.models.infrastructure import ArtifactType, InstalledArtifact

__all__ = [
    "DropinManifestError",
    "RefreshReport",
    "refresh_dropin",
    "StoreResolver",
    "PinnedResolver",
]

_MANIFEST_FILENAMES: dict[str, ArtifactType] = {
    "minigame.yaml": ArtifactType.minigame,
    "event.yaml": ArtifactType.event,
}

_DIGEST_RE = re.compile(r"@(sha256:[a-f0-9]{64}|sha512:[a-f0-9]{128})$")

# sdk-contract-v1.md §2.1: "Fixed grammar... bounds are MAJOR.MINOR (a bound
# reads as patch .0)".
_RANGE_RE = re.compile(r"^>=(\d+)\.(\d+),<(\d+)\.(\d+)$")
# SemVer 2.0.0: MAJOR.MINOR.PATCH, optional pre-release/build metadata.
_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-.]+))?(?:\+[0-9A-Za-z-.]+)?$")


class DropinManifestError(Exception):
    """One drop-in subdirectory failed to install — a schema-invalid
    manifest, a bare-tag `image`, or an unrecognized manifest filename.
    Carries the fully-formed message `refresh_dropin` collects into its
    report rather than raising past the caller, so one bad artifact does
    not stop the rest of the directory from being read.
    """


@dataclass
class RefreshReport:
    installed: list[str] = field(default_factory=list[str])
    errors: list[str] = field(default_factory=list[str])


def _extract_digest(image: str, artifact_id: str) -> str:
    match = _DIGEST_RE.search(image)
    if match is None:
        raise DropinManifestError(
            f"minigame '{artifact_id}': image '{image}' carries no digest — "
            "a drop-in image reference must be digest-pinned (…@sha256:… or …@sha512:…)"
        )
    return match.group(1)


def _read_manifest(subdir: Path) -> tuple[ArtifactType, dict[str, Any], Path]:
    for filename, artifact_type in _MANIFEST_FILENAMES.items():
        path = subdir / filename
        if path.is_file():
            try:
                text = path.read_text()
            except (OSError, UnicodeDecodeError) as exc:
                raise DropinManifestError(f"{filename}: cannot read file — {exc}") from exc
            try:
                manifest = yaml.safe_load(text)
            except yaml.YAMLError as exc:
                raise DropinManifestError(f"{filename}: invalid YAML — {exc}") from exc
            return artifact_type, manifest, path
    raise DropinManifestError(
        f"{subdir.name}: no minigame.yaml or event.yaml found — theme and "
        "language drop-ins are refused (M7)"
    )


def _install_one(db: Session, subdir: Path) -> str:
    artifact_type, manifest, path = _read_manifest(subdir)

    errors = (
        validate_minigame(manifest)
        if artifact_type is ArtifactType.minigame
        else validate_event(manifest)
    )
    if errors:
        raise DropinManifestError(f"{path.name}: {'; '.join(errors)}")

    artifact_id = manifest["id"]
    version = manifest["version"]

    image_digest = None
    if artifact_type is ArtifactType.minigame:
        image_digest = _extract_digest(manifest["image"], artifact_id)

    existing = db.execute(
        select(InstalledArtifact).where(
            InstalledArtifact.type == artifact_type,
            InstalledArtifact.artifact_id == artifact_id,
            InstalledArtifact.version == version,
        )
    ).scalar_one_or_none()

    if existing is not None:
        existing.manifest = manifest
        existing.image_digest = image_digest
        existing.source = str(subdir)
        existing.verified = False
    else:
        db.add(
            InstalledArtifact(
                type=artifact_type,
                artifact_id=artifact_id,
                version=version,
                manifest=manifest,
                image_digest=image_digest,
                verified=False,
                source=str(subdir),
            )
        )
    db.flush()
    return f"{artifact_type.value}/{artifact_id}/{version}"


def refresh_dropin(db: Session, settings: Settings) -> RefreshReport:
    """Reads the operator drop-in directory, one subdirectory per artifact
    (data-model.md §3.26). An absent directory — the common case on a
    fresh installation, before any operator has dropped anything in —
    reads as empty rather than as an error.
    """
    report = RefreshReport()
    dropin_dir = settings.dropin_dir

    if not dropin_dir.is_dir():
        db.commit()
        return report

    for subdir in sorted(p for p in dropin_dir.iterdir() if p.is_dir()):
        try:
            installed = _install_one(db, subdir)
        except DropinManifestError as exc:
            report.errors.append(str(exc))
            continue
        report.installed.append(installed)

    db.commit()
    return report


def _parse_version(version: str) -> tuple[int, int, int] | None:
    """`None` for anything that is not a bare `MAJOR.MINOR.PATCH` — in
    particular a pre-release, which sdk-contract-v1.md §2.1 says "never
    match" any range, so it is excluded from resolution entirely rather
    than compared against the bounds.
    """
    match = _VERSION_RE.match(version)
    if match is None or match.group(4) is not None:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def _satisfies(parsed: tuple[int, int, int], version_range: str) -> bool:
    range_match = _RANGE_RE.match(version_range)
    if range_match is None:
        return False
    lo_major, lo_minor, hi_major, hi_minor = (int(g) for g in range_match.groups())
    return (lo_major, lo_minor, 0) <= parsed < (hi_major, hi_minor, 0)


@dataclass
class StoreResolver:
    """`gameframework_sdk.validation.MinigameResolver` over
    `installed_artifact` (sdk-contract-v1.md §3.4): the *first*-resolution
    rule — the highest installed version satisfying the range, by SemVer
    precedence. This is the resolver import and dry-run's first validation
    pass use; every later pass reads `PinnedResolver` instead.
    """

    db: Session

    def resolve_row(self, minigame_id: str, version_range: str) -> InstalledArtifact | None:
        """The winning row itself, not only its manifest — Task 10's pin
        recording needs `(version, image_digest)` together
        (data-model.md §3.5), which the manifest blob alone does not carry.
        `resolve()` below is this method plus one attribute access, so the
        highest-satisfying comparison is written once.
        """
        rows = (
            self.db.execute(
                select(InstalledArtifact).where(
                    InstalledArtifact.type == ArtifactType.minigame,
                    InstalledArtifact.artifact_id == minigame_id,
                )
            )
            .scalars()
            .all()
        )
        best: tuple[int, int, int] | None = None
        best_row: InstalledArtifact | None = None
        for row in rows:
            parsed = _parse_version(row.version)
            if parsed is None or not _satisfies(parsed, version_range):
                continue
            if best is None or parsed > best:
                best = parsed
                best_row = row
        return best_row

    def resolve(self, minigame_id: str, version_range: str) -> dict[str, Any] | None:
        row = self.resolve_row(minigame_id, version_range)
        return row.manifest if row is not None else None


@dataclass
class PinnedResolver:
    """`gameframework_sdk.validation.MinigameResolver` returning exactly
    what a document's *first* validation pass pinned (sdk-contract-v1.md
    §3.4, pin-once-resolve-against-pins) — every later pass (dry-run, a
    post-publication content edit, the run preflight's artifact-presence
    check) resolves against this rather than re-running highest-satisfying
    against a store that may have moved since. `version_range` is ignored:
    the range already did its job at the first resolution, and applying it
    a second time is exactly the bug this class exists to prevent.

    `pins` maps `minigame_id -> (version, image_digest)` — the pair the
    first pass recorded (data-model.md §3.5: `minigame_version`,
    `minigame_image_digest`). A pin resolves only when the store still
    holds a row matching *both*: a version absent from the store, or a
    version present under a different digest (the drop-in was replaced
    under the same version number), each fail the same way — the pin has
    left the store — rather than silently serving a manifest nothing
    pinned at the digest this definition was validated against.
    """

    db: Session
    pins: dict[str, tuple[str, str]]

    def resolve_row(self, minigame_id: str, version_range: str) -> InstalledArtifact | None:
        """The winning row itself — see `StoreResolver.resolve_row` above
        for why a caller needs the row rather than only its manifest.
        `version_range` is ignored, same as `resolve()` below.
        """
        pin = self.pins.get(minigame_id)
        if pin is None:
            return None
        version, image_digest = pin
        return self.db.execute(
            select(InstalledArtifact).where(
                InstalledArtifact.type == ArtifactType.minigame,
                InstalledArtifact.artifact_id == minigame_id,
                InstalledArtifact.version == version,
                InstalledArtifact.image_digest == image_digest,
            )
        ).scalar_one_or_none()

    def resolve(self, minigame_id: str, version_range: str) -> dict[str, Any] | None:
        row = self.resolve_row(minigame_id, version_range)
        return row.manifest if row is not None else None
