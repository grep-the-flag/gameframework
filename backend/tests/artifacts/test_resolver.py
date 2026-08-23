"""M2-Task-Plan.md Task 9 Step 3: the two `MinigameResolver` implementations
(sdk-contract-v1.md §3.4). `StoreResolver` is the *first*-resolution rule —
highest SemVer-satisfying version, over a store that may hold several.
`PinnedResolver` is the opposite case: pin-once-resolve-against-pins, so it
must return the pin even once a newer satisfying version exists, which is
why both suites below install more than one version rather than one —
a fixture with only the pinned version installed would pass against either
rule and prove nothing about which one the class implements.
"""

from sqlalchemy.orm import Session

from gameframework.services.artifacts import PinnedResolver, StoreResolver

from ..conftest import make_installed_artifact

_DIGEST = "sha256:" + "a" * 64


def _manifest(version: str) -> dict[str, object]:
    return {"id": "demo-minigame", "version": version, "marker": version}


def test_store_resolver_returns_the_highest_satisfying_version(db_session: Session) -> None:
    make_installed_artifact(
        db_session, artifact_id="demo-minigame", version="1.0.0", manifest=_manifest("1.0.0")
    )
    make_installed_artifact(
        db_session, artifact_id="demo-minigame", version="1.2.0", manifest=_manifest("1.2.0")
    )
    make_installed_artifact(
        db_session, artifact_id="demo-minigame", version="1.5.0", manifest=_manifest("1.5.0")
    )

    resolver = StoreResolver(db_session)
    manifest = resolver.resolve("demo-minigame", ">=1.0,<2.0")

    assert manifest is not None
    assert manifest["marker"] == "1.5.0"


def test_store_resolver_returns_none_when_no_version_satisfies(db_session: Session) -> None:
    make_installed_artifact(
        db_session, artifact_id="demo-minigame", version="2.5.0", manifest=_manifest("2.5.0")
    )

    resolver = StoreResolver(db_session)

    assert resolver.resolve("demo-minigame", ">=1.0,<2.0") is None


def test_store_resolver_ignores_a_pre_release_version(db_session: Session) -> None:
    """sdk-contract-v1.md §2.1: "pre-releases never match" — a pre-release
    row must not win resolution even though its numeric bounds fall inside
    the range, so a manifest at 1.5.0 stays the answer."""
    make_installed_artifact(
        db_session,
        artifact_id="demo-minigame",
        version="1.9.0-beta",
        manifest=_manifest("1.9.0-beta"),
    )
    make_installed_artifact(
        db_session, artifact_id="demo-minigame", version="1.5.0", manifest=_manifest("1.5.0")
    )

    resolver = StoreResolver(db_session)
    manifest = resolver.resolve("demo-minigame", ">=1.0,<2.0")

    assert manifest is not None
    assert manifest["marker"] == "1.5.0"


def test_store_resolver_returns_none_for_a_malformed_range(db_session: Session) -> None:
    make_installed_artifact(
        db_session, artifact_id="demo-minigame", version="1.5.0", manifest=_manifest("1.5.0")
    )

    resolver = StoreResolver(db_session)

    assert resolver.resolve("demo-minigame", "not-a-range") is None


def test_pinned_resolver_returns_the_pin_even_after_a_newer_satisfying_version_is_installed(
    db_session: Session,
) -> None:
    """The whole point of pin-once-resolve-against-pins: installing 1.5.0
    after the pin was recorded at 1.2.0 must not change what a later
    validation pass reads — a test installing only 1.2.0 would pass
    against a resolver that just re-resolves highest-satisfying every
    time, which is exactly the bug this class exists to prevent.
    """
    make_installed_artifact(
        db_session,
        artifact_id="demo-minigame",
        version="1.2.0",
        manifest=_manifest("1.2.0"),
        image_digest=_DIGEST,
    )

    resolver = PinnedResolver(db_session, pins={"demo-minigame": ("1.2.0", _DIGEST)})
    before = resolver.resolve("demo-minigame", ">=1.0,<2.0")

    make_installed_artifact(
        db_session,
        artifact_id="demo-minigame",
        version="1.5.0",
        manifest=_manifest("1.5.0"),
        image_digest=_DIGEST,
    )
    after = resolver.resolve("demo-minigame", ">=1.0,<2.0")

    assert before is not None
    assert before["marker"] == "1.2.0"
    assert after is not None
    assert after["marker"] == "1.2.0"


def test_pinned_resolver_returns_none_when_the_pin_has_left_the_store(db_session: Session) -> None:
    """No row was ever installed at the pinned version — the pin left the
    store (or never existed), which must fail by name rather than
    resolving to a neighbouring version."""
    make_installed_artifact(
        db_session,
        artifact_id="demo-minigame",
        version="1.5.0",
        manifest=_manifest("1.5.0"),
        image_digest=_DIGEST,
    )

    resolver = PinnedResolver(db_session, pins={"demo-minigame": ("1.2.0", _DIGEST)})

    assert resolver.resolve("demo-minigame", ">=1.0,<2.0") is None


def test_pinned_resolver_returns_none_when_the_version_matches_but_the_digest_does_not(
    db_session: Session,
) -> None:
    """A drop-in replaced under the same version number: the store holds
    `1.2.0` again, but under a different digest than what this definition
    was validated against. The version alone is not enough — the pin must
    fail exactly as it would if the version itself were absent, rather
    than silently serving a manifest nothing pinned at this digest."""
    other_digest = "sha256:" + "b" * 64
    make_installed_artifact(
        db_session,
        artifact_id="demo-minigame",
        version="1.2.0",
        manifest=_manifest("1.2.0"),
        image_digest=other_digest,
    )

    resolver = PinnedResolver(db_session, pins={"demo-minigame": ("1.2.0", _DIGEST)})

    assert resolver.resolve("demo-minigame", ">=1.0,<2.0") is None


def test_pinned_resolver_returns_none_when_no_pin_is_recorded_for_the_minigame(
    db_session: Session,
) -> None:
    """A minigame id with no entry in `pins` at all — distinct from a pin
    that left the store: this one was never resolved by the first pass."""
    make_installed_artifact(
        db_session,
        artifact_id="other-minigame",
        version="1.0.0",
        manifest=_manifest("1.0.0"),
        image_digest=_DIGEST,
    )

    resolver = PinnedResolver(db_session, pins={})

    assert resolver.resolve("other-minigame", ">=1.0,<2.0") is None
