"""M2-Task-Plan.md Task 9 Step 2: the operator drop-in directory
(data-model.md §3.26; api-surface.md §2.18). `services/artifacts.py` does
not exist yet, so every call below fails at collection/import time rather
than on an assertion — the same collection-level red Task 7's
`test_import.py` and Task 8's `test_atomic_creation.py` documented for a
module not yet on disk (Working-Agreement "a collection error is not a red
proof": the exception it names is for code already on disk, which this is
not).

Four things this suite binds by mutation once the implementation exists
(see the PR body for the table):

- the digest comes from the manifest's own `image` field, and a bare tag
  is rejected naming the artifact (sequencing decision 3) — asserted on
  the extracted digest itself on the accepting side, not merely that a
  row appeared;
- `verified = false` on every drop-in row;
- idempotence is per `(type, artifact_id, version)`, and two versions of
  one artifact coexist;
- (resolver behaviour is `test_resolver.py`'s, Step 3).
"""

from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.config import Settings
from gameframework.db.models.identity import Role
from gameframework.db.models.infrastructure import ArtifactType, InstalledArtifact
from gameframework.services.artifacts import refresh_dropin
from gameframework.services.passwords import hash_password

from ..conftest import make_installed_artifact, make_user

ADMIN_PASSWORD = "Admin-Passw0rd!"
_DIGEST = "sha256:" + "a" * 64


def _settings(dropin_dir: Path) -> Settings:
    return Settings(
        database_url="postgresql+psycopg://test:test@localhost/test",
        frontend_origin="https://app.event.example.com",
        data_dir=dropin_dir.parent,
        cookie_domain="event.example.com",
        dropin_dir=dropin_dir,
        player_tcp_host="event.example.com",
        event_domain="event.example.com",
        tcp_port_range=(20000, 29999),
    )


def test_dropin_dir_defaults_to_a_subdirectory_of_data_dir(tmp_path: Path) -> None:
    """`dropin_dir` is the one setting among Task 9's that takes a default
    rather than refusing one (config.py) — it must fall out of `data_dir`
    when the operator sets no override. Omitting the argument here is the
    point of the test: pydantic's `mode="before"` validator fills it in at
    runtime, which pyright's synthesized `__init__` cannot see, hence the
    narrow suppression on the one line that deliberately relies on it.
    """
    settings = Settings(  # pyright: ignore[reportCallIssue]
        database_url="postgresql+psycopg://test:test@localhost/test",
        frontend_origin="https://app.event.example.com",
        data_dir=tmp_path / "data",
        cookie_domain="event.example.com",
        player_tcp_host="event.example.com",
        event_domain="event.example.com",
        tcp_port_range=(20000, 29999),
    )

    assert settings.dropin_dir == tmp_path / "data" / "dropin"


def test_empty_env_dropin_dir_falls_back_to_the_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`GF_DROPIN_DIR=` left blank — the exact commented-out form
    `.env.example` documents — arrives as `""`, not absent: `values.get(
    "dropin_dir") is None` misses it, so `Path("")` (`PosixPath(".")`, the
    process's own working directory) would win over the intended default.
    """
    from gameframework.config import get_settings

    monkeypatch.setenv("GF_DATABASE_URL", "postgresql+psycopg://test:test@localhost/test")
    monkeypatch.setenv("GF_FRONTEND_ORIGIN", "https://app.event.example.com")
    monkeypatch.setenv("GF_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("GF_COOKIE_DOMAIN", "event.example.com")
    monkeypatch.setenv("GF_DROPIN_DIR", "")
    get_settings.cache_clear()
    try:
        settings = get_settings()
    finally:
        get_settings.cache_clear()

    assert settings.dropin_dir == tmp_path / "data" / "dropin"


def test_dropin_dir_override_is_kept_rather_than_replaced(tmp_path: Path) -> None:
    """A value asserted against its source needs a second, different
    source value bound to it (Working Agreement verification standard) —
    proving the override actually reaches the field rather than the
    default happening to coincide with it."""
    override = tmp_path / "elsewhere" / "artifacts"
    settings = Settings(
        database_url="postgresql+psycopg://test:test@localhost/test",
        frontend_origin="https://app.event.example.com",
        data_dir=tmp_path / "data",
        cookie_domain="event.example.com",
        dropin_dir=override,
        player_tcp_host="event.example.com",
        event_domain="event.example.com",
        tcp_port_range=(20000, 29999),
    )

    assert settings.dropin_dir == override


def _write_manifest(subdir: Path, filename: str, content: dict[str, object]) -> None:
    subdir.mkdir(parents=True, exist_ok=True)
    (subdir / filename).write_text(yaml.safe_dump(content))


def _minigame_manifest(*, artifact_id: str, version: str, image: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "contract": ">=0.1,<1.0",
        "id": artifact_id,
        "version": version,
        "name": {"en": "Demo"},
        "description": {"en": "Demo minigame"},
        "image": image,
        "http": {"port": 8000},
        "rewards": {"produces": [{"name": "flag_token", "type": "token"}]},
        "resources": {"cpu": "0.5", "memory": "512M"},
    }


def _event_manifest(*, artifact_id: str, version: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "contract": ">=0.1,<1.0",
        "id": artifact_id,
        "version": version,
        "name": {"en": "Demo Event"},
        "story": {"en": "One continuous story."},
        "scoring": "casual",
        "unlock_mode": "manual",
        "challenges": [
            {
                "id": "chal-1",
                "order": 1,
                "title": {"en": "Chal"},
                "text": {"en": "Text"},
                "minigame": {"id": "some-minigame", "version": ">=1.0,<2.0"},
                "points": 100,
            }
        ],
    }


def _login_as_admin(client: TestClient, db_session: Session) -> None:
    admin = make_user(
        db_session,
        role=Role.admin,
        must_change_password=False,
        password_hash=hash_password(ADMIN_PASSWORD),
    )
    response = client.post(
        "/api/v1/auth/login", json={"username": admin.username, "password": ADMIN_PASSWORD}
    )
    assert response.status_code == 200


def _artifact_rows(db_session: Session, artifact_id: str) -> list[InstalledArtifact]:
    return list(
        db_session.execute(
            select(InstalledArtifact).where(InstalledArtifact.artifact_id == artifact_id)
        )
        .scalars()
        .all()
    )


def test_valid_minigame_manifest_produces_a_row_with_verified_false_and_extracted_digest(
    db_session: Session, tmp_path: Path
) -> None:
    """The accepting side of sequencing decision 3: the digest is read out
    of the manifest's own `image` field, not merely present as a row —
    asserted on the extracted value itself.
    """
    dropin_dir = tmp_path / "dropin"
    _write_manifest(
        dropin_dir / "demo-minigame",
        "minigame.yaml",
        _minigame_manifest(
            artifact_id="demo-minigame", version="1.0.0", image=f"ghcr.io/example/demo@{_DIGEST}"
        ),
    )

    report = refresh_dropin(db_session, _settings(dropin_dir))

    assert report.errors == []
    rows = _artifact_rows(db_session, "demo-minigame")
    assert len(rows) == 1
    row = rows[0]
    assert row.type is ArtifactType.minigame
    assert row.version == "1.0.0"
    assert row.image_digest == _DIGEST
    assert row.verified is False


def test_bare_tag_image_is_rejected_naming_the_artifact(
    db_session: Session, tmp_path: Path
) -> None:
    """Sequencing decision 3's refusal half: a bare-tag `image` (no digest)
    is rejected, and no row is written for it — the pair with the
    acceptance test above, so a reader that rejects everything cannot pass
    both.
    """
    dropin_dir = tmp_path / "dropin"
    _write_manifest(
        dropin_dir / "demo-minigame",
        "minigame.yaml",
        _minigame_manifest(
            artifact_id="demo-minigame", version="1.0.0", image="ghcr.io/example/demo:1.0.0"
        ),
    )

    report = refresh_dropin(db_session, _settings(dropin_dir))

    assert len(report.errors) == 1
    assert "demo-minigame" in report.errors[0]
    assert _artifact_rows(db_session, "demo-minigame") == []


def test_schema_invalid_manifest_is_rejected_naming_the_file(
    db_session: Session, tmp_path: Path
) -> None:
    """A manifest missing a required field (`resources`) fails the SDK
    schema pass and is rejected naming the file it came from."""
    dropin_dir = tmp_path / "dropin"
    manifest = _minigame_manifest(
        artifact_id="demo-minigame", version="1.0.0", image=f"ghcr.io/example/demo@{_DIGEST}"
    )
    del manifest["resources"]
    _write_manifest(dropin_dir / "demo-minigame", "minigame.yaml", manifest)

    report = refresh_dropin(db_session, _settings(dropin_dir))

    assert len(report.errors) == 1
    assert "minigame.yaml" in report.errors[0]
    assert _artifact_rows(db_session, "demo-minigame") == []


def test_unparseable_yaml_is_collected_as_an_error_and_does_not_stop_the_rest(
    db_session: Session, tmp_path: Path
) -> None:
    """A syntax error in one operator's drop-in must not crash the reader
    for every other artifact next to it — the module docstring's promise
    ("one bad manifest is collected... rather than aborting every other
    artifact"), which currently holds only for errors the reader itself
    raises. `yaml.safe_load` raises `yaml.YAMLError` on malformed YAML,
    which nothing catches yet."""
    dropin_dir = tmp_path / "dropin"
    (dropin_dir / "broken-minigame").mkdir(parents=True)
    (dropin_dir / "broken-minigame" / "minigame.yaml").write_text("id: [unclosed")
    _write_manifest(
        dropin_dir / "demo-minigame",
        "minigame.yaml",
        _minigame_manifest(
            artifact_id="demo-minigame", version="1.0.0", image=f"ghcr.io/example/demo@{_DIGEST}"
        ),
    )

    report = refresh_dropin(db_session, _settings(dropin_dir))

    assert len(report.errors) == 1
    assert "minigame.yaml" in report.errors[0]
    assert _artifact_rows(db_session, "demo-minigame") != []


def test_empty_manifest_file_is_reported_as_an_error_not_a_crash(
    db_session: Session, tmp_path: Path
) -> None:
    """`yaml.safe_load` on an empty file returns `None`, not an exception —
    the reader must still name the file rather than let `None` reach the
    SDK validation pass unlabelled."""
    dropin_dir = tmp_path / "dropin"
    (dropin_dir / "empty-minigame").mkdir(parents=True)
    (dropin_dir / "empty-minigame" / "minigame.yaml").write_text("")

    report = refresh_dropin(db_session, _settings(dropin_dir))

    assert len(report.errors) == 1
    assert "minigame.yaml" in report.errors[0]
    assert report.installed == []


def test_rereading_is_idempotent_per_type_artifact_id_version(
    db_session: Session, tmp_path: Path
) -> None:
    """The positive half of the uniqueness claim: reading the same
    drop-in twice writes exactly one row for `(type, artifact_id,
    version)`, never two."""
    dropin_dir = tmp_path / "dropin"
    _write_manifest(
        dropin_dir / "demo-minigame",
        "minigame.yaml",
        _minigame_manifest(
            artifact_id="demo-minigame", version="1.0.0", image=f"ghcr.io/example/demo@{_DIGEST}"
        ),
    )

    refresh_dropin(db_session, _settings(dropin_dir))
    refresh_dropin(db_session, _settings(dropin_dir))

    assert len(_artifact_rows(db_session, "demo-minigame")) == 1


def test_rereading_resets_verified_to_false_even_on_an_update(
    db_session: Session, tmp_path: Path
) -> None:
    """data-model.md §3.26: `verified` is true only at registry admission,
    false for every direct file install — a drop-in refresh is a direct
    file install, whether it inserts a new row or updates one that
    already existed under the same `(type, artifact_id, version)`. A row
    that was ever admitted through the registry and then gets refreshed
    from a drop-in loses that status; the update branch must set
    `verified = False` exactly as the insert branch does, not leave a
    pre-existing value standing."""
    dropin_dir = tmp_path / "dropin"
    _write_manifest(
        dropin_dir / "demo-minigame",
        "minigame.yaml",
        _minigame_manifest(
            artifact_id="demo-minigame", version="1.0.0", image=f"ghcr.io/example/demo@{_DIGEST}"
        ),
    )
    make_installed_artifact(
        db_session,
        type=ArtifactType.minigame,
        artifact_id="demo-minigame",
        version="1.0.0",
        manifest={},
        verified=True,
    )

    refresh_dropin(db_session, _settings(dropin_dir))

    rows = _artifact_rows(db_session, "demo-minigame")
    assert len(rows) == 1
    assert rows[0].verified is False


def test_two_versions_of_one_artifact_coexist(db_session: Session, tmp_path: Path) -> None:
    """The negative half of the uniqueness claim: two distinct versions of
    one artifact are two rows, never collapsed to one — the case a reader
    that overwrites everything on the artifact id alone fails."""
    dropin_dir = tmp_path / "dropin"
    _write_manifest(
        dropin_dir / "demo-minigame-v1",
        "minigame.yaml",
        _minigame_manifest(
            artifact_id="demo-minigame", version="1.0.0", image=f"ghcr.io/example/demo@{_DIGEST}"
        ),
    )
    _write_manifest(
        dropin_dir / "demo-minigame-v2",
        "minigame.yaml",
        _minigame_manifest(
            artifact_id="demo-minigame", version="1.1.0", image=f"ghcr.io/example/demo@{_DIGEST}"
        ),
    )

    refresh_dropin(db_session, _settings(dropin_dir))

    rows = _artifact_rows(db_session, "demo-minigame")
    assert {row.version for row in rows} == {"1.0.0", "1.1.0"}


def test_event_manifest_installs_with_no_image_digest(db_session: Session, tmp_path: Path) -> None:
    """`event.yaml` drop-ins carry no `image` field (data-model.md §3.26:
    "null for the three non-container types") — the reader dispatches on
    which manifest filename is present rather than assuming minigame."""
    dropin_dir = tmp_path / "dropin"
    _write_manifest(
        dropin_dir / "demo-event",
        "event.yaml",
        _event_manifest(artifact_id="demo-event", version="0.1.0"),
    )

    report = refresh_dropin(db_session, _settings(dropin_dir))

    assert report.errors == []
    rows = _artifact_rows(db_session, "demo-event")
    assert len(rows) == 1
    assert rows[0].type is ArtifactType.event
    assert rows[0].image_digest is None
    assert rows[0].verified is False


def test_unrecognized_manifest_is_refused_naming_m7(db_session: Session, tmp_path: Path) -> None:
    """A drop-in subdirectory holding neither `minigame.yaml` nor
    `event.yaml` — a theme or language pack — is refused rather than
    silently skipped, naming M7 (data-model.md §3.26)."""
    dropin_dir = tmp_path / "dropin"
    _write_manifest(dropin_dir / "demo-theme", "theme.yaml", {"id": "demo-theme"})

    report = refresh_dropin(db_session, _settings(dropin_dir))

    assert len(report.errors) == 1
    assert "M7" in report.errors[0]
    assert _artifact_rows(db_session, "demo-theme") == []


def test_absent_dropin_directory_reads_as_empty(db_session: Session, tmp_path: Path) -> None:
    """A fresh installation has no drop-in directory at all yet — the
    common case on first start, which must not raise (Daniel's Step 1
    clarification: an absent directory reads as empty, not as an error)."""
    dropin_dir = tmp_path / "dropin"
    assert not dropin_dir.exists()

    report = refresh_dropin(db_session, _settings(dropin_dir))

    assert report.installed == []
    assert report.errors == []


def test_post_catalog_refresh_rereads_the_dropin_directory_and_reports(
    client: TestClient, db_session: Session, tmp_path: Path
) -> None:
    """`POST /catalog/refresh` (api-surface.md §2.18, admin, M2 = drop-in
    only): re-reads the drop-in directory and reports what it found.

    `app.dependency_overrides[get_settings]`, `model_copy`ing the real
    settings — the established pattern (`test_login.py`,
    `test_blocking.py`) for driving one field of `Settings` through a live
    route without disturbing the rest (`cookie_domain`, `frontend_origin`)
    that `client`'s login already depends on.
    """
    from gameframework.config import get_settings
    from gameframework.main import app

    dropin_dir = tmp_path / "dropin"
    _write_manifest(
        dropin_dir / "demo-minigame",
        "minigame.yaml",
        _minigame_manifest(
            artifact_id="demo-minigame", version="1.0.0", image=f"ghcr.io/example/demo@{_DIGEST}"
        ),
    )
    settings = get_settings().model_copy(update={"dropin_dir": dropin_dir})
    app.dependency_overrides[get_settings] = lambda: settings

    try:
        _login_as_admin(client, db_session)
        response = client.post("/api/v1/catalog/refresh")
    finally:
        app.dependency_overrides.pop(get_settings, None)

    assert response.status_code == 200
    body = response.json()
    assert any("demo-minigame" in entry for entry in body["installed"])
    assert _artifact_rows(db_session, "demo-minigame") != []


def test_startup_reads_the_dropin_directory(
    db_session: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """M2-Task-Plan.md Task 9 Step 2: "startup performs the same read."
    The shared `client` fixture already runs the ASGI lifespan on every
    test, but against the real, process-wide settings — whose
    `dropin_dir` does not exist, so that alone proves nothing about
    whether startup reads it. This test drives `GF_DROPIN_DIR` at a
    populated `tmp_path` and builds its own app from that changed
    environment (`test_csrf.py`'s
    `test_cors_allowance_follows_a_different_configured_frontend_origin`
    is the model): `get_settings.cache_clear()` lets the new value in,
    `dependency_overrides[get_session]` routes the lifespan's own write
    onto this test's isolated `db_session` rather than the real database,
    and the cache is cleared again on the way out so the next test's
    `get_settings()` does not inherit this one's cached object.
    """
    from collections.abc import Iterator

    from gameframework.config import get_settings
    from gameframework.db.session import get_session
    from gameframework.main import create_app

    dropin_dir = tmp_path / "dropin"
    _write_manifest(
        dropin_dir / "demo-minigame",
        "minigame.yaml",
        _minigame_manifest(
            artifact_id="demo-minigame", version="1.0.0", image=f"ghcr.io/example/demo@{_DIGEST}"
        ),
    )

    monkeypatch.setenv("GF_DROPIN_DIR", str(dropin_dir))
    get_settings.cache_clear()
    try:
        fresh_app = create_app()

        def _override_get_session() -> Iterator[Session]:
            yield db_session

        fresh_app.dependency_overrides[get_session] = _override_get_session
        try:
            with TestClient(fresh_app, base_url="https://app.event.example.com"):
                pass
        finally:
            fresh_app.dependency_overrides.pop(get_session, None)
    finally:
        get_settings.cache_clear()

    assert _artifact_rows(db_session, "demo-minigame") != []


def test_post_catalog_refresh_refuses_non_admin(client: TestClient, db_session: Session) -> None:
    """Admin-only (api-surface.md §2.18) — a gameadmin is refused."""
    gameadmin = make_user(
        db_session,
        role=Role.gameadmin,
        must_change_password=False,
        password_hash=hash_password(ADMIN_PASSWORD),
    )
    response = client.post(
        "/api/v1/auth/login", json={"username": gameadmin.username, "password": ADMIN_PASSWORD}
    )
    assert response.status_code == 200

    response = client.post("/api/v1/catalog/refresh")

    assert response.status_code == 403
    assert response.json()["code"] == "role_denied"
