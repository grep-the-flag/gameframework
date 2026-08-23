"""The framework-minted initial admin (M2-Task-Plan.md Task 5; ADR-0007
"Onboarding, initial password and OTP"; data-model.md §5).

`fresh_install_db` (Task 1a), not `db_session`, is what these tests need:
"a fresh installation comes up with exactly one admin" and "two fresh
installs yield different passwords" both describe a database nothing else
has ever written to, which a shared, rolled-back-per-test schema cannot
express. Only the file-removal test below drives the `client` fixture
instead, because it is the one assertion that needs `POST /auth/login`
itself — the lifespan hook that mints the admin runs there too, honoring
the test client's `db_session` override (`main.py`'s `lifespan`), so the
admin it mints is visible to that same test's own isolated transaction.
"""

import stat
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from gameframework.config import Settings, get_settings
from gameframework.db.models.feedback import AuditLog, AuditScope
from gameframework.db.models.identity import Role, User
from gameframework.services.bootstrap import credentials_path, ensure_initial_admin

from ..conftest import make_user


def _settings(data_dir: Path) -> Settings:
    return Settings(
        database_url="postgresql+psycopg://test:test@localhost/test",
        frontend_origin="https://app.event.example.com",
        data_dir=data_dir,
        cookie_domain="event.example.com",
        dropin_dir=data_dir / "dropin",
    )


def test_fresh_install_comes_up_with_exactly_one_admin(
    fresh_install_db: Session, tmp_path: Path
) -> None:
    settings = _settings(tmp_path / "data")

    ensure_initial_admin(fresh_install_db, settings)

    admins = fresh_install_db.execute(select(User).where(User.role == Role.admin)).scalars().all()
    assert len(admins) == 1
    assert admins[0].username == "admin"


def test_no_second_admin_minted_when_a_differently_named_admin_exists(
    fresh_install_db: Session, tmp_path: Path
) -> None:
    """The plan's Produces line says "when no admin exists, mints admin" —
    any row with the admin role, not a row named `admin` specifically. The
    two differ once Task 6 can delete users: an operator who removes the
    framework-minted `admin` account while another admin remains must not
    get it silently recreated, with a fresh credential file written into
    the data volume, on the next restart.
    """
    make_user(fresh_install_db, username="alice", role=Role.admin, must_change_password=False)
    settings = _settings(tmp_path / "data")

    ensure_initial_admin(fresh_install_db, settings)

    admins = fresh_install_db.execute(select(User).where(User.role == Role.admin)).scalars().all()
    assert len(admins) == 1
    assert admins[0].username == "alice"
    assert not credentials_path(settings).exists()


def test_two_fresh_installs_yield_different_passwords(
    fresh_install_db: Session, tmp_path: Path
) -> None:
    """The negative the plan names: neither installation's password may
    equal the fixed username, and the two must differ from each other —
    two installs agreeing by coincidence and two installs both using a
    constant are otherwise indistinguishable. A second "fresh install" is
    simulated by deleting the admin row `ensure_initial_admin` just
    minted from this same `fresh_install_db`, restoring the
    no-admin-exists precondition the function checks, rather than
    building a second database.
    """
    settings_a = _settings(tmp_path / "install-a")
    ensure_initial_admin(fresh_install_db, settings_a)
    _, password_a = credentials_path(settings_a).read_text().splitlines()

    admin = fresh_install_db.execute(select(User).where(User.username == "admin")).scalar_one()
    fresh_install_db.delete(admin)
    fresh_install_db.commit()

    settings_b = _settings(tmp_path / "install-b")
    ensure_initial_admin(fresh_install_db, settings_b)
    _, password_b = credentials_path(settings_b).read_text().splitlines()

    assert password_a != password_b
    assert password_a != "admin"
    assert password_b != "admin"


def test_initial_admin_has_no_forced_password_change(
    fresh_install_db: Session, tmp_path: Path
) -> None:
    settings = _settings(tmp_path / "data")

    ensure_initial_admin(fresh_install_db, settings)

    admin = fresh_install_db.execute(select(User).where(User.username == "admin")).scalar_one()
    assert admin.must_change_password is False


def test_credentials_file_is_mode_0600(fresh_install_db: Session, tmp_path: Path) -> None:
    settings = _settings(tmp_path / "data")

    ensure_initial_admin(fresh_install_db, settings)

    path = credentials_path(settings)
    assert path.is_file()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_minting_is_audited_installation_scope(fresh_install_db: Session, tmp_path: Path) -> None:
    settings = _settings(tmp_path / "data")

    ensure_initial_admin(fresh_install_db, settings)

    admin = fresh_install_db.execute(select(User).where(User.username == "admin")).scalar_one()
    entry = fresh_install_db.execute(
        select(AuditLog).where(AuditLog.action == "initial_admin_minted")
    ).scalar_one()
    assert entry.scope is AuditScope.installation
    assert entry.target_type == "user"
    assert entry.target_id == admin.id
    assert entry.event_run_id is None


def test_ensure_initial_admin_is_idempotent(fresh_install_db: Session, tmp_path: Path) -> None:
    """A second call on a database that already has an admin must change
    nothing — not merely not crash: no second row, no changed password
    hash, no second audit entry, and (simulating a restart after the
    account's first login already removed the file) no resurrected file.
    """
    settings = _settings(tmp_path / "data")
    ensure_initial_admin(fresh_install_db, settings)

    admin = fresh_install_db.execute(select(User).where(User.username == "admin")).scalar_one()
    original_password_hash = admin.password_hash
    audit_count_before = fresh_install_db.execute(
        select(func.count()).select_from(AuditLog).where(AuditLog.action == "initial_admin_minted")
    ).scalar_one()
    credentials_path(settings).unlink()

    ensure_initial_admin(fresh_install_db, settings)

    admins = fresh_install_db.execute(select(User).where(User.username == "admin")).scalars().all()
    assert len(admins) == 1
    assert admins[0].password_hash == original_password_hash
    audit_count_after = fresh_install_db.execute(
        select(func.count()).select_from(AuditLog).where(AuditLog.action == "initial_admin_minted")
    ).scalar_one()
    assert audit_count_after == audit_count_before
    assert not credentials_path(settings).exists()


def test_credentials_file_exists_before_and_is_removed_after_first_login(
    client: TestClient,
) -> None:
    settings = get_settings()
    path = credentials_path(settings)
    # `client`'s own fixture setup already ran the ASGI lifespan, which
    # mints the admin for this test's own isolated db_session — the file
    # exists before login, which is the negative half of "removed at
    # first successful login": without it, "removed" and "never written"
    # would be the same assertion.
    assert path.exists()
    username, password = path.read_text().splitlines()

    response = client.post("/api/v1/auth/login", json={"username": username, "password": password})

    assert response.status_code == 200
    assert not path.exists()
