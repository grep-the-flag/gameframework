"""The two host commands (M2-Task-Plan.md Task 5; ADR-0007 "Recovery and
reset"): `python -m gameframework.cli initial-admin-credentials` and
`... reset-admin <username>`.

`reset-admin` opens its own database connection the way a real `docker
exec` invocation would — outside any FastAPI dependency, via
`db.session.get_engine()` — rather than the test client's overridable
`get_session`. `fresh_install_db` (Task 1a) is a real, disposable
database of its own, so pointing `gameframework.cli.get_engine` at its
underlying engine reaches the exact same physical database as the
`Session` object the test already holds, without building a second
database, session or client.
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from gameframework.cli import main
from gameframework.config import Settings
from gameframework.db.models.identity import BlockedAddress, Role
from gameframework.services.bootstrap import credentials_path
from gameframework.services.passwords import verify_password

from .conftest import make_blocked_address, make_user


def _settings(data_dir: Path) -> Settings:
    return Settings(
        database_url="postgresql+psycopg://test:test@localhost/test",
        frontend_origin="https://app.event.example.com",
        data_dir=data_dir,
        cookie_domain="event.example.com",
        dropin_dir=data_dir / "dropin",
    )


@pytest.fixture()
def redirect_cli_to(
    fresh_install_db: Session, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Settings]:
    settings = _settings(tmp_path / "data")
    monkeypatch.setattr("gameframework.cli.get_settings", lambda: settings)
    monkeypatch.setattr("gameframework.cli.get_engine", lambda: fresh_install_db.bind)
    yield settings


def test_initial_admin_credentials_prints_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    settings = _settings(tmp_path / "data")
    settings.data_dir.mkdir(parents=True)
    path = credentials_path(settings)
    path.write_text("admin\nsome-generated-password\n")
    monkeypatch.setattr("gameframework.cli.get_settings", lambda: settings)

    exit_code = main(["initial-admin-credentials"])

    assert exit_code == 0
    assert capsys.readouterr().out == "admin\nsome-generated-password\n"


def test_initial_admin_credentials_fails_cleanly_when_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    settings = _settings(tmp_path / "data")
    monkeypatch.setattr("gameframework.cli.get_settings", lambda: settings)

    exit_code = main(["initial-admin-credentials"])

    assert exit_code != 0
    assert capsys.readouterr().err != ""


def test_reset_admin_sets_password_rewrites_file_and_clears_blocks(
    fresh_install_db: Session,
    redirect_cli_to: Settings,
) -> None:
    admin = make_user(
        fresh_install_db, username="admin", role=Role.admin, must_change_password=False
    )
    original_hash = admin.password_hash
    make_blocked_address(fresh_install_db)
    make_blocked_address(fresh_install_db)
    blocked_count_before = fresh_install_db.execute(
        select(func.count()).select_from(BlockedAddress)
    ).scalar_one()
    assert blocked_count_before == 2

    exit_code = main(["reset-admin", "admin"])

    assert exit_code == 0
    assert admin.password_hash != original_hash

    path = credentials_path(redirect_cli_to)
    username, password = path.read_text().splitlines()
    assert username == "admin"
    assert verify_password(password, admin.password_hash)

    blocked_count_after = fresh_install_db.execute(
        select(func.count()).select_from(BlockedAddress)
    ).scalar_one()
    assert blocked_count_after == 0


def test_reset_admin_reports_unknown_username(
    fresh_install_db: Session,
    redirect_cli_to: Settings,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(["reset-admin", "no-such-admin"])

    assert exit_code != 0
    assert capsys.readouterr().err != ""
