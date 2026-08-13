"""The framework-owned session-signing key (ADR-0007, "Session model" —
Signing key; M2-Task-Plan.md Task 3 Step 2). `ensure_signing_key` is the one
place the key is ever read: a first start draws 32 bytes from a CSPRNG and
writes them to `<data_dir>/session-signing.key` at mode 0600; every later
call reuses whatever is on disk. Replacing the file's contents is therefore
enough to invalidate every outstanding session at once — the mechanism the
M6 factory reset drives, with no separate rotation code path here.

`issue_session` does not exist yet (Task 3 Step 4), so the reuse and
rotation assertions below mint and verify tokens with PyJWT directly, HS256
(ADR-0007), under the bytes `ensure_signing_key` returns.
"""

import base64
import logging
import secrets
import stat
from pathlib import Path

import jwt
import pytest

from gameframework.config import Settings
from gameframework.services.secrets import ensure_signing_key

_ALGORITHM = "HS256"


def _settings(data_dir: Path) -> Settings:
    return Settings(
        database_url="postgresql+psycopg://test:test@localhost/test",
        frontend_origin="https://app.event.example.com",
        data_dir=data_dir,
    )


def test_first_start_writes_key_file_at_mode_0600(tmp_path: Path) -> None:
    settings = _settings(tmp_path / "data")

    ensure_signing_key(settings)

    key_path = tmp_path / "data" / "session-signing.key"
    assert key_path.is_file()
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600


def test_second_start_reuses_key_so_a_token_survives_it(tmp_path: Path) -> None:
    settings = _settings(tmp_path / "data")

    key_before_restart = ensure_signing_key(settings)
    token = jwt.encode({"sub": "user-1"}, key_before_restart, algorithm=_ALGORITHM)

    key_after_restart = ensure_signing_key(settings)

    assert key_after_restart == key_before_restart
    decoded = jwt.decode(token, key_after_restart, algorithms=[_ALGORITHM])
    assert decoded["sub"] == "user-1"


def test_different_data_dirs_yield_different_keys(tmp_path: Path) -> None:
    key_a = ensure_signing_key(_settings(tmp_path / "a"))
    key_b = ensure_signing_key(_settings(tmp_path / "b"))

    assert key_a != key_b


def test_replacing_key_file_invalidates_previous_tokens(tmp_path: Path) -> None:
    settings = _settings(tmp_path / "data")

    old_key = ensure_signing_key(settings)
    token = jwt.encode({"sub": "user-1"}, old_key, algorithm=_ALGORITHM)

    # Simulates the rotation mechanism M6's factory reset drives: the key
    # file's contents change underneath ensure_signing_key, not through it.
    key_path = tmp_path / "data" / "session-signing.key"
    key_path.write_bytes(secrets.token_bytes(32))

    new_key = ensure_signing_key(settings)

    assert new_key != old_key
    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(token, new_key, algorithms=[_ALGORITHM])


def test_key_never_appears_in_a_log_line(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    settings = _settings(tmp_path / "data")

    with caplog.at_level(logging.DEBUG):
        key = ensure_signing_key(settings)

    key_hex = key.hex()
    key_b64 = base64.b64encode(key).decode()
    for record in caplog.records:
        message = record.getMessage()
        assert key_hex not in message
        assert key_b64 not in message


def test_key_never_appears_in_settings_repr(tmp_path: Path) -> None:
    settings = _settings(tmp_path / "data")

    key = ensure_signing_key(settings)

    settings_repr = repr(settings)
    assert key.hex() not in settings_repr
    assert base64.b64encode(key).decode() not in settings_repr
