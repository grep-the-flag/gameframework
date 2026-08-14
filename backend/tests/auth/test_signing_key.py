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
import os
import secrets
import stat
import threading
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
        cookie_domain="event.example.com",
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
    # A bytes field embedded in a dataclass/pydantic repr renders through
    # bytes.__repr__ (b'\x..'), not .hex() or base64 — the form the key
    # would actually take if some future field ever held it.
    assert repr(key) not in settings_repr


def test_concurrent_first_starts_never_hand_out_a_torn_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two processes can reach `ensure_signing_key` at once on a data dir
    that has never held a key — a container restarted twice in quick
    succession, or two processes starting for the first time together.
    The loser of the race must never observe a file that the winner has
    created but not yet finished writing. `token_bytes` is where the
    winner is parked mid-write: by the time it is called, any file it may
    already have on disk is guaranteed empty, so blocking there and letting
    a second caller run is the sharpest way to hit that window.
    """
    settings = _settings(tmp_path / "data")
    generating = threading.Event()
    release = threading.Event()
    real_token_bytes = secrets.token_bytes

    def blocking_token_bytes(n: int) -> bytes:
        generating.set()
        assert release.wait(timeout=5), "test deadlocked waiting for release"
        return real_token_bytes(n)

    monkeypatch.setattr("gameframework.services.secrets.secrets.token_bytes", blocking_token_bytes)

    first_result: dict[str, bytes] = {}
    first = threading.Thread(
        target=lambda: first_result.__setitem__("key", ensure_signing_key(settings))
    )
    first.start()
    assert generating.wait(timeout=5), "first caller never reached key generation"

    # Second caller runs to completion on the main thread while the first is
    # still parked above — real token_bytes, so it does not also block.
    monkeypatch.setattr("gameframework.services.secrets.secrets.token_bytes", real_token_bytes)
    second_key = ensure_signing_key(settings)

    release.set()
    first.join(timeout=5)
    assert not first.is_alive(), "first caller never finished"

    assert len(second_key) == 32
    assert first_result["key"] == second_key


def test_key_file_mode_is_0600_regardless_of_umask(tmp_path: Path) -> None:
    """0o600 passed to os.open is a request, not a guarantee — the kernel
    masks it with the process umask. A umask of 0o777 (deny everything)
    makes that masking maximally visible: it proves the code fixes the
    mode explicitly rather than relying on whatever umask happens to be in
    the container. The data dir is created before the umask is changed so
    only the key file's own mode is under test.
    """
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    settings = _settings(data_dir)

    previous_umask = os.umask(0o777)
    try:
        ensure_signing_key(settings)
    finally:
        os.umask(previous_umask)

    key_path = data_dir / "session-signing.key"
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600


def test_wrong_length_key_file_raises_instead_of_being_silently_reused(
    tmp_path: Path,
) -> None:
    """A key file that is not exactly 32 bytes — empty, truncated by a crash
    mid-write, hand-edited — must never be silently handed out or silently
    regenerated. PyJWT itself only rejects a fully empty key
    (InvalidKeyError); any other wrong length it accepts and signs with,
    degraded and silent (verified separately, not assumed). The one place
    the key is ever read is therefore also the one place a wrong length is
    caught.
    """
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    key_path = data_dir / "session-signing.key"
    key_path.write_bytes(b"short")
    settings = _settings(data_dir)

    with pytest.raises(ValueError) as exc_info:
        ensure_signing_key(settings)

    assert str(key_path) in str(exc_info.value)
    assert key_path.read_bytes() == b"short"


def test_race_loser_read_also_rejects_a_wrong_length_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The race-loser branch re-reads key_path after os.link loses to a
    concurrent winner. That is the same file as the top-level read but a
    different code path — the length check has to apply there too, not
    just at the top.
    """
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    key_path = data_dir / "session-signing.key"
    settings = _settings(data_dir)

    def fake_link(src: Path, dst: Path) -> None:
        dst.write_bytes(b"corrupt")
        raise FileExistsError

    monkeypatch.setattr("gameframework.services.secrets.os.link", fake_link)

    with pytest.raises(ValueError) as exc_info:
        ensure_signing_key(settings)

    assert str(key_path) in str(exc_info.value)


def test_publish_fsyncs_the_key_data_then_the_directory_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Durability, not just atomicity: the temp file's data must be fsynced
    before it is linked into place, and the directory itself must be
    fsynced afterward — the link is what makes the directory entry
    durable, not the file write, and without the second fsync the entry
    can be lost to a power failure even though the data behind it landed.
    """
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    settings = _settings(data_dir)

    events: list[str] = []
    real_fsync = os.fsync
    real_link = os.link

    def tracking_fsync(fd: int) -> None:
        events.append("fsync")
        real_fsync(fd)

    def tracking_link(src: Path, dst: Path) -> None:
        events.append("link")
        real_link(src, dst)

    monkeypatch.setattr("gameframework.services.secrets.os.fsync", tracking_fsync)
    monkeypatch.setattr("gameframework.services.secrets.os.link", tracking_link)

    ensure_signing_key(settings)

    assert events == ["fsync", "link", "fsync"]


def test_unsupported_hard_links_raise_an_operator_facing_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """os.link is not universally available (some NFS configurations,
    certain volume drivers). When it fails for a reason other than losing
    the race (FileExistsError), the operator needs to know why the app
    would not start, not see a bare 'Operation not supported'.
    """
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    settings = _settings(data_dir)

    def failing_link(src: Path, dst: Path) -> None:
        raise OSError(45, "Operation not supported")

    monkeypatch.setattr("gameframework.services.secrets.os.link", failing_link)

    with pytest.raises(OSError) as exc_info:
        ensure_signing_key(settings)

    assert "hard link" in str(exc_info.value)
