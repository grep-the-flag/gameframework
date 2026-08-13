"""The framework-owned session-signing key (ADR-0007, "Session model" —
Signing key). `ensure_signing_key` is the one place the key is ever read: a
first start draws 32 bytes from a CSPRNG and writes them to
`<data_dir>/session-signing.key` at mode 0600. Every later call reuses
whatever is on disk, which is also what makes replacing the file's contents
(the M6 factory reset's rotation) enough to invalidate every session at
once, with no separate rotation code path here.

The write is staged through a uniquely-named temp file in the same
directory and published with `os.link`, never written at `key_path`
directly: two callers can reach this function at once on a data dir that
has never held a key — a fresh start racing a restart, or two processes
starting together — and `os.link` is the POSIX primitive that is both
exclusive (fails if `key_path` already exists, so it never overwrites a
concurrent winner) and atomic (the destination is either absent or the
fully-written file, never one mid-write). `os.replace` was considered and
rejected: it is atomic but not exclusive, and would let the loser of the
race silently overwrite the winner's key. `os.link` is not universal —
some NFS configurations and volume drivers do not support it — so a
failure other than losing the race is re-raised naming the cause, not left
as a bare OSError. Mode 0600 is set with `os.fchmod` on the open
descriptor rather than trusted to the `os.open` mode argument, because
that argument is masked by the process umask before it reaches the
filesystem. The temp file's data is fsynced before the link and the
directory is fsynced after: the link is what makes the directory entry
durable, not the file write, and without the second fsync the entry itself
can be lost to a power failure even though the data behind it landed.

A file at `key_path` that is not exactly 32 bytes — corrupted, truncated by
a crash mid-write, hand-edited — is never silently reused or silently
regenerated: silent regeneration is its own outage, ending every session at
a moment nobody chose, the exact failure the no-default `data_dir` setting
exists to prevent. It is also not safe to leave to PyJWT downstream: PyJWT
raises only on a fully empty key and otherwise signs with whatever length
it is given, silently. Both places this function reads the file — the
ordinary path and the race-loser's re-read — check the length and raise if
it is wrong, naming the path and telling the operator to remove the file.
"""

import os
import secrets
from pathlib import Path

from gameframework.config import Settings

_KEY_FILENAME = "session-signing.key"
_KEY_LENGTH = 32


def _validated(data: bytes, key_path: Path) -> bytes:
    if len(data) != _KEY_LENGTH:
        raise ValueError(
            f"session signing key at {key_path} is {len(data)} bytes, expected "
            f"{_KEY_LENGTH}. Remove the file to let the framework draw a new one."
        )
    return data


def ensure_signing_key(settings: Settings) -> bytes:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    key_path = settings.data_dir / _KEY_FILENAME
    try:
        return _validated(key_path.read_bytes(), key_path)
    except FileNotFoundError:
        pass

    key = secrets.token_bytes(_KEY_LENGTH)
    tmp_key_path = settings.data_dir / f".{_KEY_FILENAME}.tmp-{secrets.token_hex(8)}"
    fd = os.open(tmp_key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as tmp_key_file:
            tmp_key_file.write(key)
            tmp_key_file.flush()
            os.fsync(tmp_key_file.fileno())
        try:
            os.link(tmp_key_path, key_path)
        except FileExistsError:
            # Lost the race to another concurrent first start; its key is
            # the one already on disk, complete — use that instead of ours.
            key = _validated(key_path.read_bytes(), key_path)
        except OSError as exc:
            raise OSError(
                f"could not publish the session signing key at {key_path}: {exc}. "
                "The data directory must sit on a filesystem that supports hard "
                "links (os.link)."
            ) from exc
        else:
            dir_fd = os.open(settings.data_dir, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    finally:
        tmp_key_path.unlink(missing_ok=True)
    return key
