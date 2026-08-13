"""The framework-owned session-signing key (ADR-0007, "Session model" —
Signing key). `ensure_signing_key` is the one place the key is ever read: a
first start draws 32 bytes from a CSPRNG and writes them to
`<data_dir>/session-signing.key` at mode 0600 — created at that mode
directly (`os.open` with `O_EXCL`) so the file is never briefly readable by
anyone but its owner. Every later call reuses whatever is on disk, which is
also what makes replacing the file's contents (the M6 factory reset's
rotation) enough to invalidate every session at once, with no separate
rotation code path here.
"""

import os
import secrets

from gameframework.config import Settings

_KEY_FILENAME = "session-signing.key"


def ensure_signing_key(settings: Settings) -> bytes:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    key_path = settings.data_dir / _KEY_FILENAME
    try:
        fd = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return key_path.read_bytes()
    key = secrets.token_bytes(32)
    with os.fdopen(fd, "wb") as key_file:
        key_file.write(key)
    return key
