"""The framework-minted initial admin (ADR-0007 "Onboarding, initial
password and OTP"; data-model.md §5) and the credential-file mechanics its
two host commands share (M2-Task-Plan.md Task 5).

`ensure_initial_admin` mints the account exactly once, at first start and
again after a factory reset (M6): idempotent because it checks for an
existing `admin` row first, the same check-then-create shape
`services/blocking.py`'s `register_failure` already uses elsewhere in this
codebase, rather than a filesystem-level exclusive publish. The framework
runs as one backend replica in v1 (ADR-0006, cited in `services/blocking.py`
for the same reason) — `user.username`'s unique index, already proven in
`tests/db/test_constraints.py`, is the safety net a second replica racing
this call would need, not a torn-write race this module has to solve
itself the way `services/secrets.py` does for a file nothing else
serializes.

The credential file this module writes borrows three of
`services/secrets.py`'s four publish properties for `session-signing.key`
and deliberately drops the fourth:

- **Mode 0600 via `os.fchmod` on the open descriptor** — carries over
  unchanged. `os.open`'s mode argument is masked by the process umask
  before it reaches the filesystem regardless of which secret is being
  written.
- **`fsync` the data before publish, `fsync` the directory after** —
  carries over unchanged. The rename is what makes the directory entry
  durable, not the write, whether the file is being created for the first
  time by `ensure_initial_admin` or replaced later by `reset_admin`.
- **Published through a temp file, but with `os.replace` rather than
  `os.link`** — this is the deliberate difference, not an oversight.
  `os.link`'s exclusivity exists to stop a concurrent *second* writer from
  overwriting a first writer's key; here that role is already played by
  `user.username`'s unique index, which fails the *loser's* database
  commit before it ever reaches the filesystem — so only one process is
  ever the process that publishes this file for a given mint. And unlike
  the signing key, which is never replaced by `ensure_signing_key` itself
  and only rotates out-of-band (`services/secrets.py` module docstring),
  this file *must* be replaceable through ordinary code: `reset_admin`
  overwrites it on purpose, as its own recovery path. `os.link` would
  refuse that overwrite outright; `os.replace` is the atomic primitive
  that allows it.
- **Every read validates the file's shape, and a wrong one is never
  silently reused or regenerated** — does not carry over, and not because
  it was inconvenient: nothing in the framework ever reads this file back
  to reconstitute security state. The signing key is read on every process
  start and must be exactly 32 bytes before PyJWT will sign anything with
  it safely; this file has no equivalent consumer — it is a write-only
  artifact for a human operator's `docker exec`, never parsed by the
  application itself. Its one reader, the `initial-admin-credentials` CLI
  command, has to handle the file's *absence* — removed at the account's
  first successful login (data-model.md §5) — which is a different
  failure mode from the corrupted-shape one the signing key guards
  against, and is handled where that command lives (`cli.py`).
"""

import os
import secrets
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from gameframework.config import Settings
from gameframework.db.models.feedback import AuditScope
from gameframework.db.models.identity import BlockedAddress, Role, User
from gameframework.services.audit import write_audit
from gameframework.services.passwords import hash_password

INITIAL_ADMIN_USERNAME = "admin"
_CREDENTIALS_FILENAME = "initial-admin-credentials"
_PASSWORD_ENTROPY_BYTES = 24


def credentials_path(settings: Settings) -> Path:
    return settings.data_dir / _CREDENTIALS_FILENAME


def generate_password() -> str:
    return secrets.token_urlsafe(_PASSWORD_ENTROPY_BYTES)


def publish_credentials_file(settings: Settings, username: str, password: str) -> None:
    """Temp file + `os.replace`, `fchmod`'d to 0600, data fsynced before
    the rename and the directory fsynced after — see the module docstring
    for why this is `os.replace` rather than `services/secrets.py`'s
    `os.link`.
    """
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    path = credentials_path(settings)
    tmp_path = settings.data_dir / f".{_CREDENTIALS_FILENAME}.tmp-{secrets.token_hex(8)}"
    fd = os.open(tmp_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as tmp_file:
            tmp_file.write(f"{username}\n{password}\n")
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
        os.replace(tmp_path, path)
        dir_fd = os.open(settings.data_dir, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        tmp_path.unlink(missing_ok=True)


def remove_initial_admin_credentials_if_present(settings: Settings) -> None:
    """data-model.md §5 / ADR-0007: removed on the account's first
    successful login, never on a later password change — an admin who
    never gets round to choosing their own password would otherwise leave
    a recoverable credential in the data volume for the life of the
    installation. Idempotent by construction: every login after the first
    finds nothing to remove.
    """
    credentials_path(settings).unlink(missing_ok=True)


def ensure_initial_admin(db: Session, settings: Settings) -> None:
    """ADR-0007 "The initial admin is minted by the framework." Idempotent:
    a second call against a database that already has an admin changes
    nothing — no new row, no rewritten file, no second audit entry.

    The guard is "no user holds the admin role", not "no user is named
    `admin`": the plan's Produces line says "when no admin exists, mints
    `admin`", and a renamed or otherwise-named admin is still an admin.
    Checking the fixed username specifically would silently recreate the
    framework-minted account — with a fresh credential file written into
    the data volume — on the next restart after an operator (Task 6)
    deletes it while another admin remains.
    """
    existing = db.execute(select(User).where(User.role == Role.admin)).scalars().first()
    if existing is not None:
        return

    password = generate_password()
    user = User(
        username=INITIAL_ADMIN_USERNAME,
        password_hash=hash_password(password),
        role=Role.admin,
        is_active=True,
        must_change_password=False,
        preferred_language="en",
    )
    db.add(user)
    db.commit()

    publish_credentials_file(settings, user.username, password)

    write_audit(
        db,
        actor_user_id=None,
        scope=AuditScope.installation,
        event_run_id=None,
        action="initial_admin_minted",
        target_type="user",
        target_id=user.id,
        details={},
    )


def reset_admin(db: Session, settings: Settings, username: str) -> bool:
    """ADR-0007 "Recovery and reset" — the installation's second host
    command, for when it has locked itself out entirely. Scoped to
    `role == admin`, matching the ADR's own wording ("a named admin
    account"): a locked-out gameadmin recovers through the ordinary
    admin-driven reset an admin performs from the web interface, not a
    host command that requires no authentication at all.

    Returns `False` for an unknown username rather than raising, so the
    CLI can report it and exit non-zero instead of crashing.
    """
    user = db.execute(
        select(User).where(User.username == username, User.role == Role.admin)
    ).scalar_one_or_none()
    if user is None:
        return False

    password = generate_password()
    user.password_hash = hash_password(password)
    user.must_change_password = False
    db.execute(delete(BlockedAddress))
    db.commit()

    publish_credentials_file(settings, username, password)
    return True
