"""OTP issuance (M2-Task-Plan.md Task 4 Step 3; ADR-0007 "OTP properties";
data-model.md §3.1). Source-address blocking — `register_failure`,
`check_blocked`, `register_full_success`, `normalize_source` — is Step 4/5's
and lives elsewhere; this file is issuance only.
"""

import secrets
import string
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session as DbSession

from gameframework.db.models.identity import User
from gameframework.db.models.runs import EventRun
from gameframework.services.passwords import hash_password

# ADR-0007 "OTP properties" — Format: "8 characters from an unambiguous
# alphabet (no 0/O, 1/l)". Only those four are named as excluded; every
# other digit and letter, upper- and lowercase, stays in.
_AMBIGUOUS = frozenset("0O1l")
_ALPHABET = "".join(
    ch
    for ch in string.ascii_uppercase + string.ascii_lowercase + string.digits
    if ch not in _AMBIGUOUS
)
_OTP_LENGTH = 8


def issue_otp(db: DbSession, target_user: User, run: EventRun) -> str:
    """Generates, hashes and stores a fresh OTP for `target_user`, returning
    the plaintext once — the only time it is ever available, since
    `User.otp_hash` holds only its hash (ADR-0007 "OTP properties" — At
    rest).

    Expiry is resolved **at issue**, from `run.otp_lifetime_minutes`, and
    never revisited: data-model.md §3.1 states this precisely so that a
    later change to the run's setting cannot move an OTP already handed to
    someone. Issuing supersedes any outstanding OTP — the three columns are
    a single overwrite, which is what clears `otp_consumed_at` even for a
    fresh code that was never consumed (data-model.md §3.1).
    """
    raw_otp = "".join(secrets.choice(_ALPHABET) for _ in range(_OTP_LENGTH))
    target_user.otp_hash = hash_password(raw_otp)
    target_user.otp_expires_at = datetime.now(UTC) + timedelta(minutes=run.otp_lifetime_minutes)
    target_user.otp_consumed_at = None
    db.add(target_user)
    db.commit()
    return raw_otp
