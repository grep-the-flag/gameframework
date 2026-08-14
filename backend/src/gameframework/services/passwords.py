"""Argon2id password/OTP hashing (ADR-0007, data-model.md §3.1) via
argon2-cffi. One hasher, one algorithm, for both `password_hash` and
`otp_hash` (ADR-0007: "Hashed with the password hash function").
"""

import logging

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher()
_logger = logging.getLogger(__name__)


def hash_password(plain: str) -> str:
    return _hasher.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """`POST /auth/login` is public, so a malformed stored hash must never
    surface as a 500 here — that would be an oracle for which accounts
    carry a broken hash. `VerifyMismatchError` (ordinary wrong password)
    is the common case and stays silent; a hash that is not Argon2 at all
    (`InvalidHashError`, a `ValueError` sibling, not an `Argon2Error`) or
    one that is Argon2-shaped but corrupt (`VerificationError`) are both
    operator-facing defects and log at warning, with distinct messages and
    no hash material — but no user id either, since it is not part of
    this signature.
    """
    try:
        return _hasher.verify(hashed, plain)
    except VerifyMismatchError:
        return False
    except InvalidHashError:
        _logger.warning("stored hash is not an Argon2 hash")
        return False
    except VerificationError:
        _logger.warning("stored hash failed verification")
        return False
