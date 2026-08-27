"""Argon2id password/OTP hashing (ADR-0007, data-model.md §3.1) via
argon2-cffi. One hasher, one algorithm, for both `password_hash` and
`otp_hash` (ADR-0007: "Hashed with the password hash function").
"""

import logging
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher()
_logger = logging.getLogger(__name__)


def hash_password(plain: str) -> str:
    return _hasher.hash(plain)


DUMMY_PASSWORD_HASH = hash_password(secrets.token_urlsafe(32))
"""M2 security gate Task 20, finding: Medium. `POST /auth/login` used to
answer an unknown username immediately, before `verify_password` ever
ran, while a known username with a wrong password paid a full Argon2id
verification a few lines later — both answer the byte-identical `401
invalid_credentials`, so latency alone told the two apart, an oracle
ADR-0007's accepted login oracle never names (its four categories are
distinguished by response content, never by timing). Verifying against
this fixed hash — drawn once from a CSPRNG, matching nothing any real
account could hold — on the unknown-username path pays the same cost the
known-username path already pays, closing the gap; the result is always
discarded, since the answer there is unconditionally "unknown account."
"""


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
