"""`hash_password`/`verify_password` (ADR-0007 Session model, data-model.md
§3.1; M2-Task-Plan.md Task 3 Step 3). Argon2id via argon2-cffi is the
decided algorithm — not a design question here, just the ten lines that
implement it — and it lands in this step rather than Step 6 because every
later auth fixture needs a real hash from the start (Task 3 Step 3): a
plaintext placeholder would let Step 4's login route pass on a string
comparison, a defect nothing downstream is obliged to notice.
"""

import logging

import pytest

from gameframework.services.passwords import hash_password, verify_password


def _corrupt(hashed: str) -> str:
    """An Argon2-shaped hash the C library itself rejects during
    verification — distinct from a string that never parses as one at
    all (`InvalidHashError`, tested below): flipping the last digest
    character keeps the format intact and corrupts only the payload.
    """
    last = hashed[-1]
    return hashed[:-1] + ("a" if last != "a" else "b")


def test_hash_password_returns_an_argon2id_hash() -> None:
    hashed = hash_password("correct horse battery staple")

    assert hashed.startswith("$argon2id$")


def test_verify_password_accepts_the_correct_plaintext() -> None:
    hashed = hash_password("correct horse battery staple")

    assert verify_password("correct horse battery staple", hashed) is True


def test_verify_password_rejects_the_wrong_plaintext() -> None:
    hashed = hash_password("correct horse battery staple")

    assert verify_password("wrong password", hashed) is False


def test_hash_password_is_salted_so_two_hashes_of_the_same_password_differ() -> None:
    first = hash_password("correct horse battery staple")
    second = hash_password("correct horse battery staple")

    assert first != second
    assert verify_password("correct horse battery staple", first) is True
    assert verify_password("correct horse battery staple", second) is True


def test_verify_password_returns_false_for_a_value_that_is_not_an_argon2_hash_at_all() -> None:
    """`PasswordHasher.verify` raises `InvalidHashError` here (a `ValueError`
    sibling, not an `Argon2Error`/`VerificationError` subclass — checked
    live, not assumed). The route this feeds is reachable unauthenticated;
    an uncaught exception there would be a 500, and a 500 is an oracle for
    which stored hashes are broken.
    """
    assert verify_password("whatever", "not-an-argon2-hash-at-all") is False


def test_verify_password_returns_false_for_a_corrupted_argon2_shaped_hash() -> None:
    """`PasswordHasher.verify` raises `VerificationError` here — a true
    `Argon2Error` subclass, distinct from `VerifyMismatchError` — checked
    live against a hash the C library recognizes as Argon2-shaped but
    rejects as corrupt.
    """
    corrupted = _corrupt(hash_password("correct horse battery staple"))

    assert verify_password("correct horse battery staple", corrupted) is False


def test_verify_password_logs_nothing_for_an_ordinary_wrong_password(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """`VerifyMismatchError` is the ordinary case — every failed login
    attempt takes this path — so it must not log, or the two malformed-
    hash warnings below would be lost in the noise exactly when an
    operator most wants to read them.
    """
    hashed = hash_password("correct horse battery staple")

    with caplog.at_level(logging.WARNING):
        verify_password("wrong password", hashed)

    assert caplog.records == []


def test_verify_password_logs_a_warning_naming_the_reason_for_a_non_argon2_value(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        verify_password("whatever", "not-an-argon2-hash-at-all")

    assert len(caplog.records) == 1
    assert caplog.records[0].levelno == logging.WARNING
    assert "not an Argon2 hash" in caplog.records[0].getMessage()


def test_verify_password_logs_a_warning_naming_the_reason_for_a_corrupted_hash(
    caplog: pytest.LogCaptureFixture,
) -> None:
    corrupted = _corrupt(hash_password("correct horse battery staple"))

    with caplog.at_level(logging.WARNING):
        verify_password("correct horse battery staple", corrupted)

    assert len(caplog.records) == 1
    assert caplog.records[0].levelno == logging.WARNING
    assert "failed verification" in caplog.records[0].getMessage()


def test_verify_password_never_logs_hash_material_for_a_malformed_hash(
    caplog: pytest.LogCaptureFixture,
) -> None:
    hashed = hash_password("correct horse battery staple")
    corrupted = _corrupt(hashed)

    with caplog.at_level(logging.WARNING):
        verify_password("whatever", "not-an-argon2-hash-at-all")
        verify_password("correct horse battery staple", corrupted)

    for record in caplog.records:
        message = record.getMessage()
        assert "not-an-argon2-hash-at-all" not in message
        assert corrupted not in message
        assert hashed not in message
