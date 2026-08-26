"""M2-Task-Plan.md Task 17: the vault envelope (data-model.md §7, ADR-0010).
Positive/format claims — round trip, AAD binding, the malformed-envelope
traps 1a's ruling added, the M2 DB-dump acceptance criterion, and the
logging contract. `test_fail_closed.py` carries the failure/misconfiguration
half.

`_settings()`/`_vault_key_env()` build a `Settings` object directly, the
same local-helper pattern `tests/auth/test_signing_key.py` uses for
`data_dir` — this suite's own varying field is `vault_key`.
"""

import base64
import logging
import os
import uuid
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text

from gameframework.config import Settings, VaultKey
from gameframework.db.models.play import VaultEntry
from gameframework.db.models.runs import RunStatus
from gameframework.services.vault import (
    TeamRunMismatchError,
    VaultAuthenticationError,
    VaultCrypto,
    VaultEnvelopeError,
    read_vault_value,
    store_vault_value,
)

from ..conftest import (
    make_challenge,
    make_event_definition,
    make_event_run,
    make_reward_definition,
    make_team,
)

_PLAINTEXT = b"super-secret-vault-value-4f9c21a8-do-not-leak"


def _settings(vault_key: object = None, **overrides: object) -> Settings:
    defaults: dict[str, Any] = dict(
        database_url="postgresql+psycopg://test:test@localhost/test",
        frontend_origin="https://app.event.example.com",
        data_dir=Path("/tmp/gameframework-vault-test"),
        cookie_domain="event.example.com",
        dropin_dir=Path("/tmp/gameframework-vault-test/dropin"),
        player_tcp_host="event.example.com",
        event_domain="event.example.com",
        tcp_port_range=(20000, 29999),
        vault_key=vault_key,
    )
    defaults.update(overrides)
    return Settings(**defaults)  # type: ignore[arg-type]


def _vault_key_env(version: int = 1, key: bytes | None = None) -> str:
    key = key if key is not None else os.urandom(32)
    return f"{version}:{base64.b64encode(key).decode()}"


# ---------------------------------------------------------------------------
# Settings: GF_VAULT_KEY parses to (version, key)
# ---------------------------------------------------------------------------


def test_settings_parses_vault_key_version_and_base64_key() -> None:
    key = os.urandom(32)

    settings = _settings(vault_key=f"3:{base64.b64encode(key).decode()}")

    assert settings.vault_key == VaultKey(version=3, key=key)


# ---------------------------------------------------------------------------
# Round trip, key_version carried
# ---------------------------------------------------------------------------


def test_round_trip_returns_original_plaintext() -> None:
    crypto = VaultCrypto(_settings(vault_key=_vault_key_env()))
    row_pk = uuid.uuid4()

    envelope = crypto.encrypt(_PLAINTEXT, row_pk)

    assert crypto.decrypt(envelope, row_pk) == _PLAINTEXT


def test_envelope_carries_the_configured_key_version() -> None:
    crypto = VaultCrypto(_settings(vault_key=_vault_key_env(version=7)))

    envelope = crypto.encrypt(b"value", uuid.uuid4())

    assert envelope[0] == 7


def test_empty_plaintext_round_trips_at_the_minimum_envelope_size() -> None:
    """The negative case for the length check below: exactly the minimum
    size (1 + 12 + 16 = 29 bytes, from an empty plaintext) must be accepted,
    not rejected by an off-by-one in the `<` comparison.
    """
    crypto = VaultCrypto(_settings(vault_key=_vault_key_env()))
    row_pk = uuid.uuid4()

    envelope = crypto.encrypt(b"", row_pk)

    assert len(envelope) == 29
    assert crypto.decrypt(envelope, row_pk) == b""


# ---------------------------------------------------------------------------
# AAD binding: a ciphertext moved to another row's PK must fail
# authentication. The same envelope must still decrypt under its own PK,
# which is what proves the failure above is the AAD and not a broken
# round trip (or a constant AAD accepted by both calls).
# ---------------------------------------------------------------------------


def test_ciphertext_moved_to_another_rows_pk_fails_authentication() -> None:
    crypto = VaultCrypto(_settings(vault_key=_vault_key_env()))
    row_a = uuid.uuid4()
    row_b = uuid.uuid4()

    envelope = crypto.encrypt(_PLAINTEXT, row_a)

    with pytest.raises(VaultAuthenticationError):
        crypto.decrypt(envelope, row_b)
    assert crypto.decrypt(envelope, row_a) == _PLAINTEXT


# ---------------------------------------------------------------------------
# Malformed envelope: too short, or key_version 0 — both raise
# VaultEnvelopeError, not VaultAuthenticationError (1a's ruling)
# ---------------------------------------------------------------------------


def test_envelope_shorter_than_minimum_raises_envelope_error() -> None:
    crypto = VaultCrypto(_settings(vault_key=_vault_key_env()))

    with pytest.raises(VaultEnvelopeError):
        crypto.decrypt(b"\x01" + b"\x00" * 20, uuid.uuid4())  # 21 bytes; minimum is 29


def test_envelope_with_key_version_zero_is_rejected() -> None:
    crypto = VaultCrypto(_settings(vault_key=_vault_key_env()))
    # Structurally the right length (1 + 12 + 16), but key_version 0 — the
    # shape a zero-filled or truncated-then-padded bytea would take.
    envelope = b"\x00" + os.urandom(12) + os.urandom(16)

    with pytest.raises(VaultEnvelopeError):
        crypto.decrypt(envelope, uuid.uuid4())


# ---------------------------------------------------------------------------
# The M2 acceptance criterion: a value stored through the service appears
# nowhere in plaintext when the raw bytea column is SELECTed directly.
# ---------------------------------------------------------------------------


def test_value_stored_through_service_appears_nowhere_in_plaintext_in_raw_column(
    db_session,  # type: ignore[no-untyped-def]
) -> None:
    definition = make_event_definition(db_session)
    run = make_event_run(db_session, definition=definition, status=RunStatus.running)
    team = make_team(db_session, run=run)
    challenge = make_challenge(db_session, definition=definition)
    reward_definition = make_reward_definition(db_session, challenge=challenge)
    settings = _settings(vault_key=_vault_key_env())

    entry = store_vault_value(
        db_session,
        run=run,
        team=team,
        reward_definition=reward_definition,
        value=_PLAINTEXT,
        settings=settings,
    )

    raw = db_session.execute(
        text("SELECT encrypted_value FROM vault_entry WHERE id = :id"),
        {"id": entry.id},
    ).scalar_one()

    assert isinstance(raw, bytes)
    assert _PLAINTEXT not in raw


def test_store_vault_value_does_not_commit(db_session) -> None:  # type: ignore[no-untyped-def]
    """§6: reward-value generation composes into M3's atomic solve/
    provisioning transaction, so `store_vault_value` must flush only (see
    module docstring). The `db_session` fixture's savepoint-per-test
    isolation does not distinguish flush from commit for most assertions —
    both make the row visible to a later query in the same test — so this
    is bound the same way `tests/scoring/test_ledger.py::
    test_append_entry_does_not_commit` binds the identical claim for
    `append_entry`: call, then roll back the *test's own* session. A wrong
    implementation that commits internally would have already released the
    row past that rollback.
    """
    definition = make_event_definition(db_session)
    run = make_event_run(db_session, definition=definition, status=RunStatus.running)
    team = make_team(db_session, run=run)
    challenge = make_challenge(db_session, definition=definition)
    reward_definition = make_reward_definition(db_session, challenge=challenge)
    settings = _settings(vault_key=_vault_key_env())

    entry = store_vault_value(
        db_session,
        run=run,
        team=team,
        reward_definition=reward_definition,
        value=b"value",
        settings=settings,
    )
    entry_id = entry.id

    db_session.rollback()

    assert db_session.get(VaultEntry, entry_id) is None


def test_read_returns_none_when_no_value_stored_yet(db_session) -> None:  # type: ignore[no-untyped-def]
    definition = make_event_definition(db_session)
    run = make_event_run(db_session, definition=definition, status=RunStatus.running)
    team = make_team(db_session, run=run)
    challenge = make_challenge(db_session, definition=definition)
    reward_definition = make_reward_definition(db_session, challenge=challenge)
    settings = _settings(vault_key=_vault_key_env())

    result = read_vault_value(
        db_session, team=team, reward_definition=reward_definition, settings=settings
    )

    assert result is None


# ---------------------------------------------------------------------------
# Logging: key_version is logged; plaintext and key material never are (§7)
# ---------------------------------------------------------------------------


def test_operations_log_key_version_and_never_key_material_or_plaintext(
    db_session,  # type: ignore[no-untyped-def]
    caplog: pytest.LogCaptureFixture,
) -> None:
    definition = make_event_definition(db_session)
    run = make_event_run(db_session, definition=definition, status=RunStatus.running)
    team = make_team(db_session, run=run)
    challenge = make_challenge(db_session, definition=definition)
    reward_definition = make_reward_definition(db_session, challenge=challenge)
    key = os.urandom(32)
    settings = _settings(vault_key=_vault_key_env(version=5, key=key))

    with caplog.at_level(logging.DEBUG):
        store_vault_value(
            db_session,
            run=run,
            team=team,
            reward_definition=reward_definition,
            value=_PLAINTEXT,
            settings=settings,
        )
        read_vault_value(
            db_session, team=team, reward_definition=reward_definition, settings=settings
        )

    messages = [record.getMessage() for record in caplog.records]
    joined = "\n".join(messages)

    # Bound per operation, not "any log line" — store_vault_value's encrypt
    # and read_vault_value's decrypt are two separate log calls, and an
    # "any" assertion is satisfied by either one alone logging key_version,
    # leaving the other's claim unbound (found by mutation: dropping
    # key_version from encrypt's log call alone left this test green until
    # split this way).
    assert any("vault encrypt: key_version=5" in message for message in messages)
    assert any("vault decrypt: key_version=5" in message for message in messages)
    assert _PLAINTEXT.decode() not in joined
    assert key.hex() not in joined
    assert base64.b64encode(key).decode() not in joined
    assert repr(key) not in joined


# ---------------------------------------------------------------------------
# §6 run/definition coherence, named explicitly for vault_entry: the team
# must belong to the given run, and the reward's producing challenge must
# resolve against the run's own event_definition_id. Mirrors
# tests/scoring/test_ledger.py's equivalent pair for score_entry.
# ---------------------------------------------------------------------------


def test_store_requires_team_to_belong_to_the_given_run(db_session) -> None:  # type: ignore[no-untyped-def]
    # Only one run may be `running`/`paused` at a time (uq_event_run_single_active);
    # run_b's own lifecycle status is irrelevant to this test. reward_definition's
    # challenge is deliberately scoped to run_a's own definition, so this test
    # isolates the team/run mismatch alone — a reward_definition from an
    # unrelated definition would also (and misleadingly) trip the separate
    # reward/definition coherence check below.
    definition = make_event_definition(db_session)
    run_a = make_event_run(db_session, definition=definition, status=RunStatus.running)
    run_b = make_event_run(db_session, status=RunStatus.created)
    team_of_run_b = make_team(db_session, run=run_b)
    challenge = make_challenge(db_session, definition=definition)
    reward_definition = make_reward_definition(db_session, challenge=challenge)
    settings = _settings(vault_key=_vault_key_env())

    with pytest.raises(TeamRunMismatchError):
        store_vault_value(
            db_session,
            run=run_a,
            team=team_of_run_b,
            reward_definition=reward_definition,
            value=b"value",
            settings=settings,
        )


def test_store_requires_reward_definitions_challenge_to_belong_to_runs_definition(
    db_session,  # type: ignore[no-untyped-def]
) -> None:
    other_definition = make_event_definition(db_session)
    make_event_run(db_session, definition=other_definition, status=RunStatus.created)
    other_challenge = make_challenge(db_session, definition=other_definition)
    other_reward_definition = make_reward_definition(db_session, challenge=other_challenge)

    definition = make_event_definition(db_session)
    run = make_event_run(db_session, definition=definition, status=RunStatus.running)
    team = make_team(db_session, run=run)
    settings = _settings(vault_key=_vault_key_env())

    with pytest.raises(ValueError):
        store_vault_value(
            db_session,
            run=run,
            team=team,
            reward_definition=other_reward_definition,
            value=b"value",
            settings=settings,
        )
