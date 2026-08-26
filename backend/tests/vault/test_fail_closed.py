"""M2-Task-Plan.md Task 17: fail-closed behavior (data-model.md §7). Two
distinct failure modes, per the ruling in this task's Step 1:

- **Missing** (`GF_VAULT_KEY` unset): a legitimate, if incomplete,
  deployment state. The app boots; `VaultUnavailableError` is raised only
  when the vault is actually used (`VaultCrypto`/`store_vault_value`/
  `read_vault_value`), and store leaves no row behind.
- **Present but invalid** (wrong length, bad grammar, non-base64, version
  0): unambiguous misconfiguration with no legitimate reading, caught
  eagerly as a `pydantic.ValidationError` at `Settings` construction —
  before the app ever boots — the same precedent
  `services/secrets.py::ensure_signing_key` established for the session
  signing key. `VaultUnavailableError` stays reserved strictly for
  "missing".

Two requirements apply to every validation-error case here: the raised
error must never echo the raw key material (a `pydantic.ValidationError`
echoes its input by default), and `vault_key` must never appear in
`repr(Settings)`.
"""

import base64
import os
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select

from gameframework.config import Settings
from gameframework.db.models.play import VaultEntry
from gameframework.db.models.runs import RunStatus
from gameframework.services.vault import VaultUnavailableError, read_vault_value, store_vault_value

from ..conftest import (
    make_challenge,
    make_event_definition,
    make_event_run,
    make_reward_definition,
    make_team,
)


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


# ---------------------------------------------------------------------------
# Missing key: raises at use, nothing written, raises on read regardless of
# row existence
# ---------------------------------------------------------------------------


def test_store_raises_and_writes_no_row_with_no_key_configured(db_session) -> None:  # type: ignore[no-untyped-def]
    definition = make_event_definition(db_session)
    run = make_event_run(db_session, definition=definition, status=RunStatus.running)
    team = make_team(db_session, run=run)
    challenge = make_challenge(db_session, definition=definition)
    reward_definition = make_reward_definition(db_session, challenge=challenge)
    settings = _settings(vault_key=None)

    with pytest.raises(VaultUnavailableError):
        store_vault_value(
            db_session,
            run=run,
            team=team,
            reward_definition=reward_definition,
            value=b"should never be written",
            settings=settings,
        )

    count = db_session.execute(select(func.count()).select_from(VaultEntry)).scalar_one()
    assert count == 0


def test_read_raises_regardless_of_row_existence_with_no_key_configured(
    db_session,  # type: ignore[no-untyped-def]
) -> None:
    definition = make_event_definition(db_session)
    run = make_event_run(db_session, definition=definition, status=RunStatus.running)
    team = make_team(db_session, run=run)
    challenge = make_challenge(db_session, definition=definition)
    reward_definition = make_reward_definition(db_session, challenge=challenge)
    settings = _settings(vault_key=None)

    with pytest.raises(VaultUnavailableError):
        read_vault_value(
            db_session, team=team, reward_definition=reward_definition, settings=settings
        )


def test_blank_vault_key_env_is_treated_as_absent() -> None:
    settings = _settings(vault_key="")

    assert settings.vault_key is None


# ---------------------------------------------------------------------------
# Present but invalid: a startup-time ValidationError, not
# VaultUnavailableError
# ---------------------------------------------------------------------------


def test_wrong_length_key_raises_validation_error_at_settings_construction() -> None:
    key = os.urandom(24)  # AES-192 length; the vault requires 32 (AES-256)

    with pytest.raises(ValidationError):
        _settings(vault_key=f"1:{base64.b64encode(key).decode()}")


def test_malformed_grammar_raises_validation_error_at_settings_construction() -> None:
    with pytest.raises(ValidationError):
        _settings(vault_key="not-the-expected-shape")


def test_non_base64_key_segment_raises_validation_error_at_settings_construction() -> None:
    with pytest.raises(ValidationError):
        _settings(vault_key="1:not valid base64!!")


def test_whitespace_tampered_key_segment_is_rejected_not_leniently_decoded() -> None:
    """A stray character lenient base64 decoding silently discards (a space,
    here) is not the same claim as "not valid base64" above — a padding
    error fires either way for that input, so it does not by itself prove
    `validate=True` matters. This tampered string decodes CORRECTLY to the
    original 32-byte key under lenient decoding (proven directly against
    `base64.b64decode` without `validate=True` while writing this test), so
    only strict validation tells the two apart. Found by mutation: removing
    `validate=True` left the suite green until this case was added.
    """
    key = os.urandom(32)
    b64 = base64.b64encode(key).decode()
    tampered = b64[:10] + " " + b64[10:]

    with pytest.raises(ValidationError):
        _settings(vault_key=f"1:{tampered}")


def test_version_zero_raises_validation_error_at_settings_construction() -> None:
    key = os.urandom(32)

    with pytest.raises(ValidationError):
        _settings(vault_key=f"0:{base64.b64encode(key).decode()}")


def test_version_above_255_raises_validation_error_at_settings_construction() -> None:
    """The envelope's key_version occupies exactly 1 byte (data-model.md
    §7 / this task's Step 1 ruling); a configured version above 255 must be
    refused at Settings construction rather than overflowing at the first
    `encrypt()` call.
    """
    key = os.urandom(32)

    with pytest.raises(ValidationError):
        _settings(vault_key=f"256:{base64.b64encode(key).decode()}")


# ---------------------------------------------------------------------------
# The trap: pydantic echoes the offending input by default. The validator's
# own message never repeats it (only lengths), and hide_input_in_errors
# suppresses pydantic's own automatic echo — bound against the raw key
# material actually making it into the exception, not just against the
# validator's own wording.
# ---------------------------------------------------------------------------


def test_validation_error_never_echoes_the_raw_key_material() -> None:
    key = os.urandom(24)  # wrong length, guaranteed to raise
    key_b64 = base64.b64encode(key).decode()
    raw_value = f"1:{key_b64}"

    with pytest.raises(ValidationError) as exc_info:
        _settings(vault_key=raw_value)

    message = str(exc_info.value)
    assert raw_value not in message
    assert key_b64 not in message
    assert key.hex() not in message
    assert repr(key) not in message


def test_vault_key_never_appears_in_settings_repr() -> None:
    key = os.urandom(32)
    key_b64 = base64.b64encode(key).decode()
    raw_value = f"9:{key_b64}"

    settings = _settings(vault_key=raw_value)

    settings_repr = repr(settings)
    assert "vault_key" not in settings_repr
    assert key_b64 not in settings_repr
    assert raw_value not in settings_repr
    assert key.hex() not in settings_repr
    # A bytes field embedded in a pydantic repr renders through
    # bytes.__repr__ (b'\x..'), not .hex() or base64 — the form the key
    # would actually take if repr=False ever lapsed (M2-Task-Plan.md Task 3
    # carried the identical assertion for the session signing key).
    assert repr(key) not in settings_repr
