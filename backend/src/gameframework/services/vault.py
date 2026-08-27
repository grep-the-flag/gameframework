"""Vault crypto and storage substrate (M2-Task-Plan.md Task 17; data-model.md
§7; ADR-0010). Scope is exactly `vault_entry.encrypted_value` (§3.13) and
nothing else — reward *generation* (what a `token`, `ssh_keypair`, `password`
or `ssl_cert` is made of) is normative in SDK contract §6 and belongs to M3;
this module is the crypto and storage substrate M3's reward generation and
provisioning will call.

Envelope, flat in the `bytea`, with no framing beyond fixed positions — §7's
`{key_version, nonce, ciphertext+tag}` describes contents, not a JSON
mandate; `cryptography`'s AESGCM already returns ciphertext with its tag
appended, and the nonce is fixed at exactly 12 bytes, so nothing here is
variable-length except the trailing remainder:

    key_version (1 byte, uint8) || nonce (12 bytes) || ciphertext+tag (rest)

Version 0 is never written (config.py's `Settings.vault_key` validator
requires >= 1) and is rejected on read: a zero-filled or truncated `bytea`
must not decode as a plausible envelope. `VaultCrypto.decrypt` validates the
total length (minimum 29 bytes: 1 + 12 + the 16-byte GCM tag) and rejects a
0 key_version before slicing anything, so a malformed envelope raises
`VaultEnvelopeError` naming the problem instead of being sliced into
plausible-looking garbage that then surfaces as an authentication failure —
the two are different diagnoses an operator acts on differently.

AAD is the row's own primary key, as its raw 16 bytes (`uuid.UUID.bytes`),
never its 36-character string form: raw bytes are the one representation of
a UUID with no case/dash-formatting variant to keep in sync between the
encrypt and decrypt call sites.

Key and version travel as one `Settings.vault_key` (`config.VaultKey`),
parsed from `GF_VAULT_KEY=<version>:<base64-key>` — never two settings that
could independently drift (a rotated key with a forgotten version bump, or
the reverse), which nothing in M2 would catch, since only one key is ever
configured at a time and AES-GCM's tag only catches a *wrong* key, not a
*mislabeled* one.

Optional at boot, fail-closed at use: `Settings.vault_key` defaults to
`None`, so an installation that has not configured the vault yet still
starts — §7's failure behavior ("a missing key fails closed: provisioning
reports the vault as unavailable") describes something that happens when the
vault is used, not when the app boots. `VaultCrypto(settings)` raises
`VaultUnavailableError` immediately when unset, so `store_vault_value` and
`read_vault_value` below both fail before doing anything else — for a store,
before any row is added to the session; for a read, regardless of whether a
row already exists for the given team and reward. Never a plaintext
fallback, never ciphertext served as data.

**This is not yet wired to an operator-facing check.** §2.6's run preflight
is where a missing or invalid vault key belongs — a run should not be
startable (and a gamemaster-enabled run already must resolve a reachable
provider there, by the same section) without a vault an operator can
actually use. That wiring is M3's (provisioning); this module only raises
when something actually calls it.

`store_vault_value` does not commit, for the same reason `services.ledger.
append_entry` does not (see that module's docstring): data-model.md §6 lists
reward-value generation as part of M3's atomic solve/provisioning
transaction ("generating any of this team's produced reward values that do
not exist yet ... commit together or not at all"). A function that commits
its own transaction cannot be composed into that one, so this flushes only
and the caller owns the commit.

Run/definition coherence (§6: "every row joining a team with a challenge —
`team_challenge`, `ai_conversation`, `score_entry.challenge_id`, and
`vault_entry` via its `reward_definition` — joins a team of run R with a
challenge of R's definition") names `vault_entry` explicitly, so
`store_vault_value` checks both halves the same way `services.ledger.
append_entry` checks them for `score_entry`: the team must belong to the
given run, and the reward definition's producing challenge must resolve
against the run's own `event_definition_id` (via `services.invariants.
resolve_challenge_for_definition`) rather than being trusted bare.

Logs carry `key_version` only (§7) — never key material, never a plaintext
or decrypted value.
"""

import logging
import os
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.orm import Session

from gameframework.config import Settings
from gameframework.db.models.authoring import RewardDefinition
from gameframework.db.models.play import VaultEntry
from gameframework.db.models.runs import EventRun, Team
from gameframework.services.invariants import resolve_challenge_for_definition

_logger = logging.getLogger(__name__)

_VERSION_SIZE = 1
_NONCE_SIZE = 12
_TAG_SIZE = 16
_MIN_ENVELOPE_SIZE = _VERSION_SIZE + _NONCE_SIZE + _TAG_SIZE


class VaultUnavailableError(Exception):
    """No vault key is configured (`Settings.vault_key is None`). Reserved
    strictly for "not configured" — a present-but-invalid `GF_VAULT_KEY` is
    a `pydantic.ValidationError` at `Settings` construction instead
    (config.py), and a malformed stored envelope is `VaultEnvelopeError`
    below.
    """


class VaultEnvelopeError(Exception):
    """The stored envelope is malformed: shorter than the minimum possible
    size, or carries `key_version` 0. Distinct from `VaultAuthenticationError`
    below because the two are different diagnoses an operator acts on
    differently — a malformed envelope is corrupted or foreign data; a
    failed authentication is a wrong key, or a ciphertext moved to (or
    tampered against) a row it was not encrypted for.
    """


class VaultAuthenticationError(Exception):
    """AES-GCM authentication failed on decrypt. Wraps `cryptography`'s
    `InvalidTag` so callers need not import from `cryptography.exceptions`.
    """


class TeamRunMismatchError(Exception):
    """§6 run/definition coherence, the team half: a vault entry's team
    must belong to the run it is being stored against.
    """


# M2 security gate Task 20, finding: Low. AES-256's own key size — restated
# here rather than imported from config.py's private `_VAULT_KEY_BYTES`,
# since both modules derive it independently from the same external fact
# (the AES-256-GCM spec), not from each other.
_KEY_SIZE = 32


class VaultCrypto:
    """The envelope primitive: `encrypt`/`decrypt` over the layout described
    in the module docstring. `store_vault_value`/`read_vault_value` below
    are the row-level operations built on it.
    """

    def __init__(self, settings: Settings) -> None:
        if settings.vault_key is None:
            raise VaultUnavailableError("no vault key configured (GF_VAULT_KEY unset)")
        self._version, self._key = settings.vault_key
        # M2 security gate Task 20, finding: Low. `Settings`' own validator
        # (config.py's `_parse_vault_key`) is what enforces exactly 32
        # bytes today, but that runs only at `Settings` construction — this
        # module's own docstring states "AES-256-GCM" as a fixed fact, and
        # a fact stated only in a caller's validator is not enforced by the
        # module that depends on it. `cryptography`'s AESGCM constructor
        # accepts any of the three standard AES key sizes (16/24/32 bytes)
        # and would silently encrypt under AES-128-GCM or AES-192-GCM for a
        # 16- or 24-byte key rather than rejecting it — a real gap this
        # closes independently of whatever constructed `settings`.
        if len(self._key) != _KEY_SIZE:
            raise ValueError(
                f"vault key is {len(self._key)} bytes; AES-256-GCM requires exactly {_KEY_SIZE}"
            )

    def encrypt(self, plaintext: bytes, row_pk: uuid.UUID) -> bytes:
        nonce = os.urandom(_NONCE_SIZE)
        ciphertext_and_tag = AESGCM(self._key).encrypt(nonce, plaintext, row_pk.bytes)
        _logger.info("vault encrypt: key_version=%d", self._version)
        return self._version.to_bytes(_VERSION_SIZE, "big") + nonce + ciphertext_and_tag

    def decrypt(self, envelope: bytes, row_pk: uuid.UUID) -> bytes:
        if len(envelope) < _MIN_ENVELOPE_SIZE:
            raise VaultEnvelopeError(
                f"vault envelope is {len(envelope)} bytes, minimum is {_MIN_ENVELOPE_SIZE}"
            )
        version = envelope[0]
        if version == 0:
            raise VaultEnvelopeError("vault envelope carries key_version 0, which is never written")
        nonce = envelope[_VERSION_SIZE : _VERSION_SIZE + _NONCE_SIZE]
        ciphertext_and_tag = envelope[_VERSION_SIZE + _NONCE_SIZE :]
        _logger.info("vault decrypt: key_version=%d", version)
        try:
            return AESGCM(self._key).decrypt(nonce, ciphertext_and_tag, row_pk.bytes)
        except InvalidTag as exc:
            raise VaultAuthenticationError("vault envelope failed authentication") from exc


def store_vault_value(
    db: Session,
    *,
    run: EventRun,
    team: Team,
    reward_definition: RewardDefinition,
    value: bytes,
    settings: Settings,
) -> VaultEntry:
    """Encrypts `value` and inserts the row. Does not commit (see module
    docstring) — the caller's transaction owns the commit. Fail-closed: with
    no vault key configured, `VaultCrypto(settings)` raises
    `VaultUnavailableError` before the row's id is even generated, so
    nothing is added to the session and nothing is written.
    """
    crypto = VaultCrypto(settings)

    if team.event_run_id != run.id:
        raise TeamRunMismatchError(
            f"team {team.id} belongs to run {team.event_run_id}, not {run.id}"
        )
    resolve_challenge_for_definition(
        db, run.event_definition_id, reward_definition.producer_challenge_id
    )

    row_id = uuid.uuid4()
    encrypted_value = crypto.encrypt(value, row_id)
    entry = VaultEntry(
        id=row_id,
        event_run_id=run.id,
        team_id=team.id,
        reward_definition_id=reward_definition.id,
        encrypted_value=encrypted_value,
    )
    db.add(entry)
    db.flush()
    return entry


def read_vault_value(
    db: Session,
    *,
    team: Team,
    reward_definition: RewardDefinition,
    settings: Settings,
) -> bytes | None:
    """Returns the decrypted value for this team and reward, or `None` if no
    row exists yet. `VaultUnavailableError` if no vault key is configured —
    unconditionally, before the row lookup, and regardless of whether a row
    exists: a caller must be able to tell "the vault is not usable right
    now" apart from "this team legitimately has no value yet", and a `None`
    return in the unavailable case would collapse that distinction silently.
    """
    crypto = VaultCrypto(settings)
    entry = db.execute(
        select(VaultEntry).where(
            VaultEntry.team_id == team.id,
            VaultEntry.reward_definition_id == reward_definition.id,
        )
    ).scalar_one_or_none()
    if entry is None:
        return None
    return crypto.decrypt(entry.encrypted_value, entry.id)
