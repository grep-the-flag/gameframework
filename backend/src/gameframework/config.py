import base64
import binascii
import re
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, NamedTuple, cast

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

_TCP_PORT_RANGE_RE = re.compile(r"^(\d+)-(\d+)$")
_VAULT_KEY_RE = re.compile(r"^(\d+):(.+)$")
# data-model.md §7: AES-256-GCM. M2-Task-Plan.md Task 17: the envelope's
# key_version occupies exactly 1 byte, so a configured version above 255
# would overflow it at the first encrypt() rather than at startup.
_VAULT_KEY_BYTES = 32
_VAULT_KEY_MAX_VERSION = 255


class VaultKey(NamedTuple):
    """The parsed `GF_VAULT_KEY` (M2-Task-Plan.md Task 17). Version and key
    material travel as one string, `<version>:<base64-key>`, never as two
    independent settings: two values that must agree but can be edited
    separately are a divergence on a timer — an operator rotating the key
    and forgetting the version, or the reverse — and in M2 nothing would
    catch it, since only one key is ever configured at a time and AES-GCM's
    tag only catches a *wrong* key, not a *mislabeled* one.
    """

    version: int
    key: bytes


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GF_", hide_input_in_errors=True)

    database_url: str
    frontend_origin: str
    data_dir: Path
    cookie_domain: str
    # ADR-0007 "Failed authentication is answered per source address" rule
    # 1: CIDR blocks the proxy in front of this installation is reached
    # through. Defaults empty — an installation that configures none
    # counts every request against its own socket peer, the fail-closed
    # reading for a framework reached directly, never a plausible-looking
    # wrong one. No `.env.example`/compose guard: unlike `frontend_origin`,
    # `data_dir` and `cookie_domain`, there is no value an operator must
    # set before the installation runs correctly.
    trusted_proxies: list[str] = []
    # data-model.md §3.3 `blocked_address.expires_at`: how long a source
    # stays blocked once it crosses five consecutive failures.
    block_window_minutes: int = 15
    # data-model.md §3.26 / M2-Task-Plan.md Task 9: the operator drop-in
    # directory, "in the data volume". Unlike `data_dir`, `frontend_origin`
    # and `cookie_domain` this takes a default rather than refusing one: it
    # derives from a setting that is already required, and Task 3's compose
    # volume interpolates its mount target from that same setting, so
    # anything under it sits inside the persistent volume by construction.
    # A separate required variable would reintroduce exactly the mismatch
    # that closes — an operator typing a path outside the volume, whose
    # dropped artifacts vanish on the next recreate. Stays overridable for
    # an installation mounting an artifact share elsewhere.
    dropin_dir: Path
    # M2-Task-Plan.md Task 10 / sdk-contract-v1.md §3.4 check 14: labels this
    # installation has put a framework surface on, beyond the contract's own
    # floor. `gameframework_sdk.validation.RESERVED_HOST_LABELS` (currently
    # {"callback"}) is refused by validate_event with or without a
    # caller-supplied list — it is the SDK's own floor, not this
    # installation's configuration — so a required variable here would make
    # an operator restate a floor they cannot lower. Unlike `data_dir`,
    # `frontend_origin` and `cookie_domain`, there is no wrong-but-plausible
    # value to guess: an installation that names none has, correctly, put no
    # framework surface under the event domain beyond the callback ingress
    # (true by construction — M2 ships no frontend), so it earns no
    # `.env.example`/compose guard either, exactly like `trusted_proxies`.
    # `NoDecode` opts this field out of pydantic-settings' default JSON
    # parsing for complex types: `GF_RESERVED_HOST_LABELS=` would otherwise
    # fail `json.loads("")` instead of reading as "no labels" (an empty
    # environment variable is a value, not an absence) — the validator below
    # parses the comma-separated form `.env.example` documents instead.
    reserved_host_labels: Annotated[list[str], NoDecode] = []
    # M2-Task-Plan.md Task 13: the operator-facing address a minigame's TCP
    # tier is reachable on — what `{{minigame.port}}`'s sibling placeholder
    # `{{minigame.host}}` renders (data-model.md §3.16), and part of the
    # preflight config hash. Refuses a default, in the same class as
    # `frontend_origin`/`data_dir`/`cookie_domain`: a wrong-but-plausible
    # value here looks like a working deployment from inside the
    # installation and is not — the preflight has no way to tell a real
    # reachable host from a typo, so a guessed default would pass every
    # check and hand players an address nothing answers on.
    player_tcp_host: str
    # M2-Task-Plan.md Task 13, data-model.md §3.15: the domain a minigame's
    # HTTP tier publishes under, `<host_label>.<event_domain>` — the same
    # wildcard DNS entry and certificate ADR-0007 already requires for
    # `cookie_domain`, so no new infrastructure is needed, but the two are
    # separate settings because they scope two different things (a cookie
    # vs. an instance hostname) even where an operator types the same
    # string into both. Refuses a default for the same silent-failure
    # reason as `cookie_domain`: every minigame would publish under a
    # hostname nothing serves, and nothing inside the installation can
    # detect that.
    event_domain: str
    # M2-Task-Plan.md Task 13, sdk-contract-v1.md §4.1: the range the
    # framework allocates published TCP entrypoints from. Required, but
    # *not* for the silent-failure reason above — a range that is too
    # small does not fail quietly: the run preflight refuses it loudly,
    # naming the size it would need (api-surface.md §2.6). The reason is
    # operational instead: an operator who never chose a range has opened
    # no firewall rule for it, and a range colliding with something else
    # already bound on the host surfaces at bind time in the proxy (M3),
    # not here — a default would let the installation look configured
    # before either question has actually been answered. `NoDecode` for
    # the same reason as `reserved_host_labels` above: this is a tuple,
    # not a JSON-decodable scalar, and `.env.example` documents the
    # `start-end` form the validator below parses (e.g. "20000-29999");
    # a malformed value — missing dash, non-numeric, a bound outside
    # 1-65535, or start > end — is refused at startup rather than
    # silently coerced, and so is the blank form (`GF_TCP_PORT_RANGE=`),
    # which is a value and not an absence.
    tcp_port_range: Annotated[tuple[int, int], NoDecode]
    # M2-Task-Plan.md Task 17, data-model.md §7 / ADR-0010: the vault's
    # installation key, from the deployment's secret mechanism. Deliberately
    # NOT in the no-default family with `data_dir`/`frontend_origin`/
    # `cookie_domain`/`player_tcp_host`/`event_domain`: §7's failure
    # behavior ("a missing key fails closed: provisioning reports the vault
    # as unavailable") describes something that happens when the vault is
    # *used*, not when the app boots, and a required field would refuse to
    # start an installation that has not configured the vault yet — a
    # stronger claim than §7 makes. `services.vault.VaultUnavailableError`
    # is the boundary that actually enforces "missing"; the run preflight
    # (§2.6) is where that becomes an operator-facing readiness check
    # (M3's wiring, not this task's). A blank value (`GF_VAULT_KEY=`, the
    # line an operator uncomments and leaves empty) is treated the same as
    # absent, matching `reserved_host_labels` above, not as a malformed
    # value to reject. `repr=False`: unlike every other field here, this
    # one holds key material and must never render — see
    # `services/vault.py` for why logs carry `key_version` only.
    vault_key: Annotated[VaultKey | None, Field(repr=False)] = None

    @field_validator("vault_key", mode="before")
    @classmethod
    def _parse_vault_key(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        if value == "":
            return None
        match = _VAULT_KEY_RE.match(value)
        if match is None:
            raise ValueError("GF_VAULT_KEY must be '<version>:<base64-key>', e.g. '1:...'")
        version = int(match.group(1))
        if not (1 <= version <= _VAULT_KEY_MAX_VERSION):
            raise ValueError(f"GF_VAULT_KEY version must be 1-{_VAULT_KEY_MAX_VERSION}")
        try:
            key_bytes = base64.b64decode(match.group(2), validate=True)
        except binascii.Error as exc:
            raise ValueError("GF_VAULT_KEY key segment is not valid base64") from exc
        if len(key_bytes) != _VAULT_KEY_BYTES:
            raise ValueError(
                f"GF_VAULT_KEY must decode to a {_VAULT_KEY_BYTES}-byte AES-256 key, "
                f"got {len(key_bytes)} bytes"
            )
        return VaultKey(version=version, key=key_bytes)

    @field_validator("reserved_host_labels", mode="before")
    @classmethod
    def _parse_reserved_host_labels(cls, value: Any) -> Any:
        if isinstance(value, str):
            return [label.strip() for label in value.split(",") if label.strip()]
        return value

    @field_validator("tcp_port_range", mode="before")
    @classmethod
    def _parse_tcp_port_range(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        match = _TCP_PORT_RANGE_RE.match(value)
        if match is None:
            raise ValueError("GF_TCP_PORT_RANGE must be 'start-end', e.g. '20000-29999'")
        start, end = int(match.group(1)), int(match.group(2))
        if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
            raise ValueError("GF_TCP_PORT_RANGE bounds must be 1-65535 with start <= end")
        return (start, end)

    @model_validator(mode="before")
    @classmethod
    def _default_dropin_dir(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        values = cast(dict[str, Any], data)
        if not values.get("dropin_dir") and values.get("data_dir") is not None:
            values["dropin_dir"] = Path(values["data_dir"]) / "dropin"
        return values


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]  # pydantic-settings fills fields from GF_* env
