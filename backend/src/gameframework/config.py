import re
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, cast

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

_TCP_PORT_RANGE_RE = re.compile(r"^(\d+)-(\d+)$")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GF_")

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
