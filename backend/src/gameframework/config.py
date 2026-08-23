from functools import lru_cache
from pathlib import Path
from typing import Any, cast

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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
