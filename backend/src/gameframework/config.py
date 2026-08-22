from functools import lru_cache
from pathlib import Path

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


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]  # pydantic-settings fills fields from GF_* env
