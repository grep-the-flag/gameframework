from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GF_")

    database_url: str
    frontend_origin: str
    data_dir: Path
    cookie_domain: str


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]  # pydantic-settings fills fields from GF_* env
