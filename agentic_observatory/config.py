from __future__ import annotations

from functools import lru_cache

from pydantic import AnyHttpUrl, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OBSERVATORY_", env_file=".env", extra="ignore")

    environment: str = "production"
    base_url: str = "https://observatory.servify.network"
    host: str = "127.0.0.1"
    port: int = 8780

    session_secret: str = Field(default="dev-session-secret-change-me", min_length=16)
    csrf_secret: str = Field(default="dev-csrf-secret-change-me", min_length=16)
    operator_username: str = "operator"
    operator_password_hash: str = ""
    session_ttl_seconds: int = 12 * 60 * 60

    database_url: str = "sqlite+aiosqlite:///./observatory.db"

    collector_base_url: AnyHttpUrl | None = None
    noc_base_url: AnyHttpUrl | None = None
    noc_loop_console_secret: str = ""
    github_token: str = ""

    actions_enabled: bool = False
    read_only: bool = True
    request_timeout_seconds: float = 10.0

    @property
    def noc_actions_available(self) -> bool:
        return bool(self.noc_base_url and self.noc_loop_console_secret)


@lru_cache
def get_settings() -> Settings:
    return Settings()
