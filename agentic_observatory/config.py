from __future__ import annotations

from functools import lru_cache

from pydantic import AnyHttpUrl, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Write actions the observatory can proxy to the NOC loop-console API. The
# operator opts in to each one via OBSERVATORY_ENABLED_ACTIONS, so low-risk
# actions (feedback, ack) can go live while higher-impact ones (suppress, …)
# stay gated until a later rollout stage.
KNOWN_ACTIONS: frozenset[str] = frozenset(
    {"feedback", "ack", "suppress", "artifact_review", "verification_result", "insight_label"}
)


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
    # Bearer token for collector ingest (insight_label writes). Must match the
    # collector's HYRULE_COLLECTOR_INGEST_TOKEN; labels drive gate relaxation,
    # so enable the token before enabling the insight_label action.
    collector_ingest_token: str = ""
    noc_base_url: AnyHttpUrl | None = None
    noc_loop_console_secret: str = ""
    github_token: str = ""
    knowledge_export_db_path: str = "/opt/knowledge/exports/knowledge.sqlite"
    # Standalone Knowledge read API (insight metrics + concepts). Read-only.
    knowledge_api_base_url: AnyHttpUrl | None = None
    # "Sync now" dispatches this workflow_dispatch — the durable ledger sync
    # runs as a reviewed PR, never an ad-hoc write from the console.
    insight_sync_workflow_repo: str = "AS215932/knowledge"
    insight_sync_workflow_file: str = "insight-sync.yml"
    insight_sync_workflow_ref: str = "main"

    actions_enabled: bool = False
    read_only: bool = True
    # Comma-separated allowlist of actions permitted when the write subsystem
    # is on, e.g. "feedback,ack". Empty means no action is permitted even when
    # actions_enabled is true (deny-by-default for staged rollout).
    enabled_actions: str = ""
    request_timeout_seconds: float = 10.0
    live_case_max_age_hours: float = 24.0

    @property
    def noc_actions_available(self) -> bool:
        return bool(self.noc_base_url and self.noc_loop_console_secret)

    @property
    def enabled_action_set(self) -> frozenset[str]:
        names = {token.strip().lower() for token in self.enabled_actions.split(",")}
        return frozenset(names & KNOWN_ACTIONS)

    def allowed_actions(self) -> frozenset[str]:
        """Actions currently permitted, after the master write gate."""
        if self.read_only or not self.actions_enabled:
            return frozenset()
        return self.enabled_action_set

    def action_allowed(self, action: str) -> bool:
        return action in self.allowed_actions()


@lru_cache
def get_settings() -> Settings:
    return Settings()
