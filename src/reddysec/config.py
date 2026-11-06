"""Runtime configuration.

All settings come from environment variables prefixed ``RS_`` (or a ``.env``
file in development). Nothing here is secret by default; production values
are injected from Azure Key Vault by the deployment (see infra/azure).
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

SandboxBackendName = Literal["local", "docker", "aci"]
LlmProvider = Literal["none", "anthropic", "azure_foundry", "azure_openai", "openai"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="RS_", env_file=".env", extra="ignore")

    # --- deployment -----------------------------------------------------
    env: Literal["dev", "test", "staging", "prod"] = "dev"
    base_url: str = "http://localhost:8000"
    log_level: str = "INFO"

    # --- secrets --------------------------------------------------------
    secret_key: SecretStr = SecretStr("dev-only-secret-change-me")
    # 32 random bytes, base64. Empty in dev -> derived from secret_key.
    token_kek: SecretStr = SecretStr("")
    # During a key rotation the previous KEK stays readable until every stored
    # credential has been re-encrypted (see core.crypto.TokenCipher.needs_rotation).
    token_kek_previous: SecretStr = SecretStr("")
    # Shared secret the Gmail Pub/Sub push subscription presents as ?token=.
    pubsub_token: SecretStr = SecretStr("")

    # --- storage --------------------------------------------------------
    database_url: str = "sqlite+aiosqlite:///./var/reddysec.db"
    artifacts_dir: str = "./var/artifacts"
    # Azure Blob Storage for artifacts. Empty -> local directory above.
    storage_account_url: str = ""  # https://<account>.blob.core.windows.net
    artifacts_container: str = "artifacts"

    # --- Google / Gmail --------------------------------------------------
    google_client_id: str = ""
    google_client_secret: SecretStr = SecretStr("")
    google_redirect_path: str = "/auth/google/callback"
    # Optional: Pub/Sub topic for gmail.users.watch push. Empty -> polling.
    google_pubsub_topic: str = ""
    gmail_poll_seconds: int = 15

    # --- IMAP (Yahoo, iCloud, Outlook.com) -------------------------------
    imap_poll_seconds: int = 30

    # --- analysis -------------------------------------------------------
    sandbox_backend: SandboxBackendName = "local"
    detonation_timeout_s: int = 45
    detonation_max_concurrency: int = 2
    safe_browsing_api_key: SecretStr = SecretStr("")
    intel_online: bool = False  # tests stay offline; prod turns this on
    # Second-opinion language model for wire-fraud intent and plain summaries.
    # "anthropic" = Claude via the Messages API; "azure_foundry" = any model on
    # an Azure AI Foundry inference endpoint; "azure_openai" = an Azure OpenAI
    # deployment. None of them is ever the only reason for a verdict.
    llm_provider: LlmProvider = "none"
    anthropic_api_key: SecretStr = SecretStr("")
    anthropic_model: str = "claude-haiku-4-5"
    azure_foundry_endpoint: str = ""  # https://<resource>.services.ai.azure.com
    azure_foundry_api_key: SecretStr = SecretStr("")
    azure_foundry_model: str = ""
    azure_openai_endpoint: str = ""
    azure_openai_api_key: SecretStr = SecretStr("")
    azure_openai_deployment: str = ""

    # --- hold mode safety ------------------------------------------------
    # If the pipeline has not heart-beaten for this long, release all held mail.
    hold_dead_man_minutes: int = 10
    hold_timeout_s: int = 120

    # --- reading room ----------------------------------------------------
    reading_room_idle_timeout_s: int = 300
    reading_room_max_sessions: int = 10

    # --- notifications ---------------------------------------------------
    notification_from: str = "alerts@secureddy.local"
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: SecretStr = SecretStr("")
    notify_webhook_url: str = ""  # optional generic webhook (SMS/push bridge)

    # --- development conveniences ---------------------------------------
    dev_login_enabled: bool = Field(default=False, description="Allow password-less dev sign-in. Never in prod.")

    @property
    def google_redirect_uri(self) -> str:
        return self.base_url.rstrip("/") + self.google_redirect_path

    @property
    def is_prod(self) -> bool:
        return self.env == "prod"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    """Tests call this after changing environment variables."""
    get_settings.cache_clear()
