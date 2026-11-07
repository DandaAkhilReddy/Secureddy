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
# "" means "follow llm_provider" (and "none" when that is unset too).
AssistantProvider = Literal["", "none", "anthropic", "azure_foundry", "azure_openai"]
DEFAULT_ASSISTANT_ANTHROPIC_MODEL = "claude-sonnet-5-5"


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

    # --- Microsoft (Outlook.com, Hotmail, Microsoft 365) via Graph ---------
    # The Entra app authenticates with a certificate, not a client secret
    # (tenant policy): RS_MICROSOFT_CLIENT_CERT is the PEM bundle (private key
    # + certificate) and RS_MICROSOFT_CERT_THUMBPRINT its SHA-1 thumbprint in
    # hex. The button is shown only when the client id and certificate are set.
    microsoft_client_id: str = ""
    microsoft_client_cert: SecretStr = SecretStr("")
    microsoft_cert_thumbprint: str = ""
    microsoft_redirect_path: str = "/auth/microsoft/callback"
    microsoft_authority: str = "https://login.microsoftonline.com/common"
    graph_poll_seconds: int = 15

    # --- Yahoo ("Sign in with Yahoo"; mail itself uses an app password) ----
    yahoo_client_id: str = ""
    yahoo_client_secret: SecretStr = SecretStr("")
    yahoo_redirect_path: str = "/auth/yahoo/callback"

    # --- IMAP (Yahoo, iCloud, Outlook.com) -------------------------------
    imap_poll_seconds: int = 30

    # --- checking older mail ("backfill") --------------------------------
    # A newly set-up mailbox checks this many days of mail already in it
    # (at most initial_backfill_limit messages) so its first screen is not
    # empty. 0 days turns it off.
    initial_backfill_days: int = 2
    initial_backfill_limit: int = 50
    # Older mail is fetched and checked this many messages per worker cycle,
    # after new mail, so new mail is never kept waiting.
    backfill_batch_size: int = 20
    # A mailbox that fails this many cycles in a row is shown as needing
    # attention; the worker keeps retrying it with a growing pause.
    mailbox_failures_before_error: int = 3
    mailbox_retry_max_seconds: int = 1800

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
    anthropic_model: str = "claude-haiku-5-5"
    anthropic_base_url: str = "https://api.anthropic.com"
    # Keyless Claude: Workload Identity Federation. When the rule, organization
    # and service account ids are all set, the app exchanges a short-lived
    # Microsoft Entra token from its managed identity for a short-lived Claude
    # token (core.anthropic_auth) and RS_ANTHROPIC_API_KEY is not needed. These
    # are identifiers, not secrets. See docs/claude-keyless-setup.md.
    anthropic_federation_rule_id: str = ""  # fdrl_...
    anthropic_organization_id: str = ""  # organization UUID
    anthropic_service_account_id: str = ""  # svac_...
    anthropic_workspace_id: str = ""  # wrkspc_... (needed when the rule covers several workspaces)
    anthropic_wif_audience: str = ""  # api://<Entra app id> the managed identity asks a token for
    # Client id of the user-assigned managed identity (Container Apps). Empty =
    # the system-assigned identity.
    azure_identity_client_id: str = ""
    azure_foundry_endpoint: str = ""  # https://<resource>.services.ai.azure.com
    azure_foundry_api_key: SecretStr = SecretStr("")
    azure_foundry_model: str = ""
    azure_openai_endpoint: str = ""
    azure_openai_api_key: SecretStr = SecretStr("")
    azure_openai_deployment: str = ""

    # --- "Ask Secureddy" in-app assistant ---------------------------------
    # Reuses the keys above. Empty provider = follow llm_provider. The model
    # defaults per provider: claude-sonnet-5-5 for Anthropic, the Foundry model
    # or the Azure OpenAI deployment otherwise.
    assistant_provider: AssistantProvider = ""
    assistant_model: str = ""
    assistant_max_turns: int = 6  # tool rounds per question
    assistant_daily_message_limit: int = 200  # questions per user per UTC day
    # "Let the assistant read this email": at most this much plain text of one
    # email is sent, only after the person clicks the button for that email.
    assistant_read_email_max_chars: int = 6000

    # --- signed-in devices and app lock ----------------------------------
    # A device stays signed in until the person signs out: the session slides
    # forward with use and ends after this many idle days, or this many days
    # after sign-in whatever happens.
    session_idle_days: int = 90
    session_absolute_days: int = 365

    # --- reading mail inside Secureddy ----------------------------------
    # "Load images" fetches remote images through our server, at most this big.
    image_proxy_max_bytes: int = 5 * 1024 * 1024
    # "Search inside emails" asks each provider and waits at most this long.
    live_search_timeout_s: float = 8.0

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

    # --- who may open an account (free, invite-only) ----------------------
    # Secureddy is free and for a handful of people. "invite_only": a sign-in
    # that would create an account needs an open invite for that verified
    # email (Admin -> People, or `reddysec invite`) and a free place below
    # max_users. "open": anyone may sign up (self-hosters), still capped at
    # max_users. People who already have an account are never locked out.
    max_users: int = 5
    signup_mode: Literal["invite_only", "open"] = "invite_only"
    # While no account is an admin, the account with this email becomes one
    # (at sign-in, and by the startup migration for an existing account).
    bootstrap_admin_email: str = ""

    # --- development conveniences ---------------------------------------
    dev_login_enabled: bool = Field(default=False, description="Allow password-less dev sign-in. Never in prod.")

    @property
    def google_redirect_uri(self) -> str:
        return self.base_url.rstrip("/") + self.google_redirect_path

    @property
    def microsoft_redirect_uri(self) -> str:
        return self.base_url.rstrip("/") + self.microsoft_redirect_path

    @property
    def yahoo_redirect_uri(self) -> str:
        return self.base_url.rstrip("/") + self.yahoo_redirect_path

    @property
    def microsoft_enabled(self) -> bool:
        return bool(self.microsoft_client_id and self.microsoft_client_cert.get_secret_value())

    @property
    def yahoo_enabled(self) -> bool:
        return bool(self.yahoo_client_id and self.yahoo_client_secret.get_secret_value())

    @property
    def effective_assistant_provider(self) -> str:
        """The assistant's provider after following ``llm_provider`` when unset."""
        if self.assistant_provider:
            return self.assistant_provider
        provider = self.llm_provider
        return "azure_openai" if provider == "openai" else provider

    @property
    def effective_assistant_model(self) -> str:
        if self.assistant_model:
            return self.assistant_model
        return {
            "anthropic": DEFAULT_ASSISTANT_ANTHROPIC_MODEL,
            "azure_foundry": self.azure_foundry_model,
            "azure_openai": self.azure_openai_deployment,
        }.get(self.effective_assistant_provider, "")

    @property
    def anthropic_wif_enabled(self) -> bool:
        """Keyless Claude is on when its three required ids are set."""
        return bool(
            self.anthropic_federation_rule_id and self.anthropic_organization_id and self.anthropic_service_account_id
        )

    @property
    def anthropic_configured(self) -> bool:
        return self.anthropic_wif_enabled or bool(self.anthropic_api_key.get_secret_value())

    @property
    def is_prod(self) -> bool:
        return self.env == "prod"

    def __repr_args__(self):  # type: ignore[override]
        """``repr(settings)`` (tracebacks, debuggers, a stray print) shows every
        secret as ``**********`` (SecretStr) and masks credentials embedded in
        URLs, such as a database password."""
        from reddysec.core.redact import MASK, is_secret_key, redact_text

        for name, value in super().__repr_args__():
            if isinstance(value, str) and name and is_secret_key(name):
                yield name, (MASK if value else value)
            elif isinstance(value, str):
                yield name, redact_text(value)
            else:
                yield name, value


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    """Tests call this after changing environment variables."""
    get_settings.cache_clear()
