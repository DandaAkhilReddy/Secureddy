"""Chamber contracts: detonation jobs/results and Reading Room sessions.

Rule: nothing in a DetonationJob identifies the client. A detonation must look
like an anonymous visitor, so an attacker who controls the page learns nothing
about who we protect.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field


class DetonationKind(str, Enum):
    URL = "url"
    FILE = "file"


class DetonationProfile(BaseModel):
    user_agent: str | None = None  # None -> backend default (a current desktop Chrome)
    locale: str = "en-US"
    timezone: str = "America/Los_Angeles"
    viewport_width: int = 1366
    viewport_height: int = 768
    referer: str | None = None
    # Simulate a human: small scroll, mouse movement, short dwell. Defeats the
    # cheapest "is this a bot" checks used by phishing kits.
    interact: bool = True
    max_wait_ms: int = 15000


class DetonationJob(BaseModel):
    job_id: str
    kind: DetonationKind
    url: str | None = None
    file_ref: str | None = None  # artifact-store reference (see core.artifacts)
    file_name: str | None = None
    timeout_s: int = 45
    profile: DetonationProfile = Field(default_factory=DetonationProfile)


class RedirectHop(BaseModel):
    url: str
    status: int | None = None
    kind: Literal["http", "js", "meta", "client", "unknown"] = "http"


class NetworkRequest(BaseModel):
    url: str
    host: str
    resource_type: str = ""
    status: int | None = None
    is_third_party: bool = False


class DownloadRecord(BaseModel):
    suggested_filename: str
    sha256: str
    size: int
    sniffed_type: str | None = None
    stored_ref: str | None = None
    safe_copy_ref: str | None = None


class FormRecord(BaseModel):
    action_url: str | None = None
    action_host: str | None = None
    has_password: bool = False
    has_identity_field: bool = False  # email / username / phone
    field_names: list[str] = Field(default_factory=list)


class PageFeatures(BaseModel):
    title: str | None = None
    final_url: str | None = None
    final_host: str | None = None
    forms: list[FormRecord] = Field(default_factory=list)
    has_password_field: bool = False
    external_form_action: bool = False
    brand_keywords: list[str] = Field(default_factory=list)
    meta_refresh: bool = False
    js_redirect: bool = False
    obfuscated_js_score: int = 0  # 0..100
    iframe_count: int = 0
    hidden_text_ratio: float = 0.0
    text_excerpt: str = ""
    qr_codes: list[str] = Field(default_factory=list)
    captcha_detected: bool = False
    automation_blocked_hint: bool = False
    status_code: int | None = None


class DetonationStatus(str, Enum):
    OK = "ok"
    TIMEOUT = "timeout"
    ERROR = "error"
    BLOCKED = "blocked"  # sandbox refused (private address, unsupported scheme, ...)


class DetonationResult(BaseModel):
    job_id: str
    status: DetonationStatus
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    duration_ms: int = 0
    redirects: list[RedirectHop] = Field(default_factory=list)
    requests: list[NetworkRequest] = Field(default_factory=list)
    features: PageFeatures | None = None
    downloads: list[DownloadRecord] = Field(default_factory=list)
    screenshot_ref: str | None = None
    console_errors: list[str] = Field(default_factory=list)
    error: str | None = None
    sandbox_backend: str = ""

    @property
    def final_host(self) -> str | None:
        return self.features.final_host if self.features else None


@runtime_checkable
class Detonator(Protocol):
    """Implemented by chamber.backends; faked in analysis tests."""

    async def detonate(self, job: DetonationJob) -> DetonationResult: ...


class RoomState(str, Enum):
    STARTING = "starting"
    READY = "ready"
    CLOSED = "closed"
    ERROR = "error"


class ReadingRoomSession(BaseModel):
    session_id: str
    principal_id: str
    url: str
    state: RoomState = RoomState.STARTING
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_activity_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    viewport_width: int = 1280
    viewport_height: int = 800
    downloads: list[DownloadRecord] = Field(default_factory=list)
    current_url: str | None = None
    error: str | None = None
