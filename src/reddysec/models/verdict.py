"""Verdict contracts: what the analysis engine says about a message."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field

# Score bands. The engine produces 0..100; these cut it into a verdict.
SUSPICIOUS_THRESHOLD = 35
MALICIOUS_THRESHOLD = 70


class VerdictLevel(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"  # analysis failed or timed out; policy decides what to do

    @property
    def rank(self) -> int:
        return {"safe": 0, "unknown": 1, "suspicious": 2, "malicious": 3}[self.value]


def level_for_score(score: int) -> VerdictLevel:
    if score >= MALICIOUS_THRESHOLD:
        return VerdictLevel.MALICIOUS
    if score >= SUSPICIOUS_THRESHOLD:
        return VerdictLevel.SUSPICIOUS
    return VerdictLevel.SAFE


class TriageLane(str, Enum):
    RELEASE_FAST = "release_fast"  # no links, no attachments: static checks only
    TRUSTED = "trusted"  # known-good sender, authenticated, clean static pass
    DETONATE = "detonate"  # unknown links/attachments: full dynamic analysis
    BLOCK = "block"  # static evidence already conclusive


class SignalStage(str, Enum):
    STATIC = "static"
    INTEL = "intel"
    DYNAMIC = "dynamic"
    BEC = "bec"
    HISTORY = "history"


class Signal(BaseModel):
    """One piece of evidence. ``code`` is stable and machine-readable
    (e.g. ``url.new_domain``); ``title`` is what the client reads."""

    code: str
    stage: SignalStage
    weight: int = Field(ge=-60, le=100)  # negative weights express trust
    title: str = Field(max_length=120)
    detail: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)


ClickAdvice = Literal["safe_to_open", "open_in_reading_room", "do_not_open"]


class DownloadInfo(BaseModel):
    """What opening a link downloaded, in words the client can act on."""

    filename: str
    sha256: str = ""
    size: int = 0
    file_type: str = ""  # sniffed content type tag (pe, zip, iso9660, lnk, ...)
    category: str = "other"  # program, script, installer, archive, password_archive, disk_image, shortcut, document, other
    dangerous: bool = False
    why: str = ""


class UrlVerdict(BaseModel):
    url: str
    level: VerdictLevel
    score: int = Field(ge=0, le=100)
    signals: list[Signal] = Field(default_factory=list)
    final_url: str | None = None
    screenshot_ref: str | None = None
    detonation_job_id: str | None = None
    detonated: bool = False
    # Per-link "is it safe to click?" (analysis.click_advice). Optional and
    # additive: verdicts written before these fields existed leave them empty.
    click_advice: ClickAdvice | None = None
    click_advice_reason: str = ""
    downloads_summary: list[DownloadInfo] = Field(default_factory=list)
    # Wrappers and redirects the link hides behind, outermost first, ending
    # at the address we analysed (open redirects, Safe Links, shorteners).
    redirect_chain: list[str] = Field(default_factory=list)


class AttachmentVerdict(BaseModel):
    filename: str
    sha256: str
    level: VerdictLevel
    score: int = Field(ge=0, le=100)
    signals: list[Signal] = Field(default_factory=list)
    safe_copy_ref: str | None = None  # CDR output (flattened PDF) if produced
    detonation_job_id: str | None = None


TrustOutcome = Literal["confirmed", "changed", "incomplete"]


class TrustCheck(BaseModel):
    """How a message from a sender the client (or policy) trusts fared.

    Trust never skips the checks: mail from a sender the client marked safe is
    still analysed in full, links included. ``outcome`` says what we found:

    * ``confirmed``  the new check is clean; the report says "Confirmed again".
    * ``changed``    something serious turned up; the report and a notification
                     say "This sender is on your trusted list, but this email
                     looks different".
    * ``incomplete`` we could not finish checking it (a sandbox timeout), so
                     we neither confirm nor accuse.

    ``scope``/``value`` name the trusted entry that matched (``domain`` +
    ``walmart.com`` or ``address`` + ``ana@example.com``); ``reason`` is the
    client's own reason in words, when they gave one.
    """

    trusted_by_client: bool
    reason: str = ""
    outcome: TrustOutcome
    scope: str = ""
    value: str = ""


class Verdict(BaseModel):
    level: VerdictLevel
    score: int = Field(ge=0, le=100)
    summary: str  # one or two plain sentences written for the client
    lane: TriageLane
    signals: list[Signal] = Field(default_factory=list)
    urls: list[UrlVerdict] = Field(default_factory=list)
    attachments: list[AttachmentVerdict] = Field(default_factory=list)
    needs_human_review: bool = False
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    duration_ms: int = 0
    engine_version: str = ""
    # What we could verify about the sender (analysis.trust). The web app uses
    # it to decide what "This is safe" may trust: a verified domain, or only
    # one address. Empty for verdicts written before these fields existed.
    verified_domain: str = ""
    bulk_sender: bool = False
    # Set when the sender is trusted (by the client or by policy). See TrustCheck.
    trust_check: TrustCheck | None = None
    # "Links: 2 safe · 1 open only in Reading Room · 1 do not open" and the
    # counts behind it (keys: the ClickAdvice values). Empty without links.
    links_summary: str = ""
    link_advice_counts: dict[str, int] = Field(default_factory=dict)

    @property
    def top_signals(self) -> list[Signal]:
        return sorted(self.signals, key=lambda s: -s.weight)[:5]
