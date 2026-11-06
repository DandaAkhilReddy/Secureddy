"""Business email compromise (BEC) and wire-fraud heuristics.

BEC mail has no malware and often no link: it is a plain request from
"your lawyer" or "the CEO" to move money, buy gift cards or change payroll
details. For a wealthy private client this is the attack most likely to
cost real money, so these checks run on every message, including the ones
the fast lane releases without detonation.

Two layers:

* Pattern heuristics (:func:`bec_signals`) that are deterministic, explainable
  and free.
* An optional LLM assessment (:class:`LlmAssessor`) that reads the message the
  way a sceptical assistant would. It only ever *adds* a bounded signal and a
  plain-English summary; it can never make a message safe.
"""

from __future__ import annotations

import json
import re
from typing import Any, Protocol, runtime_checkable

import httpx
from pydantic import BaseModel, Field, ValidationError

from reddysec.core.logging import get_logger
from reddysec.models import ParsedMessage, SenderHistory, Signal, SignalStage

from .common import EMAIL_RE, is_freemail, make_signal, truncate
from .domains import lookalike_analysis
from .intel import is_popular
from .urls import registrable_domain

log = get_logger(__name__)

_PAYMENT_CHANGE_RE = re.compile(
    r"\b(?:new (?:bank|banking|account|wire|wiring|payment|remittance) (?:details|information|instructions|account)|"
    r"updated? (?:wire|wiring|banking|bank|payment|remittance|ach) (?:instructions|details|information)|"
    r"(?:bank|account|routing|wire) (?:details|information|instructions|number) (?:has|have) (?:been )?(?:changed|updated)|"
    r"change(?:d|s)? (?:of |to |in )?(?:our |the |my )?(?:bank|banking|payment|wire|wiring|remittance) (?:account|details|instructions|information)|"
    r"new (?:beneficiary|payee)|(?:update|change) (?:the |our |your )?(?:payee|beneficiary|vendor) (?:details|information|record)|"
    r"remit(?:tance)? (?:all |future |the )?(?:payments? )?to (?:the following|our new|this|the new))\b",
    re.IGNORECASE,
)
# Bank-detail nouns are ordinary in statements; they only matter next to a change word.
_BANK_DETAIL_RE = re.compile(r"\b(?:routing number|account number|iban|swift(?: code)?|bic code|sort code|beneficiary)\b", re.I)
_CHANGE_WORD_RE = re.compile(r"\b(?:new|updated?|changed?|revised|different|replace(?:d|s)?|switch(?:ed)?|instead|no longer)\b", re.I)
_WIRE_CONTEXT_RE = re.compile(
    r"\b(?:wire transfer|wire|ach(?: transfer)?|escrow|closing (?:funds|costs|date|statement)|title company|"
    r"settlement statement|earnest money|down payment|closing disclosure|funds? transfer|bank transfer)\b",
    re.IGNORECASE,
)
_GIFT_CARD_RE = re.compile(
    r"\b(?:gift ?cards?|e-?gift|(?:apple|itunes|google play|steam|ebay|amazon|visa|vanilla|target|walmart|sephora|xbox|"
    r"playstation|razer gold|roblox) ?(?:gift )?cards?|scratch (?:off )?the (?:back|code|pin)|"
    r"send (?:me )?(?:the )?(?:codes?|pins?|pictures? of the cards?)|card (?:codes?|pins?|numbers?))\b",
    re.IGNORECASE,
)
_SECRECY_RE = re.compile(
    r"\b(?:keep (?:this|it) (?:confidential|between us|quiet|private|to yourself)|"
    r"(?:do not|don'?t|dont) (?:tell|mention|share|discuss|inform|involve|let anyone)|between (?:us|you and me)|"
    r"strictly confidential|highly confidential|in (?:strict )?confidence|discreet(?:ly)?|hush|off the record|"
    r"not (?:a word|to anyone))\b",
    re.IGNORECASE,
)
_URGENCY_RE = re.compile(
    r"\b(?:urgent(?:ly)?|asap|as soon as possible|right away|immediately|straight away|within the (?:hour|next hour)|"
    r"before (?:end of (?:the )?day|eod|close of business|cob|noon|5 ?pm|the bank closes)|time[- ]sensitive|"
    r"today(?: itself)?|no later than|deadline|cannot wait|can'?t wait|must be (?:done|sent|completed) today)\b",
    re.IGNORECASE,
)
_EXEC_OPENER_RE = re.compile(
    r"\b(?:are you (?:available|at your desk|in the office|free|around|there)|quick (?:task|favou?r|request|question|one)|"
    r"i need (?:you to|a favou?r|your help|something done)|can you (?:handle|do|take care of|help with) (?:something|a task|this)|"
    r"i'?m (?:in|stuck in|about to go into) (?:a|back to back) meetings?|can'?t talk (?:right )?now|"
    r"(?:reply|respond|answer) (?:by|via|through|over) (?:email|e-mail|text) only|"
    r"(?:text|reach|contact) me (?:on|at) (?:my )?(?:cell|mobile|this number)|do you have a moment|need this done|"
    r"handle (?:this|it) (?:personally|discreetly|quietly)|i am (?:travel+ing|out of (?:the )?office|in a conference))\b",
    re.IGNORECASE,
)
_PAYROLL_RE = re.compile(
    r"\b(?:w-?2s?|w-?4|1099s?|payroll|direct deposit|pay ?stubs?|pay ?checks?|salary (?:account|payment)|"
    r"(?:update|change) my (?:bank|deposit|payroll|banking) (?:account|information|details)|employee (?:records?|list|roster)|"
    r"tax (?:forms?|documents?|statements?))\b",
    re.IGNORECASE,
)
_CHANNEL_SWITCH_RE = re.compile(
    r"\b(?:(?:text|whatsapp|telegram|imessage|call|sms|ping|message) me (?:at|on|via|directly|back on)|"
    r"(?:reach|contact|message|text) me on (?:whatsapp|telegram|signal|my cell|my mobile|my personal)|"
    r"my personal (?:email|e-mail|cell|number|phone|gmail|line)|"
    r"(?:send|forward|reply|respond) (?:it |this |them |back )?to my (?:personal|private|other) (?:email|e-mail|address|number)|"
    r"(?:on|via|through|over) whatsapp|whatsapp (?:me|number)|telegram (?:me|handle))\b",
    re.IGNORECASE,
)
_INVOICE_RE = re.compile(
    r"\b(?:invoice|payment due|overdue|past due|outstanding (?:balance|payment|invoice)|remittance|statement of account|"
    r"purchase order|p\.?o\.? number|amount due|please (?:process|settle|pay))\b",
    re.IGNORECASE,
)
_SIGNATURE_DOMAIN_RE = re.compile(r"(?:https?://)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b", re.IGNORECASE)
_SOCIAL_DOMAINS: frozenset[str] = frozenset(
    {"linkedin.com", "twitter.com", "x.com", "facebook.com", "instagram.com", "youtube.com", "tiktok.com",
     "calendly.com", "zoom.us", "wa.me", "t.me", "bit.ly"}
)
MAX_BODY_FOR_ANALYSIS = 20_000


def _text_for(parsed: ParsedMessage) -> str:
    body = parsed.text_body or ""
    if len(body) > MAX_BODY_FOR_ANALYSIS:
        body = body[:MAX_BODY_FOR_ANALYSIS]
    names = " ".join(a.filename for a in parsed.attachments if not a.is_inline)
    return f"{parsed.subject}\n{body}\n{names}"


def _signature_domains(text: str) -> list[str]:
    """Domains named in the last lines of the body: the signature block."""
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    tail = "\n".join(lines[-15:])
    found: list[str] = []
    for m in EMAIL_RE.finditer(tail):
        rd = registrable_domain(m.group(0).rsplit("@", 1)[-1])
        if rd and rd not in found:
            found.append(rd)
    for m in _SIGNATURE_DOMAIN_RE.finditer(tail):
        host = m.group(1).lower()
        if host.count(".") == 0 or re.fullmatch(r"[\d.]+", host):
            continue
        if not re.search(r"\.(?:com|net|org|law|legal|io|co|us|uk|ca|biz|info|group|llc|inc|partners|cpa|ai|de|fr|in)$", host):
            continue
        rd = registrable_domain(host)
        if rd and rd not in found:
            found.append(rd)
    return found


def _is_first_time(history: SenderHistory | None) -> bool:
    return history is None or history.message_count == 0


def _reply_to_mismatch(parsed: ParsedMessage) -> bool:
    from_rd = registrable_domain(parsed.from_domain) if parsed.from_domain else ""
    return any(registrable_domain(a.rsplit("@", 1)[-1]) != from_rd for a in parsed.reply_to if "@" in a)


def bec_signals(
    parsed: ParsedMessage, history: SenderHistory | None, contact_domains: tuple[str, ...] = ()
) -> list[Signal]:
    """Wire-fraud and impersonation heuristics over subject, body and attachment names."""
    signals: list[Signal] = []
    text = _text_for(parsed)
    first_time = _is_first_time(history)
    reply_mismatch = _reply_to_mismatch(parsed)
    freemail = is_freemail(parsed.from_domain)

    payment = _PAYMENT_CHANGE_RE.findall(text)
    if not payment and _BANK_DETAIL_RE.search(text) and _CHANGE_WORD_RE.search(text):
        payment = [m.group(0) for m in _BANK_DETAIL_RE.finditer(text)]
    if payment:
        weight = 60 if (first_time or reply_mismatch) else 45
        signals.append(
            make_signal(
                "bec.payment_change", SignalStage.BEC, weight,
                "Asks to pay to new or changed bank details",
                "Changing where money goes is how wire fraud works. Confirm by phone on a number you already have.",
                phrases=sorted({p.lower() for p in payment})[:5], first_time_sender=first_time,
                reply_to_mismatch=reply_mismatch,
            )
        )
    elif _WIRE_CONTEXT_RE.search(text) and re.search(r"\b(?:please|kindly|need|must|send|transfer|wire)\b", text, re.I):
        signals.append(
            make_signal(
                "bec.wire_request", SignalStage.BEC, 25,
                "Talks about wiring or transferring money", "Money-movement requests deserve a phone call.",
            )
        )

    gift = _GIFT_CARD_RE.findall(text)
    if gift:
        signals.append(
            make_signal(
                "bec.gift_card", SignalStage.BEC, 50,
                "Asks for gift cards or card codes",
                "No real executive, agency or friend needs gift-card codes by email.",
                phrases=sorted({g.lower() for g in gift})[:5],
            )
        )

    secrecy = _SECRECY_RE.search(text) is not None
    urgency = _URGENCY_RE.search(text) is not None
    if secrecy and urgency:
        signals.append(
            make_signal(
                "bec.urgency_secrecy", SignalStage.BEC, 25,
                "Demands speed and secrecy at the same time",
                "Scammers combine both so the target has no time to check with anyone.",
            )
        )
    elif secrecy:
        signals.append(make_signal("bec.secrecy", SignalStage.BEC, 15, "Asks you to keep the request confidential"))

    if _EXEC_OPENER_RE.search(text):
        weight = 30 if (freemail or reply_mismatch) else 20
        signals.append(
            make_signal(
                "bec.executive_opener", SignalStage.BEC, weight,
                "Reads like a 'quick favour' request from a boss or colleague",
                "The opener of most CEO-fraud emails; the ask comes in the next reply.",
            )
        )

    if _PAYROLL_RE.search(text) and re.search(r"\b(?:update|change|switch|new|send|provide|copies|copy)\b", text, re.I):
        signals.append(
            make_signal(
                "bec.payroll_change", SignalStage.BEC, 35,
                "Asks about payroll, direct deposit or tax forms",
                "Payroll diversion and W-2 theft start with exactly this request.",
            )
        )

    if _CHANNEL_SWITCH_RE.search(text):
        signals.append(
            make_signal(
                "bec.channel_switch", SignalStage.BEC, 25,
                "Asks to continue on WhatsApp, text or a personal address",
                "Moving off email removes the record and the security checks.",
            )
        )

    if first_time and _INVOICE_RE.search(text) and (
        any(_INVOICE_RE.search(a.filename) for a in parsed.attachments) or re.search(r"\$\s?\d|\d\s?(?:usd|eur|gbp)\b|\bamount\b", text, re.I)
    ):
        signals.append(
            make_signal(
                "bec.invoice_first_time", SignalStage.BEC, 20,
                "An invoice or payment request from someone who has never written before",
            )
        )

    if parsed.from_domain:
        look = lookalike_analysis(parsed.from_domain, contact_domains=contact_domains)
        if look.is_lookalike and look.is_contact:
            signals.append(
                make_signal(
                    "bec.from_lookalike_contact", SignalStage.BEC, 60,
                    f"Sender domain {parsed.from_domain} imitates your contact's {look.target_domain}",
                    look.detail, target_domain=look.target_domain, reason=look.reason.value if look.reason else None,
                )
            )

    from_rd = registrable_domain(parsed.from_domain) if parsed.from_domain else ""
    sig_domains = [d for d in _signature_domains(parsed.text_body or "") if d not in _SOCIAL_DOMAINS and not is_popular(d)]
    foreign = [d for d in sig_domains if d != from_rd and not is_freemail(d)]
    if from_rd and foreign:
        weight = 30 if freemail else 20
        signals.append(
            make_signal(
                "bec.signature_domain_mismatch", SignalStage.BEC, weight,
                f"Signature names {foreign[0]} but the email came from {from_rd}",
                "A corporate signature on a personal or unrelated address is a classic impersonation tell.",
                signature_domains=foreign[:3], from_domain=from_rd,
            )
        )
    return signals


# --------------------------------------------------------------------------- LLM assessment


class LlmAssessment(BaseModel):
    """Strictly validated output of the language-model reviewer."""

    is_bec_likely: bool
    confidence: float = Field(ge=0.0, le=1.0)
    intent: str = Field(max_length=80)
    plain_summary: str = Field(max_length=400)


@runtime_checkable
class LlmAssessor(Protocol):
    async def assess(self, parsed: ParsedMessage, static_summary: str) -> LlmAssessment | None: ...


class NoopLlm:
    """The default: no model, no opinion."""

    async def assess(self, parsed: ParsedMessage, static_summary: str) -> LlmAssessment | None:
        return None


_SYSTEM_PROMPT = (
    "You are a fraud analyst protecting a private individual's inbox. Read the email and the static "
    "findings. Decide whether it is a social-engineering attempt (business email compromise, wire fraud, "
    "gift-card scam, payroll diversion, impersonation of a contact or executive, credential phishing). "
    "Respond with JSON only, with exactly these keys: is_bec_likely (boolean), confidence (number 0-1), "
    "intent (short phrase, under 80 characters, e.g. 'wire fraud via changed bank details' or 'ordinary "
    "newsletter'), plain_summary (one or two short sentences for a non-technical reader, under 300 "
    "characters, no jargon). Never include markdown."
)


class AzureOpenAiAssessor:
    """Chat-completions call to an Azure OpenAI deployment with JSON output.

    Failures of any kind (network, HTTP status, malformed JSON, schema
    violations) return ``None``: the model is an advisor, not a dependency.
    """

    def __init__(
        self,
        http: httpx.AsyncClient,
        endpoint: str,
        api_key: str,
        deployment: str,
        *,
        api_version: str = "2024-10-21",
        timeout_s: float = 8.0,
        max_body_chars: int = 6000,
    ) -> None:
        self._http = http
        self._endpoint = endpoint.rstrip("/")
        self._api_key = api_key
        self._deployment = deployment
        self._api_version = api_version
        self._timeout = timeout_s
        self._max_body_chars = max_body_chars

    @property
    def url(self) -> str:
        return f"{self._endpoint}/openai/deployments/{self._deployment}/chat/completions?api-version={self._api_version}"

    def build_user_message(self, parsed: ParsedMessage, static_summary: str) -> str:
        body = truncate(parsed.text_body or "", self._max_body_chars)
        attachments = ", ".join(a.filename for a in parsed.attachments if not a.is_inline) or "none"
        links = "\n".join(f"- {u.normalized}" for u in parsed.urls[:10]) or "none"
        return (
            f"From: {parsed.from_name or ''} <{parsed.from_address}>\n"
            f"Reply-To: {', '.join(parsed.reply_to) or 'none'}\n"
            f"Subject: {parsed.subject}\n"
            f"Attachments: {attachments}\n"
            f"Links:\n{links}\n"
            f"Static findings:\n{static_summary or 'none'}\n"
            f"Body:\n{body}"
        )

    def extra_payload(self) -> dict[str, Any]:
        """Fields a sibling API needs on top of the OpenAI chat shape (none here)."""
        return {}

    async def assess(self, parsed: ParsedMessage, static_summary: str) -> LlmAssessment | None:
        if not self._endpoint or not self._api_key or not self._deployment:
            return None
        payload: dict[str, Any] = {
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": self.build_user_message(parsed, static_summary)},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0,
            "max_tokens": 300,
            **self.extra_payload(),
        }
        try:
            resp = await self._http.post(
                self.url, json=payload, headers={"api-key": self._api_key}, timeout=self._timeout
            )
        except httpx.HTTPError as exc:
            log.warning("llm_request_failed", error=type(exc).__name__)
            return None
        except Exception as exc:
            log.warning("llm_request_error", error=str(exc))
            return None
        if resp.status_code != 200:
            log.warning("llm_bad_status", status=resp.status_code)
            return None
        try:
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            if isinstance(content, list):  # some SDK shapes return content parts
                content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
            parsed_json = json.loads(content)
            return LlmAssessment.model_validate(parsed_json)
        except (KeyError, IndexError, TypeError, ValueError, ValidationError) as exc:
            log.warning("llm_response_invalid", error=type(exc).__name__)
            return None


class AzureFoundryAssessor(AzureOpenAiAssessor):
    """Azure AI Foundry's model-inference endpoint: the same chat-completions
    JSON as Azure OpenAI, served at ``<endpoint>/models/chat/completions`` with
    the model name in the body. Lets us run Foundry-hosted models (Llama, Phi,
    Mistral, DeepSeek) without changing the rest of the pipeline."""

    def __init__(self, http: httpx.AsyncClient, endpoint: str, api_key: str, model: str, **kw: Any) -> None:
        kw.setdefault("api_version", "2024-05-01-preview")
        super().__init__(http, endpoint, api_key, model, **kw)

    @property
    def url(self) -> str:
        return f"{self._endpoint}/models/chat/completions?api-version={self._api_version}"

    def extra_payload(self) -> dict[str, Any]:
        return {"model": self._deployment}


_JSON_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)


def _strip_fence(text: str) -> str:
    """Models sometimes wrap JSON in a code fence despite instructions."""
    return _JSON_FENCE.sub("", text.strip())


class AnthropicAssessor:
    """Claude via the Anthropic Messages API (``POST /v1/messages``).

    Same contract as the Azure assessors: an advisor whose every failure is a
    ``None``. We ask for JSON only and tolerate a stray code fence. The prompt
    never contains client identity beyond what is in the email itself, and the
    body is truncated so a 40-page newsletter cannot run up the bill.
    """

    def __init__(
        self,
        http: httpx.AsyncClient,
        api_key: str,
        model: str,
        *,
        base_url: str = "https://api.anthropic.com",
        api_version: str = "2023-06-01",
        timeout_s: float = 8.0,
        max_body_chars: int = 6000,
    ) -> None:
        self._http = http
        self._api_key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._api_version = api_version
        self._timeout = timeout_s
        self._builder = AzureOpenAiAssessor(http, "unused", "unused", "unused", max_body_chars=max_body_chars)

    @property
    def url(self) -> str:
        return f"{self._base_url}/v1/messages"

    async def assess(self, parsed: ParsedMessage, static_summary: str) -> LlmAssessment | None:
        if not self._api_key or not self._model:
            return None
        payload: dict[str, Any] = {
            "model": self._model,
            "max_tokens": 300,
            "temperature": 0,
            "system": _SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": self._builder.build_user_message(parsed, static_summary)}],
        }
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": self._api_version,
            "content-type": "application/json",
        }
        try:
            resp = await self._http.post(self.url, json=payload, headers=headers, timeout=self._timeout)
        except httpx.HTTPError as exc:
            log.warning("llm_request_failed", error=type(exc).__name__)
            return None
        except Exception as exc:
            log.warning("llm_request_error", error=str(exc))
            return None
        if resp.status_code != 200:
            log.warning("llm_bad_status", status=resp.status_code)
            return None
        try:
            data = resp.json()
            text = "".join(
                block.get("text", "") for block in data.get("content", []) if isinstance(block, dict)
            )
            return LlmAssessment.model_validate(json.loads(_strip_fence(text)))
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            log.warning("llm_response_invalid", error=type(exc).__name__)
            return None


def llm_from_settings(settings: Any, http: httpx.AsyncClient | None = None) -> LlmAssessor:
    """Pick the reviewer from ``RS_LLM_PROVIDER``; anything unconfigured is a no-op."""
    provider = getattr(settings, "llm_provider", "none")
    if provider == "none":
        return NoopLlm()
    client = http or httpx.AsyncClient()
    if provider == "anthropic":
        return AnthropicAssessor(
            client, settings.anthropic_api_key.get_secret_value(), settings.anthropic_model
        )
    if provider == "azure_foundry":
        return AzureFoundryAssessor(
            client,
            settings.azure_foundry_endpoint,
            settings.azure_foundry_api_key.get_secret_value(),
            settings.azure_foundry_model,
        )
    if provider in ("azure_openai", "openai"):
        return AzureOpenAiAssessor(
            client,
            settings.azure_openai_endpoint,
            settings.azure_openai_api_key.get_secret_value(),
            settings.azure_openai_deployment,
        )
    return NoopLlm()


def llm_signal(assessment: LlmAssessment | None) -> Signal | None:
    """A bounded BEC signal from a positive assessment; nothing for a negative one."""
    if assessment is None or not assessment.is_bec_likely:
        return None
    weight = min(30, round(30 * assessment.confidence))
    if weight <= 0:
        return None
    return make_signal(
        "bec.llm_assessment", SignalStage.BEC, weight,
        f"Reads like {assessment.intent}" if assessment.intent else "Reads like a social-engineering attempt",
        assessment.plain_summary, confidence=assessment.confidence, intent=assessment.intent,
    )
