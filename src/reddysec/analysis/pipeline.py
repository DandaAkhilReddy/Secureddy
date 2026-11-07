"""The analysis pipeline: ParsedMessage in, Verdict out.

Order of operations::

    static signals (sender, BEC, per-URL, per-attachment)
      -> sender trust (analysis.trust: verified bulk senders, client feedback)
      -> triage lane
      -> [DETONATE] open selected links/files in the chamber, concurrently
         (the LLM reviewer, if any, runs alongside)
      -> combine -> plain-English summary -> Verdict

Guarantees:

* ``analyze`` never raises. An internal failure yields an UNKNOWN verdict
  flagged for human review, so the worker always has something to act on.
* Deterministic for the same inputs: no randomness, job ids derived from the
  message and the URL, timing only in ``duration_ms``.
* Nothing that identifies the client is put into a DetonationJob.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlsplit

from reddysec import ENGINE_VERSION
from reddysec.core.artifacts import ArtifactStore
from reddysec.core.logging import get_logger
from reddysec.models import (
    Attachment,
    AttachmentVerdict,
    ClientFeedback,
    DetonationJob,
    DetonationKind,
    DetonationResult,
    DetonationStatus,
    Detonator,
    ExtractedUrl,
    ParsedMessage,
    PolicyConfig,
    SenderHistory,
    Signal,
    SignalStage,
    TriageLane,
    TrustCheck,
    UrlVerdict,
    Verdict,
    VerdictLevel,
    level_for_score,
)

from .attachments import attachment_signals
from .bec import LlmAssessment, LlmAssessor, bec_signals, llm_signal
from .click_advice import advise, links_summary
from .common import make_signal
from .domains import brands_mentioned
from .dynamic import dynamic_signals, file_dynamic_signals, static_risk, url_static_signals
from .headers import sender_signals
from .intel import IntelClient
from .policy import choose_lane, select_attachments_to_detonate, select_urls_to_detonate, sender_is_blocked
from .redirects import unwrap_chain
from .scoring import attachment_verdict, combine, dedupe_by_code, summarize, url_verdict
from .trust import (
    SenderTrust,
    assess_sender,
    dedupe_opaque_tokens,
    protected_weight,
    soften_dynamic,
    soften_static,
    trust_signals,
)
from .urls import registrable_domain

log = get_logger(__name__)

FALLBACK_SUMMARY = (
    "We could not finish checking this email. Please treat its links and attachments with care until we do."
)
LLM_TIMEOUT_S = 10.0
RISKY_STATIC_THRESHOLD = 20  # an un-openable link with this much static risk needs a human


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass
class AnalysisContext:
    """Everything ``analyze`` needs besides the message itself.

    ``contact_domains`` (an addition to the original contract, defaulting to
    empty) lets the worker pass the registrable domains of people the client
    corresponds with, so lookalikes of *those* domains are caught too.

    ``feedback`` carries what the client told us about senders ("This is
    safe" / "This is fake"). It defaults to empty; ``analysis.trust`` decides
    what each entry is worth.
    """

    policy: PolicyConfig
    history: SenderHistory | None
    intel: IntelClient
    detonator: Detonator | None
    llm: LlmAssessor | None = None
    artifact_store: ArtifactStore | None = None
    detonation_timeout_s: float = 45
    max_concurrent_detonations: int = 2
    now: Callable[[], datetime] = utcnow
    contact_domains: tuple[str, ...] = field(default_factory=tuple)
    feedback: ClientFeedback | None = None


@dataclass
class _Detonated:
    job_id: str
    result: DetonationResult
    failed: bool  # we could not get a usable result (exception / timeout / chamber error)


def _job_id(parsed: ParsedMessage, target: str) -> str:
    digest = hashlib.sha256(f"{parsed.provider_message_id}|{parsed.mailbox_id}|{target}".encode()).hexdigest()
    return f"det_{digest[:26]}"


def _static_summary(signals: list[Signal]) -> str:
    strong = sorted((s for s in signals if s.weight > 0), key=lambda s: -s.weight)[:8]
    return "\n".join(f"- {s.title}" for s in strong)


async def _run_llm(llm: LlmAssessor, parsed: ParsedMessage, static_summary: str) -> LlmAssessment | None:
    try:
        return await asyncio.wait_for(llm.assess(parsed, static_summary), timeout=LLM_TIMEOUT_S)
    except TimeoutError:
        log.warning("llm_timeout")
        return None
    except Exception as exc:
        log.warning("llm_failed", error=str(exc))
        return None


async def _detonate(ctx: AnalysisContext, job: DetonationJob, sem: asyncio.Semaphore) -> _Detonated:
    assert ctx.detonator is not None
    async with sem:
        try:
            result = await asyncio.wait_for(ctx.detonator.detonate(job), timeout=ctx.detonation_timeout_s)
        except TimeoutError:
            log.warning("detonation_timeout", job_id=job.job_id)
            return _Detonated(
                job.job_id,
                DetonationResult(job_id=job.job_id, status=DetonationStatus.TIMEOUT, error="detonation timed out"),
                True,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("detonation_failed", job_id=job.job_id, error=str(exc))
            return _Detonated(
                job.job_id,
                DetonationResult(job_id=job.job_id, status=DetonationStatus.ERROR, error=f"{type(exc).__name__}: {exc}"),
                True,
            )
    if not isinstance(result, DetonationResult):
        return _Detonated(
            job.job_id,
            DetonationResult(job_id=job.job_id, status=DetonationStatus.ERROR, error="chamber returned no result"),
            True,
        )
    failed = result.status in (DetonationStatus.TIMEOUT, DetonationStatus.ERROR)
    return _Detonated(job.job_id, result, failed)


async def _safe_hash_lookup(intel: IntelClient, sha256: str) -> bool | None:
    try:
        return await intel.hash_is_known_bad(sha256)
    except Exception:
        return None


async def _safe_age_lookup(intel: IntelClient, domain: str) -> int | None:
    if not domain:
        return None
    try:
        return await intel.domain_age_days(domain)
    except Exception:
        return None


def _final_domain(url: ExtractedUrl, result: DetonationResult) -> str:
    if result.features and result.features.final_host:
        return registrable_domain(result.features.final_host)
    if result.redirects:
        return registrable_domain(urlsplit(result.redirects[-1].url).hostname or "")
    return url.registrable_domain


async def analyze(parsed: ParsedMessage, ctx: AnalysisContext) -> Verdict:
    """Analyse one parsed message. Never raises."""
    started = time.perf_counter()
    try:
        return await _analyze(parsed, ctx, started)
    except Exception as exc:
        log.error("analysis_failed", provider_message_id=parsed.provider_message_id, error=str(exc))
        return Verdict(
            level=VerdictLevel.UNKNOWN,
            score=0,
            summary=FALLBACK_SUMMARY,
            lane=TriageLane.DETONATE,
            needs_human_review=True,
            analyzed_at=_now(ctx),
            duration_ms=int((time.perf_counter() - started) * 1000),
            engine_version=ENGINE_VERSION,
        )


def _now(ctx: AnalysisContext) -> datetime:
    try:
        return ctx.now()
    except Exception:
        return utcnow()


async def _analyze(parsed: ParsedMessage, ctx: AnalysisContext, started: float) -> Verdict:
    history = ctx.history
    contacts = tuple(ctx.contact_domains)

    # ---- static -----------------------------------------------------------
    sender = sender_signals(parsed, history, contacts)
    trust = assess_sender(parsed, contact_domains=contacts, feedback=ctx.feedback, sender_signals=sender)
    bec = soften_static(bec_signals(parsed, history, contacts), trust)
    sender = soften_static(sender, trust)

    url_static: dict[str, list[Signal]] = {}
    url_results = await asyncio.gather(
        *(url_static_signals(u, ctx.intel, history, contacts, trust) for u in parsed.urls), return_exceptions=True
    )
    for url, sigs in zip(parsed.urls, url_results, strict=True):
        if isinstance(sigs, BaseException):
            log.warning("url_static_failed", url=url.normalized, error=str(sigs))
            sigs = []
        url_static.setdefault(url.normalized, []).extend(soften_static(sigs, trust))
    dedupe_opaque_tokens(url_static)

    attachment_static: dict[str, list[Signal]] = {}
    analysable = [a for a in parsed.attachments if not a.is_inline or not (a.content_type or "").startswith("image/")]
    for att in analysable:
        sigs = attachment_signals(att, parsed.text_body)
        if att.sha256 and await _safe_hash_lookup(ctx.intel, att.sha256):
            sigs.append(
                make_signal(
                    "attachment.known_bad", SignalStage.INTEL, 100,
                    f"Attachment {att.filename[:40]} is a known malicious file",
                    "Its fingerprint matches a file seen in previous attacks.", filename=att.filename, sha256=att.sha256,
                )
            )
        attachment_static[_att_key(att)] = sigs

    lane = choose_lane(parsed, history, ctx.policy, url_static, attachment_static, trust)
    policy_signals: list[Signal] = []
    if sender_is_blocked(parsed, ctx.policy):
        policy_signals.append(
            make_signal(
                "policy.blocked_sender", SignalStage.STATIC, 100,
                f"{parsed.from_address or 'This sender'} is on your block list",
            )
        )

    static_all = sender + bec + policy_signals + [s for v in url_static.values() for s in v]
    static_all += [s for v in attachment_static.values() for s in v]
    llm_task: asyncio.Task[LlmAssessment | None] | None = None
    if ctx.llm is not None:
        llm_task = asyncio.create_task(_run_llm(ctx.llm, parsed, _static_summary(static_all)))
    try:
        return await _finish(parsed, ctx, started, lane, sender, bec, policy_signals, url_static, attachment_static,
                             analysable, llm_task, trust)
    finally:
        if llm_task is not None and not llm_task.done():
            llm_task.cancel()


async def _finish(
    parsed: ParsedMessage,
    ctx: AnalysisContext,
    started: float,
    lane: TriageLane,
    sender: list[Signal],
    bec: list[Signal],
    policy_signals: list[Signal],
    url_static: dict[str, list[Signal]],
    attachment_static: dict[str, list[Signal]],
    analysable: list[Attachment],
    llm_task: asyncio.Task[LlmAssessment | None] | None,
    trust: SenderTrust | None = None,
) -> Verdict:
    """Dynamic analysis, LLM result, combination and the final Verdict."""
    # ---- dynamic ----------------------------------------------------------
    brands_in_email = brands_mentioned(f"{parsed.subject} {parsed.from_name or ''} {parsed.text_body[:3000]}")
    url_dynamic: dict[str, list[Signal]] = {}
    url_detonations: dict[str, _Detonated] = {}
    att_dynamic: dict[str, list[Signal]] = {}
    att_detonations: dict[str, _Detonated] = {}

    # Trust never skips the checks. A sender the client marked safe takes the
    # TRUSTED lane (the cheap heuristics stay off for them) but its links and
    # files are still opened in the sandbox: the client asked us to re-check
    # and confirm, and a hacked vendor account looks exactly like a trusted one.
    client_recheck = lane is TriageLane.TRUSTED and trust is not None and trust.client_trust is not None
    if (lane is TriageLane.DETONATE or client_recheck) and ctx.detonator is not None:
        selected_urls = select_urls_to_detonate(parsed, ctx.policy, url_static)
        if not ctx.policy.detonate_all_links:
            selected_urls = [u for u in selected_urls if static_risk(url_static.get(u.normalized, [])) >= 10]
        selected_atts: list[Attachment] = []
        if ctx.artifact_store is not None:
            selected_atts = [a for a in select_attachments_to_detonate(parsed) if a.data]
        sem = asyncio.Semaphore(max(1, ctx.max_concurrent_detonations))

        url_jobs = [
            DetonationJob(job_id=_job_id(parsed, u.normalized), kind=DetonationKind.URL, url=u.normalized,
                          timeout_s=int(ctx.detonation_timeout_s))
            for u in selected_urls
        ]
        att_jobs: list[tuple[Attachment, DetonationJob]] = []
        for att in selected_atts:
            try:
                assert ctx.artifact_store is not None and att.data is not None
                ref = ctx.artifact_store.put(att.data, suffix=att.declared_extension)
            except Exception as exc:
                log.warning("artifact_store_put_failed", filename=att.filename, error=str(exc))
                continue
            att_jobs.append(
                (att, DetonationJob(job_id=_job_id(parsed, f"file:{att.sha256}"), kind=DetonationKind.FILE,
                                    file_ref=ref, file_name=att.filename, timeout_s=int(ctx.detonation_timeout_s)))
            )

        outcomes = await asyncio.gather(
            *(_detonate(ctx, job, sem) for job in url_jobs), *(_detonate(ctx, job, sem) for _a, job in att_jobs)
        )
        url_outcomes = outcomes[: len(url_jobs)]
        att_outcomes = outcomes[len(url_jobs):]

        for url, det in zip(selected_urls, url_outcomes, strict=True):
            url_detonations[url.normalized] = det
            age: int | None = None
            if not det.failed:
                final_rd = _final_domain(url, det.result)
                age = await _safe_age_lookup(ctx.intel, final_rd)
            url_dynamic[url.normalized] = soften_dynamic(
                dynamic_signals(url.normalized, det.result, age, brands_in_email), trust or SenderTrust()
            )
        for (att, _job), det in zip(att_jobs, att_outcomes, strict=True):
            att_detonations[_att_key(att)] = det
            att_dynamic[_att_key(att)] = file_dynamic_signals(att.filename, det.result)

    # ---- llm --------------------------------------------------------------
    assessment: LlmAssessment | None = None
    if llm_task is not None:
        assessment = await llm_task
    llm_sig = llm_signal(assessment)

    # ---- per-item verdicts -------------------------------------------------
    url_verdicts: list[UrlVerdict] = []
    risky_unknown = False
    any_unknown = False
    for url in parsed.urls:
        sigs = list(url_static.get(url.normalized, [])) + list(url_dynamic.get(url.normalized, []))
        det = url_detonations.get(url.normalized)
        unavailable = det is not None and det.failed
        verdict = url_verdict(
            url, sigs,
            result=det.result if det is not None else None,
            detonated=det is not None and not det.failed,
            job_id=det.job_id if det is not None else None,
            unavailable=unavailable,
        )
        if verdict.level is VerdictLevel.UNKNOWN:
            any_unknown = True
            if static_risk(url_static.get(url.normalized, [])) >= RISKY_STATIC_THRESHOLD:
                risky_unknown = True
        _add_click_advice(verdict, url, det, trust, bec)
        url_verdicts.append(verdict)

    att_verdicts: list[AttachmentVerdict] = []
    for att in analysable:
        key = _att_key(att)
        sigs = list(attachment_static.get(key, [])) + list(att_dynamic.get(key, []))
        det = att_detonations.get(key)
        verdict = attachment_verdict(
            att, sigs, job_id=det.job_id if det is not None else None, unavailable=det is not None and det.failed
        )
        if verdict.level is VerdictLevel.UNKNOWN:
            any_unknown = True
            if static_risk(attachment_static.get(key, [])) >= RISKY_STATIC_THRESHOLD:
                risky_unknown = True
        att_verdicts.append(verdict)

    # ---- combine ----------------------------------------------------------
    all_signals: list[Signal] = sender + bec + policy_signals
    for v in url_verdicts:
        all_signals.extend(v.signals)
    for v in att_verdicts:
        all_signals.extend(v.signals)
    if llm_sig is not None:
        all_signals.append(llm_sig)
    if trust is not None:
        # Message-level cap: soft sandbox findings across all links together.
        all_signals = soften_dynamic(all_signals, trust)
        all_signals.extend(trust_signals(trust, protected_weight(all_signals)))

    score = combine(dedupe_by_code(all_signals))
    level = level_for_score(score)
    if level is VerdictLevel.SAFE and risky_unknown:
        level = VerdictLevel.UNKNOWN

    has_trust = any(s.weight < 0 for s in all_signals)
    needs_human_review = (
        level is VerdictLevel.SUSPICIOUS
        or level is VerdictLevel.UNKNOWN
        or risky_unknown
        or (lane is TriageLane.BLOCK and has_trust)
    )

    top = sorted(all_signals, key=lambda s: -s.weight)[:8]
    llm_summary = assessment.plain_summary if assessment is not None and assessment.is_bec_likely else None
    summary = summarize(level, lane, top, llm_summary, parsed)
    check = trust_check_for(trust, lane, level, ctx.feedback)
    if check is not None and check.trusted_by_client:
        summary = trust_summary(check, summary)
        if check.outcome == "confirmed":
            all_signals.append(
                make_signal(
                    "history.trust_confirmed", SignalStage.HISTORY, 0, "Confirmed again",
                    "You trust this sender, and we checked this email too. It is safe.",
                    scope=check.scope, value=check.value,
                )
            )

    log.info(
        "analysis_complete",
        provider_message_id=parsed.provider_message_id,
        level=level.value,
        score=score,
        lane=lane.value,
        urls=len(url_verdicts),
        attachments=len(att_verdicts),
        detonated=sum(1 for v in url_verdicts if v.detonated),
        unknown=any_unknown,
    )
    links_line, link_counts = links_summary(url_verdicts)
    return Verdict(
        links_summary=links_line,
        link_advice_counts=link_counts,
        level=level,
        score=score,
        summary=summary,
        lane=lane,
        signals=all_signals,
        urls=url_verdicts,
        attachments=att_verdicts,
        needs_human_review=needs_human_review,
        analyzed_at=_now(ctx),
        duration_ms=int((time.perf_counter() - started) * 1000),
        engine_version=ENGINE_VERSION,
        verified_domain=trust.aligned_domain if trust is not None else "",
        bulk_sender=bool(trust is not None and trust.authenticated_bulk_sender),
        trust_check=check,
    )


REASON_IN_SUMMARY_MAX = 120
MAX_CHAIN_SHOWN = 10


def _add_click_advice(
    verdict: UrlVerdict, url: ExtractedUrl, det: _Detonated | None, trust: SenderTrust | None, message_signals: list[Signal]
) -> None:
    """Fill the per-link "is it safe to click?" fields (analysis.click_advice). Never raises."""
    try:
        result = det.result if det is not None else None
        advice, reason, downloads = advise(
            verdict, result, detonated=det is not None and not det.failed,
            verified_domain=trust.aligned_domain if trust is not None else "",
            message_signals=[s for s in message_signals if s.code == "bec.device_code_lure"],
        )
        verdict.click_advice = advice  # type: ignore[assignment]
        verdict.click_advice_reason = reason
        verdict.downloads_summary = downloads
        chain = [h.url for h in unwrap_chain(url.raw)] if url.raw and url.raw != url.normalized else []
        if result is not None:
            for hop in result.redirects:
                if not chain or hop.url.split("#", 1)[0] != chain[-1].split("#", 1)[0]:
                    chain.append(hop.url)
        if len(chain) > 1:
            verdict.redirect_chain = [c[:500] for c in chain[:MAX_CHAIN_SHOWN]]
    except Exception as exc:  # advice is a convenience; it must never cost a verdict
        log.warning("click_advice_failed", url=url.normalized, error=str(exc))


def trust_check_for(
    trust: SenderTrust | None, lane: TriageLane, level: VerdictLevel, feedback: ClientFeedback | None
) -> TrustCheck | None:
    """How a trusted sender's message fared (see ``models.TrustCheck``).

    Set for senders the client trusts ("Not suspicious?" / "Not fake?") and
    for senders that took the TRUSTED lane for another reason (a known
    correspondent, a policy-trusted domain). ``None`` for everyone else and
    for blocked senders.
    """
    if trust is None or trust.client_blocked:
        return None
    by_client = trust.client_trust is not None
    if not by_client and lane is not TriageLane.TRUSTED:
        return None
    if by_client:
        scope = str(trust.client_trust)
        value = trust.aligned_domain if scope == "domain" else trust.from_address
    else:
        scope = "domain" if trust.aligned_domain else "address"
        value = trust.aligned_domain or trust.from_address
    reason = (feedback.reasons.get(value.lower(), "") if feedback is not None and by_client else "").strip()
    if level is VerdictLevel.SAFE:
        outcome = "confirmed"
    elif level is VerdictLevel.UNKNOWN:
        outcome = "incomplete"
    else:
        outcome = "changed"
    return TrustCheck(trusted_by_client=by_client, reason=reason, outcome=outcome, scope=scope, value=value)


def trust_summary(check: TrustCheck, summary: str) -> str:
    """The client-facing summary for a sender the client trusts."""
    if check.outcome == "confirmed":
        reason = check.reason.rstrip(". ")
        if len(reason) > REASON_IN_SUMMARY_MAX:
            reason = reason[: REASON_IN_SUMMARY_MAX - 1].rstrip() + "…"
        why = f" (reason: {reason})" if reason else ""
        return f"You told us you trust this sender{why}. We checked this one too. It's safe."
    if check.outcome == "changed":
        return f"This sender is on your trusted list, but this email looks different. {summary}"
    return summary


def _att_key(att: Attachment) -> str:
    return f"{att.sha256}:{att.filename}"
