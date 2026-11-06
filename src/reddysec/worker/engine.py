"""The worker: poll every active mailbox, analyze what is new, act, notify.

Guiding rule (from the README): our failures must never trap mail. In HOLD
mode every path through ``process_message`` ends with the message either
released or quarantined on evidence; analysis timeouts and crashes release
with an UNKNOWN verdict (unless the policy says to hold and page the
concierge), and the dead man's switch covers the case where this process is
not running at all.

Client requests ("This is fake", "This is safe", "Check again") are recorded
by the web app as message states and carried out here, because only the worker
holds mailbox access. They are handled after new mail on every cycle, and
re-checks are rationed (``RESCORES_PER_CYCLE``) so a "re-check last 7 days"
can never starve the protection of new mail.

Dependencies on the analysis and chamber packages are resolved lazily and are
injectable, so this module is testable with fakes and can be imported before
those packages exist.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx
from pydantic import ValidationError

from reddysec import ENGINE_VERSION
from reddysec.config import Settings
from reddysec.core.artifacts import ArtifactStore, artifact_store_from_settings
from reddysec.core.logging import get_logger
from reddysec.mail.base import AuthExpired, ConnectorError, MailboxConnector
from reddysec.mail.factory import ConnectorFactory, connector_factory_from_settings
from reddysec.mail.gmail import should_quarantine
from reddysec.models import (
    ClientFeedback,
    ParsedMessage,
    PolicyConfig,
    ProtectionMode,
    RawMessage,
    SenderHistory,
    Signal,
    SignalStage,
    TriageLane,
    Verdict,
    VerdictLevel,
)
from reddysec.store import repo
from reddysec.store.db import Database
from reddysec.store.models import MailboxRow, MessageRow, utcnow
from reddysec.worker.notify import LEVEL_ALERT, Notifier

log = get_logger(__name__)

MODE_KEY = "_mode"  # stored in mailbox.labels so a mode change re-runs setup
SCAN_TIMEOUT_SLACK_S = 30
RESCORES_PER_CYCLE = 10

Parser = Callable[..., ParsedMessage]
Analyzer = Callable[[ParsedMessage, Any], Awaitable[Verdict]]
ContextFactory = Callable[..., Any]


@dataclass
class CycleStats:
    mailboxes: int = 0
    messages: int = 0
    skipped: int = 0
    failed: int = 0
    restored: int = 0
    client_requests: int = 0
    mailbox_errors: list[str] = field(default_factory=list)


def _default_parser() -> Parser:
    from reddysec.analysis.parser import parse_raw  # lazy: built by another team

    return parse_raw


def _default_analyzer() -> Analyzer:
    from reddysec.analysis.pipeline import analyze  # lazy: built by another team

    return analyze


def _default_context_factory() -> ContextFactory:
    from reddysec.analysis.pipeline import AnalysisContext  # lazy: built by another team

    return AnalysisContext


def _default_llm(settings: Settings, http: httpx.AsyncClient | None = None) -> Any:
    from reddysec.analysis.bec import llm_from_settings  # lazy: keeps worker import light

    return llm_from_settings(settings, http)


def _default_intel(settings: Settings, http: httpx.AsyncClient | None = None) -> Any:
    """Offline lists always; online lookups (Safe Browsing, URLhaus, RDAP) only
    when RS_INTEL_ONLINE is set, so tests and air-gapped runs stay deterministic."""
    from reddysec.analysis.intel import CompositeIntel, OfflineIntel  # lazy: built by another team

    offline = OfflineIntel()
    if not settings.intel_online:
        return CompositeIntel(offline, None, False)
    from reddysec.analysis.intel import OnlineIntel

    key = settings.safe_browsing_api_key.get_secret_value() or None
    online = OnlineIntel(http or httpx.AsyncClient(timeout=10.0), key)
    return CompositeIntel(offline, online, True)


def _default_detonator(settings: Settings, artifact_store: ArtifactStore) -> Any:
    try:
        from reddysec.chamber import make_chamber  # the contract's name
    except ImportError:  # the chamber team keeps the factory next to the backends
        from reddysec.chamber.backends import make_chamber

    return make_chamber(settings, artifact_store)


def fallback_verdict(reason: str, *, released: bool) -> Verdict:
    """What we record when analysis did not produce a verdict. UNKNOWN keeps the
    client informed without claiming either safety or danger."""
    if released:
        summary = (
            "We could not finish checking this message in time, so we delivered it. "
            "Open its links in the Reading Room rather than directly."
        )
    else:
        summary = "We could not finish checking this message in time. It is being held for a human check."
    code = "engine.timeout" if reason == "timeout" else "engine.error"
    return Verdict(
        level=VerdictLevel.UNKNOWN,
        score=0,
        summary=summary,
        lane=TriageLane.DETONATE,
        signals=[
            Signal(
                code=code,
                stage=SignalStage.DYNAMIC,
                weight=0,
                title="Analysis did not complete",
                detail=reason,
            )
        ],
        needs_human_review=True,
        engine_version=ENGINE_VERSION,
    )


def policy_for(mailbox: MailboxRow) -> PolicyConfig:
    """The mailbox's stored policy with its mode made authoritative. A corrupt
    policy document falls back to defaults rather than stopping protection."""
    data = dict(mailbox.policy or {})
    data["mode"] = mailbox.mode
    try:
        return PolicyConfig.model_validate(data)
    except ValidationError as exc:
        log.warning("worker.policy_invalid", mailbox_id=mailbox.id, error=str(exc))
        return PolicyConfig(mode=ProtectionMode(mailbox.mode))


class Worker:
    """See the module docstring. Construct once; ``run_forever`` or ``run_cycle``.

    ``connector_factory`` maps a mailbox row to a connector (default: the
    vault-backed ``build_connector``). ``parser``/``analyzer``/``context_factory``
    default to ``reddysec.analysis``; ``detonator`` to ``reddysec.chamber``.
    """

    def __init__(
        self,
        db: Database,
        settings: Settings,
        *,
        connector_factory: ConnectorFactory | None = None,
        parser: Parser | None = None,
        analyzer: Analyzer | None = None,
        detonator: Any | None = None,
        intel: Any | None = None,
        notifier: Notifier | None = None,
        context_factory: ContextFactory | None = None,
        artifact_store: ArtifactStore | None = None,
        http: httpx.AsyncClient | None = None,
        clock: Callable[[], datetime] = utcnow,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ):
        self._db = db
        self._settings = settings
        self._connector_factory = connector_factory or connector_factory_from_settings(
            settings, db, http=http
        )
        self._parser = parser
        self._analyzer = analyzer
        self._context_factory = context_factory
        self._detonator = detonator
        self._intel = intel
        self._llm: Any | None = None
        self._artifact_store = artifact_store
        self._http = http
        self._notifier = notifier or Notifier(db, settings, http=http)
        self._clock = clock
        self._sleep = sleep or self._sleep_until_wake
        self._wake = asyncio.Event()
        self.cycles = 0

    # ------------------------------------------------------------ wiring
    @property
    def parser(self) -> Parser:
        if self._parser is None:
            self._parser = _default_parser()
        return self._parser

    @property
    def analyzer(self) -> Analyzer:
        if self._analyzer is None:
            self._analyzer = _default_analyzer()
        return self._analyzer

    @property
    def context_factory(self) -> ContextFactory:
        if self._context_factory is None:
            self._context_factory = _default_context_factory()
        return self._context_factory

    @property
    def artifact_store(self) -> ArtifactStore:
        if self._artifact_store is None:
            self._artifact_store = artifact_store_from_settings(self._settings)
        return self._artifact_store

    @property
    def intel(self) -> Any:
        if self._intel is None:
            self._intel = _default_intel(self._settings, self._http)
        return self._intel

    @property
    def llm(self) -> Any:
        if self._llm is None:
            self._llm = _default_llm(self._settings, self._http)
        return self._llm

    @property
    def detonator(self) -> Any:
        if self._detonator is None:
            self._detonator = _default_detonator(self._settings, self.artifact_store)
        return self._detonator

    @property
    def notifier(self) -> Notifier:
        return self._notifier

    # ------------------------------------------------------------- loop
    @property
    def poll_interval_s(self) -> float:
        return float(
            min(self._settings.gmail_poll_seconds, self._settings.imap_poll_seconds, self._settings.graph_poll_seconds)
        )

    def wake(self) -> None:
        """Run the next cycle now (e.g. a Gmail Pub/Sub push arrived)."""
        self._wake.set()

    async def _sleep_until_wake(self, seconds: float) -> None:
        try:
            await asyncio.wait_for(self._wake.wait(), timeout=seconds)
        except TimeoutError:
            pass
        self._wake.clear()

    async def run_forever(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            try:
                await self.run_cycle()
            except Exception:  # noqa: BLE001 - the loop must survive anything
                log.exception("worker.cycle_crashed")
            if stop_event.is_set():
                break
            await self._sleep(self.poll_interval_s)

    async def run_cycle(self) -> CycleStats:
        stats = CycleStats()
        async with self._db.session() as session:
            mailboxes = await repo.list_active_mailboxes(session)
        for mailbox in mailboxes:
            stats.mailboxes += 1
            try:
                await self.process_mailbox(mailbox, stats)
            except AuthExpired as exc:
                await self._mailbox_auth_expired(mailbox, exc)
                stats.mailbox_errors.append(mailbox.id)
            except ConnectorError as exc:
                stats.mailbox_errors.append(mailbox.id)
                if exc.retryable:
                    log.warning("worker.mailbox_retry_later", mailbox_id=mailbox.id, error=str(exc))
                    continue
                await self._mailbox_failed(mailbox, str(exc))
            except Exception as exc:  # noqa: BLE001 - one mailbox must not stop the others
                log.exception("worker.mailbox_crashed", mailbox_id=mailbox.id)
                stats.mailbox_errors.append(mailbox.id)
                async with self._db.session() as session:
                    await repo.set_mailbox_status(
                        session, mailbox.id, "active", error=f"worker error: {exc}"[:1000]
                    )
        self.cycles += 1
        return stats

    # ---------------------------------------------------------- mailbox
    async def process_mailbox(self, mailbox: MailboxRow, stats: CycleStats | None = None) -> CycleStats:
        stats = stats or CycleStats()
        mode = ProtectionMode(mailbox.mode)
        connector = await self._connector_factory(mailbox)

        labels = dict(mailbox.labels or {})
        if not labels or labels.get(MODE_KEY) != mode.value:
            # First cycle for this mailbox, or its mode changed: (re)create labels
            # and install/remove the hold rule. The web app only writes the row.
            labels = dict(await connector.setup(mode))
            labels[MODE_KEY] = mode.value
            async with self._db.session() as session:
                await repo.set_mailbox_labels(session, mailbox.id, labels)
                await repo.audit(
                    session, None, "system", "mailbox_setup", mailbox.id, details={"mode": mode.value}
                )
            mailbox.labels = labels
            log.info("worker.mailbox_setup", mailbox_id=mailbox.id, mode=mode.value)

        messages, new_cursor = await connector.poll(mailbox.cursor)
        for raw in messages:
            async with self._db.session() as session:
                existing = await repo.get_message_by_provider_id(session, mailbox.id, raw.provider_message_id)
            if existing is not None and existing.state not in repo.REPROCESSABLE_STATES:
                stats.skipped += 1
                continue
            try:
                await self.process_message(mailbox, connector, raw)
                stats.messages += 1
            except ConnectorError:
                raise
            except Exception as exc:  # noqa: BLE001 - keep going with the next message
                stats.failed += 1
                log.exception(
                    "worker.message_crashed",
                    mailbox_id=mailbox.id,
                    provider_message_id=raw.provider_message_id,
                )
                await self._message_crashed(mailbox, connector, raw, exc)

        stats.restored += await self._handle_restore_requests(mailbox, connector)
        stats.client_requests += await self._handle_client_requests(mailbox, connector)

        async with self._db.session() as session:
            await repo.update_cursor(session, mailbox.id, new_cursor)
            if mode is ProtectionMode.HOLD:
                await repo.beat(session, mailbox.id, at=self._clock())
            if mailbox.status != "active" or mailbox.last_error:
                await repo.set_mailbox_status(session, mailbox.id, "active", error=None)
        mailbox.cursor = new_cursor
        return stats

    async def _handle_restore_requests(self, mailbox: MailboxRow, connector: MailboxConnector) -> int:
        async with self._db.session() as session:
            requests = await repo.list_restore_requests(session, mailbox.id)
        done = 0
        for row in requests:
            try:
                await connector.restore(row.provider_message_id)
                if repo.client_decision(row) == "safe":
                    await connector.mark_safe(row.provider_message_id)
            except ConnectorError as exc:
                if exc.retryable:
                    raise
                async with self._db.session() as session:
                    fresh = await repo.get_message(session, row.id)
                    if fresh is not None:
                        await repo.set_message_state(session, fresh, repo.STATE_RESTORE_FAILED)
                    await repo.audit(
                        session,
                        None,
                        "system",
                        "restore_failed",
                        mailbox.id,
                        row.id,
                        {"error": str(exc)[:500]},
                    )
                continue
            async with self._db.session() as session:
                fresh = await repo.get_message(session, row.id)
                if fresh is not None:
                    await repo.mark_restored(session, fresh)
                await repo.audit(session, None, "system", "restore", mailbox.id, row.id, {})
            done += 1
        return done

    async def _handle_client_requests(self, mailbox: MailboxRow, connector: MailboxConnector) -> int:
        """Carry out "This is fake", "This is safe" and "Check again"."""
        done = 0
        async with self._db.session() as session:
            fake = await repo.list_requests(session, mailbox.id, repo.STATE_QUARANTINE_REQUESTED)
            safe = await repo.list_requests(session, mailbox.id, repo.STATE_RELABEL_SAFE_REQUESTED)
            rescore = await repo.list_requests(
                session, mailbox.id, repo.STATE_RESCORE_REQUESTED, limit=RESCORES_PER_CYCLE
            )
        for row in fake:
            if await self._client_action(mailbox, row, "client_quarantine", connector.quarantine):
                done += 1
        for row in safe:
            if await self._client_action(mailbox, row, "client_mark_safe", connector.mark_safe):
                done += 1
        feedback = await self._feedback(mailbox.id) if rescore else None
        for row in rescore:
            if await self._rescore(mailbox, connector, row, feedback or ClientFeedback()):
                done += 1
        return done

    async def _client_action(
        self, mailbox: MailboxRow, row: MessageRow, action: str, call: Callable[[str], Awaitable[None]]
    ) -> bool:
        try:
            await call(row.provider_message_id)
        except ConnectorError as exc:
            if exc.retryable:
                raise
            async with self._db.session() as session:
                fresh = await repo.get_message(session, row.id)
                if fresh is not None:
                    await repo.set_message_state(session, fresh, repo.STATE_DONE)
                await repo.audit(
                    session, None, "system", f"{action}_failed", mailbox.id, row.id, {"error": str(exc)[:500]}
                )
            return False
        async with self._db.session() as session:
            fresh = await repo.get_message(session, row.id)
            if fresh is not None:
                if action == "client_quarantine":
                    await repo.mark_quarantined_by_client(session, fresh)
                else:
                    await repo.mark_relabeled_safe(session, fresh)
            await repo.audit(session, None, "system", action, mailbox.id, row.id, {})
        return True

    async def _rescore(
        self, mailbox: MailboxRow, connector: MailboxConnector, row: MessageRow, feedback: ClientFeedback
    ) -> bool:
        """Fetch the message again, analyse it with today's rules and the
        client's feedback, swap its label, keep the old verdict as ``previous``.

        Safety rules: a message only leaves Quarantine when the new verdict is
        SAFE; anything else that was quarantined stays there. A failed re-check
        keeps the old verdict and label.
        """
        policy = policy_for(mailbox)
        try:
            raw_bytes = await connector.fetch_raw(row.provider_message_id)
        except ConnectorError as exc:
            if exc.retryable:
                raise
            await self._rescore_failed(mailbox, row, f"fetch: {exc}")
            return False
        raw = RawMessage(
            provider_message_id=row.provider_message_id,
            mailbox_id=mailbox.id,
            received_at=row.received_at,
            raw=raw_bytes,
            thread_id=row.thread_id,
        )
        try:
            parsed = self.parser(
                raw.raw,
                provider_message_id=raw.provider_message_id,
                mailbox_id=mailbox.id,
                received_at=raw.received_at,
                thread_id=raw.thread_id,
            )
        except Exception as exc:  # noqa: BLE001 - one bad message must not stop the others
            await self._rescore_failed(mailbox, row, f"parse: {type(exc).__name__}")
            return False
        async with self._db.session() as session:
            history = (
                await repo.sender_history(session, mailbox.id, parsed.from_address) if parsed.from_address else None
            )
        verdict, outcome = await self._analyze(parsed, policy, history, hold=False, feedback=feedback)
        if outcome != "ok":
            await self._rescore_failed(mailbox, row, outcome)
            return False

        was_quarantined = bool(row.quarantined)
        quarantined = should_quarantine(verdict, policy) or (was_quarantined and verdict.level is not VerdictLevel.SAFE)
        try:
            if verdict.level is VerdictLevel.SAFE:
                await connector.mark_safe(row.provider_message_id)
            else:
                await connector.apply_verdict(raw, verdict, policy, relabel=True)
                if quarantined and not should_quarantine(verdict, policy):
                    await connector.quarantine(row.provider_message_id)  # never release on a re-check
        except ConnectorError as exc:
            if exc.retryable:
                raise
            await self._rescore_failed(mailbox, row, f"label: {exc}")
            return False

        async with self._db.session() as session:
            fresh = await repo.get_message(session, row.id) or row
            previous_level = fresh.level
            await repo.record_rescore(session, fresh, verdict, quarantined)
            for url in verdict.urls:
                if url.detonation_job_id:
                    await repo.record_detonation_ref(session, fresh.id, url.detonation_job_id, "url", url.url)
            await repo.audit(
                session,
                None,
                "system",
                "rescore",
                mailbox.id,
                fresh.id,
                {"from": previous_level, "to": verdict.level.value, "score": verdict.score, "quarantined": quarantined},
            )
        return True

    async def _rescore_failed(self, mailbox: MailboxRow, row: MessageRow, reason: str) -> None:
        log.warning("worker.rescore_failed", mailbox_id=mailbox.id, message_id=row.id, reason=reason)
        async with self._db.session() as session:
            fresh = await repo.get_message(session, row.id)
            if fresh is not None:
                await repo.set_message_state(session, fresh, repo.STATE_DONE)
            await repo.audit(session, None, "system", "rescore_failed", mailbox.id, row.id, {"reason": reason[:500]})

    async def _feedback(self, mailbox_id: str) -> ClientFeedback:
        async with self._db.session() as session:
            return await repo.load_client_feedback(session, mailbox_id)

    # ---------------------------------------------------------- message
    async def process_message(
        self, mailbox: MailboxRow, connector: MailboxConnector, raw: RawMessage
    ) -> MessageRow:
        policy = policy_for(mailbox)
        hold = policy.mode is ProtectionMode.HOLD
        parsed = self.parser(
            raw.raw,
            provider_message_id=raw.provider_message_id,
            mailbox_id=mailbox.id,
            received_at=raw.received_at,
            thread_id=raw.thread_id,
        )

        async with self._db.session() as session:
            row = await repo.upsert_message(session, parsed, raw, state=repo.STATE_ANALYZING)
            history = (
                await repo.sender_history(session, mailbox.id, parsed.from_address)
                if parsed.from_address
                else None
            )
            feedback = await repo.load_client_feedback(session, mailbox.id)

        verdict, outcome = await self._analyze(parsed, policy, history, hold=hold, feedback=feedback)

        held_for_review = outcome == "timeout" and hold and not policy.release_on_timeout
        if not held_for_review:
            await connector.apply_verdict(raw, verdict, policy)
        quarantined = should_quarantine(verdict, policy)

        state = repo.STATE_DONE
        if held_for_review:
            state = repo.STATE_HELD_FOR_REVIEW
        elif outcome == "error":
            state = repo.STATE_FAILED

        async with self._db.session() as session:
            row = await repo.get_message(session, row.id) or row
            await repo.record_verdict(session, row, verdict, quarantined, state=state)
            for url in verdict.urls:
                if url.detonation_job_id:
                    await repo.record_detonation_ref(session, row.id, url.detonation_job_id, "url", url.url)
            for att in verdict.attachments:
                if att.detonation_job_id:
                    await repo.record_detonation_ref(
                        session, row.id, att.detonation_job_id, "file", att.filename
                    )
            if parsed.from_address:
                await repo.touch_contact(
                    session, mailbox.id, parsed.from_address, parsed.from_name, seen_at=raw.received_at
                )
            if verdict.trust_check is not None:
                await repo.record_trust_check(session, mailbox.id, verdict.trust_check, at=self._clock())
            await repo.audit(
                session,
                None,
                "system",
                "verdict",
                mailbox.id,
                row.id,
                {
                    "level": verdict.level.value,
                    "score": verdict.score,
                    "lane": verdict.lane.value,
                    "quarantined": quarantined,
                    "outcome": outcome,
                    "state": state,
                },
            )
            user = await repo.get_user(session, mailbox.user_id)

        trust_changed = (
            verdict.trust_check is not None
            and verdict.trust_check.trusted_by_client
            and verdict.trust_check.outcome == "changed"
        )
        if user is not None and trust_changed:
            await self._notify_trust_changed(user, row, verdict)
        elif user is not None and (verdict.level.rank >= policy.notify_at.rank or verdict.needs_human_review):
            await self._notifier.notify_verdict(user, row, verdict)
        if outcome != "ok" or verdict.needs_human_review:
            await self._notifier.notify_concierge(
                f"Message needs review ({mailbox.address})",
                f"Outcome: {outcome}. State: {state}. Level: {verdict.level.value}.\n{self._notifier.message_url(row.id)}",
            )
        return row

    async def _notify_trust_changed(self, user: Any, row: MessageRow, verdict: Verdict) -> None:
        """A sender the client trusts sent something we would not let through:
        the most important notice we send, because it is how a hacked vendor
        or friend's account shows up."""
        check = verdict.trust_check
        assert check is not None
        what = "put it in Quarantine" if row.quarantined else "marked it Suspicious"
        sender = row.from_address or check.value
        body = (
            f"You told us you trust {check.value}. This email from {sender} looks different, so we {what}. "
            f"Subject: {(row.subject or '(no subject)')[:120]}\n"
            "Do not click its links or reply until you have checked with them on a number you already have.\n"
            f"Details: {self._notifier.message_url(row.id)}"
        )
        await self._notifier.notify_user(
            user,
            level=LEVEL_ALERT,
            title="A sender you trust sent something unusual",
            body=body,
            message_id=row.id,
        )

    async def _analyze(
        self,
        parsed: ParsedMessage,
        policy: PolicyConfig,
        history: SenderHistory | None,
        *,
        hold: bool,
        feedback: ClientFeedback | None = None,
    ) -> tuple[Verdict, str]:
        """Run the analysis pipeline under a time budget. Returns (verdict, outcome)
        where outcome is "ok", "timeout" or "error"."""
        timeout = self._time_budget(parsed, policy, hold=hold)
        try:
            ctx = self.context_factory(
                policy=policy,
                history=history,
                intel=self.intel,
                detonator=self.detonator,
                llm=self.llm,
                artifact_store=self.artifact_store,
                detonation_timeout_s=self._settings.detonation_timeout_s,
                feedback=feedback,
            )
            verdict = await asyncio.wait_for(self.analyzer(parsed, ctx), timeout=timeout)
            return verdict, "ok"
        except TimeoutError:
            released = not hold or policy.release_on_timeout
            log.warning(
                "worker.analysis_timeout", provider_message_id=parsed.provider_message_id, timeout_s=timeout
            )
            return fallback_verdict("timeout", released=released), "timeout"
        except Exception as exc:  # noqa: BLE001 - analysis bugs must not trap mail
            log.exception("worker.analysis_failed", provider_message_id=parsed.provider_message_id)
            verdict = fallback_verdict(f"error: {type(exc).__name__}", released=True)
            return verdict, "error"

    def _time_budget(self, parsed: ParsedMessage, policy: PolicyConfig, *, hold: bool) -> float:
        if hold:
            return float(policy.hold_timeout_s)
        targets = max(1, len(parsed.urls) + len(parsed.real_attachments))
        return float(self._settings.detonation_timeout_s * targets + SCAN_TIMEOUT_SLACK_S)

    # ------------------------------------------------------------ errors
    async def _message_crashed(
        self, mailbox: MailboxRow, connector: MailboxConnector, raw: RawMessage, exc: Exception
    ) -> None:
        async with self._db.session() as session:
            row = await repo.get_message_by_provider_id(session, mailbox.id, raw.provider_message_id)
            if row is not None:
                await repo.mark_failed(session, row, f"{type(exc).__name__}: {exc}")
            await repo.audit(
                session,
                None,
                "system",
                "message_failed",
                mailbox.id,
                raw.provider_message_id,
                {"error": f"{type(exc).__name__}: {exc}"[:500]},
            )
        if ProtectionMode(mailbox.mode) is ProtectionMode.HOLD:
            # Fail open: a message we could not even parse must not stay held.
            try:
                await connector.release(raw.provider_message_id)
            except ConnectorError as release_exc:
                log.error("worker.release_after_crash_failed", mailbox_id=mailbox.id, error=str(release_exc))

    async def _mailbox_auth_expired(self, mailbox: MailboxRow, exc: AuthExpired) -> None:
        log.warning("worker.mailbox_auth_expired", mailbox_id=mailbox.id, error=str(exc))
        async with self._db.session() as session:
            await repo.set_mailbox_status(session, mailbox.id, "error", error=str(exc)[:1000])
            await repo.audit(
                session, None, "system", "mailbox_auth_expired", mailbox.id, details={"error": str(exc)[:500]}
            )
            user = await repo.get_user(session, mailbox.user_id)
        provider = mailbox.provider.capitalize() if mailbox.provider != "gmail" else "Gmail"
        if user is not None:
            await self._notifier.notify_user(
                user,
                level=LEVEL_ALERT,
                title=f"Reconnect your {provider} mailbox",
                body=(
                    f"We lost access to {mailbox.address}. Until you reconnect it, new mail is not being checked. "
                    f"Reconnect here: {self._settings.base_url.rstrip('/')}/mailboxes/{mailbox.id}"
                ),
            )
        await self._notifier.notify_concierge(
            f"Mailbox access lost ({mailbox.address})", f"{exc}\nMailbox {mailbox.id} is now in error state."
        )

    async def _mailbox_failed(self, mailbox: MailboxRow, error: str) -> None:
        log.error("worker.mailbox_failed", mailbox_id=mailbox.id, error=error)
        async with self._db.session() as session:
            await repo.set_mailbox_status(session, mailbox.id, "error", error=error[:1000])
            await repo.audit(
                session, None, "system", "mailbox_error", mailbox.id, details={"error": error[:500]}
            )
        await self._notifier.notify_concierge(f"Mailbox error ({mailbox.address})", error)
