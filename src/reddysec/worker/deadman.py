"""Dead man's switch for HOLD mode.

HOLD mode parks new mail outside the inbox until a verdict exists. If the
worker stops (crash, deploy gone wrong, cloud outage) that mail would wait
forever, which is worse than any phishing email. So: the worker heart-beats
per HOLD mailbox on every successful cycle, and this watchdog releases every
held message of a mailbox whose heartbeat is stale, removes the hold rule so
*new* mail flows normally, puts the mailbox in error state, and tells both
the client and the concierge.

Run it as a separate process (``reddysec deadman``), ideally on a different
host from the worker: a watchdog that dies with the thing it watches is
decoration. ``python -m reddysec.worker`` runs both together for development.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta

from reddysec.config import Settings
from reddysec.core.logging import get_logger
from reddysec.mail.base import ConnectorError
from reddysec.mail.factory import ConnectorFactory
from reddysec.store import repo
from reddysec.store.db import Database
from reddysec.store.models import MailboxRow, utcnow
from reddysec.worker.engine import MODE_KEY
from reddysec.worker.notify import LEVEL_ALERT, Notifier

log = get_logger(__name__)

DEFAULT_INTERVAL_S = 60.0


class DeadManSwitch:
    def __init__(
        self,
        db: Database,
        settings: Settings,
        *,
        connector_factory: ConnectorFactory,
        notifier: Notifier,
        clock: Callable[[], datetime] = utcnow,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        interval_s: float = DEFAULT_INTERVAL_S,
    ):
        self._db = db
        self._settings = settings
        self._connector_factory = connector_factory
        self._notifier = notifier
        self._clock = clock
        self._sleep = sleep
        self._interval_s = interval_s

    @property
    def threshold(self) -> timedelta:
        return timedelta(minutes=self._settings.hold_dead_man_minutes)

    async def run_forever(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            try:
                await self.check_once()
            except Exception:  # noqa: BLE001 - the watchdog must never die quietly
                log.exception("deadman.check_crashed")
            if stop_event.is_set():
                break
            await self._sleep(self._interval_s)

    async def check_once(self) -> list[str]:
        """Release every stale HOLD mailbox. Returns the ids that were released."""
        async with self._db.session() as session:
            stale = await repo.stale_hold_mailboxes(session, self.threshold, now=self._clock())
        released: list[str] = []
        for mailbox in stale:
            try:
                await self.release_mailbox(mailbox, reason="heartbeat stale")
                released.append(mailbox.id)
            except ConnectorError as exc:
                # Mail may still be trapped: this is the one alert that must reach a human.
                log.error("deadman.release_failed", mailbox_id=mailbox.id, error=str(exc))
                async with self._db.session() as session:
                    await repo.audit(
                        session,
                        None,
                        "system",
                        "deadman_release_failed",
                        mailbox.id,
                        details={"error": str(exc)[:500]},
                    )
                await self._notifier.notify_concierge(
                    f"URGENT: dead man's switch could not release mail ({mailbox.address})",
                    f"Mailbox {mailbox.id}: {exc}\nHeld mail may still be waiting. Release it manually.",
                )
        return released

    async def release_mailbox(
        self, mailbox: MailboxRow, *, reason: str, actor_id: str | None = None, actor_role: str = "system"
    ) -> int:
        """Release everything held for one mailbox and disarm HOLD. Also used by
        the ``reddysec release-all`` command for a manual release."""
        connector = await self._connector_factory(mailbox)
        count = await connector.release_all_pending()
        try:
            await connector.teardown()
        except ConnectorError as exc:
            # Held mail is already out; a leftover rule is a lesser problem that
            # the concierge is told about below.
            log.error("deadman.teardown_failed", mailbox_id=mailbox.id, error=str(exc))
            reason = f"{reason}; hold rule could not be removed: {exc}"

        labels = {k: v for k, v in dict(mailbox.labels or {}).items() if k != MODE_KEY}
        error_text = f"dead man's switch released {count} held message(s): {reason}"
        async with self._db.session() as session:
            await repo.mark_deadman_release(session, mailbox.id, at=self._clock())
            await repo.mark_released_by_deadman(session, mailbox.id)
            await repo.set_mailbox_labels(session, mailbox.id, labels)  # forces setup when re-activated
            await repo.set_mailbox_status(session, mailbox.id, "error", error=error_text)
            await repo.audit(
                session,
                actor_id,
                actor_role,
                "deadman_release",
                mailbox.id,
                details={"released": count, "reason": reason},
            )
            user = await repo.get_user(session, mailbox.user_id)
        log.warning("deadman.released", mailbox_id=mailbox.id, count=count, reason=reason)

        if user is not None:
            await self._notifier.notify_user(
                user,
                level=LEVEL_ALERT,
                title="We released your held mail",
                body=(
                    f"Our checking service stopped responding, so we moved {count} waiting message(s) back into "
                    f"the inbox of {mailbox.address}. Those messages were NOT checked: open their links in the "
                    "Reading Room, not directly. Hold mode is paused until we have confirmed everything is healthy."
                ),
            )
        await self._notifier.notify_concierge(
            f"Dead man's switch fired ({mailbox.address})",
            f"Mailbox {mailbox.id}: released {count} message(s). Reason: {reason}. "
            "The mailbox is in error state and its hold rule was removed; re-activate it after the fix.",
        )
        return count
