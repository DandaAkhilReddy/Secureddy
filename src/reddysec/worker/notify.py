"""Notifications: dashboard rows always, email and webhook when configured.

Every notification is first written as a ``NotificationRow`` per channel and
committed, then delivered best-effort, then marked sent (or recorded with its
error). Delivery is therefore never inside a database transaction, and a
broken SMTP server can never make the worker lose a verdict.

Email goes through the stdlib ``smtplib`` in a worker thread: it is enough for
the volume of a private-client service and keeps the dependency list short.
"""

from __future__ import annotations

import asyncio
import smtplib
from collections.abc import Callable
from datetime import datetime
from email.message import EmailMessage
from typing import Any

import httpx

from reddysec.config import Settings
from reddysec.core.logging import get_logger
from reddysec.models import Verdict, VerdictLevel
from reddysec.store import repo
from reddysec.store.db import Database
from reddysec.store.models import MessageRow, NotificationRow, UserRow, utcnow

log = get_logger(__name__)

CHANNEL_DASHBOARD = "dashboard"
CHANNEL_EMAIL = "email"
CHANNEL_WEBHOOK = "webhook"
CONCIERGE_ROLES = ("concierge", "admin")
LEVEL_ALERT = "alert"

LEVEL_TITLES = {
    VerdictLevel.SAFE: "Checked",
    VerdictLevel.SUSPICIOUS: "Suspicious message",
    VerdictLevel.MALICIOUS: "Quarantined",
    VerdictLevel.UNKNOWN: "Needs a look",
}


class Notifier:
    def __init__(
        self,
        db: Database,
        settings: Settings,
        *,
        http: httpx.AsyncClient | None = None,
        smtp_factory: Callable[[str, int], smtplib.SMTP] | None = None,
        clock: Callable[[], datetime] | None = None,
    ):
        self._db = db
        self._settings = settings
        self._http = http
        self._smtp_factory = smtp_factory or (lambda host, port: smtplib.SMTP(host, port, timeout=15))
        self._clock = clock or utcnow

    # ----------------------------------------------------------- composing
    def message_url(self, message_id: str) -> str:
        return f"{self._settings.base_url.rstrip('/')}/messages/{message_id}"

    def verdict_text(self, message_row: MessageRow, verdict: Verdict) -> tuple[str, str]:
        """Short, plain English. The client is not a security analyst."""
        subject = message_row.subject or "(no subject)"
        title = f"{LEVEL_TITLES[verdict.level]}: {subject}"
        sender = message_row.from_address or "an unknown sender"
        if message_row.from_name:
            sender = f"{message_row.from_name} <{message_row.from_address}>"
        lines = [verdict.summary.strip(), "", f"From: {sender}", f"Subject: {subject}", ""]
        if message_row.quarantined:
            lines.append(
                "We kept this message out of your inbox. If you were expecting it, you can release it from the page below."
            )
        elif verdict.level is VerdictLevel.SUSPICIOUS:
            lines.append(
                "It is in your inbox, labelled Suspicious. Open its links in the Reading Room, not directly."
            )
        elif verdict.level is VerdictLevel.UNKNOWN:
            lines.append(
                "We could not finish checking it. Treat its links and attachments with care until we have."
            )
        lines += ["", f"Details: {self.message_url(message_row.id)}"]
        return title, "\n".join(lines)

    # ------------------------------------------------------------ sending
    async def notify_verdict(
        self, user: UserRow, message_row: MessageRow, verdict: Verdict
    ) -> list[NotificationRow]:
        title, body = self.verdict_text(message_row, verdict)
        return await self.notify_user(
            user, level=verdict.level.value, title=title, body=body, message_id=message_row.id
        )

    async def notify_user(
        self, user: UserRow, *, level: str, title: str, body: str, message_id: str | None = None
    ) -> list[NotificationRow]:
        return await self._deliver(
            user.id, user.login_email, level=level, title=title, body=body, message_id=message_id
        )

    async def notify_concierge(
        self, subject: str, body: str, *, level: str = LEVEL_ALERT
    ) -> list[NotificationRow]:
        """Our analysts are users with the concierge/admin role; each gets a
        dashboard row and (if SMTP is configured) an email. The webhook, if any,
        fires once."""
        async with self._db.session() as session:
            staff = await repo.list_users(session, roles=CONCIERGE_ROLES)
        rows: list[NotificationRow] = []
        for i, person in enumerate(staff):
            rows += await self._deliver(
                person.id,
                person.login_email,
                level=level,
                title=subject,
                body=body,
                message_id=None,
                webhook=(i == 0),
            )
        if not staff:
            log.warning("notify.no_concierge_users", title=subject)
            await self._send_webhook(
                {"level": level, "title": subject, "body": body, "audience": "concierge"}
            )
        return rows

    async def _deliver(
        self,
        user_id: str,
        email: str | None,
        *,
        level: str,
        title: str,
        body: str,
        message_id: str | None,
        webhook: bool = True,
    ) -> list[NotificationRow]:
        channels = [CHANNEL_DASHBOARD]
        if self._settings.smtp_host and email:
            channels.append(CHANNEL_EMAIL)
        if webhook and self._settings.notify_webhook_url:
            channels.append(CHANNEL_WEBHOOK)

        async with self._db.session() as session:
            rows = [
                await repo.create_notification(
                    session,
                    user_id=user_id,
                    channel=channel,
                    level=level,
                    title=title,
                    body=body,
                    message_id=message_id,
                )
                for channel in channels
            ]

        outcomes: dict[str, str | None] = {}
        for row in rows:
            try:
                if row.channel == CHANNEL_EMAIL:
                    await self.send_email(email or "", title, body)
                elif row.channel == CHANNEL_WEBHOOK:
                    await self._send_webhook(
                        {
                            "level": level,
                            "title": title,
                            "body": body,
                            "user_id": user_id,
                            "message_id": message_id,
                        }
                    )
                outcomes[row.id] = None
            except Exception as exc:  # noqa: BLE001 - best effort by design
                log.warning("notify.channel_failed", channel=row.channel, error=str(exc))
                outcomes[row.id] = str(exc)[:500]

        async with self._db.session() as session:
            for row in rows:
                await repo.mark_notification_sent(session, row.id, error=outcomes.get(row.id))
                row.error = outcomes.get(row.id)
                row.sent_at = None if row.error else self._clock()
        return rows

    async def send_email(self, to: str, subject: str, body: str) -> None:
        if not self._settings.smtp_host:
            raise RuntimeError("SMTP is not configured")
        msg = EmailMessage()
        msg["From"] = self._settings.notification_from
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(body)
        await asyncio.to_thread(self._smtp_send, msg)

    def _smtp_send(self, msg: EmailMessage) -> None:
        s = self._settings
        username, password = s.smtp_username, s.smtp_password.get_secret_value()
        with self._smtp_factory(s.smtp_host, s.smtp_port) as smtp:
            if s.smtp_port == 587 and username:
                smtp.starttls()
            if username and password:
                smtp.login(username, password)
            smtp.send_message(msg)

    async def _send_webhook(self, payload: dict[str, Any]) -> None:
        url = self._settings.notify_webhook_url
        if not url:
            return
        client = self._http
        own = client is None
        if client is None:
            client = httpx.AsyncClient(timeout=10.0)
        try:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
        finally:
            if own:
                await client.aclose()
