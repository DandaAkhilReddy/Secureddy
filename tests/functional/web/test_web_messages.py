"""The report page, client actions and artifact serving."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from starlette.testclient import TestClient

from reddysec.models import Signal, SignalStage
from reddysec.store.models import AuditLog, MessageRow, NotificationRow
from reddysec.web.app import create_app

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
PDF = b"%PDF-1.4 safe copy"


@pytest.fixture
def rich_message(seed, artifact_store, make_verdict):
    """Builds a quarantined message with two links (one with a screenshot), two
    attachments (one with a safe copy) and mixed signals."""

    async def build(user, **overrides):
        mailbox = await seed.mailbox(user)
        shot = artifact_store.put(PNG, suffix="png")
        safe = artifact_store.put(PDF, suffix="pdf")
        verdict = make_verdict(
            "malicious",
            summary="This email pretends to be your bank. The link leads to a fake sign-in page.",
            urls=[
                {
                    "url": "https://secure-bank-login.example/verify",
                    "final_url": "https://evil-host.example/harvest",
                    "screenshot_ref": shot,
                    "detonated": True,
                    "signals": [
                        Signal(
                            code="url.new_domain",
                            stage=SignalStage.INTEL,
                            weight=35,
                            title="The website is three days old",
                        ).model_dump(mode="json")
                    ],
                },
                {"url": "https://example.org/newsletter", "level": "safe", "score": 2, "detonated": True},
            ],
            attachments=[
                {
                    "filename": "Statement.pdf",
                    "sha256": "a" * 64,
                    "level": "suspicious",
                    "score": 40,
                    "safe_copy_ref": safe,
                },
                {"filename": "notes.txt", "sha256": "b" * 64, "level": "safe", "score": 0},
            ],
        )
        message = await seed.message(
            mailbox, verdict=verdict, level="malicious", subject="Urgent: verify your account", **overrides
        )
        return mailbox, message, shot, safe

    return build


async def _audit_actions(db, target):
    async with db.session() as s:
        rows = (await s.execute(select(AuditLog).where(AuditLog.target == target))).scalars().all()
    return [r.action for r in rows]


async def test_report_renders_everything(client, seed, artifact_store, login, rich_message):
    user = await seed.user("report@example.com")
    _, message, shot, safe = await rich_message(user)
    login(client, "report@example.com")
    page = client.get(f"/messages/{message.id}")
    assert page.status_code == 200
    text = page.text
    assert "This email pretends to be your bank." in text
    assert "Urgent: verify your account" in text
    assert "The page asked for a password" in text and "bar-w60" in text
    assert "You have written to this sender before" in text and "signal-trust" in text
    assert "The website is three days old" in text
    assert "https://secure-bank-login.example/verify" in text
    assert "Ends up at" in text and "evil-host.example/harvest" in text
    assert "<a" not in text.split("Links in this email")[1].split("Open in Reading Room")[0].replace(
        '<a class="link"', ""
    )
    assert f'src="/artifacts/{shot}?m={message.id}"' in text
    assert f'href="/artifacts/{safe}?m={message.id}&amp;download=1"' in text
    assert "Get safe copy" in text and "Statement.pdf" in text and "notes.txt" in text
    assert (
        'action="/room/start"' in text
        and 'name="url" value="https://secure-bank-login.example/verify"' in text
    )
    assert "Release to my inbox" in text
    assert "Ask the concierge to review" in text
    # Quarantined: the primary action is "Not fake?", with its own reasons.
    assert "Not fake?" in text and "Not fake, move it back" in text and "This is fake" in text
    assert "It&#39;s from a company I use" in text and "I was expecting this" in text
    assert "Not suspicious?" not in text.split('id="decide"')[1].split("</section>")[0]
    assert "I know this sender" in text and "Asks for money or codes" in text  # quick-pick reasons
    assert f'action="/messages/{message.id}/safe"' in text and f'action="/messages/{message.id}/fake"' in text
    assert "Check again" in text and "Why we think this" in text and "What we checked" in text
    assert "Opened in our sandbox before you saw it" in text


async def test_report_without_room_router_disables_button(
    settings, db, seed, artifact_store, login, rich_message
):
    user = await seed.user("noroom@example.com")
    _, message, _, _ = await rich_message(user)
    app = create_app(settings, db=db, room_router=None, artifact_store=artifact_store)
    with TestClient(app, follow_redirects=False) as c:
        login(c, "noroom@example.com")
        page = c.get(f"/messages/{message.id}")
        assert "Reading Room unavailable" in page.text and 'action="/room/start"' not in page.text


async def test_reading_room_form_posts_to_room_router(
    client, seed, artifact_store, room_calls, login, csrf_of, rich_message
):
    user = await seed.user("room@example.com")
    _, message, _, _ = await rich_message(user)
    login(client, "room@example.com")
    token = csrf_of(client, f"/messages/{message.id}")
    response = client.post(
        "/room/start",
        data={
            "url": "https://secure-bank-login.example/verify",
            "message_id": message.id,
            "csrf_token": token,
        },
    )
    assert response.status_code == 303 and response.headers["location"].startswith("/room/")
    assert room_calls == [{"url": "https://secure-bank-login.example/verify", "message_id": message.id}]


async def test_report_is_private_to_owner_but_visible_to_staff(
    client, seed, artifact_store, login, rich_message
):
    owner = await seed.user("owner@example.com")
    _, message, _, _ = await rich_message(owner)
    await seed.user("stranger@example.com")
    await seed.user("analyst@example.com", role="concierge")
    login(client, "stranger@example.com")
    assert client.get(f"/messages/{message.id}").status_code == 404
    client.cookies.clear()
    login(client, "analyst@example.com", role="concierge")
    page = client.get(f"/messages/{message.id}")
    assert page.status_code == 200 and "<dt>State</dt>" in page.text


async def test_report_for_pending_and_malformed_verdicts(client, seed, login, make_verdict):
    user = await seed.user("pending@example.com")
    mailbox = await seed.mailbox(user)
    pending = await seed.message(mailbox, level=None, state="analyzing", subject="In the sandbox")
    broken = await seed.message(
        mailbox,
        verdict={"level": "nonsense"},
        level="unknown",
        state="failed",
        quarantined=False,
        subject="Broken verdict",
    )
    deadman = await seed.message(
        mailbox,
        level="unknown",
        state="released_by_deadman",
        quarantined=False,
        verdict=make_verdict("unknown", lane="release_fast"),
    )
    login(client, "pending@example.com")
    page = client.get(f"/messages/{pending.id}")
    assert (
        page.status_code == 200
        and "We are still checking this email" in page.text
        and "Checking" in page.text
    )
    page = client.get(f"/messages/{broken.id}")
    assert page.status_code == 200 and "could not produce a full report" in page.text
    assert "Could not check" in page.text and "Treat it with care" in page.text
    page = client.get(f"/messages/{deadman.id}")
    assert "We never hold mail hostage" in page.text


async def test_release_sets_restore_requested(client, seed, artifact_store, db, login, csrf_of, rich_message):
    user = await seed.user("release@example.com")
    _, message, _, _ = await rich_message(user)
    login(client, "release@example.com")
    token = csrf_of(client, f"/messages/{message.id}")
    response = client.post(f"/messages/{message.id}/release", data={"csrf_token": token})
    assert response.status_code == 303 and response.headers["location"] == f"/messages/{message.id}"
    async with db.session() as s:
        row = await s.get(MessageRow, message.id)
    assert row.state == "restore_requested" and row.restored_by_client is True and row.quarantined is True
    assert await _audit_actions(db, message.id) == ["restore_requested"]
    page = client.get(f"/messages/{message.id}")
    assert "moving this email back to your inbox" in page.text
    assert "You asked for this email back" in page.text
    assert "Release to my inbox" not in page.text  # no second request while one is pending
    again = client.post(f"/messages/{message.id}/release", data={"csrf_token": token})
    assert again.status_code == 303
    assert "nothing to release" in client.get(f"/messages/{message.id}").text
    assert await _audit_actions(db, message.id) == ["restore_requested"]


async def test_release_of_unquarantined_message_does_nothing(client, seed, db, login, csrf_of):
    user = await seed.user("safe@example.com")
    message = await seed.message(await seed.mailbox(user), level="safe")
    login(client, "safe@example.com")
    token = csrf_of(client, "/")
    client.post(f"/messages/{message.id}/release", data={"csrf_token": token})
    async with db.session() as s:
        row = await s.get(MessageRow, message.id)
    assert row.state == "done" and row.restored_by_client is False


async def test_actions_on_foreign_message_are_404(client, seed, login, csrf_of):
    owner = await seed.user("owner2@example.com")
    message = await seed.message(await seed.mailbox(owner))
    await seed.user("intruder@example.com")
    login(client, "intruder@example.com")
    token = csrf_of(client, "/")
    assert client.post(f"/messages/{message.id}/release", data={"csrf_token": token}).status_code == 404
    assert client.post(f"/messages/{message.id}/review", data={"csrf_token": token}).status_code == 404
    assert (
        client.post(
            f"/messages/{message.id}/feedback", data={"verdict": "fine", "csrf_token": token}
        ).status_code
        == 404
    )


async def test_concierge_request_flags_message_and_notifies_staff(client, seed, db, login, csrf_of):
    user = await seed.user("asker@example.com")
    staff = await seed.user("desk@example.com", role="concierge")
    await seed.user("retired@example.com", role="concierge", disabled=True)
    mailbox = await seed.mailbox(user)
    message = await seed.message(
        mailbox, level="suspicious", quarantined=False, subject="Wire the deposit today"
    )
    login(client, "asker@example.com")
    token = csrf_of(client, f"/messages/{message.id}")
    response = client.post(
        f"/messages/{message.id}/review", data={"note": "My lawyer never emails me", "csrf_token": token}
    )
    assert response.status_code == 303
    async with db.session() as s:
        row = await s.get(MessageRow, message.id)
        notes = (await s.execute(select(NotificationRow))).scalars().all()
    assert row.verdict["needs_human_review"] is True
    assert row.verdict["review_request"]["note"] == "My lawyer never emails me"
    assert [n.user_id for n in notes] == [staff.id]
    assert notes[0].channel == "dashboard" and "Wire the deposit today" in notes[0].body
    assert await _audit_actions(db, message.id) == ["review_requested"]
    assert "concierge will look at this email" in client.get(f"/messages/{message.id}").text


async def test_feedback_is_audited(client, seed, db, login, csrf_of):
    user = await seed.user("feedback@example.com")
    message = await seed.message(await seed.mailbox(user), level="safe")
    login(client, "feedback@example.com")
    token = csrf_of(client, "/")
    assert (
        client.post(
            f"/messages/{message.id}/feedback", data={"verdict": "bad", "csrf_token": token}
        ).status_code
        == 303
    )
    assert (
        client.post(
            f"/messages/{message.id}/feedback", data={"verdict": "meh", "csrf_token": token}
        ).status_code
        == 400
    )
    async with db.session() as s:
        entry = (await s.execute(select(AuditLog).where(AuditLog.action == "client_feedback"))).scalar_one()
    assert entry.details == {"feedback": "bad", "level": "safe"} and entry.actor_id is not None
    assert "Thank you" in client.get(f"/messages/{message.id}").text


# --------------------------------------------------------------------------
# Artifacts
# --------------------------------------------------------------------------


async def test_screenshot_served_for_own_message(client, seed, artifact_store, login, rich_message):
    user = await seed.user("shots@example.com")
    _, message, shot, safe = await rich_message(user)
    login(client, "shots@example.com")
    response = client.get(f"/artifacts/{shot}?m={message.id}")
    assert response.status_code == 200
    assert response.content == PNG
    assert response.headers["content-type"] == "image/png"
    assert response.headers["cache-control"] == "private, max-age=300"
    assert "content-disposition" not in response.headers
    pdf = client.get(f"/artifacts/{safe}?m={message.id}&download=1")
    assert pdf.status_code == 200 and pdf.content == PDF
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.headers["content-disposition"].startswith('attachment; filename="safe-copy-')


async def test_screenshot_404_for_another_users_message(client, seed, artifact_store, login, rich_message):
    owner = await seed.user("owner3@example.com")
    _, message, shot, _ = await rich_message(owner)
    await seed.user("peeker@example.com")
    login(client, "peeker@example.com")
    assert client.get(f"/artifacts/{shot}?m={message.id}").status_code == 404


async def test_artifact_must_be_referenced_by_the_message(client, seed, artifact_store, login, rich_message):
    user = await seed.user("refs@example.com")
    _, message, shot, _ = await rich_message(user)
    unrelated = artifact_store.put(b"other", suffix="png")
    other_message = await seed.message(await seed.mailbox(user, address="second@gmail.com"), level="safe")
    login(client, "refs@example.com")
    assert client.get(f"/artifacts/{unrelated}?m={message.id}").status_code == 404
    assert client.get(f"/artifacts/{shot}?m={other_message.id}").status_code == 404
    assert client.get(f"/artifacts/{shot}").status_code == 400  # message id is required
    assert client.get(f"/artifacts/{shot}?m=msg_missing").status_code == 404


async def test_artifact_rejects_traversal_refs_even_when_listed(
    client, seed, artifact_store, tmp_path, login, make_verdict
):
    """A hostile ref written into a verdict must still never reach the disk."""
    user = await seed.user("traversal@example.com")
    mailbox = await seed.mailbox(user)
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("kek")
    evil_refs = ["local:../../secret.txt", "local:/etc/passwd", "s3:bucket/key", "local:"]
    verdict = make_verdict(
        "malicious",
        urls=[{"url": f"https://x.example/{i}", "screenshot_ref": ref} for i, ref in enumerate(evil_refs)],
    )
    message = await seed.message(mailbox, verdict=verdict, level="malicious")
    login(client, "traversal@example.com")
    for ref in evil_refs:
        response = client.get(f"/artifacts/{ref}?m={message.id}")
        assert response.status_code in (404, 400), (ref, response.status_code)
        assert b"kek" not in response.content


async def test_artifact_missing_on_disk_is_404(client, seed, artifact_store, login, rich_message):
    user = await seed.user("gonefile@example.com")
    _, message, shot, _ = await rich_message(user)
    artifact_store.delete(shot)
    login(client, "gonefile@example.com")
    assert client.get(f"/artifacts/{shot}?m={message.id}").status_code == 404
