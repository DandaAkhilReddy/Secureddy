"""Audit log, concierge queue and notifications."""

from __future__ import annotations

from sqlalchemy import select

from reddysec.store.models import AuditLog, MessageRow, NotificationRow

# --------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------


async def test_audit_page_lists_actions_in_plain_english(client, seed, db, login, csrf_of):
    user = await seed.user("audit@example.com")
    mailbox = await seed.mailbox(user)
    other = await seed.user("other@example.com")
    other_box = await seed.mailbox(other)
    analyst = await seed.user("analyst@example.com", role="concierge")
    await seed.audit(
        actor_id=analyst.id,
        actor_role="concierge",
        action="verdict_override",
        mailbox_id=mailbox.id,
        target="msg_x",
        details={"from": "safe", "to": "malicious"},
    )
    await seed.audit(
        actor_id=None,
        actor_role="system",
        action="mode_changed",
        mailbox_id=mailbox.id,
        target=mailbox.address,
        details={"from": "scan", "to": "hold"},
    )
    await seed.audit(
        actor_id=other.id, actor_role="principal", action="mailbox_paused", mailbox_id=other_box.id
    )
    login(client, "audit@example.com")
    token = csrf_of(client, "/mailboxes")
    client.post(f"/mailboxes/{mailbox.id}/pause", data={"csrf_token": token})

    page = client.get("/audit")
    assert page.status_code == 200
    assert "Signed in" in page.text and "Developer sign-in" in page.text
    assert "Paused protection" in page.text
    assert "Analyst changed a verdict" in page.text and "Checked to Quarantine" in page.text
    assert "Secureddy analyst" in page.text
    assert "Secureddy (automatic)" in page.text and "Scan to Hold" in page.text
    assert "/messages/msg_x" in page.text
    assert (
        page.text.count("<tr>") - 1 == 4
    )  # own login, own pause, override, system mode change; not the other user's
    assert "You" in page.text
    assert "4 entries" in page.text


async def test_audit_pagination(client, seed, login):
    user = await seed.user("pages@example.com")
    mailbox = await seed.mailbox(user)
    for i in range(55):
        await seed.audit(
            actor_id=user.id,
            actor_role="principal",
            action="client_feedback",
            mailbox_id=mailbox.id,
            details={"feedback": "fine" if i % 2 else "bad"},
        )
    login(client, "pages@example.com")
    first = client.get("/audit")
    assert "Page 1 of 2" in first.text and "Older" in first.text and "Newer" not in first.text
    second = client.get("/audit?page=2")
    assert "Page 2 of 2" in second.text and "Newer" in second.text
    assert (
        client.get("/audit?page=99").text.count("<tr>") == 0
        or "Nothing yet" in client.get("/audit?page=99").text
    )


async def test_audit_empty_state(client, seed, db, login):
    await seed.user("empty@example.com")
    login(client, "empty@example.com")
    async with db.session() as s:
        for row in (await s.execute(select(AuditLog))).scalars():
            await s.delete(row)
    assert "Nothing yet" in client.get("/audit").text


# --------------------------------------------------------------------------
# Concierge
# --------------------------------------------------------------------------


async def test_concierge_is_staff_only(client, seed, login):
    await seed.user("client@example.com")
    login(client, "client@example.com")
    forbidden = client.get("/concierge")
    assert forbidden.status_code == 403 and "for Secureddy staff" in forbidden.text
    assert "Concierge" not in client.get("/").text.split("<main")[0]


async def test_concierge_queue_review_and_override(client, seed, db, login, csrf_of, make_verdict):
    owner = await seed.user("victim@example.com", name="Vic Tim")
    mailbox = await seed.mailbox(owner)
    flagged = await seed.message(
        mailbox,
        verdict={
            **make_verdict("suspicious", needs_human_review=True),
            "review_request": {"note": "Looks odd to me"},
        },
        level="suspicious",
        quarantined=False,
        subject="Please approve the transfer",
    )
    await seed.message(mailbox, level="safe", subject="Not flagged")
    await seed.message(
        mailbox,
        verdict=make_verdict("suspicious", needs_human_review=True),
        level="suspicious",
        quarantined=False,
        state="reviewed",
        subject="Already reviewed",
    )
    await seed.user("desk@example.com", role="concierge")
    login(client, "desk@example.com", role="concierge")

    page = client.get("/concierge")
    assert page.status_code == 200
    assert "Please approve the transfer" in page.text and "1 waiting" in page.text
    assert "Not flagged" not in page.text and "Already reviewed" not in page.text
    assert "Looks odd to me" in page.text and "Vic Tim" in page.text
    assert "Concierge" in page.text.split("<main")[0]  # nav shows the staff link

    token = csrf_of(client, "/concierge")
    override = client.post(
        f"/concierge/{flagged.id}/override",
        data={
            "level": "malicious",
            "note": "The sender domain was registered yesterday.",
            "csrf_token": token,
        },
    )
    assert override.status_code == 303 and override.headers["location"] == "/concierge"
    async with db.session() as s:
        row = await s.get(MessageRow, flagged.id)
        notes = (
            (await s.execute(select(NotificationRow).where(NotificationRow.user_id == owner.id)))
            .scalars()
            .all()
        )
        actions = [
            a.action
            for a in (
                await s.execute(select(AuditLog).where(AuditLog.target == flagged.id).order_by(AuditLog.at))
            ).scalars()
        ]
    assert row.level == "malicious" and row.score == 70 and row.state == "reviewed"
    assert row.verdict["level"] == "malicious" and row.verdict["score"] == 70
    assert row.verdict["summary"].startswith("Reviewed by a Secureddy analyst: The sender domain")
    assert (
        row.verdict["override"]["from_level"] == "suspicious"
        and row.verdict["override"]["to_level"] == "malicious"
    )
    assert row.verdict["review"]["note"].startswith("The sender domain")
    assert actions == ["concierge_reviewed", "verdict_override"]
    assert len(notes) == 1 and "now marked malicious" in notes[0].body
    after = client.get("/concierge")
    assert "The queue is empty" in after.text and "Verdict changed to Quarantine" in after.text

    # The client sees the analyst's note on the report and in their log.
    client.cookies.clear()
    login(client, "victim@example.com")
    report = client.get(f"/messages/{flagged.id}")
    assert "Analyst's note: The sender domain was registered yesterday." in report.text
    assert "One of our analysts has looked at this email." in report.text
    assert "Analyst changed a verdict" in client.get("/audit").text
    assert "Our analyst reviewed one of your emails" in client.get("/notifications").text


async def test_concierge_mark_reviewed_keeps_pending_restore(client, seed, db, login, csrf_of, make_verdict):
    owner = await seed.user("restore@example.com")
    mailbox = await seed.mailbox(owner)
    message = await seed.message(
        mailbox,
        verdict=make_verdict("malicious", needs_human_review=True),
        level="malicious",
        state="restore_requested",
        restored_by_client=True,
    )
    plain = await seed.message(
        mailbox,
        verdict=make_verdict("suspicious", needs_human_review=True),
        level="suspicious",
        quarantined=False,
    )
    await seed.user("desk2@example.com", role="admin")
    login(client, "desk2@example.com", role="admin")
    token = csrf_of(client, "/concierge")
    assert (
        client.post(
            f"/concierge/{message.id}/reviewed", data={"note": "Fine", "csrf_token": token}
        ).status_code
        == 303
    )
    assert client.post(f"/concierge/{plain.id}/reviewed", data={"csrf_token": token}).status_code == 303
    async with db.session() as s:
        kept = await s.get(MessageRow, message.id)
        closed = await s.get(MessageRow, plain.id)
    assert kept.state == "restore_requested" and kept.verdict["review"]["note"] == "Fine"
    assert closed.state == "reviewed"
    after = client.get("/concierge")
    assert "The queue is empty" in after.text and "Marked as reviewed" in after.text


async def test_concierge_bad_input(client, seed, login, csrf_of):
    await seed.user("desk3@example.com", role="concierge")
    owner = await seed.user("o@example.com")
    message = await seed.message(await seed.mailbox(owner))
    login(client, "desk3@example.com", role="concierge")
    token = csrf_of(client, "/concierge")
    assert (
        client.post(
            f"/concierge/{message.id}/override", data={"level": "banana", "csrf_token": token}
        ).status_code
        == 400
    )
    assert (
        client.post("/concierge/msg_nope/override", data={"level": "safe", "csrf_token": token}).status_code
        == 404
    )
    assert client.post("/concierge/msg_nope/reviewed", data={"csrf_token": token}).status_code == 404
    ok = client.post(
        f"/concierge/{message.id}/override", data={"level": "safe", "note": "", "csrf_token": token}
    )
    assert ok.status_code == 303


async def test_principal_cannot_use_concierge_actions(client, seed, login, csrf_of):
    owner = await seed.user("sneaky@example.com")
    message = await seed.message(await seed.mailbox(owner))
    login(client, "sneaky@example.com")
    token = csrf_of(client, "/")
    assert client.post(f"/concierge/{message.id}/reviewed", data={"csrf_token": token}).status_code == 403
    assert (
        client.post(
            f"/concierge/{message.id}/override", data={"level": "safe", "csrf_token": token}
        ).status_code
        == 403
    )


# --------------------------------------------------------------------------
# Notifications
# --------------------------------------------------------------------------


async def test_notifications_page(client, seed, login):
    user = await seed.user("notify@example.com")
    message = await seed.message(await seed.mailbox(user))
    await seed.notification(user, message=message, title="Quarantined: Reset your password now")
    await seed.notification(
        user,
        level="suspicious",
        title="Please take care with one email",
        channel="email",
        sent_at=message.received_at,
    )
    login(client, "notify@example.com")
    page = client.get("/notifications")
    assert page.status_code == 200
    assert (
        "Quarantined: Reset your password now" in page.text and "Please take care with one email" in page.text
    )
    assert "Sent by email" in page.text and "Shown here" in page.text
    assert f"/messages/{message.id}" in page.text


async def test_notifications_empty_state(client, login):
    login(client, "nonotes@example.com")
    assert "No notices" in client.get("/notifications").text
