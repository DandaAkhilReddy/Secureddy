""""This is safe" / "This is fake" / "Check again", the trusted & blocked
senders list, the clickable dashboard and the message list tabs."""

from __future__ import annotations

from sqlalchemy import select

from reddysec.models import Signal, SignalStage
from reddysec.store.models import AuditLog, MessageRow, SenderFeedbackRow

DMARC_OK = Signal(code="auth.dmarc_pass_aligned", stage=SignalStage.STATIC, weight=-15, title="Verified")


def _verdict(make_verdict, level: str, *, verified: str = "", signals=None):
    v = make_verdict(level, signals=signals)
    v["verified_domain"] = verified
    return v


async def _entries(db):
    async with db.session() as s:
        return list((await s.execute(select(SenderFeedbackRow))).scalars())


async def _message(db, message_id):
    async with db.session() as s:
        return await s.get(MessageRow, message_id)


async def _actions(db):
    async with db.session() as s:
        return [a.action for a in (await s.execute(select(AuditLog))).scalars()]


async def _setup(seed, login, client, make_verdict, *, level="suspicious", verified="walmart.com",
                 sender="help@walmart.com", **kw):
    user = await seed.user("owner@example.com")
    mailbox = await seed.mailbox(user)
    message = await seed.message(
        mailbox, level=level, verdict=_verdict(make_verdict, level, verified=verified), from_address=sender,
        from_name="Walmart.com", subject="Thanks for your order", **kw,
    )
    login(client, "owner@example.com")
    return user, mailbox, message


class TestThisIsSafe:
    async def test_verified_sender_trusts_domain_and_relabels(self, client, seed, login, csrf_of, make_verdict, db):
        _u, mailbox, message = await _setup(seed, login, client, make_verdict)
        token = csrf_of(client, f"/messages/{message.id}")
        response = client.post(f"/messages/{message.id}/safe", data={"csrf_token": token})
        assert response.status_code == 303 and response.headers["location"] == f"/messages/{message.id}"
        (entry,) = await _entries(db)
        assert (entry.scope, entry.value, entry.decision, entry.authenticated) == ("domain", "walmart.com", "trusted", True)
        assert entry.created_by and entry.source_message_id == message.id
        row = await _message(db, message.id)
        assert row.state == "relabel_safe_requested" and row.verdict["client_decision"]["decision"] == "safe"
        page = client.get(f"/messages/{message.id}").text
        assert "Done. We marked it Checked. Next time walmart.com writes, we&#39;ll still check it and tell you if it&#39;s safe." in page
        assert "Its label changes to Checked within a minute" in page
        assert "sender_trusted" in await _actions(db)

    async def test_quarantined_message_is_restored(self, client, seed, login, csrf_of, make_verdict, db):
        _u, _mb, message = await _setup(seed, login, client, make_verdict, level="malicious")
        client.post(f"/messages/{message.id}/safe", data={"csrf_token": csrf_of(client, f"/messages/{message.id}")})
        row = await _message(db, message.id)
        assert row.state == "restore_requested" and row.restored_by_client

    async def test_unverified_sender_gets_weak_address_trust(self, client, seed, login, csrf_of, make_verdict, db):
        _u, _mb, message = await _setup(seed, login, client, make_verdict, verified="", sender="Office@SmallShop.com")
        client.post(f"/messages/{message.id}/safe", data={"csrf_token": csrf_of(client, f"/messages/{message.id}")})
        (entry,) = await _entries(db)
        assert (entry.scope, entry.value, entry.authenticated) == ("address", "office@smallshop.com", False)
        page = client.get(f"/messages/{message.id}").text
        assert "Because it wasn&#39;t verified by Google, we trust it only a little." in page

    async def test_old_verdict_without_field_uses_dmarc_signal(self, client, seed, login, csrf_of, make_verdict, db):
        user = await seed.user("owner@example.com")
        mailbox = await seed.mailbox(user)
        v = make_verdict("suspicious", signals=[DMARC_OK])
        message = await seed.message(mailbox, level="suspicious", verdict=v, from_address="news@email.rei.com")
        login(client, "owner@example.com")
        client.post(f"/messages/{message.id}/safe", data={"csrf_token": csrf_of(client, f"/messages/{message.id}")})
        (entry,) = await _entries(db)
        assert (entry.scope, entry.value) == ("domain", "rei.com")

    async def test_freemail_trusts_only_the_address(self, client, seed, login, csrf_of, make_verdict, db):
        _u, _mb, message = await _setup(seed, login, client, make_verdict, verified="gmail.com",
                                        sender="friend@gmail.com")
        client.post(f"/messages/{message.id}/safe", data={"csrf_token": csrf_of(client, f"/messages/{message.id}")})
        (entry,) = await _entries(db)
        assert (entry.scope, entry.value, entry.authenticated) == ("address", "friend@gmail.com", True)
        assert "Many people send email from gmail.com" in client.get(f"/messages/{message.id}").text

    async def test_second_safe_updates_the_same_entry(self, client, seed, login, csrf_of, make_verdict, db):
        _u, _mb, message = await _setup(seed, login, client, make_verdict, level="safe")
        url = f"/messages/{message.id}"
        client.post(f"{url}/safe", data={"csrf_token": csrf_of(client, url)})
        assert (await _message(db, message.id)).state == "done"  # already Checked: nothing to move
        client.post(f"{url}/safe", data={"csrf_token": csrf_of(client, url)})
        assert len(await _entries(db)) == 1

    async def test_safe_after_fake_replaces_the_block(self, client, seed, login, csrf_of, make_verdict, db):
        _u, _mb, message = await _setup(seed, login, client, make_verdict)
        url = f"/messages/{message.id}"
        client.post(f"{url}/fake", data={"csrf_token": csrf_of(client, url)})
        assert [e.decision for e in await _entries(db)] == ["blocked"]
        async with db.session() as s:  # let the "worker" finish the quarantine
            (await s.get(MessageRow, message.id)).state = "done"
        client.post(f"{url}/safe", data={"csrf_token": csrf_of(client, url)})
        assert [e.decision for e in await _entries(db)] == ["trusted"]


class TestThisIsFake:
    async def test_blocks_domain_and_quarantines(self, client, seed, login, csrf_of, make_verdict, db):
        _u, _mb, message = await _setup(seed, login, client, make_verdict)
        client.post(f"/messages/{message.id}/fake", data={"csrf_token": csrf_of(client, f"/messages/{message.id}")})
        (entry,) = await _entries(db)
        assert (entry.scope, entry.value, entry.decision) == ("domain", "walmart.com", "blocked")
        assert (await _message(db, message.id)).state == "quarantine_requested"
        page = client.get(f"/messages/{message.id}").text
        assert "email from walmart.com goes straight to Quarantine" in page
        assert "sender_blocked" in await _actions(db)

    async def test_unverified_fake_only_blocks_unverified_mail(self, client, seed, login, csrf_of, make_verdict, db):
        _u, _mb, message = await _setup(seed, login, client, make_verdict, verified="", sender="boss@company.com")
        client.post(f"/messages/{message.id}/fake", data={"csrf_token": csrf_of(client, f"/messages/{message.id}")})
        (entry,) = await _entries(db)
        assert (entry.scope, entry.authenticated) == ("address", False)
        assert "but is not confirmed by Google" in client.get(f"/messages/{message.id}").text

    async def test_already_quarantined_message_is_not_moved_again(self, client, seed, login, csrf_of, make_verdict, db):
        _u, _mb, message = await _setup(seed, login, client, make_verdict, level="malicious")
        client.post(f"/messages/{message.id}/fake", data={"csrf_token": csrf_of(client, f"/messages/{message.id}")})
        assert (await _message(db, message.id)).state == "done"

    async def test_message_without_sender_is_400(self, client, seed, login, csrf_of, make_verdict):
        _u, _mb, message = await _setup(seed, login, client, make_verdict, verified="", sender="")
        r = client.post(f"/messages/{message.id}/fake", data={"csrf_token": csrf_of(client, f"/messages/{message.id}")})
        assert r.status_code == 400


class TestAuthorisation:
    async def test_csrf_required(self, client, seed, login, make_verdict):
        _u, _mb, message = await _setup(seed, login, client, make_verdict)
        for action in ("safe", "fake", "recheck"):
            assert client.post(f"/messages/{message.id}/{action}").status_code == 403

    async def test_another_users_message_is_404(self, client, seed, login, csrf_of, make_verdict, db):
        other = await seed.user("other@example.com")
        foreign = await seed.message(await seed.mailbox(other), level="suspicious",
                                     verdict=_verdict(make_verdict, "suspicious", verified="walmart.com"))
        await seed.user("me@example.com")
        login(client, "me@example.com")
        token = csrf_of(client, "/")
        for action in ("safe", "fake", "recheck"):
            assert client.post(f"/messages/{foreign.id}/{action}", data={"csrf_token": token}).status_code == 404
        assert await _entries(db) == []

    async def test_other_users_mailbox_actions_are_404(self, client, seed, login, csrf_of, make_verdict, db):
        owner = await seed.user("owner2@example.com")
        mailbox = await seed.mailbox(owner)
        async with db.session() as s:
            s.add(SenderFeedbackRow(id="sfb_x", mailbox_id=mailbox.id, scope="domain", value="a.com",
                                    decision="trusted", authenticated=True))
        await seed.user("me@example.com")
        login(client, "me@example.com")
        token = csrf_of(client, "/")
        assert client.post(f"/mailboxes/{mailbox.id}/senders/sfb_x/remove", data={"csrf_token": token}).status_code == 404
        assert client.post(f"/mailboxes/{mailbox.id}/recheck", data={"csrf_token": token}).status_code == 404
        assert len(await _entries(db)) == 1


class TestCheckAgain:
    async def test_message_recheck(self, client, seed, login, csrf_of, make_verdict, db):
        _u, _mb, message = await _setup(seed, login, client, make_verdict)
        url = f"/messages/{message.id}"
        client.post(f"{url}/recheck", data={"csrf_token": csrf_of(client, url)})
        assert (await _message(db, message.id)).state == "rescore_requested"
        page = client.get(url).text
        assert "checking this email again" in page and "Check again</button>" not in page
        # a second request while one is waiting changes nothing
        assert client.post(f"{url}/recheck", data={"csrf_token": csrf_of(client, url)}).status_code == 303
        assert "already being checked" in client.get(url).text
        assert "rescore_requested" in await _actions(db)

    async def test_mailbox_recheck_last_7_days(self, client, seed, login, csrf_of, make_verdict, db):
        user = await seed.user("owner@example.com")
        mailbox = await seed.mailbox(user)
        recent = await seed.message(mailbox, level="suspicious", hours_ago=30)
        old = await seed.message(mailbox, level="suspicious", hours_ago=24 * 9)
        busy = await seed.message(mailbox, level=None, verdict=None, state="analyzing", hours_ago=1)
        login(client, "owner@example.com")
        r = client.post(f"/mailboxes/{mailbox.id}/recheck", data={"csrf_token": csrf_of(client, "/mailboxes")})
        assert r.status_code == 303
        assert (await _message(db, recent.id)).state == "rescore_requested"
        assert (await _message(db, old.id)).state == "done"
        assert (await _message(db, busy.id)).state == "analyzing"
        assert "We are checking 1 email from the last 7 days again" in client.get("/mailboxes").text

    async def test_mailbox_recheck_nothing(self, client, seed, login, csrf_of):
        user = await seed.user("owner@example.com")
        mailbox = await seed.mailbox(user)
        login(client, "owner@example.com")
        client.post(f"/mailboxes/{mailbox.id}/recheck", data={"csrf_token": csrf_of(client, "/mailboxes")})
        assert "no email from the last 7 days" in client.get("/mailboxes").text


class TestSenderList:
    async def test_list_and_remove(self, client, seed, login, csrf_of, db):
        user = await seed.user("owner@example.com")
        mailbox = await seed.mailbox(user)
        async with db.session() as s:
            s.add(SenderFeedbackRow(id="sfb_1", mailbox_id=mailbox.id, scope="domain", value="walmart.com",
                                    decision="trusted", authenticated=True))
            s.add(SenderFeedbackRow(id="sfb_2", mailbox_id=mailbox.id, scope="address", value="x@bad.example",
                                    decision="blocked", authenticated=False))
        login(client, "owner@example.com")
        page = client.get("/mailboxes").text
        assert "Trusted &amp; blocked senders" in page and "walmart.com" in page and "x@bad.example" in page
        assert "Email that Google confirms is from walmart.com is marked Checked after we check it." in page
        assert "Goes to Quarantine unless Google confirms it is really them." in page
        assert 'aria-label="Remove walmart.com"' in page
        r = client.post(f"/mailboxes/{mailbox.id}/senders/sfb_1/remove", data={"csrf_token": csrf_of(client, "/mailboxes")})
        assert r.status_code == 303
        assert [e.id for e in await _entries(db)] == ["sfb_2"]
        assert "Removed walmart.com" in client.get("/mailboxes").text
        assert "sender_feedback_removed" in await _actions(db)
        missing = client.post(f"/mailboxes/{mailbox.id}/senders/sfb_nope/remove",
                              data={"csrf_token": csrf_of(client, "/mailboxes")})
        assert missing.status_code == 404

    async def test_helper_sees_list_without_remove(self, client, seed, login, db):
        principal = await seed.user("boss@example.com")
        mailbox = await seed.mailbox(principal)
        async with db.session() as s:
            s.add(SenderFeedbackRow(id="sfb_9", mailbox_id=mailbox.id, scope="domain", value="rei.com",
                                    decision="trusted", authenticated=True))
        await seed.user("helper@example.com", role="assistant", principal_id=principal.id)
        login(client, "helper@example.com", role="assistant")
        page = client.get("/mailboxes").text
        assert "rei.com" in page and "Remove rei.com" not in page and "Re-check last 7 days" not in page

    async def test_empty_list(self, client, seed, login):
        user = await seed.user("owner@example.com")
        await seed.mailbox(user)
        login(client, "owner@example.com")
        assert "None yet." in client.get("/mailboxes").text


class TestDashboardAndList:
    async def test_stat_cards_are_links(self, client, seed, login):
        user = await seed.user("owner@example.com")
        mailbox = await seed.mailbox(user)
        for _ in range(3):
            await seed.message(mailbox, level="suspicious", quarantined=False)
        await seed.message(mailbox, level="safe")
        await seed.message(mailbox, level="malicious")
        login(client, "owner@example.com")
        page = client.get("/").text
        assert 'href="/messages?level=suspicious&amp;days=7"' in page
        assert 'href="/messages?level=safe&amp;days=7"' in page
        assert 'href="/messages?filter=quarantined&amp;days=7"' in page
        assert "Tap to see why" in page
        assert 'aria-label="3 suspicious this week. See which emails and why"' in page

    async def test_suspicious_tab_shows_why(self, client, seed, login, make_verdict):
        user = await seed.user("owner@example.com")
        mailbox = await seed.mailbox(user)
        v = make_verdict("suspicious", signals=[
            Signal(code="url.display_mismatch", stage=SignalStage.STATIC, weight=60, title="t",
                   evidence={"impersonates": "chase", "shown_domain": "chase.com", "url": "https://x.example/"}),
        ])
        await seed.message(mailbox, level="suspicious", verdict=v, quarantined=False, subject="Account alert")
        await seed.message(mailbox, level="safe", subject="Lunch")
        login(client, "owner@example.com")
        page = client.get("/messages?level=suspicious&days=7").text
        assert "Account alert" in page and "Lunch" not in page
        assert "A link pretends to go to chase.com." in page
        assert 'aria-current="page">Suspicious</a>' in page
        assert "Showing the last 7 days" in page and "Show all dates" in page

    async def test_quarantine_tab_and_empty_states(self, client, seed, login):
        user = await seed.user("owner@example.com")
        mailbox = await seed.mailbox(user)
        await seed.message(mailbox, level="safe", subject="Fine")
        login(client, "owner@example.com")
        assert "Quarantine is empty" in client.get("/messages?filter=quarantined").text
        assert "Nothing suspicious" in client.get("/messages?level=suspicious").text
        assert "Fine" in client.get("/messages?level=safe").text

    async def test_pagination(self, client, seed, login):
        user = await seed.user("owner@example.com")
        mailbox = await seed.mailbox(user)
        for i in range(55):
            await seed.message(mailbox, level="safe", subject=f"Note {i:02d}", hours_ago=i + 1)
        login(client, "owner@example.com")
        first = client.get("/messages").text
        assert "Note 00" in first and "Note 49" in first and "Note 50" not in first
        assert "Page 1 of 2" in first and 'href="/messages?page=2"' in first and "Newer" not in first
        second = client.get("/messages?page=2").text
        assert "Note 50" in second and "Note 54" in second and "Note 00" not in second
        assert 'href="/messages?page=1"' in second
        assert client.get("/messages?page=0").status_code == 200

    async def test_pagination_keeps_filters(self, client, seed, login):
        user = await seed.user("owner@example.com")
        mailbox = await seed.mailbox(user)
        await seed.mailbox(user, provider="yahoo", address="owner@yahoo.com")
        for i in range(52):
            await seed.message(mailbox, level="malicious", subject=f"Bad {i:02d}", hours_ago=i + 1)
        login(client, "owner@example.com")
        page = client.get(f"/messages?filter=quarantined&days=7&mailbox={mailbox.id}").text
        assert f'href="/messages?filter=quarantined&amp;days=7&amp;mailbox={mailbox.id}&amp;page=2"' in page
        page = client.get(f"/messages?level=malicious&mailbox={mailbox.id}&page=2").text
        assert "Bad 51" in page and f'href="/messages?level=malicious&amp;mailbox={mailbox.id}&amp;page=1"' in page
        assert 'name="mailbox"' in page  # two mailboxes: the mailbox picker is shown

    async def test_days_filter(self, client, seed, login):
        user = await seed.user("owner@example.com")
        mailbox = await seed.mailbox(user)
        await seed.message(mailbox, level="suspicious", quarantined=False, subject="Recent", hours_ago=2)
        await seed.message(mailbox, level="suspicious", quarantined=False, subject="Ancient", hours_ago=24 * 20)
        login(client, "owner@example.com")
        week = client.get("/messages?level=suspicious&days=7").text
        assert "Recent" in week and "Ancient" not in week
        everything = client.get("/messages?level=suspicious&days=999").text  # unknown period: all dates
        assert "Recent" in everything and "Ancient" in everything


class TestReportPage:
    async def test_report_sections(self, client, seed, login, make_verdict):
        user = await seed.user("owner@example.com")
        mailbox = await seed.mailbox(user)
        v = make_verdict("safe", signals=[
            DMARC_OK,
            Signal(code="sender.authenticated_bulk", stage=SignalStage.STATIC, weight=0, title="x",
                   evidence={"domain": "walmart.com"}),
            Signal(code="bec.gift_card", stage=SignalStage.BEC, weight=0, title="Asks for gift cards",
                   evidence={"softened_by": "authenticated_bulk_sender", "original_weight": 50}),
        ])
        v["verified_domain"] = "walmart.com"
        message = await seed.message(mailbox, level="safe", verdict=v, from_address="help@walmart.com")
        login(client, "owner@example.com")
        page = client.get(f"/messages/{message.id}").text
        assert "This email looks safe." in page
        assert "Google confirmed this really came from walmart.com" in page
        assert "A mailing list verified as walmart.com" in page
        assert "Good signs" in page and "We found nothing wrong with this email." in page
        assert "Technical details" in page and "Asks for gift cards" in page  # softened, only in details
        assert "This email has no links." in page and "No files are attached." in page

    async def test_report_after_decision(self, client, seed, login, make_verdict):
        user = await seed.user("owner@example.com")
        mailbox = await seed.mailbox(user)
        v = make_verdict("safe")
        v["client_decision"] = {"decision": "safe"}
        v["previous"] = {"level": "suspicious"}
        message = await seed.message(mailbox, level="safe", verdict=v)
        login(client, "owner@example.com")
        page = client.get(f"/messages/{message.id}").text
        assert "You marked this email as safe." in page
        assert "This is safe &mdash;" not in page and "This is fake" in page
        assert "Before re-check" in page
        assert "You marked this sender as safe." in client.get("/messages").text
