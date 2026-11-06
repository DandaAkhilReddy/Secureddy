"""The client's own verdicts ("This is safe" / "This is fake") inside analyze()."""

from __future__ import annotations

from reddysec.analysis import analyze, parse_raw
from reddysec.analysis.intel import OfflineIntel
from reddysec.analysis.pipeline import AnalysisContext
from reddysec.models import (
    ClientFeedback,
    DetonationResult,
    DetonationStatus,
    FormRecord,
    PageFeatures,
    PolicyConfig,
    TriageLane,
    VerdictLevel,
)
from reddysec.testing.fakes import FakeDetonator

from .support import RECEIVED_AT, build_raw

PASS = "mx.google.com; dkim=pass header.i=@vendorsupplies.com; spf=pass smtp.mailfrom=billing@vendorsupplies.com; dmarc=pass header.from=vendorsupplies.com"
FAIL = "mx.google.com; dkim=none; spf=fail smtp.mailfrom=x@evil-mailer.net; dmarc=fail header.from=vendorsupplies.com"
BODY = "Hi, quick one: please process the attached invoice today. Reply ASAP.\nhttps://portal.vendorsupplies.com/invoices/7781"


def _parsed(auth: str = PASS, body: str = BODY, sender: str = "Vendor Billing <billing@vendorsupplies.com>"):
    raw = build_raw(from_header=sender, auth=auth, subject="Invoice 7781 - action required", text=body)
    return parse_raw(raw, provider_message_id="m1", mailbox_id="mbx", received_at=RECEIVED_AT)


def _ctx(feedback: ClientFeedback | None, det: FakeDetonator | None = None) -> AnalysisContext:
    return AnalysisContext(
        policy=PolicyConfig(), history=None, intel=OfflineIntel(), detonator=det or FakeDetonator(), feedback=feedback
    )


def _weights(v):
    out: dict[str, int] = {}
    for s in v.signals:
        out[s.code] = s.weight if s.code not in out else max(out[s.code], s.weight)
    return out


async def test_trusted_domain_takes_trusted_lane_is_rechecked_and_confirmed():
    det = FakeDetonator()
    feedback = ClientFeedback(trusted_domains=["vendorsupplies.com"], reasons={"vendorsupplies.com": "I ordered this"})
    v = await analyze(_parsed(), _ctx(feedback, det))
    assert v.lane is TriageLane.TRUSTED and v.level is VerdictLevel.SAFE
    assert _weights(v)["history.client_trusted"] == -30
    # Trust never skips the checks: the client asked us to re-check and confirm.
    assert [j.url for j in det.jobs] == ["https://portal.vendorsupplies.com/invoices/7781"]
    assert v.verified_domain == "vendorsupplies.com"
    assert v.trust_check is not None
    assert (v.trust_check.trusted_by_client, v.trust_check.outcome, v.trust_check.reason) == (
        True, "confirmed", "I ordered this"
    )
    assert (v.trust_check.scope, v.trust_check.value) == ("domain", "vendorsupplies.com")
    assert v.summary == "You told us you trust this sender (reason: I ordered this). We checked this one too. It's safe."
    assert "history.trust_confirmed" in _weights(v)


async def test_trusted_domain_with_foreign_link_still_detonates_but_heuristics_off():
    det = FakeDetonator()
    body = BODY + "\nhttps://files.unknown-share.net/doc/1"
    v = await analyze(_parsed(body=body), _ctx(ClientFeedback(trusted_domains=["vendorsupplies.com"]), det))
    assert v.lane is TriageLane.DETONATE and det.jobs
    assert v.level is VerdictLevel.SAFE
    assert all(s.weight <= 0 for s in v.signals if s.code.startswith(("bec.", "subject.")))


async def test_spoof_claiming_trusted_domain_gets_no_benefit():
    v = await analyze(_parsed(auth=FAIL), _ctx(ClientFeedback(trusted_domains=["vendorsupplies.com"])))
    assert "history.client_trusted" not in _weights(v)
    assert v.lane is not TriageLane.TRUSTED
    assert _weights(v)["auth.dmarc_fail"] == 40


async def test_trusted_domain_cannot_hide_a_credential_page():
    det = FakeDetonator()
    det.script(
        "https://files.unknown-share.net/doc/1",
        DetonationResult(
            job_id="s", status=DetonationStatus.OK,
            features=PageFeatures(
                title="Microsoft 365 sign in", final_url="https://files.unknown-share.net/login",
                final_host="files.unknown-share.net", has_password_field=True,
                forms=[FormRecord(has_password=True)], brand_keywords=["microsoft"], status_code=200,
            ),
        ),
    )
    body = BODY + "\nhttps://files.unknown-share.net/doc/1"
    v = await analyze(_parsed(body=body), _ctx(ClientFeedback(trusted_domains=["vendorsupplies.com"]), det))
    assert v.level is VerdictLevel.MALICIOUS
    assert _weights(v)["history.client_trusted"] == 0  # withheld: a hacked vendor account is the threat


async def test_blocked_domain_goes_to_block_lane():
    v = await analyze(_parsed(), _ctx(ClientFeedback(blocked_domains=["vendorsupplies.com"])))
    assert v.lane is TriageLane.BLOCK and v.level is VerdictLevel.MALICIOUS
    assert _weights(v)["history.client_blocked"] == 100


async def test_weak_address_trust_lowers_score_but_still_detonates():
    det = FakeDetonator()
    plain = build_raw(from_header="Shop <office@smallshop-pdx.com>", subject="Your order",
                      text="Order ready: https://smallshop-pdx.com/o/1")
    parsed = parse_raw(plain, provider_message_id="m2", mailbox_id="mbx", received_at=RECEIVED_AT)
    v = await analyze(parsed, _ctx(ClientFeedback(trusted_addresses=["office@smallshop-pdx.com"]), det))
    assert _weights(v)["history.client_trusted"] == -20
    assert det.jobs and v.lane is TriageLane.DETONATE


async def test_no_feedback_is_the_old_behaviour():
    v = await analyze(_parsed(), _ctx(None))
    assert "history.client_trusted" not in _weights(v) and "history.client_blocked" not in _weights(v)


async def test_trusted_sender_that_changes_is_flagged_as_changed():
    det = FakeDetonator()
    det.script(
        "https://portal.vendorsupplies.com/invoices/7781",
        DetonationResult(
            job_id="s", status=DetonationStatus.OK,
            features=PageFeatures(
                title="Microsoft 365 sign in", final_url="https://portal.vendorsupplies.com/login",
                final_host="portal.vendorsupplies.com", has_password_field=True,
                forms=[FormRecord(has_password=True, action_host="collector.evil.example")],
                brand_keywords=["microsoft"], status_code=200,
            ),
        ),
    )
    v = await analyze(_parsed(), _ctx(ClientFeedback(trusted_domains=["vendorsupplies.com"]), det))
    assert det.jobs, "a client-trusted sender's links are still opened"
    assert v.level is not VerdictLevel.SAFE
    assert v.trust_check is not None and v.trust_check.outcome == "changed" and v.trust_check.reason == ""
    assert v.summary.startswith("This sender is on your trusted list, but this email looks different. ")
    assert "history.trust_confirmed" not in _weights(v)


async def test_trusted_address_check_and_known_correspondent():
    from reddysec.analysis.pipeline import trust_check_for, trust_summary
    from reddysec.analysis.trust import SenderTrust
    from reddysec.models import TrustCheck

    weak = SenderTrust(from_address="a@b.com", client_trust="address")
    c = trust_check_for(weak, TriageLane.DETONATE, VerdictLevel.UNKNOWN, ClientFeedback(reasons={"a@b.com": "Friend"}))
    assert (c.scope, c.value, c.outcome, c.reason) == ("address", "a@b.com", "incomplete", "Friend")
    assert trust_summary(c, "orig") == "orig"
    known = SenderTrust(from_address="x@y.com", aligned_domain="y.com")
    c2 = trust_check_for(known, TriageLane.TRUSTED, VerdictLevel.SAFE, None)
    assert c2.trusted_by_client is False and (c2.scope, c2.value) == ("domain", "y.com")
    assert trust_check_for(known, TriageLane.DETONATE, VerdictLevel.SAFE, None) is None
    assert trust_check_for(SenderTrust(client_blocked="domain"), TriageLane.BLOCK, VerdictLevel.MALICIOUS, None) is None
    long = TrustCheck(trusted_by_client=True, reason="x" * 300, outcome="confirmed")
    assert trust_summary(long, "s").endswith("…). We checked this one too. It's safe.")
