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


async def test_trusted_domain_takes_trusted_lane_and_is_checked():
    det = FakeDetonator()
    v = await analyze(_parsed(), _ctx(ClientFeedback(trusted_domains=["vendorsupplies.com"]), det))
    assert v.lane is TriageLane.TRUSTED and v.level is VerdictLevel.SAFE
    assert _weights(v)["history.client_trusted"] == -30
    assert not det.jobs  # links on the trusted, verified domain itself need no sandbox
    assert v.verified_domain == "vendorsupplies.com"


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
