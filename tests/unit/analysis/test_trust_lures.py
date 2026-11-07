"""Lure signals are never softened: not by the client's "This is safe", not
by an authenticated mailing-list sender."""

from __future__ import annotations

import pytest

from reddysec.analysis.trust import (
    BULK_SOFT_CODES,
    SOFT_DYNAMIC_CODES,
    SenderTrust,
    is_protected,
    soften_dynamic,
    soften_static,
)
from reddysec.models import Signal, SignalStage

NEVER_SOFTENED = [
    "dynamic.clickfix", "dynamic.clipboard_hijack", "dynamic.fake_captcha", "dynamic.tech_support_scam",
    "dynamic.wallet_drainer", "dynamic.aitm_proxy", "dynamic.free_hosting_login", "dynamic.device_code_lure",
    "bec.device_code_lure", "url.oauth_consent_lure", "attachment.svg_phish", "attachment.html_clickfix",
]
TRUSTED = SenderTrust(from_address="a@vendor.example", from_domain="vendor.example", aligned_domain="vendor.example",
                      bulk=True, client_trust="domain")
BULK = SenderTrust(from_address="news@shop.example", from_domain="shop.example", aligned_domain="shop.example", bulk=True)


def sig(code, weight):
    return Signal(code=code, stage=SignalStage.DYNAMIC, weight=weight, title=code)


@pytest.mark.parametrize("code", NEVER_SOFTENED)
@pytest.mark.parametrize("sender", [TRUSTED, BULK], ids=["client_trusted_domain", "bulk"])
def test_never_softened(code, sender):
    assert is_protected(code)
    s = sig(code, 90)
    assert soften_dynamic([s], sender)[0].weight == 90
    assert soften_static([s], sender)[0].weight == 90


def test_heuristic_lure_codes_are_soft_for_verified_newsletters():
    assert {"url.free_hosting", "url.open_redirect", "bec.callback_scam"} <= BULK_SOFT_CODES
    assert {"dynamic.anti_analysis", "dynamic.ua_cloaking", "dynamic.captcha_gated_login"} <= SOFT_DYNAMIC_CODES
    assert soften_static([sig("url.free_hosting", 12)], BULK)[0].weight == 0
    assert soften_static([sig("bec.callback_scam", 45)], BULK)[0].weight == 0
