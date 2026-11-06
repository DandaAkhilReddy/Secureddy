"""Lookalike detection: every class, and the negatives that must not fire."""

from __future__ import annotations

import pytest

from reddysec.analysis.domains import (
    LookalikeReason,
    brand_for_domain,
    brands_mentioned,
    damerau_levenshtein,
    legit_domains_for,
    lookalike_analysis,
    skeleton,
    typosquat_kind,
)


class TestBrandForDomain:
    @pytest.mark.parametrize(
        "domain,brand",
        [
            ("docusign.net", "docusign"),
            ("mail.chase.com", "chase"),
            ("google.com", "google"),
            ("icloud.com", "apple"),
            ("evil-unknown.com", None),
        ],
    )
    def test_cases(self, domain, brand):
        assert brand_for_domain(domain) == brand

    def test_legit_domains_for(self):
        assert "docusign.net" in legit_domains_for("docusign")
        assert legit_domains_for("not-a-brand") == frozenset()


class TestBrandsMentioned:
    def test_keyword_match(self):
        found = brands_mentioned("Your DocuSign document is ready from Chase Bank")
        assert "docusign" in found and "chase" in found

    def test_word_boundary(self):
        assert "chase" not in brands_mentioned("We will chasethedream together")

    def test_short_keywords_need_caps(self):
        assert "irs" not in brands_mentioned("the irs is lowercase here as a word")
        assert "irs" in brands_mentioned("Notice from the IRS about your refund")

    def test_empty(self):
        assert brands_mentioned("") == []
        assert brands_mentioned(None) == []


class TestLegitimateNotFlagged:
    @pytest.mark.parametrize(
        "domain",
        ["docusign.net", "chase.com", "google.com", "accounts.google.com", "paypal.com", "icloud.com",
         "microsoftonline.com", "login.microsoftonline.com", "bankofamerica.com", "amazon.co.uk", "wellsfargo.com"],
    )
    def test_not_lookalike(self, domain):
        assert not lookalike_analysis(domain).is_lookalike

    @pytest.mark.parametrize(
        "domain",
        ["delta-dental.com", "united-way.org", "amazon-rainforest.org", "modern-furniture.com", "stack.com",
         "black.com", "cups.com", "theinformation-weekly.com", "learn-chase-strategy.net"],
    )
    def test_ordinary_domains_not_flagged(self, domain):
        # These contain or resemble brand words but are not impersonation.
        assert not lookalike_analysis(domain).is_lookalike


class TestHomoglyph:
    def test_cyrillic_a_in_paypal(self):
        r = lookalike_analysis("pаypal.com")  # Cyrillic а
        assert r.is_lookalike and r.reason is LookalikeReason.HOMOGLYPH and r.target == "paypal"

    def test_digit_one_for_l(self):
        r = lookalike_analysis("paypa1.com")
        assert r.is_lookalike and r.reason is LookalikeReason.HOMOGLYPH

    def test_rn_for_m(self):
        r = lookalike_analysis("rnicrosoft.com")
        assert r.is_lookalike and r.target == "microsoft"

    def test_punycode_decoded(self):
        r = lookalike_analysis("xn--pypal-4ve.com")
        assert r.is_lookalike and r.reason is LookalikeReason.HOMOGLYPH


class TestTyposquat:
    def test_doubled_letter(self):
        r = lookalike_analysis("chasse.com")
        assert r.is_lookalike and r.reason is LookalikeReason.TYPOSQUAT

    def test_edit_distance_long_label(self):
        r = lookalike_analysis("docusing.net")
        assert r.is_lookalike and r.reason in (LookalikeReason.TYPOSQUAT, LookalikeReason.EDIT_DISTANCE)
        assert r.target == "docusign"

    def test_short_label_noise_ignored(self):
        # "chse" is a letter off "chase" but 4 chars -> below the distance floor.
        assert not lookalike_analysis("chse.com").is_lookalike

    def test_typosquat_kind_helper(self):
        assert typosquat_kind("chse", "chase") == "missing letter"
        assert typosquat_kind("chasse", "chase") == "doubled letter"
        assert typosquat_kind("chsae", "chase") == "swapped letters"
        assert typosquat_kind("zzz", "chase") is None


class TestBrandEmbedded:
    @pytest.mark.parametrize(
        "domain,brand",
        [
            ("chase.com.secure-login.ru", "chase"),
            ("chase-online-secure.com", "chase"),
            ("secure-docusign.net", "docusign"),
            ("docusign-secure.com", "docusign"),
            ("paypal.evil.com", "paypal"),
            ("wellsfargo-alerts.com", "wellsfargo"),
            ("bankofamerica-verify.com", "bankofamerica"),
            ("appleid-verify.com", "apple"),
            ("icloud-support.net", "apple"),
        ],
    )
    def test_embedded(self, domain, brand):
        r = lookalike_analysis(domain)
        assert r.is_lookalike and r.reason is LookalikeReason.BRAND_EMBEDDED and r.target == brand

    def test_ambiguous_brand_needs_credential_word(self):
        # "box" alone is a common word; without a credential word it should not fire.
        assert not lookalike_analysis("box-factory.com").is_lookalike
        assert lookalike_analysis("box-login-secure.com").is_lookalike


class TestTldSwap:
    def test_chase_co(self):
        r = lookalike_analysis("chase.co")
        assert r.is_lookalike and r.reason is LookalikeReason.TLD_SWAP and r.target == "chase"

    def test_paypal_net(self):
        r = lookalike_analysis("paypal.net")
        assert r.is_lookalike and r.reason is LookalikeReason.TLD_SWAP


class TestContactLookalikes:
    def test_contact_tld_swap(self):
        r = lookalike_analysis("whitfieldlawgroup.net", contact_domains=["whitfieldlawgroup.com"])
        assert r.is_lookalike and r.is_contact and r.target_domain == "whitfieldlawgroup.com"

    def test_contact_edit_distance(self):
        r = lookalike_analysis("whitfieldlaw-group.com", contact_domains=["whitfieldlawgroup.com"])
        assert r.is_lookalike and r.is_contact

    def test_contact_itself_not_flagged(self):
        assert not lookalike_analysis("whitfieldlawgroup.com", contact_domains=["whitfieldlawgroup.com"]).is_lookalike

    def test_weight_ranges(self):
        assert lookalike_analysis("pаypal.com").weight == 60
        assert lookalike_analysis("chase.co").weight == 45
        assert lookalike_analysis("clean.example").weight == 0


class TestStringHelpers:
    def test_skeleton(self):
        assert skeleton("pаypа1") == "paypal"
        assert skeleton("rnicrosoft") == "microsoft"

    def test_damerau_levenshtein(self):
        assert damerau_levenshtein("docusing", "docusign") == 1  # transposition
        assert damerau_levenshtein("chase", "chase") == 0
        assert damerau_levenshtein("", "abc") == 3
        assert damerau_levenshtein("kitten", "sitting") == 3
