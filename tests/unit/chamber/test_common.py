"""Unit tests for the chamber's dependency-light helpers."""

from __future__ import annotations

import pytest

from reddysec.chamber.common import (
    BROWSER_VIEWABLE_TYPES,
    DEFAULT_USER_AGENT,
    extension_of,
    find_brand_keywords,
    host_of,
    is_image_type,
    is_third_party,
    registrable_domain,
    safe_filename,
    sniff_type,
    user_agent_for,
)


class TestHostHelpers:
    @pytest.mark.parametrize(
        "url,expected",
        [
            ("https://Login.Chase.com/path", "login.chase.com"),
            ("http://127.0.0.1:8080/x", "127.0.0.1"),
            ("https://[::1]:443/", "::1"),
            ("not a url", ""),
            (None, ""),
            ("", ""),
        ],
    )
    def test_host_of(self, url, expected):
        assert host_of(url) == expected

    @pytest.mark.parametrize(
        "host,expected",
        [
            ("login.chase.com", "chase.com"),
            ("a.b.co.uk", "b.co.uk"),
            ("CHASE.COM", "chase.com"),
            ("chase.com.", "chase.com"),
            ("localhost", "localhost"),
            ("intranet", "intranet"),
            ("127.0.0.1", "127.0.0.1"),
            ("[::1]", "::1"),
            ("foo.github.io", "github.io"),  # github.io is a private suffix, excluded by default
            ("", ""),
        ],
    )
    def test_registrable_domain(self, host, expected):
        assert registrable_domain(host) == expected

    def test_is_third_party(self):
        assert is_third_party("cdn.evil.com", "chase.com")
        assert not is_third_party("login.chase.com", "chase.com")
        assert not is_third_party("", "chase.com")
        assert not is_third_party("x.com", "")


class TestUserAgent:
    def test_default_has_no_headless_marker(self):
        assert "Headless" not in DEFAULT_USER_AGENT
        assert "Chrome/" in DEFAULT_USER_AGENT

    def test_user_agent_follows_engine_major(self):
        ua = user_agent_for("131.0.6778.33")
        assert "Chrome/131.0.0.0" in ua
        assert "Headless" not in ua

    def test_user_agent_falls_back(self):
        assert user_agent_for(None) == DEFAULT_USER_AGENT
        assert user_agent_for("garbage") == DEFAULT_USER_AGENT


class TestSniff:
    @pytest.mark.parametrize(
        "data,expected",
        [
            (b"MZ\x90\x00", "pe"),
            (b"\x7fELF\x02", "elf"),
            (b"%PDF-1.7", "pdf"),
            (b"PK\x03\x04", "zip"),
            (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
            (b"{\\rtf1", "rtf"),
            (b"\x89PNG\r\n\x1a\n", "png"),
            (b"\xff\xd8\xff\xe0", "jpeg"),
            (b"GIF89a", "gif"),
            (b"RIFF\x00\x00\x00\x00WEBPVP8 ", "webp"),
            (b"<!DOCTYPE html><html>", "html"),
            (b"  <html>", "html"),
            (b"@echo off\r\ndel x", "script"),
            (b"powershell -enc ZQ==", "script"),
            (b"just some plain text here", "text"),
            (b"", "empty"),
            (b"\x00\x01\x02\x03\xff\xfe", "unknown"),
        ],
    )
    def test_sniff_type(self, data, expected):
        assert sniff_type(data) == expected

    def test_bmp_needs_header(self):
        assert sniff_type(b"BM\x1e\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00rest") == "bmp"
        # "BM..." that is really text must not be mislabelled a bitmap
        assert sniff_type(b"BMW dealership newsletter, read inside for offers") == "text"

    def test_image_and_viewable_helpers(self):
        assert is_image_type("png") and is_image_type("jpeg")
        assert not is_image_type("pdf")
        assert "pdf" in BROWSER_VIEWABLE_TYPES and "html" in BROWSER_VIEWABLE_TYPES
        assert "pe" not in BROWSER_VIEWABLE_TYPES


class TestFilenames:
    @pytest.mark.parametrize(
        "name,expected",
        [
            ("invoice.pdf", "invoice.pdf"),
            ("../../etc/passwd", "passwd"),  # path separators drop to the last segment
            ("a b c.docx", "a_b_c.docx"),
            ("....hidden", "hidden"),
            ("", "download.bin"),
            (None, "download.bin"),
            ("C:\\Users\\x\\report.xlsx", "report.xlsx"),
        ],
    )
    def test_safe_filename(self, name, expected):
        assert safe_filename(name) == expected

    def test_safe_filename_truncates_keeping_extension(self):
        out = safe_filename("a" * 300 + ".pdf", max_len=40)
        assert len(out) <= 40 and out.endswith(".pdf")

    def test_extension_of(self):
        assert extension_of("x.PDF") == "pdf"
        assert extension_of("archive.tar.gz") == "gz"
        assert extension_of("noext") == ""
        assert extension_of(None) == ""


class TestBrandKeywords:
    def test_matches_whole_words(self):
        found = find_brand_keywords("Sign in to your Chase account at PayPal or Bank of America")
        assert "chase" in found and "paypal" in found and "bank of america" in found

    def test_no_substring_false_positives(self):
        # "apple" must not match "pineapple"; "citi" must not match "citizen"
        assert "apple" not in find_brand_keywords("I ate a pineapple")
        assert "citi" not in find_brand_keywords("a good citizen pays taxes")

    def test_case_and_whitespace_insensitive(self):
        assert "office 365" in find_brand_keywords("Your OFFICE\n365   subscription")
