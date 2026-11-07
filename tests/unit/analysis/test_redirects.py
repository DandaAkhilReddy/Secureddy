"""``analysis.redirects``: unwrapping wrappers and open redirects, free hosting."""

from __future__ import annotations

import base64

import pytest

from reddysec.analysis.redirects import (
    HIDDEN_DESTINATION,
    OPEN_REDIRECT,
    SECURITY_WRAPPER,
    free_hosting_match,
    generic_redirect_target,
    unwrap,
    unwrap_chain,
)
from reddysec.analysis.urls import normalize_url

TARGET = "https://evil.example/login"
BING = "a1" + base64.urlsafe_b64encode(TARGET.encode()).decode().rstrip("=")


@pytest.mark.parametrize(
    ("wrapped", "kind"),
    [
        ("https://www.google.com/url?q=https://evil.example/login&sa=D", OPEN_REDIRECT),
        ("https://google.co.uk/url?url=https://evil.example/login", OPEN_REDIRECT),
        ("https://www.google.com/amp/s/evil.example/login", OPEN_REDIRECT),
        (f"https://www.bing.com/ck/a?!&&p=abc&u={BING}&ntb=1", OPEN_REDIRECT),
        ("https://l.facebook.com/l.php?u=https%3A%2F%2Fevil.example%2Flogin&h=x", OPEN_REDIRECT),
        ("https://www.youtube.com/redirect?q=https://evil.example/login", OPEN_REDIRECT),
        ("https://www.linkedin.com/redir/redirect?url=https%3A%2F%2Fevil.example%2Flogin", OPEN_REDIRECT),
        ("https://slack-redir.net/link?url=https://evil.example/login", OPEN_REDIRECT),
        ("https://duckduckgo.com/l/?uddg=https%3A%2F%2Fevil.example%2Flogin", OPEN_REDIRECT),
        ("https://nam02.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2Flogin&data=1", SECURITY_WRAPPER),
        ("https://urldefense.com/v3/__https://evil.example/login__;!!abc$", SECURITY_WRAPPER),
        ("https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.example_login&d=x", SECURITY_WRAPPER),
        ("https://linkprotect.cudasvc.com/url?a=https%3A%2F%2Fevil.example%2Flogin&c=E", SECURITY_WRAPPER),
    ],
)
def test_unwrap(wrapped, kind):
    chain = unwrap_chain(wrapped)
    assert chain[0].kind == kind and chain[-1].url == TARGET and chain[-1].kind == ""
    assert unwrap(wrapped) == TARGET


def test_nested_wrappers():
    inner = "https://www.google.com/url?q=" + TARGET
    outer = "https://nam02.safelinks.protection.outlook.com/?url=" + inner.replace(":", "%3A").replace("/", "%2F").replace("?", "%3F").replace("=", "%3D")
    chain = unwrap_chain(outer)
    assert [h.kind for h in chain] == [SECURITY_WRAPPER, OPEN_REDIRECT, ""]
    assert normalize_url(outer) == TARGET


@pytest.mark.parametrize("url", ["https://www.linkedin.com/slink?code=abc", "https://protect-us.mimecast.com/s/abc"])
def test_hidden_destination(url):
    chain = unwrap_chain(url)
    assert len(chain) == 1 and chain[0].kind == HIDDEN_DESTINATION and unwrap(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/page?q=https://other.example/",  # not a known redirector
        "https://www.google.com/search?q=https://evil.example",  # a search, not /url
        "https://www.bing.com/ck/a?u=a1!!!notbase64",  # undecodable -> hidden, handled below
        "not a url at all",
    ],
)
def test_not_unwrapped(url):
    assert unwrap(url) == url


def test_generic_redirect_target_is_shown_not_unwrapped():
    url = "https://click.news.example/c?url=https%3A%2F%2Fshop.example%2Fsale"
    assert generic_redirect_target(url) == "https://shop.example/sale"
    assert unwrap(url) == url
    assert generic_redirect_target("https://example.com/?url=https://example.com/x") is None
    assert generic_redirect_target("https://example.com/plain") is None


@pytest.mark.parametrize(
    ("url", "match"),
    [
        ("https://m365-login.pages.dev/x", "pages.dev"),
        ("https://a.b.workers.dev/", "workers.dev"),
        ("https://pub-123.r2.dev/doc.html", "r2.dev"),
        ("https://acme-share.web.app/", "web.app"),
        ("https://firebasestorage.googleapis.com/v0/b/x/o/a.html", "firebasestorage.googleapis.com"),
        ("https://acct.blob.core.windows.net/$web/index.html", "blob.core.windows.net"),
        ("https://docs.google.com/forms/d/e/abc/viewform", "docs.google.com/forms"),
        ("https://docs.google.com/drawings/d/abc/edit", "docs.google.com/drawings"),
        ("https://bafybeih.ipfs.dweb.link/", "dweb.link"),
        ("https://gateway.example/ipfs/bafy", None),
        ("https://bafybeih.ipfs.w3s.link/", "w3s.link"),
        ("https://x.ngrok-free.app/", "ngrok-free.app"),
        ("https://acme.notion.site/Invoice", "notion.site"),
        ("https://jane.github.io/", "github.io"),
        ("https://docs.google.com/document/d/1/edit", None),
        ("https://www.walmart.com/", None),
        ("https://pages.devious.example/", None),
    ],
)
def test_free_hosting(url, match):
    assert free_hosting_match(url) == match
