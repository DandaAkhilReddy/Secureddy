"""The web app in a real Chromium: "Ask Secureddy" streams an answer with
result cards and can be stopped; the app lock's PIN pad; reading an email in
its sandboxed frame; no horizontal scroll on a phone. Optionally (when
RS_ANTHROPIC_API_KEY is set in the environment) one question against the real
Claude API."""

from __future__ import annotations

import asyncio
import os

import pytest

from reddysec.assistant.llm import ChatReply

from .web_demo import DemoChat, DemoServer, sign_in

pytestmark = pytest.mark.integration
playwright = pytest.importorskip("playwright.sync_api")


@pytest.fixture
def server(tmp_path):
    srv = DemoServer(tmp_path).start()
    yield srv
    srv.stop()


@pytest.fixture
def browser():
    with playwright.sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()


def test_ask_secureddy_streams_cards_and_follows_links(server, browser):
    page = browser.new_page(viewport={"width": 1280, "height": 900})
    errors: list[str] = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    sign_in(page, server.base_url)
    page.goto(server.base_url + "/assistant")
    assert page.locator("#composer-input").is_enabled()
    page.locator(".suggest").first.click()  # "2 emails need a look. Show them" style suggestion
    page.wait_for_selector(".ccard-ranked .ccard-row")
    page.wait_for_selector("[data-send]:not([hidden])")
    assert page.locator(".ccard-rank").count() >= 2
    text = page.locator(".bubble-assistant").last.inner_text()
    assert "need a look" in text and "<" not in text
    assert page.url.startswith(server.base_url + "/assistant/cnv_")  # the conversation got its address
    page.locator(".ccard-row").first.click()
    page.wait_for_url("**/messages/msg_*")
    assert "dangerous" in page.locator("h1").inner_text()
    assert errors == []


def test_stop_button(browser, tmp_path):
    class Slow(DemoChat):
        async def stream(self, system, messages, tools):
            for i in range(200):
                await asyncio.sleep(0.05)
                yield f"word{i} "
            yield ChatReply("never")

    (tmp_path / "slow").mkdir()
    slow = DemoServer(tmp_path / "slow", chat=Slow()).start()
    try:
        page = browser.new_page()
        sign_in(page, slow.base_url)
        page.goto(slow.base_url + "/assistant")
        page.fill("#composer-input", "Tell me a story")
        page.keyboard.press("Enter")
        page.wait_for_selector(".bubble-draft:not(:empty)")
        page.click("[data-stop]")
        page.wait_for_selector("[data-send]:not([hidden])")
        assert "Stopped" in page.locator(".bubble-assistant").last.inner_text()
    finally:
        slow.stop()


def test_off_topic_question_gets_one_line(server, browser):
    page = browser.new_page()
    sign_in(page, server.base_url)
    page.goto(server.base_url + "/assistant")
    page.fill("#composer-input", "What's the weather in Paris?")
    page.keyboard.press("Enter")
    page.wait_for_selector("[data-send]:not([hidden])")
    page.wait_for_function("document.querySelectorAll('.bubble-assistant').length >= 1 && "
                           "!document.querySelector('.bubble-live')")
    assert "only help with your email safety" in page.locator(".bubble-assistant").last.inner_text()


def test_read_email_in_sandboxed_frame(server, browser):
    page = browser.new_page()
    sign_in(page, server.base_url)
    page.goto(server.base_url + "/messages")
    page.click("text=Your order could not be delivered")
    page.click("text=Read email")
    frame = page.frame_locator("iframe.read-frame")
    frame.locator("text=Confirm delivery").wait_for()
    assert page.locator("iframe.read-frame").get_attribute("sandbox") == "allow-top-navigation-by-user-activation"
    with page.expect_navigation():
        frame.locator("text=Confirm delivery").click()
    assert "/go?" in page.url and "Do not open this link" in page.content()


def test_pin_lock_on_a_phone(server, browser):
    ctx = browser.new_context(viewport={"width": 390, "height": 844}, has_touch=True, is_mobile=True)
    page = ctx.new_page()
    sign_in(page, server.base_url)
    page.goto(server.base_url + "/settings/security#lock")
    form = page.locator("form[action='/settings/lock']").last
    form.locator("input[name=secret]").fill("482913")
    form.locator("input[name=confirm]").fill("482913")
    form.locator("button[type=submit]").click()
    page.wait_for_url("**/settings/security#lock")
    page.goto(server.base_url + "/messages")
    page.locator("form[action='/lock/now'] button").evaluate("b => b.form.submit()")
    page.wait_for_url("**/lock")
    for digit in "482913":
        page.click(f".pin-key[data-digit='{digit}']")
    page.wait_for_url(server.base_url + "/")
    for path in ("/", "/messages", "/mailboxes", "/settings/security", "/assistant"):
        page.goto(server.base_url + path)
        assert page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth"), path
    ctx.close()


@pytest.mark.skipif(not os.environ.get("RS_ANTHROPIC_API_KEY"), reason="no RS_ANTHROPIC_API_KEY in the environment")
def test_real_claude_once(tmp_path, browser):  # pragma: no cover - needs the network and a key
    import httpx
    from pydantic import SecretStr

    from reddysec.assistant.llm import chat_model_from_settings
    from reddysec.config import Settings

    settings = Settings(assistant_provider="anthropic", anthropic_api_key=SecretStr(os.environ["RS_ANTHROPIC_API_KEY"]),
                        assistant_model=os.environ.get("RS_ASSISTANT_MODEL", "claude-sonnet-5-5"))
    chat = chat_model_from_settings(settings, httpx.AsyncClient(timeout=60))
    srv = DemoServer(tmp_path, chat=chat).start()
    try:
        page = browser.new_page()
        sign_in(page, srv.base_url)
        page.goto(srv.base_url + "/assistant")
        page.fill("#composer-input", "Show me the most suspicious emails")
        page.keyboard.press("Enter")
        page.wait_for_selector(".ccard-row", timeout=60000)
    finally:
        srv.stop()


DARK_BG = "rgb(14, 19, 24)"  # --bg, dark
LIGHT_BG = "rgb(246, 241, 231)"  # --bg, light


def _bg(page) -> str:
    return page.evaluate("getComputedStyle(document.body).backgroundColor")


@pytest.mark.parametrize("os_scheme", ["dark", "light"])
def test_appearance_dark_light_system(server, browser, os_scheme):
    """Settings → Appearance in a real browser: the choice applies at once,
    survives a reload and other pages, and System follows the device."""
    ctx = browser.new_context(color_scheme=os_scheme, viewport={"width": 390, "height": 844})
    page = ctx.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    sign_in(page, server.base_url)
    system_bg = DARK_BG if os_scheme == "dark" else LIGHT_BG
    assert _bg(page) == system_bg  # nothing chosen yet: follow the device
    for choice, expected in (("dark", DARK_BG), ("light", LIGHT_BG), ("system", system_bg)):
        page.goto(server.base_url + "/settings/security#look")
        with page.expect_navigation():
            page.locator(f"input[name=theme][value={choice}]").check()  # no Save button: it saves itself
        assert _bg(page) == expected, (os_scheme, choice)
        page.reload()
        assert _bg(page) == expected
        for path in ("/", "/messages", "/assistant"):
            page.goto(server.base_url + path)
            assert _bg(page) == expected, (choice, path)
            attr = page.evaluate("document.documentElement.getAttribute('data-theme')")
            assert attr == (None if choice == "system" else choice)
    # System follows the device when it changes.
    page.emulate_media(color_scheme="light" if os_scheme == "dark" else "dark")
    assert _bg(page) == (LIGHT_BG if os_scheme == "dark" else DARK_BG)
    # The explicit choices ignore the device.
    page.goto(server.base_url + "/settings/security")
    with page.expect_navigation():
        page.locator("input[name=theme][value=dark]").check()
    page.emulate_media(color_scheme="light")
    assert _bg(page) == DARK_BG
    assert errors == []
    ctx.close()


def test_appearance_applies_before_the_page_reloads(server, browser):
    ctx = browser.new_context(color_scheme="dark")
    page = ctx.new_page()
    sign_in(page, server.base_url)
    page.goto(server.base_url + "/settings/security")
    page.evaluate("HTMLFormElement.prototype.submit = function () {}")  # hold the save
    page.locator("input[name=theme][value=light]").check()
    assert _bg(page) == LIGHT_BG
    assert page.evaluate("document.querySelector('meta[name=color-scheme]').content") == "light"
    page.locator("input[name=theme][value=system]").check()
    assert _bg(page) == DARK_BG and page.evaluate("document.documentElement.hasAttribute('data-theme')") is False
    ctx.close()


def test_two_step_sign_in_in_a_browser(server, browser):
    """Set up two-step sign-in from the QR page, sign out, sign in again and
    pass the code step; the time zone cookie is set for Today."""
    import re
    import time

    import pyotp

    ctx = browser.new_context(viewport={"width": 1280, "height": 900}, timezone_id="America/Los_Angeles")
    page = ctx.new_page()
    sign_in(page, server.base_url)
    assert any(c["name"] == "rs_tz" and c["value"] == "America/Los_Angeles" for c in ctx.cookies())
    page.goto(server.base_url + "/settings/security#two-step")
    assert page.locator("#two-step svg.qr").is_visible()
    key = page.locator("#two-step .manual-key").inner_text().replace(" ", "")
    page.fill("#enable-code", pyotp.TOTP(key).now())
    page.click("form[action='/settings/security/totp/enable'] button[type=submit]")
    page.wait_for_selector(".recovery-codes")
    assert page.locator(".recovery-codes li").count() == 10
    page.goto(server.base_url + "/")
    page.locator("form[action='/auth/logout'] button").first.evaluate("b => b.form.submit()")
    page.wait_for_url("**/login")
    page.goto(f"{server.base_url}/login")
    page.evaluate("document.querySelectorAll('details').forEach(function (d) { d.open = true; })")
    dev = page.locator("form[action='/auth/dev-login']")
    dev.locator("input[name=email]").fill("avery@example.com")
    dev.locator("button[type=submit]").click()
    page.wait_for_url("**/auth/mfa")
    page.fill("input.mfa-code", pyotp.TOTP(key).at(time.time() + 30))
    page.check("input[name=remember]")
    page.click("form[action='/auth/mfa'] button[type=submit]")
    page.wait_for_url(server.base_url + "/")
    assert re.search(r"Welcome back", page.content())
    assert any(c["name"] == "rs_mfa_dev" for c in ctx.cookies())
    ctx.close()
