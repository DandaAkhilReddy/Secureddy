"""Settings → Appearance: System follows the device, Dark forces dark, Light
forces light. The server puts the choice on <html data-theme> for the first
paint, keeps it for the person (every device) and in a device cookie (the
sign-in and lock pages)."""

from __future__ import annotations

import re

import pytest
from starlette.testclient import TestClient

HTML_TAG = re.compile(r"<html[^>]*>")


def html_tag(page: str) -> str:
    match = HTML_TAG.search(page)
    assert match
    return match.group(0)


def choose(client, csrf_of, theme: str, **extra):
    return client.post(
        "/settings/theme", data={"csrf_token": csrf_of(client, "/settings/security"), "theme": theme, **extra}
    )


@pytest.mark.parametrize(
    ("choice", "tag", "scheme"),
    [
        ("dark", '<html lang="en" data-theme="dark">', 'content="dark"'),
        ("light", '<html lang="en" data-theme="light">', 'content="light"'),
        ("system", '<html lang="en">', 'content="dark light"'),
    ],
)
async def test_each_choice_on_every_page(client, seed, login, csrf_of, choice, tag, scheme):
    user = await seed.user("look@example.com")
    await seed.mailbox(user)
    login(client, "look@example.com")
    r = choose(client, csrf_of, choice)
    assert r.status_code == 303 and r.headers["location"] == "/settings/security#look"
    assert f"rs_theme={choice}" in r.headers["set-cookie"]
    for path in ("/", "/messages", "/settings/security", "/mailboxes", "/assistant"):
        page = client.get(path).text
        assert html_tag(page) == tag, path
        assert f'<meta name="color-scheme" {scheme}>' in page, path
    settings_page = client.get("/settings/security").text
    assert f'value="{choice}" checked data-theme-choice' in settings_page


async def test_choice_follows_the_person_to_another_device(app, client, seed, login, csrf_of):
    await seed.user("two@example.com")
    login(client, "two@example.com")
    choose(client, csrf_of, "light")
    with TestClient(app, follow_redirects=False) as phone:  # a new device: no rs_theme cookie yet
        assert 'data-theme' not in html_tag(phone.get("/login").text)
        login(phone, "two@example.com")
        home = phone.get("/")
        assert html_tag(home.text) == '<html lang="en" data-theme="light">'
        assert "rs_theme=light" in home.headers.get("set-cookie", "")  # the device copy catches up
        # Next page: cookie already right, nothing more to write.
        again = phone.get("/")
        assert "rs_theme" not in again.headers.get("set-cookie", "")
        # Signed out, the device cookie keeps the sign-in page in the same look.
        phone.post("/auth/logout", data={"csrf_token": csrf_of(phone, "/settings/security")})
        assert html_tag(phone.get("/login").text) == '<html lang="en" data-theme="light">'


async def test_saved_choice_beats_a_stale_device_cookie(client, seed, login, csrf_of):
    await seed.user("stale@example.com")
    login(client, "stale@example.com")
    choose(client, csrf_of, "dark")
    client.cookies.set("rs_theme", "light")  # e.g. changed on another device meanwhile
    page = client.get("/")
    assert 'data-theme="dark"' in html_tag(page.text) and "rs_theme=dark" in page.headers["set-cookie"]


async def test_unknown_values_fall_back_to_system(client, seed, login, csrf_of):
    await seed.user("odd@example.com")
    login(client, "odd@example.com")
    choose(client, csrf_of, "neon")
    assert html_tag(client.get("/").text) == '<html lang="en">'
    client.cookies.set("rs_theme", "purple")
    assert html_tag(client.get("/").text) == '<html lang="en">'


async def test_lock_page_uses_the_saved_choice(client, seed, login, csrf_of):
    await seed.user("locked@example.com")
    login(client, "locked@example.com")
    choose(client, csrf_of, "light")
    client.post("/settings/lock", data={"csrf_token": csrf_of(client, "/settings/security"), "kind": "pin",
                                        "secret": "482913", "confirm": "482913", "timeout": "5m"})
    client.post("/lock/now", data={"csrf_token": csrf_of(client, "/settings/security")})
    client.cookies.delete("rs_theme")
    page = client.get("/lock")
    assert page.status_code == 200 and "Secureddy is locked" in page.text
    assert html_tag(page.text) == '<html lang="en" data-theme="light">'


async def test_theme_form_works_without_scripts_and_returns_to_next(client, seed, login, csrf_of):
    await seed.user("next@example.com")
    login(client, "next@example.com")
    page = client.get("/settings/security").text
    assert "<noscript><button" in page and "data-theme-form" in page
    r = choose(client, csrf_of, "dark", next="/messages")
    assert r.headers["location"] == "/messages"
    r = choose(client, csrf_of, "dark", next="https://evil.example/")
    assert r.headers["location"] == "/settings/security#look"
