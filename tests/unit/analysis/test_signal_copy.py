"""``analysis.signal_copy``: every lure signal the engine can emit has calm,
plain-English copy with a title, an explanation and what to do."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from reddysec.analysis import signal_copy
from reddysec.analysis.click_advice import DO_NOT_OPEN, READING_ROOM, SAFE
from reddysec.chamber import lures as chamber_lures

SRC = Path(signal_copy.__file__).resolve().parent
_CODE_RE = re.compile(r'"((?:url|dynamic|attachment|bec|sender)\.[a-z_]+)"')
# The modules that introduced the lure signals (and the codes they added to
# older modules). Every code they emit must have copy here.
NEW_CODES = {
    "sender.display_hidden_chars", "attachment.svg_phish", "attachment.html_clickfix", "attachment.filename_trick",
}


def lure_codes() -> set[str]:
    return set(_CODE_RE.findall((SRC / "lures.py").read_text())) | NEW_CODES


def test_scanner_finds_the_lure_codes():
    assert {"dynamic.clickfix", "dynamic.clipboard_hijack", "dynamic.fake_captcha", "bec.device_code_lure"} <= lure_codes()


@pytest.mark.parametrize("code", sorted(lure_codes()))
def test_every_lure_code_has_copy(code):
    entry = signal_copy.copy_for(code)
    assert entry is not None, f"no copy for {code}"
    assert set(entry) == {"title", "explanation", "what_to_do"}
    assert all(entry[k].strip() for k in entry)
    assert len(entry["title"]) <= 60
    text = " ".join(entry.values())
    for jargon in ("PowerShell", "clipboard API", "AiTM", "OAuth", "payload", "DOM", "base64", "JavaScript"):
        assert jargon not in text, f"{code}: jargon {jargon!r}"


def test_clickfix_copy_matches_the_brief():
    entry = signal_copy.SIGNAL_COPY["dynamic.clickfix"]
    assert entry["title"] == "Fake 'I'm not a robot' check"
    assert "Real websites never do this" in entry["explanation"]
    assert "disconnect from the internet" in entry["what_to_do"]


def test_placeholders_are_known():
    allowed = {"filename", "host", "brand"}
    for code, entry in signal_copy.SIGNAL_COPY.items():
        for value in entry.values():
            assert set(re.findall(r"{(\w+)}", value)) <= allowed, code


def test_click_advice_copy():
    assert set(signal_copy.CLICK_ADVICE_COPY) == {SAFE, READING_ROOM, DO_NOT_OPEN}
    assert signal_copy.CLICK_ADVICE_COPY[DO_NOT_OPEN]["label"] == "Do not open"


def test_unknown_code():
    assert signal_copy.copy_for("x.unknown") is None


def test_chamber_module_is_dependency_free():
    source = Path(chamber_lures.__file__).read_text()
    imports = {m.group(1) for m in re.finditer(r"^(?:from|import)\s+([\w.]+)", source, re.M)}
    assert imports <= {"__future__", "re", "dataclasses"}
