"""WCAG AA contrast for every text/background pair used on chips and buttons.

The colours are read from the ``:root`` tokens in ``static/app.css`` so a
palette change that breaks contrast fails here, not in a client's eyes.
AA needs 4.5:1 for normal text (chips and buttons are small, bold text).
"""

from __future__ import annotations

import re

import pytest

from reddysec.web.templating import package_path

TOKEN_RE = re.compile(r"--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})\s*;")


def tokens(theme: str = "dark") -> dict[str, str]:
    css = package_path("static").joinpath("app.css").read_text()
    root = css.split(":root {", 1)[1].split("}", 1)[0]
    base = dict(TOKEN_RE.findall(root))
    if theme == "dark":
        return base
    light = css.split(':root[data-theme="light"] {', 1)[1].split("}", 1)[0]
    return {**base, **dict(TOKEN_RE.findall(light))}


def light_blocks_match() -> bool:
    """The "match my device" copy of the light tokens equals the explicit one."""
    css = package_path("static").joinpath("app.css").read_text()
    explicit = css.split(':root[data-theme="light"] {', 1)[1].split("}", 1)[0]
    media = css.split(':root:not([data-theme="dark"]) {', 1)[1].split("}", 1)[0]
    return dict(TOKEN_RE.findall(explicit)) == dict(TOKEN_RE.findall(media))


def luminance(hex_colour: str) -> float:
    rgb = [int(hex_colour[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def contrast(fg: str, bg: str) -> float:
    a, b = sorted((luminance(fg), luminance(bg)), reverse=True)
    return (a + 0.05) / (b + 0.05)


PAIRS = {
    # chips
    "chip Checked": ("ok", "ok-bg"),
    "chip Suspicious": ("warn", "warn-bg"),
    "chip Quarantine": ("bad", "bad-bg"),
    "chip grey": ("grey", "grey-bg"),
    "chip accent": ("accent-strong", "accent-soft"),
    # buttons
    "btn primary": ("accent-ink", "accent"),
    "btn primary hover": ("accent-ink", "accent-strong"),
    "btn default": ("text", "surface-2"),
    "btn calm (Not suspicious?)": ("ok", "ok-bg"),
    "btn danger outline": ("bad", "surface"),
    "btn danger solid": ("bad-ink", "bad-solid"),
    # body text
    "text on bg": ("text", "bg"),
    "muted on surface": ("text-muted", "surface"),
    "dim on surface": ("text-dim", "surface"),
    "dim on bg": ("text-dim", "bg"),
    "link on surface": ("accent-strong", "surface"),
}


@pytest.mark.parametrize("theme", ["dark", "light"])
@pytest.mark.parametrize("name", sorted(PAIRS))
def test_aa_contrast(name, theme):
    t = tokens(theme)
    fg, bg = PAIRS[name]
    ratio = contrast(t[fg], t[bg])
    assert ratio >= 4.5, f"{theme} {name}: {ratio:.2f}:1"


def test_light_theme_copies_agree():
    assert light_blocks_match()


def test_contrast_helper_is_right():
    assert contrast("#000000", "#ffffff") == pytest.approx(21.0)
    assert contrast("#777777", "#777777") == pytest.approx(1.0)


if __name__ == "__main__":  # pragma: no cover - prints the table for the report
    t = tokens()
    for name, (fg, bg) in PAIRS.items():
        print(f"{name:32s} {t[fg]} on {t[bg]}  {contrast(t[fg], t[bg]):5.2f}:1")
