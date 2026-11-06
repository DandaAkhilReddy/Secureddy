"""Small helpers shared by the analysis modules.

Everything here is pure and offline. The bundled data files live next to this
module in ``data/`` so the engine never depends on a network fetch at import
time (tldextract, for instance, would otherwise try to refresh the public
suffix list).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterable
from functools import cache
from pathlib import Path
from typing import Any

from reddysec.models import Signal, SignalStage

DATA_DIR = Path(__file__).resolve().parent / "data"

# Consumer mailbox providers. A message from one of these is from a person (or
# an attacker), never from a company's own mail system.
FREEMAIL_DOMAINS: frozenset[str] = frozenset(
    {
        "gmail.com",
        "googlemail.com",
        "yahoo.com",
        "yahoo.co.uk",
        "yahoo.ca",
        "yahoo.fr",
        "yahoo.de",
        "yahoo.co.in",
        "ymail.com",
        "rocketmail.com",
        "outlook.com",
        "hotmail.com",
        "hotmail.co.uk",
        "live.com",
        "msn.com",
        "aol.com",
        "protonmail.com",
        "protonmail.ch",
        "proton.me",
        "pm.me",
        "icloud.com",
        "me.com",
        "mac.com",
        "mail.com",
        "gmx.com",
        "gmx.net",
        "gmx.de",
        "zoho.com",
        "zohomail.com",
        "yandex.com",
        "yandex.ru",
        "mail.ru",
        "fastmail.com",
        "hey.com",
        "tutanota.com",
        "tuta.io",
        "tuta.com",
    }
)

# Words that make a display name read like an organisation rather than a
# person ("Chase Fraud Department", "IT Support", "Payroll Team").
COMPANY_WORDS_RE = re.compile(
    r"\b(?:department|dept|team|support|service|services|security|fraud|billing|alerts?|"
    r"notifications?|bank|banking|online|accounts?|customer|care|helpdesk|help\s*desk|"
    r"it\s*desk|payroll|hr|human\s+resources|admin|administrator|office|inc|llc|ltd|corp|"
    r"corporation|company|group|holdings|partners|capital|wealth|advisors|foundation|trust|"
    r"legal|law|attorney|verification|center|centre|desk)\b",
    re.IGNORECASE,
)

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-']+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def load_lines(name: str) -> frozenset[str]:
    """Read a bundled ``data/*.txt`` list: one lowercase entry per line, ``#`` comments."""
    path = DATA_DIR / name
    entries: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            entries.add(line.lower())
    return frozenset(entries)


@cache
def cached_lines(name: str) -> frozenset[str]:
    return load_lines(name)


def make_signal(
    code: str,
    stage: SignalStage,
    weight: int | float,
    title: str,
    detail: str = "",
    **evidence: Any,
) -> Signal:
    """Build a Signal while honouring the model's bounds.

    Weights are clamped to [-60, 100] and titles cut to 120 characters so a
    detector can never produce an invalid Verdict because of a long filename
    or a weight computed from a confidence score.
    """
    w = int(round(weight))
    w = max(-60, min(100, w))
    if len(title) > 120:
        title = title[:117] + "..."
    clean_evidence = {k: v for k, v in evidence.items() if v is not None}
    return Signal(code=code, stage=stage, weight=w, title=title, detail=detail, evidence=clean_evidence)


def shannon_entropy(text: str) -> float:
    """Bits per character. Random tokens score > 3.5; English words score < 3.2."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def clamp(value: int | float, low: int, high: int) -> int:
    return int(max(low, min(high, round(value))))


def is_freemail(domain: str) -> bool:
    d = domain.lower().strip(".")
    return d in FREEMAIL_DOMAINS or d.startswith("yahoo.") or d.startswith("hotmail.") or d.startswith("outlook.")


def looks_like_company(display_name: str | None) -> bool:
    return bool(display_name) and COMPANY_WORDS_RE.search(display_name) is not None


def truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)] + "..."


def safe_decode(data: bytes, limit: int | None = None) -> str:
    """Decode bytes as UTF-8 (then latin-1) without ever raising."""
    if limit is not None:
        data = data[:limit]
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace")


def dedupe_preserving_order(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
