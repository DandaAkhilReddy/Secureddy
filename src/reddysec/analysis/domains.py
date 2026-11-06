"""Brand knowledge and lookalike-domain detection.

Phishing works by looking like someone the reader trusts. This module answers
three questions: which brand does a legitimate domain belong to, which brands
does a piece of text mention, and does a host *resemble* a brand domain or one
of the client's own correspondents without being it.

Lookalike classes detected (``LookalikeReason``):

* HOMOGLYPH      ``pаypal.com`` with a Cyrillic ``а``, ``paypa1.com``, ``rnicrosoft.com``
* TYPOSQUAT      one letter missing, doubled or swapped: ``chse.com``, ``chasse.com``
* EDIT_DISTANCE  within Damerau-Levenshtein 2 of a target label: ``docusing.net``
* BRAND_EMBEDDED the brand is a token of a host it does not own:
  ``chase.com.secure-login.ru``, ``chase-online-secure.com``, ``secure-docusign.net``
* TLD_SWAP       right label, wrong suffix: ``paypal.net`` when only ``paypal.com`` is real

``data/brands.json`` is deliberately small and curated: it covers the brands
that appear in consumer phishing, not the whole internet. False positives cost
the client trust in the product, so every rule below has a guard against
ordinary words (``delta-dental.com`` is not Delta Air Lines).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache

from pydantic import BaseModel

from .common import DATA_DIR
from .urls import registrable_domain, split_host

# Unicode confusables and ASCII look-alikes mapped onto the Latin letter they
# imitate. Multi-character sequences are applied before single characters.
# "cl" -> "d" is a real confusable too, but it mangles ordinary words (icloud, click)
# far more often than it catches an attack, so it is left out on purpose.
_MULTI_CONFUSABLES: tuple[tuple[str, str], ...] = (("rn", "m"), ("vv", "w"))
_CONFUSABLES: dict[str, str] = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "ԛ": "q", "ԝ": "w", "һ": "h", "ӏ": "l", "к": "k", "м": "m", "т": "t",
    "в": "b", "н": "h", "ғ": "f", "ԍ": "g", "ɡ": "g",
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "ι": "i", "κ": "k", "υ": "u", "ε": "e",
    "η": "n", "μ": "u", "χ": "x", "ω": "w", "β": "b", "γ": "y",
    # Latin letters with diacritics
    "ä": "a", "à": "a", "á": "a", "â": "a", "ã": "a", "å": "a", "ā": "a", "ă": "a", "ą": "a",
    "é": "e", "è": "e", "ê": "e", "ë": "e", "ē": "e", "ė": "e", "ę": "e", "ě": "e",
    "í": "i", "ì": "i", "î": "i", "ï": "i", "ī": "i", "ı": "i", "į": "i",
    "ó": "o", "ò": "o", "ô": "o", "ö": "o", "õ": "o", "ø": "o", "ō": "o", "ő": "o",
    "ú": "u", "ù": "u", "û": "u", "ü": "u", "ū": "u", "ů": "u", "ű": "u",
    "ç": "c", "ć": "c", "č": "c", "ñ": "n", "ń": "n", "ň": "n", "ś": "s", "š": "s", "ş": "s",
    "ý": "y", "ÿ": "y", "ž": "z", "ź": "z", "ż": "z", "ğ": "g", "ł": "l", "ď": "d", "ť": "t",
    "ŕ": "r", "ř": "r", "ķ": "k", "ļ": "l", "ņ": "n", "ţ": "t",
    # Digits and symbols used as letters
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "$": "s", "@": "a", "|": "l",
}

# Words that, next to a brand token, turn an ordinary-looking host into a
# credential lure (``ups-tracking-secure.com``). They also unlock matching of
# brand tokens that are ordinary words on their own.
_CREDENTIAL_WORDS: frozenset[str] = frozenset(
    {
        "secure", "security", "login", "logon", "signin", "sign-in", "auth", "verify", "verification",
        "account", "accounts", "update", "support", "billing", "portal", "alert", "alerts", "service",
        "services", "online", "banking", "id", "password", "recovery", "confirm", "validate", "wallet",
        "payment", "payments", "invoice", "docs", "document", "documents", "share", "file", "files",
        "mail", "webmail", "office", "cloud", "notice", "help", "helpdesk", "customer", "team",
        "tracking", "delivery", "parcel", "refund", "reward", "rewards", "bonus", "unlock", "suspended",
        "mfa", "2fa", "otp", "sso", "e-sign", "esign", "signature", "review", "statement", "tax",
        "meeting", "join", "webinar", "conference", "invite", "invitation", "voicemail", "fax", "shared",
    }
)

# Brand tokens that are also everyday words or surnames. Alone they prove
# nothing; with a credential word next to them they are a lure.
_COMMON_WORD_TOKENS: frozenset[str] = frozenset(
    {
        "delta", "united", "american", "target", "apple", "amazon", "chase", "box", "meta", "spectrum",
        "discover", "zoom", "slack", "mint", "uber", "square", "ring", "nest", "max", "live", "office",
        "windows", "force", "shop", "marcus", "kraken", "norton", "hilton", "marriott", "charter",
        "frontier", "ally", "gemini", "wise", "plaid", "capital", "teams", "azure", "sharepoint", "skype",
        "audible", "prime", "citi", "intuit", "okta", "lyft", "etsy", "ebay", "venmo", "zelle", "gs", "ms",
        "costco", "walmart", "fedex", "usps", "ups", "dhl", "irs", "ssa", "att", "adp", "wix", "aa", "wf",
        "td", "ml", "x", "t", "fb", "wa", "db", "we", "me", "mac", "go", "app", "my", "sf", "hs", "rs",
    }
)
_GENERIC_LABELS: frozenset[str] = frozenset(
    {"live", "mac", "me", "we", "wa", "go", "x", "t", "db", "ml", "wf", "gs", "ms", "aa", "td", "fb", "shop",
     "force", "mint", "max", "app", "mail", "my", "sf", "hs", "rs", "en25", "mkt", "a2z", "vzw", "e", "ct",
     "prime", "news", "jobs", "windows", "office", "teams", "azure"}
)


class LookalikeReason(str, Enum):
    HOMOGLYPH = "homoglyph"
    TYPOSQUAT = "typosquat"
    EDIT_DISTANCE = "edit_distance"
    BRAND_EMBEDDED = "brand_embedded"
    TLD_SWAP = "tld_swap"


class LookalikeResult(BaseModel):
    """Outcome of :func:`lookalike_analysis`.

    ``target`` is the brand name (``"chase"``) or the contact domain the host
    imitates; ``target_domain`` is the legitimate domain it was compared with.
    """

    is_lookalike: bool = False
    reason: LookalikeReason | None = None
    target: str | None = None
    target_domain: str | None = None
    is_contact: bool = False
    detail: str = ""

    @property
    def weight(self) -> int:
        """How strongly this class of lookalike should count (max 60)."""
        if not self.is_lookalike or self.reason is None:
            return 0
        return {
            LookalikeReason.HOMOGLYPH: 60,
            LookalikeReason.BRAND_EMBEDDED: 60,
            LookalikeReason.TYPOSQUAT: 55,
            LookalikeReason.EDIT_DISTANCE: 50,
            LookalikeReason.TLD_SWAP: 45,
        }[self.reason]


@dataclass(frozen=True)
class Brand:
    name: str
    keywords: tuple[str, ...]
    domains: tuple[str, ...]

    @property
    def primary_domain(self) -> str:
        return registrable_domain(self.domains[0]) if self.domains else ""


@lru_cache(maxsize=1)
def brands() -> tuple[Brand, ...]:
    data = json.loads((DATA_DIR / "brands.json").read_text(encoding="utf-8"))
    return tuple(
        Brand(
            name=entry["brand"].lower(),
            keywords=tuple(k.lower() for k in entry.get("keywords", ())),
            domains=tuple(d.lower() for d in entry.get("domains", ())),
        )
        for entry in data
    )


@lru_cache(maxsize=1)
def _domain_to_brand() -> dict[str, str]:
    mapping: dict[str, str] = {}
    for b in brands():
        for d in b.domains:
            mapping.setdefault(registrable_domain(d), b.name)
    return mapping


@lru_cache(maxsize=1)
def brand_domains() -> frozenset[str]:
    """Every legitimate registrable domain in the brand list."""
    return frozenset(_domain_to_brand())


@lru_cache(maxsize=1)
def _label_index() -> dict[str, tuple[str, str]]:
    """Second-level label -> (brand name, the legitimate domain using that label).

    Generic labels (``live``, ``me``, ``shop``) are left out: they are real
    brand domains, but no attacker needs to imitate them and every second
    legitimate host would otherwise look like a typo of one.
    """
    index: dict[str, tuple[str, str]] = {}
    for b in brands():
        for d in b.domains:
            label = split_host(d)[1]
            if label and label not in _GENERIC_LABELS:
                index.setdefault(label, (b.name, registrable_domain(d)))
    return index


@lru_cache(maxsize=1)
def _embedded_tokens() -> dict[str, tuple[str, str]]:
    """Tokens that, found inside a foreign host, mean the host borrows a brand's name."""
    tokens: dict[str, tuple[str, str]] = {}
    for b in brands():
        tokens.setdefault(b.name, (b.name, b.primary_domain))
        for kw in b.keywords:
            compact = re.sub(r"[^a-z0-9]", "", kw)
            if len(compact) >= 3:
                tokens.setdefault(compact, (b.name, b.primary_domain))
        for d in b.domains:
            label = split_host(d)[1]
            if label and len(label) >= 5 and label not in _GENERIC_LABELS:
                tokens.setdefault(label, (b.name, registrable_domain(d)))
    return tokens


@lru_cache(maxsize=1)
def _keyword_patterns() -> tuple[tuple[str, str, re.Pattern[str]], ...]:
    pats: list[tuple[str, str, re.Pattern[str]]] = []
    for b in brands():
        for kw in b.keywords:
            escaped = re.escape(kw).replace(r"\ ", r"[\s\-]*")
            pats.append((b.name, kw, re.compile(rf"(?<![a-z0-9]){escaped}(?![a-z0-9])", re.IGNORECASE)))
    return tuple(pats)


def brand_for_domain(domain: str) -> str | None:
    """Brand that legitimately owns ``domain`` (host or registrable domain), else None."""
    if not domain:
        return None
    return _domain_to_brand().get(registrable_domain(domain))


def legit_domains_for(brand: str) -> frozenset[str]:
    for b in brands():
        if b.name == brand.lower():
            return frozenset(registrable_domain(d) for d in b.domains)
    return frozenset()


def brands_mentioned(text: str | None) -> list[str]:
    """Brands named in free text, by keyword (word-bounded, case-insensitive).

    Very short keywords (``irs``, ``ups``, ``adp``) only count when written in
    capitals, because as lowercase words they are everyday English.
    """
    if not text:
        return []
    found: list[str] = []
    for name, kw, pat in _keyword_patterns():
        if name in found:
            continue
        for m in pat.finditer(text):
            if len(kw) <= 3 and not m.group(0).isupper():
                continue
            found.append(name)
            break
    return found


# --------------------------------------------------------------------------- string distance


def skeleton(label: str) -> str:
    """Collapse confusable characters onto their Latin look-alike."""
    s = label.lower()
    for seq, repl in _MULTI_CONFUSABLES:
        s = s.replace(seq, repl)
    return "".join(_CONFUSABLES.get(ch, ch) for ch in s)


def damerau_levenshtein(a: str, b: str) -> int:
    """Optimal string alignment distance: insert, delete, substitute, swap adjacent."""
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def unicode_host(host: str) -> str:
    """Decode punycode labels so ``xn--pypal-4ve.com`` becomes ``pаypal.com``."""
    out: list[str] = []
    for label in host.lower().split("."):
        if label.startswith("xn--"):
            try:
                out.append(label.encode("ascii").decode("idna"))
                continue
            except (UnicodeError, ValueError):
                pass
        out.append(label)
    return ".".join(out)


def typosquat_kind(candidate: str, target: str) -> str | None:
    """'missing letter', 'doubled letter', 'swapped letters', or None if not that simple."""
    if len(candidate) + 1 == len(target):
        for i in range(len(target)):
            if target[:i] + target[i + 1 :] == candidate:
                return "missing letter"
    if len(candidate) == len(target) + 1:
        for i in range(1, len(candidate)):
            if candidate[:i] + candidate[i + 1 :] == target and candidate[i] == candidate[i - 1]:
                return "doubled letter"
    if len(candidate) == len(target):
        diffs = [i for i, (x, y) in enumerate(zip(candidate, target, strict=True)) if x != y]
        if len(diffs) == 2 and diffs[1] == diffs[0] + 1:
            i = diffs[0]
            if candidate[i] == target[i + 1] and candidate[i + 1] == target[i]:
                return "swapped letters"
    return None


def _distance_allowed(candidate: str, target: str) -> int:
    """Shorter labels tolerate less distance: ``ubr`` vs ``uber`` is noise, ``docusing`` is not.

    Five-letter labels are the hard case (``apply`` is one substitution from
    ``apple``), so at that length the caller additionally requires a classic
    typo shape (missing, doubled or swapped letter) rather than any edit.
    """
    shortest = min(len(candidate), len(target))
    if shortest >= 8:
        return 2
    if shortest >= 5:
        return 1
    return 0


def _contact_targets(contact_domains: Iterable[str]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for c in contact_domains:
        c = (c or "").strip().lower()
        if not c:
            continue
        rd = registrable_domain(c)
        label = split_host(rd)[1]
        if label and rd not in seen:
            seen.add(rd)
            out.append((label, rd))
    return out


def lookalike_analysis(
    host: str, registrable: str | None = None, contact_domains: Iterable[str] = ()
) -> LookalikeResult:
    """Decide whether ``host`` imitates a known brand or one of the client's contacts.

    Legitimate brand domains and the contact domains themselves are never
    lookalikes, no matter how similar they are to one another.
    """
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return LookalikeResult()
    rd = (registrable or registrable_domain(host)).lower()
    contacts = _contact_targets(contact_domains)
    if rd in brand_domains() or rd in {c_rd for _, c_rd in contacts}:
        return LookalikeResult()

    _sub, label, suffix = split_host(rd)
    if not label or not suffix:
        return LookalikeResult()
    u_label = split_host(unicode_host(rd))[1] or label
    label_skel = skeleton(u_label)

    def hit(reason: LookalikeReason, name: str, domain: str, is_contact: bool, detail: str) -> LookalikeResult:
        return LookalikeResult(
            is_lookalike=True, reason=reason, target=name, target_domain=domain, is_contact=is_contact, detail=detail
        )

    # 1. Homoglyphs: after collapsing confusables the label *is* a target label.
    if label_skel != label:
        brand_hit = _label_index().get(label_skel)
        if brand_hit is not None:
            return hit(LookalikeReason.HOMOGLYPH, brand_hit[0], brand_hit[1], False, f"{rd} imitates {brand_hit[1]}")
        for t_label, c_rd in contacts:
            if label_skel == skeleton(t_label):
                return hit(LookalikeReason.HOMOGLYPH, c_rd, c_rd, True, f"{rd} imitates {c_rd}")

    # 2. Same label, different suffix.
    if len(label) >= 4:
        brand_hit = _label_index().get(label)
        if brand_hit is not None:
            return hit(LookalikeReason.TLD_SWAP, brand_hit[0], brand_hit[1], False, f"{rd} borrows the name of {brand_hit[1]}")
        for t_label, c_rd in contacts:
            if label == t_label:
                return hit(LookalikeReason.TLD_SWAP, c_rd, c_rd, True, f"{rd} borrows the name of {c_rd}")

    # 3. Typos and small edits against brand labels and contact labels.
    targets: list[tuple[str, str, str, bool]] = [
        (t_label, b_name, b_domain, False) for t_label, (b_name, b_domain) in _label_index().items()
    ] + [(t_label, c_rd, c_rd, True) for t_label, c_rd in contacts]
    best: tuple[int, LookalikeResult] | None = None
    for t_label, name, domain, is_contact in targets:
        allowed = _distance_allowed(label, t_label)
        if allowed == 0:
            continue
        d = min(damerau_levenshtein(label, t_label), damerau_levenshtein(label_skel, t_label))
        if not (0 < d <= allowed) or (best is not None and d >= best[0]):
            continue
        kind = typosquat_kind(label, t_label) or typosquat_kind(label_skel, t_label)
        if kind is None and min(len(label), len(t_label)) < 6:
            continue
        reason = LookalikeReason.TYPOSQUAT if kind else LookalikeReason.EDIT_DISTANCE
        detail = f"{rd} is a {kind} away from {domain}" if kind else f"{rd} is {d} edit(s) from {domain}"
        best = (d, hit(reason, name, domain, is_contact, detail))
    if best is not None:
        return best[1]

    # 4. Brand or contact name used as a token of a host it does not own.
    suffix_labels = set(suffix.split("."))
    raw_tokens = [t for t in re.split(r"[.\-_]", unicode_host(host)) if t and t not in suffix_labels]
    # Each token is tried as written and with confusables collapsed, so both
    # ``paypal.evil.com`` and ``paypa1.evil.com`` resolve to the same brand.
    tokens = [t for t in raw_tokens if t not in {label, u_label}]
    token_set = {t for tok in tokens for t in (tok, skeleton(tok))}
    has_credential_word = bool(set(raw_tokens) & _CREDENTIAL_WORDS)
    for tok in tokens:
        for token in (tok, skeleton(tok)):
            brand_hit = _embedded_tokens().get(token)
            if brand_hit is None:
                continue
            distinctive = len(token) >= 5 and token not in _COMMON_WORD_TOKENS
            if distinctive or has_credential_word:
                return hit(
                    LookalikeReason.BRAND_EMBEDDED, brand_hit[0], brand_hit[1], False, f"{host} contains the name {token}"
                )
    for t_label, c_rd in contacts:
        if t_label in token_set and (len(t_label) >= 6 or has_credential_word):
            return hit(LookalikeReason.BRAND_EMBEDDED, c_rd, c_rd, True, f"{host} contains the name {t_label}")
    return LookalikeResult()
