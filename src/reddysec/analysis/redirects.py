"""Open redirects, link wrappers and free hosting: where a link really goes.

Two related questions about a link, both answered offline from the URL alone:

* **Where does it really go?** Attackers start a link on a domain everyone
  trusts (``google.com/url?q=``, ``bing.com/ck/a``, ``l.facebook.com``,
  ``linkedin.com/slink``) so filters and people see a good name first.
  Security wrappers (Outlook Safe Links, Proofpoint URL Defense, Barracuda)
  do the same for benign reasons. :func:`unwrap_chain` peels every layer we
  can decode and returns the chain, outermost first; the last element is the
  address the engine scores and detonates.
* **Is the destination on a free hosting platform?** See
  ``data/abused_hosts.txt`` and :func:`free_hosting_match`.

Pure and offline: nothing here fetches a URL.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from functools import cache
from urllib.parse import parse_qsl, unquote, urlsplit

from .common import DATA_DIR

MAX_UNWRAP_HOPS = 6

# Benign security wrappers: unwrap, never a signal.
SECURITY_WRAPPER = "security_wrapper"
# Redirectors on trusted domains that anyone can point anywhere.
OPEN_REDIRECT = "open_redirect"
# Redirectors whose destination is stored server-side: we cannot decode it,
# only say the destination is hidden (the sandbox follows it).
HIDDEN_DESTINATION = "hidden_destination"

_URL_PARAM_NAMES = ("url", "u", "q", "target", "dest", "destination", "redirect", "redirect_url", "redirect_uri",
                    "goto", "link", "to", "uddg", "out", "r")


@dataclass(frozen=True)
class Hop:
    url: str
    kind: str  # SECURITY_WRAPPER | OPEN_REDIRECT | HIDDEN_DESTINATION | "" (final)
    via: str = ""  # wrapper name, for the report


def _params(query: str) -> dict[str, str]:
    return {k.lower(): v for k, v in parse_qsl(query, keep_blank_values=True)}


def _absolute(value: str) -> str | None:
    value = (value or "").strip()
    if value.lower().startswith(("http://", "https://")):
        return value
    if value.lower().startswith("www."):
        return "http://" + value
    return None


def _b64_url(value: str) -> str | None:
    """bing.com/ck/a carries ``u=a1<base64url of the target>``."""
    raw = value[2:] if value[:2] in {"a1", "a0"} else value
    raw = raw + "=" * (-len(raw) % 4)
    try:
        decoded = base64.urlsafe_b64decode(raw.encode()).decode("utf-8", errors="strict")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return _absolute(decoded)


def _urldefense_v2(value: str) -> str:
    # https-3A__example.com_path -> https://example.com/path
    return unquote(value.replace("-", "%").replace("_", "/"))


_URLDEFENSE_V3_RE = re.compile(r"^/v3/__(.+?)__;", re.S)


def unwrap_once(url: str) -> Hop | None:
    """The next hop behind ``url`` when it is a known wrapper/redirector, else ``None``.

    Returns a :class:`Hop` whose ``url`` is the destination and whose ``kind``
    describes the wrapper we peeled (``HIDDEN_DESTINATION`` hops return the
    wrapper itself as ``url``: there is nothing to peel).
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    path = parts.path or "/"
    params = _params(parts.query)

    # -- benign security wrappers
    if host.endswith("safelinks.protection.outlook.com") and params.get("url"):
        target = _absolute(params["url"])
        return Hop(target, SECURITY_WRAPPER, "Outlook Safe Links") if target else None
    if host == "urldefense.proofpoint.com" and params.get("u"):
        target = _absolute(_urldefense_v2(params["u"]))
        return Hop(target, SECURITY_WRAPPER, "Proofpoint URL Defense") if target else None
    if host == "urldefense.com":
        m = _URLDEFENSE_V3_RE.match(path + ("?" + parts.query if parts.query else ""))
        target = _absolute(m.group(1)) if m else None
        return Hop(target, SECURITY_WRAPPER, "Proofpoint URL Defense") if target else None
    if host == "linkprotect.cudasvc.com" and params.get("a"):
        target = _absolute(params["a"])
        return Hop(target, SECURITY_WRAPPER, "Barracuda Link Protection") if target else None
    if host.endswith("mimecastprotect.com") or (host.startswith("protect") and host.endswith("mimecast.com")):
        return Hop(url, HIDDEN_DESTINATION, "Mimecast")

    # -- open redirects on trusted domains
    google = host in {"google.com", "www.google.com"} or re.fullmatch(r"(?:www\.)?google\.[a-z.]{2,6}", host)
    if google and path == "/url":
        target = _absolute(params.get("q") or params.get("url") or "")
        return Hop(target, OPEN_REDIRECT, "google.com") if target else None
    if google and path.startswith("/amp/s/"):
        return Hop("https://" + path[len("/amp/s/"):] + ("?" + parts.query if parts.query else ""), OPEN_REDIRECT, "Google AMP")
    if host in {"bing.com", "www.bing.com"} and path.startswith("/ck/a") and params.get("u"):
        target = _b64_url(params["u"])
        return Hop(target, OPEN_REDIRECT, "bing.com") if target else Hop(url, HIDDEN_DESTINATION, "bing.com")
    if host in {"l.facebook.com", "lm.facebook.com", "l.instagram.com", "l.messenger.com"} and params.get("u"):
        target = _absolute(params["u"])
        return Hop(target, OPEN_REDIRECT, host) if target else None
    if host in {"www.youtube.com", "youtube.com"} and path == "/redirect" and params.get("q"):
        target = _absolute(params["q"])
        return Hop(target, OPEN_REDIRECT, "youtube.com") if target else None
    if host in {"www.linkedin.com", "linkedin.com"} and path.startswith("/redir/redirect") and params.get("url"):
        target = _absolute(params["url"])
        return Hop(target, OPEN_REDIRECT, "linkedin.com") if target else None
    if host in {"www.linkedin.com", "linkedin.com"} and path.startswith("/slink"):
        return Hop(url, HIDDEN_DESTINATION, "LinkedIn Smart Link")
    if host == "slack-redir.net" and params.get("url"):
        target = _absolute(params["url"])
        return Hop(target, OPEN_REDIRECT, "slack-redir.net") if target else None
    if host in {"duckduckgo.com", "www.duckduckgo.com"} and path.startswith("/l/") and params.get("uddg"):
        target = _absolute(params["uddg"])
        return Hop(target, OPEN_REDIRECT, "duckduckgo.com") if target else None
    if host == "away.vk.com" and params.get("to"):
        target = _absolute(params["to"])
        return Hop(target, OPEN_REDIRECT, "vk.com") if target else None
    return None


def unwrap_chain(url: str, max_hops: int = MAX_UNWRAP_HOPS) -> list[Hop]:
    """Peel every known wrapper. Returns ``[Hop(outer, kind), ..., Hop(final, "")]``;
    a URL that is not wrapped comes back as a single final hop."""
    chain: list[Hop] = []
    current = url
    for _ in range(max_hops):
        nxt = unwrap_once(current)
        if nxt is None:
            break
        chain.append(Hop(current, nxt.kind, nxt.via))
        if nxt.kind == HIDDEN_DESTINATION or nxt.url == current:
            return chain
        current = nxt.url
    chain.append(Hop(current, ""))
    return chain


def unwrap(url: str) -> str:
    """The innermost address we can decode (``url`` itself when not wrapped)."""
    chain = unwrap_chain(url)
    return chain[-1].url if chain else url


def generic_redirect_target(url: str) -> str | None:
    """An absolute URL carried in a redirect-looking query parameter of an
    unknown redirector (``click.example/?url=https://other.example/``). Used
    only to *show* the chain; it is not unwrapped for scoring because ESP
    click trackers look exactly like this."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    params = _params(parts.query)
    host = (parts.hostname or "").lower()
    for name in _URL_PARAM_NAMES:
        target = _absolute(unquote(params.get(name, "")))
        if target and (urlsplit(target).hostname or "").lower() != host:
            return target
    return None


# --------------------------------------------------------------------------- free hosting


@cache
def _abused_entries() -> tuple[tuple[str, str], ...]:
    out: list[tuple[str, str]] = []
    for line in (DATA_DIR / "abused_hosts.txt").read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if not line:
            continue
        host, _, path = line.partition("/")
        out.append((host, "/" + path if path else ""))
    return tuple(out)


def free_hosting_match(url: str) -> str | None:
    """The ``abused_hosts.txt`` entry ``url`` falls under, or ``None``."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    host = (parts.hostname or "").lower().rstrip(".")
    path = (parts.path or "/").lower()
    if not host:
        return None
    for suffix, prefix in _abused_entries():
        if host == suffix or host.endswith("." + suffix):
            if prefix and not path.startswith(prefix):
                continue
            return suffix + prefix
    # IPFS content addressed by subdomain gateway: <cid>.ipfs.<gateway>
    if ".ipfs." in host or host.startswith("ipfs."):
        return "ipfs gateway"
    return None
