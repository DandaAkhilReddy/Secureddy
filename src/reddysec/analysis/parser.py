"""RFC 5322 / MIME parsing into the :class:`ParsedMessage` contract.

Design rules:

* Never raise. Phishing kits produce broken MIME on purpose; a message we
  cannot fully parse is *more* interesting, not less, so every step degrades
  to a partial result and the pipeline keeps going.
* Use the receiving provider's ``Authentication-Results`` header, not the
  attacker's. Gmail, Yahoo, iCloud and Outlook.com each write it slightly
  differently; :func:`parse_authentication_results` normalises all four.
* Attachment bytes stay in memory on the model (``Attachment.data``), never
  serialised; everything else about an attachment is metadata.
"""

from __future__ import annotations

import email
import email.policy
import email.utils
import hashlib
import mimetypes
import re
from collections.abc import Iterable
from datetime import UTC, datetime
from email.message import Message

from bs4 import BeautifulSoup

from reddysec.core.logging import get_logger
from reddysec.models import Attachment, AuthResults, ParsedMessage

from . import urls
from .attachments import sniff_type
from .common import EMAIL_RE, safe_decode

log = get_logger(__name__)

THREAD_ID_HEADER = "x-reddysec-thread-id"  # carries the provider thread id without changing the contract
MAX_BODY_CHARS = 2_000_000

# Authentication-Results authserv-ids of the consumer providers we protect.
_PROVIDER_AUTHSERV_HINTS = ("mx.google.com", "yahoo", "icloud", "me.com", "outlook", "hotmail", "protection.outlook.com")
_AUTH_METHODS = ("spf", "dkim", "dmarc")
_RESULT_WORDS = frozenset({"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "policy", "bestguesspass"})


# --------------------------------------------------------------------------- header helpers


def _header_str(msg: Message, name: str) -> str:
    """Decoded header value, or the raw bytes-as-text when the decoder chokes."""
    try:
        value = msg.get(name)
    except Exception:
        value = None
    if value is None:
        return ""
    try:
        return str(value)
    except Exception:
        return ""


def _all_headers(msg: Message) -> dict[str, str]:
    headers: dict[str, str] = {}
    try:
        items = msg.items()
    except Exception:
        return headers
    for key, value in items:
        k = str(key).lower()
        if k in headers:
            continue
        try:
            headers[k] = str(value)
        except Exception:
            headers[k] = ""
    return headers


def _parse_address(value: str) -> tuple[str | None, str]:
    """(display name, address) tolerant of broken quoting and junk."""
    if not value:
        return None, ""
    name, addr = email.utils.parseaddr(value)
    if not addr or "@" not in addr:
        m = EMAIL_RE.search(value)
        addr = m.group(0) if m else ""
        if not name:
            name = value.replace(addr, "").strip(" <>\"',") if addr else value.strip()
    name = name.strip().strip('"').strip() or None
    return name, addr.strip().lower()


def _parse_address_list(value: str) -> list[str]:
    if not value:
        return []
    out: list[str] = []
    try:
        pairs = email.utils.getaddresses([value])
    except Exception:
        pairs = []
    for _name, addr in pairs:
        if addr and "@" in addr:
            out.append(addr.strip().lower())
    if not out:
        out = [m.group(0).lower() for m in EMAIL_RE.finditer(value)]
    return list(dict.fromkeys(out))


def _parse_date(value: str) -> datetime | None:
    if not value:
        return None
    try:
        dt = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


# --------------------------------------------------------------------------- Authentication-Results


def _strip_comments(value: str) -> str:
    """Remove RFC 5322 comments, honouring nesting: ``spf=pass (google.com: domain (x) ...)``."""
    out: list[str] = []
    depth = 0
    for ch in value:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif depth == 0:
            out.append(ch)
    return "".join(out)


def _parse_one_auth_header(value: str) -> tuple[str, dict[str, dict[str, str]]]:
    """Return (authserv-id, {method: {"result": ..., prop: value, ...}})."""
    cleaned = _strip_comments(value.replace("\r", " ").replace("\n", " "))
    segments = [s.strip() for s in cleaned.split(";") if s.strip()]
    authserv = ""
    if segments and "=" not in segments[0].split()[0]:
        authserv = segments.pop(0).split()[0].lower()
    methods: dict[str, dict[str, str]] = {}
    for seg in segments:
        tokens = seg.split()
        if not tokens or "=" not in tokens[0]:
            continue
        method, _, result = tokens[0].partition("=")
        method = method.lower().strip()
        result = result.lower().strip()
        if method not in _AUTH_METHODS:
            continue
        if result not in _RESULT_WORDS:
            result = result.split()[0] if result else "none"
        props: dict[str, str] = {"result": result}
        for tok in tokens[1:]:
            if "=" in tok:
                k, _, v = tok.partition("=")
                props[k.lower()] = v.strip().strip('"')
        existing = methods.get(method)
        # Several DKIM signatures: keep the passing one, it is the one that counts.
        if existing is None or (existing.get("result") != "pass" and result == "pass"):
            methods[method] = props
    return authserv, methods


def _domain_of(value: str) -> str:
    v = value.strip().lower().lstrip("@")
    if "@" in v:
        v = v.rsplit("@", 1)[-1]
    return v.strip(".")


def parse_authentication_results(values: Iterable[str], from_domain: str) -> AuthResults:
    """Fold one or more Authentication-Results headers into :class:`AuthResults`.

    Headers are listed top-down as they appear in the message; the first one
    is the receiving MTA's. We prefer a header whose authserv-id looks like one
    of the providers we protect, then fall back to the first. Methods missing
    from the preferred header are filled from the others.
    """
    values = [v for v in values if v and v.strip()]
    if not values:
        return AuthResults()
    parsed = [_parse_one_auth_header(v) for v in values]
    order = list(range(len(parsed)))
    preferred = [i for i in order if any(h in parsed[i][0] for h in _PROVIDER_AUTHSERV_HINTS)]
    order = preferred + [i for i in order if i not in preferred]

    merged: dict[str, dict[str, str]] = {}
    for i in order:
        for method, props in parsed[i][1].items():
            merged.setdefault(method, props)

    spf = merged.get("spf", {}).get("result")
    dkim = merged.get("dkim", {}).get("result")
    dmarc = merged.get("dmarc", {}).get("result")
    dkim_props = merged.get("dkim", {})
    dkim_domain = _domain_of(dkim_props.get("header.d") or dkim_props.get("header.i") or "") or None
    mailfrom = _domain_of(merged.get("spf", {}).get("smtp.mailfrom") or "")

    from_rd = urls.registrable_domain(from_domain) if from_domain else ""
    aligned: bool | None = None
    if spf or dkim or dmarc:
        aligned = False
        if dmarc == "pass":
            aligned = True
        elif dkim == "pass" and dkim_domain and from_rd and urls.registrable_domain(dkim_domain) == from_rd:
            aligned = True
        elif spf == "pass" and mailfrom and from_rd and urls.registrable_domain(mailfrom) == from_rd:
            aligned = True
    return AuthResults(spf=spf, dkim=dkim, dmarc=dmarc, dkim_domain=dkim_domain, aligned=aligned, raw=" | ".join(values))


# --------------------------------------------------------------------------- bodies and parts


def _part_text(part: Message) -> str:
    """Decoded text of a text/* part, tolerant of lying charsets."""
    try:
        content = part.get_content()
        if isinstance(content, str):
            return content[:MAX_BODY_CHARS]
        if isinstance(content, bytes):
            return safe_decode(content, MAX_BODY_CHARS)
    except Exception:
        pass
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        payload = None
    if isinstance(payload, bytes):
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="replace")[:MAX_BODY_CHARS]
        except LookupError:
            return safe_decode(payload, MAX_BODY_CHARS)
    raw = part.get_payload()
    return raw[:MAX_BODY_CHARS] if isinstance(raw, str) else ""


def _part_bytes(part: Message) -> bytes:
    try:
        if part.get_content_type() == "message/rfc822":
            payload = part.get_payload()
            if isinstance(payload, list) and payload:
                return payload[0].as_bytes()
        data = part.get_payload(decode=True)
    except Exception:
        data = None
    if isinstance(data, bytes):
        return data
    try:
        raw = part.get_payload()
    except Exception:
        return b""
    if isinstance(raw, str):
        return raw.encode("utf-8", errors="replace")
    return b""


def _filename(part: Message, index: int) -> str:
    name = None
    try:
        name = part.get_filename()
    except Exception:
        name = None
    if not name:
        try:
            name = part.get_param("name", header="content-type")
        except Exception:
            name = None
    if isinstance(name, tuple):  # RFC 2231 encoded (charset, language, value)
        try:
            name = email.utils.collapse_rfc2231_value(name)
        except Exception:
            name = name[-1] if name else None
    if name:
        return str(name).strip().replace("\r", "").replace("\n", "")[:255]
    ext = mimetypes.guess_extension(part.get_content_type() or "") or ""
    if part.get_content_type() == "message/rfc822":
        ext = ".eml"
    return f"part-{index}{ext}"


def _declared_extension(filename: str) -> str:
    base = filename.strip()
    if "." not in base:
        return ""
    return base.rsplit(".", 1)[-1].strip().lower()[:16]


def html_to_text(html: str) -> str:
    try:
        soup = BeautifulSoup(html, "lxml")
        for tag in soup(["script", "style", "head", "title"]):
            tag.decompose()
        text = soup.get_text(" ", strip=True)
        return re.sub(r"[ \t]+", " ", text)[:MAX_BODY_CHARS]
    except Exception:
        return re.sub(r"<[^>]+>", " ", html)[:MAX_BODY_CHARS]


def _is_attachment(part: Message) -> bool:
    disposition = (part.get_content_disposition() or "").lower()
    if disposition == "attachment":
        return True
    ctype = part.get_content_type()
    if ctype in {"text/plain", "text/html"} and disposition != "attachment" and not part.get_filename():
        return False
    if ctype.startswith("multipart/"):
        return False
    return True


def _walk(msg: Message) -> Iterable[Message]:
    try:
        yield from msg.walk()
    except Exception:
        yield msg


# --------------------------------------------------------------------------- entry point


def parse_raw(
    raw: bytes,
    *,
    provider_message_id: str,
    mailbox_id: str,
    received_at: datetime,
    thread_id: str | None = None,
) -> ParsedMessage:
    """Parse a raw RFC 5322 message. Never raises; degrades to a partial message.

    ``thread_id`` has no slot in :class:`ParsedMessage`; it is carried in
    ``headers[THREAD_ID_HEADER]`` so downstream code can correlate without a
    contract change.
    """
    raw = raw or b""
    parsed = ParsedMessage(
        provider_message_id=provider_message_id,
        mailbox_id=mailbox_id,
        received_at=received_at,
        raw_size=len(raw),
        raw_sha256=hashlib.sha256(raw).hexdigest(),
    )
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.default)
    except Exception as exc:
        log.warning("mime_parse_failed", provider_message_id=provider_message_id, error=str(exc))
        parsed.headers["x-reddysec-parse-error"] = str(exc)[:200]
        parsed.text_body = safe_decode(raw, 100_000)
        parsed.urls = urls.extract_all(parsed.text_body, None, [])
        return parsed

    try:
        _fill_headers(parsed, msg)
    except Exception as exc:
        log.warning("header_parse_failed", provider_message_id=provider_message_id, error=str(exc))
        parsed.headers["x-reddysec-parse-error"] = f"headers: {exc}"[:200]
    if thread_id:
        parsed.headers[THREAD_ID_HEADER] = thread_id

    try:
        _fill_bodies_and_attachments(parsed, msg)
    except Exception as exc:
        log.warning("body_parse_failed", provider_message_id=provider_message_id, error=str(exc))
        parsed.headers["x-reddysec-parse-error"] = f"body: {exc}"[:200]

    try:
        parsed.urls = urls.extract_all(parsed.text_body, parsed.html_body, parsed.attachments)
    except Exception as exc:
        log.warning("url_extraction_failed", provider_message_id=provider_message_id, error=str(exc))
    return parsed


def _fill_headers(parsed: ParsedMessage, msg: Message) -> None:
    parsed.headers = _all_headers(msg)
    from_name, from_addr = _parse_address(_header_str(msg, "From"))
    if not from_addr:
        from_name2, from_addr = _parse_address(_header_str(msg, "Sender"))
        from_name = from_name or from_name2
    parsed.from_address = from_addr
    parsed.from_name = from_name
    parsed.reply_to = _parse_address_list(_header_str(msg, "Reply-To"))
    parsed.to = _parse_address_list(_header_str(msg, "To"))
    parsed.cc = _parse_address_list(_header_str(msg, "Cc"))
    parsed.subject = _header_str(msg, "Subject").replace("\r", " ").replace("\n", " ").strip()[:998]
    parsed.date = _parse_date(_header_str(msg, "Date"))
    message_id = _header_str(msg, "Message-ID").strip().strip("<>")
    parsed.rfc_message_id = message_id or None
    parsed.has_list_unsubscribe = "list-unsubscribe" in parsed.headers
    try:
        auth_values = msg.get_all("Authentication-Results") or []
        auth_values = [str(v) for v in auth_values]
    except Exception:
        auth_values = []
    parsed.auth = parse_authentication_results(auth_values, parsed.from_domain)


def _fill_bodies_and_attachments(parsed: ParsedMessage, msg: Message) -> None:
    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[Attachment] = []
    index = 0
    for part in _walk(msg):
        try:
            ctype = part.get_content_type()
        except Exception:
            ctype = "application/octet-stream"
        if ctype.startswith("multipart/"):
            continue
        if ctype == "text/calendar":
            parsed.has_calendar_invite = True
        if not _is_attachment(part):
            if ctype == "text/plain":
                text_parts.append(_part_text(part))
            elif ctype == "text/html":
                html_parts.append(_part_text(part))
            continue
        index += 1
        data = _part_bytes(part)
        filename = _filename(part, index)
        disposition = (part.get_content_disposition() or "").lower()
        content_id = _header_str(part, "Content-ID").strip().strip("<>") or None
        ext = _declared_extension(filename)
        if ext == "ics" or ctype == "text/calendar":
            parsed.has_calendar_invite = True
        attachments.append(
            Attachment(
                filename=filename,
                content_type=ctype,
                size=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
                declared_extension=ext,
                sniffed_type=sniff_type(data) if data else "empty",
                content_id=content_id,
                is_inline=disposition == "inline",
                data=data,
            )
        )

    parsed.text_body = "\n".join(p for p in text_parts if p).strip()
    html_body = "\n".join(p for p in html_parts if p).strip() or None
    parsed.html_body = html_body
    if not parsed.text_body and html_body:
        parsed.text_body = html_to_text(html_body)
    if not parsed.text_body and not html_body and not msg.is_multipart() and not attachments:
        # A bare non-text single part (rare): keep whatever text it has.
        parsed.text_body = _part_text(msg) if msg.get_content_type().startswith("text/") else ""

    if html_body:
        referenced = {m.group(1).strip() for m in re.finditer(r"cid:([^\"'\s>)]+)", html_body, re.I)}
        for att in attachments:
            if att.content_id and att.content_id in referenced:
                att.is_inline = True
    parsed.attachments = attachments

