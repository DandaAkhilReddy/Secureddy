"""Builders shared by the analysis unit tests: compose raw MIME and detonation
results without repeating boilerplate in every test.

This is a plain module (not ``conftest.py``) imported by name, so the two
same-named test directories (unit/analysis and functional/analysis) do not
collide under pytest's prepend import mode.
"""

from __future__ import annotations

from datetime import UTC, datetime

from reddysec.models import (
    DetonationResult,
    DetonationStatus,
    DownloadRecord,
    FormRecord,
    NetworkRequest,
    PageFeatures,
    RedirectHop,
)

RECEIVED_AT = datetime(2026, 11, 5, 18, 0, tzinfo=UTC)


def build_raw(
    *,
    from_header: str = "Sender <sender@example.com>",
    to: str = "client@gmail.com",
    subject: str = "Hello",
    date: str = "Wed, 05 Nov 2026 09:00:00 -0800",
    message_id: str = "<msg-1@example.com>",
    auth: str | None = None,
    auth_headers: list[str] | None = None,
    extra_headers: dict[str, str] | None = None,
    text: str | None = "Plain body.",
    html: str | None = None,
    attachments: list[tuple[str, str, bytes, str | None]] | None = None,
) -> bytes:
    """Hand-assemble an RFC 5322 message so tests control the exact bytes.

    ``attachments`` items are (filename, content_type, data, disposition);
    disposition None means a normal attachment, "inline" an inline part.
    """
    headers: list[str] = [f"From: {from_header}", f"To: {to}", f"Subject: {subject}", f"Date: {date}",
                          f"Message-ID: {message_id}", "MIME-Version: 1.0"]
    for value in auth_headers or ([auth] if auth else []):
        headers.append(f"Authentication-Results: {value}")
    for key, value in (extra_headers or {}).items():
        headers.append(f"{key}: {value}")

    import base64
    from email.utils import make_msgid  # noqa: F401 (kept for parity with real messages)

    boundary = "BOUNDARY42"
    parts: list[str] = []
    has_mime_parts = bool(attachments) or (text is not None and html is not None)
    if has_mime_parts:
        headers.append(f'Content-Type: multipart/mixed; boundary="{boundary}"')
        body_lines = [f"--{boundary}"]
        if text is not None and html is not None:
            inner = "ALT99"
            body_lines.append(f'Content-Type: multipart/alternative; boundary="{inner}"')
            body_lines.append("")
            body_lines += [f"--{inner}", 'Content-Type: text/plain; charset="utf-8"', "", text]
            body_lines += [f"--{inner}", 'Content-Type: text/html; charset="utf-8"', "", html, f"--{inner}--"]
        elif text is not None:
            body_lines += ['Content-Type: text/plain; charset="utf-8"', "", text]
        elif html is not None:
            body_lines += ['Content-Type: text/html; charset="utf-8"', "", html]
        for filename, ctype, data, disposition in attachments or []:
            encoded = base64.encodebytes(data).decode()
            body_lines.append(f"--{boundary}")
            body_lines.append(f'Content-Type: {ctype}; name="{filename}"')
            disp = disposition or "attachment"
            body_lines.append(f'Content-Disposition: {disp}; filename="{filename}"')
            body_lines.append(f"Content-ID: <{filename}>")
            body_lines.append("Content-Transfer-Encoding: base64")
            body_lines.append("")
            body_lines.append(encoded)
        body_lines.append(f"--{boundary}--")
        parts = body_lines
    elif html is not None and text is None:
        headers.append('Content-Type: text/html; charset="utf-8"')
        parts = ["", html]
    else:
        headers.append('Content-Type: text/plain; charset="utf-8"')
        parts = ["", text or ""]
    return ("\r\n".join(headers) + "\r\n" + "\r\n".join(parts)).encode("utf-8")


def ok_result(
    *,
    job_id: str = "det_x",
    final_url: str = "https://example.com/",
    final_host: str = "example.com",
    title: str = "Example",
    has_password: bool = False,
    brand_keywords: list[str] | None = None,
    redirects: list[str] | None = None,
    downloads: list[DownloadRecord] | None = None,
    external_form_action: bool = False,
    meta_refresh: bool = False,
    js_redirect: bool = False,
    obfuscated_js_score: int = 0,
    captcha: bool = False,
    qr_codes: list[str] | None = None,
    third_party_hosts: int = 0,
    status: DetonationStatus = DetonationStatus.OK,
) -> DetonationResult:
    forms = [FormRecord(has_password=True, action_host=final_host)] if has_password else []
    requests = [NetworkRequest(url=f"https://cdn{i}.net/x", host=f"cdn{i}.net", is_third_party=True)
                for i in range(third_party_hosts)]
    return DetonationResult(
        job_id=job_id,
        status=status,
        features=PageFeatures(
            title=title,
            final_url=final_url,
            final_host=final_host,
            has_password_field=has_password,
            forms=forms,
            brand_keywords=brand_keywords or [],
            external_form_action=external_form_action,
            meta_refresh=meta_refresh,
            js_redirect=js_redirect,
            obfuscated_js_score=obfuscated_js_score,
            captcha_detected=captcha,
            qr_codes=qr_codes or [],
            status_code=200,
        ),
        redirects=[RedirectHop(url=u) for u in (redirects or [])],
        downloads=downloads or [],
        requests=requests,
        sandbox_backend="fake",
    )
