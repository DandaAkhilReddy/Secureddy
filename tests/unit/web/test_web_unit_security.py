"""Unit tests for sessions, CSRF, rate limiting, passwords and redirects."""

from __future__ import annotations

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from reddysec.web.auth import hash_password, new_totp_secret, totp_uri, verify_password, verify_totp
from reddysec.web.security import (
    SESSION_MAX_AGE_S,
    RateLimiter,
    SessionCodec,
    client_ip,
    csrf_protect,
    csrf_token,
    current_user_id,
    flash,
    login_session,
    logout_session,
    pop_flashes,
    safe_return_to,
    tokens_match,
)


class FakeClock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make_request(
    method: str = "POST",
    path: str = "/x",
    *,
    session: dict | None = None,
    headers: dict | None = None,
    body: bytes = b"",
    content_type: str = "application/x-www-form-urlencoded",
) -> Request:
    raw_headers = [(b"content-type", content_type.encode())]
    for k, v in (headers or {}).items():
        raw_headers.append((k.lower().encode(), v.encode()))
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": raw_headers,
        "client": ("203.0.113.9", 1234),
        "scheme": "http",
        "server": ("testserver", 80),
    }
    if session is not None:
        scope["session"] = session
    sent = {"done": False}

    async def receive():
        if sent["done"]:
            return {"type": "http.disconnect"}
        sent["done"] = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive)


# --------------------------------------------------------------------------
# Session codec
# --------------------------------------------------------------------------


class TestSessionCodec:
    def test_round_trip(self):
        codec = SessionCodec("secret-key")
        value = codec.encode({"uid": "usr_1", "csrf": "t"})
        assert codec.decode(value) == {"uid": "usr_1", "csrf": "t"}

    def test_rejects_tampering_and_garbage(self):
        codec = SessionCodec("secret-key")
        value = codec.encode({"uid": "usr_1"})
        assert codec.decode(value[:-2] + "zz") is None
        assert codec.decode("") is None
        assert codec.decode(None) is None
        assert codec.decode("not.a.token") is None
        other = SessionCodec("another-key")
        assert other.decode(value) is None

    def test_rejects_non_dict_payload(self):
        codec = SessionCodec("secret-key")
        value = codec._serializer.dumps(["not", "a", "dict"])
        assert codec.decode(value) is None

    def test_signature_expires_after_max_age(self):
        clock = FakeClock()
        codec = SessionCodec("secret-key", max_age=100, clock=clock)
        value = codec.encode({"uid": "usr_1"})
        clock.advance(99)
        assert codec.decode(value) == {"uid": "usr_1"}
        clock.advance(2)
        assert codec.decode(value) is None

    def test_absolute_lifetime_from_iat_survives_rewrites(self):
        clock = FakeClock()
        codec = SessionCodec("secret-key", clock=clock)
        issued = clock()
        clock.advance(SESSION_MAX_AGE_S - 10)
        rewritten = codec.encode({"uid": "usr_1", "iat": issued})  # fresh signature, old iat
        assert codec.decode(rewritten) is not None
        clock.advance(20)
        assert codec.decode(rewritten) is None

    def test_requires_secret(self):
        with pytest.raises(ValueError):
            SessionCodec("")


# --------------------------------------------------------------------------
# Session helpers
# --------------------------------------------------------------------------


class TestSessionHelpers:
    def test_login_rotates_and_logout_clears(self):
        request = make_request(session={"csrf": "old", "flash": [{"kind": "ok", "text": "hi"}], "oauth": {}})
        login_session(request, "usr_1", now=123.0)
        assert request.session["uid"] == "usr_1" and request.session["iat"] == 123
        assert request.session["csrf"] != "old" and "oauth" not in request.session
        assert current_user_id(request) == "usr_1"
        logout_session(request)
        assert request.session == {} and current_user_id(request) is None

    def test_current_user_id_ignores_non_strings(self):
        assert current_user_id(make_request(session={"uid": 42})) is None
        assert current_user_id(make_request(session={"uid": ""})) is None

    def test_flash_queue_is_bounded_and_popped_once(self):
        request = make_request(session={})
        for i in range(8):
            flash(request, f"m{i}", "warn")
        flashes = pop_flashes(request)
        assert [f["text"] for f in flashes] == ["m3", "m4", "m5", "m6", "m7"]
        assert all(f["kind"] == "warn" for f in flashes)
        assert pop_flashes(request) == []
        assert pop_flashes(make_request()) == []  # no session middleware at all

    def test_pop_flashes_drops_malformed_entries(self):
        request = make_request(session={"flash": ["junk", {"kind": "ok"}, {"kind": "ok", "text": "fine"}]})
        assert pop_flashes(request) == [{"kind": "ok", "text": "fine"}]

    def test_csrf_token_is_created_once(self):
        request = make_request(session={})
        first = csrf_token(request)
        assert first and csrf_token(request) == first
        request.session["csrf"] = 123  # corrupted
        assert csrf_token(request) != first


# --------------------------------------------------------------------------
# CSRF dependency
# --------------------------------------------------------------------------


class TestCsrfProtect:
    async def test_safe_methods_pass(self):
        await csrf_protect(make_request("GET", session={}))
        await csrf_protect(make_request("HEAD"))

    async def test_form_token_required(self):
        session = {"csrf": "tok-123"}
        await csrf_protect(make_request(session=session, body=b"csrf_token=tok-123&x=1"))
        with pytest.raises(HTTPException) as missing:
            await csrf_protect(make_request(session=session, body=b"x=1"))
        assert missing.value.status_code == 403
        with pytest.raises(HTTPException):
            await csrf_protect(make_request(session=session, body=b"csrf_token=wrong"))
        with pytest.raises(HTTPException):
            await csrf_protect(make_request(session={}, body=b"csrf_token=tok-123"))
        with pytest.raises(HTTPException):
            await csrf_protect(make_request(body=b"csrf_token=tok-123"))  # no session scope at all

    async def test_json_body_is_not_a_token(self):
        with pytest.raises(HTTPException):
            await csrf_protect(
                make_request(
                    session={"csrf": "t"}, body=b'{"csrf_token": "t"}', content_type="application/json"
                )
            )

    async def test_api_uses_header(self):
        session = {"csrf": "tok-123"}
        await csrf_protect(
            make_request(path="/api/thing", session=session, headers={"X-CSRF-Token": "tok-123"})
        )
        with pytest.raises(HTTPException):
            await csrf_protect(
                make_request(path="/api/thing", session=session, headers={"X-CSRF-Token": "nope"})
            )
        with pytest.raises(HTTPException):
            await csrf_protect(make_request(path="/api/thing", session=session, body=b"csrf_token=tok-123"))

    def test_tokens_match_is_strict(self):
        assert tokens_match("abc", "abc")
        assert not tokens_match("abc", "abd")
        assert not tokens_match(None, "abc")
        assert not tokens_match("abc", None)
        assert not tokens_match("", "")


# --------------------------------------------------------------------------
# Rate limiter
# --------------------------------------------------------------------------


class TestRateLimiter:
    def test_burst_then_refill(self):
        clock = FakeClock()
        limiter = RateLimiter(rate=3, per=60.0, clock=clock)
        assert [limiter.allow("ip") for _ in range(3)] == [True, True, True]
        assert limiter.allow("ip") is False
        assert limiter.retry_after("ip") == 20
        clock.advance(20)
        assert limiter.allow("ip") is True
        assert limiter.allow("ip") is False
        assert limiter.allow("other-ip") is True  # per key

    def test_bucket_never_overfills(self):
        clock = FakeClock()
        limiter = RateLimiter(rate=2, per=10.0, clock=clock)
        limiter.allow("ip")
        clock.advance(10_000)
        assert [limiter.allow("ip") for _ in range(3)] == [True, True, False]

    def test_retry_after_zero_when_allowed(self):
        limiter = RateLimiter(rate=2, per=10.0, clock=FakeClock())
        assert limiter.retry_after("fresh") == 0

    def test_prunes_full_buckets(self):
        clock = FakeClock()
        limiter = RateLimiter(rate=1, per=1.0, clock=clock, max_keys=5)
        for i in range(6):
            limiter.allow(f"ip{i}")
        assert len(limiter._buckets) == 6
        clock.advance(5)
        limiter.allow("ip-new")  # triggers prune of the refilled buckets
        assert set(limiter._buckets) == {"ip-new"}

    def test_rejects_bad_configuration(self):
        with pytest.raises(ValueError):
            RateLimiter(rate=0)
        with pytest.raises(ValueError):
            RateLimiter(per=0)

    def test_client_ip(self):
        assert client_ip({"client": ("10.0.0.1", 5)}) == "10.0.0.1"
        assert client_ip({"client": None}) == "unknown"
        assert client_ip({}) == "unknown"


# --------------------------------------------------------------------------
# Passwords, TOTP, redirects
# --------------------------------------------------------------------------


class TestPasswords:
    def test_hash_and_verify(self):
        hashed = hash_password("correct horse battery staple")
        assert hashed.startswith("$argon2")
        assert verify_password(hashed, "correct horse battery staple")
        assert not verify_password(hashed, "wrong")
        assert not verify_password(hashed, "")
        assert not verify_password(None, "anything")
        assert not verify_password("not-a-hash", "anything")

    def test_totp_helpers(self):
        import pyotp

        secret = new_totp_secret()
        assert "otpauth://totp/" in totp_uri(secret, "me@example.com") and "issuer=Secureddy" in totp_uri(
            secret, "x"
        )
        code = pyotp.TOTP(secret).now()
        assert verify_totp(secret, code)
        assert verify_totp(secret, code[:3] + " " + code[3:])  # spaces are tolerated
        assert not verify_totp(secret, "12345")
        assert not verify_totp(secret, None)
        assert not verify_totp("", code)
        assert not verify_totp(secret, "abcdef")


class TestSafeReturnTo:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (None, "/"),
            ("", "/"),
            ("/mailboxes", "/mailboxes"),
            ("/messages/msg_1?x=1", "/messages/msg_1?x=1"),
            ("//evil.example/x", "/"),
            ("https://evil.example", "/"),
            ("mailboxes", "/"),
            ("/back\\slash", "/"),
            ("/line\nbreak", "/"),
        ],
    )
    def test_cases(self, value, expected):
        assert safe_return_to(value) == expected

    def test_custom_default(self):
        assert safe_return_to("javascript:alert(1)", default="/home") == "/home"
