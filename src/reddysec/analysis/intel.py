"""Threat intelligence: reputation lookups and domain age.

Three implementations share the :class:`IntelClient` protocol:

* :class:`OfflineIntel` answers from bundled lists (popular domains, tracking
  domains) and an optional local blocklist. It is what the test suite uses and
  what production falls back to when the network is unavailable.
* :class:`OnlineIntel` asks Google Safe Browsing (when a key is configured),
  URLhaus and RDAP. Every call has a 3 second budget and a 10 minute cache,
  and every failure degrades to ``None`` ("unknown"), never to an exception:
  an intel outage must slow a verdict down, not break it.
* :class:`CompositeIntel` consults offline first and online second.

The contract for all three: ``True`` = known bad, ``False`` = known good /
checked and clean, ``None`` = no information.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any, Protocol, runtime_checkable

import httpx

from reddysec.core.logging import get_logger

from .common import cached_lines
from .domains import brand_domains
from .urls import normalize_url, registrable_domain

log = get_logger(__name__)

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
URLHAUS_HOST_URL = "https://urlhaus-api.abuse.ch/v1/host/"
URLHAUS_PAYLOAD_URL = "https://urlhaus-api.abuse.ch/v1/payload/"
RDAP_URL = "https://rdap.org/domain/{domain}"

DEFAULT_TIMEOUT_S = 3.0
DEFAULT_CACHE_TTL_S = 600.0
# Domains on the popular list are, by construction, old. Reporting a large age
# lets callers treat them uniformly instead of special-casing "unknown".
POPULAR_DOMAIN_AGE_DAYS = 3650
# ``.google`` is a brand top-level domain: only Google can register under it.
_POPULAR_SUFFIXES = (".gov", ".mil", ".edu", ".gov.uk", ".ac.uk", ".edu.au", ".gov.au", ".gc.ca", ".google")


@runtime_checkable
class IntelClient(Protocol):
    """Reputation source. Implementations must never raise; return None when unsure."""

    async def url_is_known_bad(self, url: str) -> bool | None: ...

    async def hash_is_known_bad(self, sha256: str) -> bool | None: ...

    async def domain_age_days(self, registrable_domain: str) -> int | None: ...


# --------------------------------------------------------------------------- bundled knowledge


@lru_cache(maxsize=1)
def brand_shorteners() -> frozenset[str]:
    """Shorteners that only redirect to their owner's own sites (``w-mt.co``)."""
    return cached_lines("brand_shorteners.txt")


@lru_cache(maxsize=1)
def popular_domains() -> frozenset[str]:
    return cached_lines("popular_domains.txt") | brand_domains() | brand_shorteners()


@lru_cache(maxsize=1)
def tracking_domains() -> frozenset[str]:
    return cached_lines("tracking_domains.txt")


def is_popular(domain: str) -> bool:
    """Well-known registrable domain, or anything under .gov/.mil/.edu."""
    if not domain:
        return False
    d = domain.strip().lower().rstrip(".")
    rd = registrable_domain(d)
    if rd in popular_domains():
        return True
    return rd.endswith(_POPULAR_SUFFIXES)


def is_brand_shortener(domain: str) -> bool:
    if not domain:
        return False
    return registrable_domain(domain.strip().lower().rstrip(".")) in brand_shorteners()


def is_tracking_domain(domain: str) -> bool:
    """Click/open tracking host of an email service provider."""
    if not domain:
        return False
    d = domain.strip().lower().rstrip(".")
    return d in tracking_domains() or registrable_domain(d) in tracking_domains()


# --------------------------------------------------------------------------- offline


class OfflineIntel:
    """Bundled lists plus an optional local blocklist. Deterministic and instant."""

    def __init__(
        self,
        bad_urls: Iterable[str] = (),
        bad_domains: Iterable[str] = (),
        bad_hashes: Iterable[str] = (),
        domain_ages: Mapping[str, int] | None = None,
    ) -> None:
        self._bad_urls = {normalize_url(u) or u.strip().lower() for u in bad_urls}
        self._bad_domains = {registrable_domain(d) for d in bad_domains if d.strip()}
        self._bad_hashes = {h.strip().lower() for h in bad_hashes if h.strip()}
        self._ages: dict[str, int] = {registrable_domain(k): v for k, v in (domain_ages or {}).items()}

    @classmethod
    def from_blocklist_file(cls, path: str) -> OfflineIntel:
        """Load ``url``, ``domain`` or ``sha256`` entries, one per line, ``#`` comments."""
        urls: list[str] = []
        domains: list[str] = []
        hashes: list[str] = []
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                entry = line.strip()
                if not entry or entry.startswith("#"):
                    continue
                if "://" in entry:
                    urls.append(entry)
                elif len(entry) == 64 and all(c in "0123456789abcdefABCDEF" for c in entry):
                    hashes.append(entry)
                else:
                    domains.append(entry)
        return cls(bad_urls=urls, bad_domains=domains, bad_hashes=hashes)

    def add_bad_domain(self, domain: str) -> None:
        self._bad_domains.add(registrable_domain(domain))

    async def url_is_known_bad(self, url: str) -> bool | None:
        normalized = normalize_url(url) or url.strip().lower()
        if normalized in self._bad_urls:
            return True
        host = httpx.URL(normalized).host if "://" in normalized else ""
        rd = registrable_domain(host) if host else ""
        if rd and rd in self._bad_domains:
            return True
        if rd and is_popular(rd):
            return False
        return None

    async def hash_is_known_bad(self, sha256: str) -> bool | None:
        return True if sha256.strip().lower() in self._bad_hashes else None

    async def domain_age_days(self, registrable_domain_: str) -> int | None:
        rd = registrable_domain(registrable_domain_)
        if rd in self._ages:
            return self._ages[rd]
        if is_popular(rd):
            return POPULAR_DOMAIN_AGE_DAYS
        return None


# --------------------------------------------------------------------------- online


class _TtlCache:
    def __init__(self, ttl_s: float, clock: Callable[[], float]) -> None:
        self._ttl = ttl_s
        self._clock = clock
        self._items: dict[str, tuple[float, Any]] = {}

    def get(self, key: str) -> tuple[bool, Any]:
        item = self._items.get(key)
        if item is None:
            return False, None
        expires_at, value = item
        if self._clock() >= expires_at:
            del self._items[key]
            return False, None
        return True, value

    def put(self, key: str, value: Any) -> None:
        self._items[key] = (self._clock() + self._ttl, value)

    def __len__(self) -> int:
        return len(self._items)


class OnlineIntel:
    """Safe Browsing v4 (optional key), URLhaus and RDAP over one httpx client.

    Results, including negative ones, are cached for ``cache_ttl_s`` so a burst
    of messages linking to the same domain costs one lookup. All network errors,
    timeouts and malformed responses become ``None``.
    """

    def __init__(
        self,
        http: httpx.AsyncClient,
        safe_browsing_key: str | None = None,
        *,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        cache_ttl_s: float = DEFAULT_CACHE_TTL_S,
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._http = http
        self._key = safe_browsing_key or None
        self._timeout = timeout_s
        self._cache = _TtlCache(cache_ttl_s, clock)
        self._now = now

    @property
    def cache_size(self) -> int:
        return len(self._cache)

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response | None:
        try:
            return await asyncio.wait_for(
                self._http.request(method, url, timeout=self._timeout, follow_redirects=True, **kwargs),
                timeout=self._timeout + 1.0,
            )
        except (httpx.HTTPError, TimeoutError, ValueError) as exc:
            log.debug("intel_request_failed", url=url, error=type(exc).__name__)
            return None
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # defensive: an intel source must never take the engine down
            log.warning("intel_request_error", url=url, error=str(exc))
            return None

    async def _safe_browsing(self, url: str) -> bool | None:
        if not self._key:
            return None
        body = {
            "client": {"clientId": "reddysecurity", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        resp = await self._request("POST", SAFE_BROWSING_URL, params={"key": self._key}, json=body)
        if resp is None or resp.status_code != 200:
            return None
        try:
            data = resp.json()
        except ValueError:
            return None
        if not isinstance(data, dict):
            return None
        return bool(data.get("matches"))

    async def _urlhaus_host(self, host: str) -> bool | None:
        resp = await self._request("POST", URLHAUS_HOST_URL, data={"host": host})
        if resp is None or resp.status_code != 200:
            return None
        try:
            data = resp.json()
        except ValueError:
            return None
        if not isinstance(data, dict):
            return None
        status = data.get("query_status")
        if status == "ok":
            # URLhaus lists hosts that served malware; a listed host with no
            # URL records is a stale entry, which we treat as "no information".
            return True if data.get("urls") else None
        if status == "no_results":
            return False
        return None

    async def url_is_known_bad(self, url: str) -> bool | None:
        normalized = normalize_url(url)
        if normalized is None or not normalized.startswith("http"):
            return None
        key = f"url:{normalized}"
        cached, value = self._cache.get(key)
        if cached:
            return value
        host = httpx.URL(normalized).host
        verdict: bool | None = None
        sb = await self._safe_browsing(normalized)
        if sb is True:
            verdict = True
        else:
            haus = await self._urlhaus_host(host)
            if haus is True:
                verdict = True
            elif sb is False:
                # Safe Browsing checked it and found nothing; URLhaus silence
                # (or an error there) does not change that.
                verdict = False
            else:
                verdict = None
        self._cache.put(key, verdict)
        return verdict

    async def hash_is_known_bad(self, sha256: str) -> bool | None:
        digest = sha256.strip().lower()
        if len(digest) != 64:
            return None
        key = f"hash:{digest}"
        cached, value = self._cache.get(key)
        if cached:
            return value
        resp = await self._request("POST", URLHAUS_PAYLOAD_URL, data={"sha256_hash": digest})
        verdict: bool | None = None
        if resp is not None and resp.status_code == 200:
            try:
                data = resp.json()
                status = data.get("query_status") if isinstance(data, dict) else None
                if status == "ok":
                    verdict = True
                elif status == "no_results":
                    verdict = None
            except ValueError:
                verdict = None
        self._cache.put(key, verdict)
        return verdict

    async def domain_age_days(self, registrable_domain_: str) -> int | None:
        rd = registrable_domain(registrable_domain_)
        if not rd or "." not in rd:
            return None
        key = f"age:{rd}"
        cached, value = self._cache.get(key)
        if cached:
            return value
        resp = await self._request("GET", RDAP_URL.format(domain=rd), headers={"Accept": "application/rdap+json"})
        age: int | None = None
        if resp is not None and resp.status_code == 200:
            try:
                age = self._age_from_rdap(resp.json())
            except ValueError:
                age = None
        self._cache.put(key, age)
        return age

    def _age_from_rdap(self, data: Any) -> int | None:
        if not isinstance(data, dict):
            return None
        events = data.get("events")
        if not isinstance(events, list):
            return None
        for event in events:
            if not isinstance(event, dict) or event.get("eventAction") != "registration":
                continue
            stamp = event.get("eventDate")
            if not isinstance(stamp, str):
                continue
            try:
                registered = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            except ValueError:
                continue
            if registered.tzinfo is None:
                registered = registered.replace(tzinfo=UTC)
            return max(0, (self._now() - registered).days)
        return None


# --------------------------------------------------------------------------- composite


class CompositeIntel:
    """Offline knowledge first (free, deterministic), online second (when enabled)."""

    def __init__(self, offline: IntelClient, online: IntelClient | None, online_enabled: bool) -> None:
        self._offline = offline
        self._online = online if online_enabled else None

    async def _ask(self, name: str, *args: Any) -> Any:
        try:
            result = await getattr(self._offline, name)(*args)
        except Exception as exc:
            log.warning("offline_intel_error", method=name, error=str(exc))
            result = None
        if result is not None or self._online is None:
            return result
        try:
            return await getattr(self._online, name)(*args)
        except Exception as exc:
            log.warning("online_intel_error", method=name, error=str(exc))
            return None

    async def url_is_known_bad(self, url: str) -> bool | None:
        return await self._ask("url_is_known_bad", url)

    async def hash_is_known_bad(self, sha256: str) -> bool | None:
        return await self._ask("hash_is_known_bad", sha256)

    async def domain_age_days(self, registrable_domain_: str) -> int | None:
        return await self._ask("domain_age_days", registrable_domain_)
