"""In-memory stand-ins for the slow or external parts of the system."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from reddysec.models import (
    DetonationJob,
    DetonationResult,
    DetonationStatus,
    PageFeatures,
    PolicyConfig,
    ProtectionMode,
    Provider,
    RawMessage,
    Verdict,
    VerdictLevel,
)


class FakeDetonator:
    """Returns scripted results keyed by URL (or filename); default is a boring
    safe page. Records every job so tests can assert what was detonated."""

    def __init__(self) -> None:
        self.scripts: dict[str, DetonationResult | Callable[[DetonationJob], DetonationResult]] = {}
        self.jobs: list[DetonationJob] = []
        self.fail_with: Exception | None = None

    def script(self, key: str, result: DetonationResult | Callable[[DetonationJob], DetonationResult]) -> None:
        self.scripts[key] = result

    async def detonate(self, job: DetonationJob) -> DetonationResult:
        self.jobs.append(job)
        if self.fail_with:
            raise self.fail_with
        key = job.url or job.file_name or ""
        scripted = self.scripts.get(key)
        if callable(scripted):
            return scripted(job)
        if scripted is not None:
            return scripted.model_copy(update={"job_id": job.job_id})
        host = ""
        if job.url:
            from urllib.parse import urlsplit

            host = urlsplit(job.url).hostname or ""
        return DetonationResult(
            job_id=job.job_id,
            status=DetonationStatus.OK,
            duration_ms=120,
            features=PageFeatures(title="Example", final_url=job.url, final_host=host, status_code=200),
            sandbox_backend="fake",
        )


class FakeMailbox:
    """A connector-shaped in-memory mailbox. Messages are keyed by provider id;
    labels are tracked so tests can assert on quarantine/release behaviour."""

    provider = Provider.GMAIL

    def __init__(self, mailbox_id: str = "mbx_test") -> None:
        self.mailbox_id = mailbox_id
        self.messages: dict[str, RawMessage] = {}
        self.labels: dict[str, set[str]] = {}  # provider_message_id -> label names
        self.in_inbox: dict[str, bool] = {}
        self.mode: ProtectionMode = ProtectionMode.SCAN
        self.hold_rule_installed = False
        self.actions: list[tuple[str, str]] = []
        self._seq = 0

    def deliver(self, raw: bytes, provider_message_id: str | None = None) -> RawMessage:
        self._seq += 1
        pid = provider_message_id or f"m{self._seq}"
        msg = RawMessage(
            provider_message_id=pid, mailbox_id=self.mailbox_id, received_at=datetime.now(UTC), raw=raw
        )
        self.messages[pid] = msg
        held = self.mode is ProtectionMode.HOLD and self.hold_rule_installed
        self.labels[pid] = {"Secureddy/Checking"} if held else set()
        self.in_inbox[pid] = not held
        return msg

    async def setup(self, mode: ProtectionMode) -> dict[str, str]:
        self.mode = mode
        self.hold_rule_installed = mode is ProtectionMode.HOLD
        return {"Secureddy": "L1", "Secureddy/Checking": "L2"}

    async def poll(self, cursor: str | None) -> tuple[list[RawMessage], str | None]:
        start = int(cursor or 0)
        items = [m for i, m in enumerate(self.messages.values()) if i >= start]
        return items, str(len(self.messages))

    async def fetch_raw(self, provider_message_id: str) -> bytes:
        return self.messages[provider_message_id].raw

    async def apply_verdict(
        self, msg: RawMessage, verdict: Verdict, policy: PolicyConfig, *, relabel: bool = False
    ) -> None:
        pid = msg.provider_message_id
        labels = self.labels.setdefault(pid, set())
        labels.discard("Secureddy/Checking")
        if relabel:
            labels.discard("Secureddy/Checked")
            labels.discard("Secureddy/Suspicious")
            self.actions.append(("relabel", pid))
        if verdict.level is VerdictLevel.MALICIOUS:
            labels.add("Secureddy/Quarantine")
        elif verdict.level is VerdictLevel.SUSPICIOUS:
            labels.add("Secureddy/Suspicious")
        else:
            labels.add("Secureddy/Checked")
        if verdict.level.rank >= policy.quarantine_at.rank and verdict.level is not VerdictLevel.UNKNOWN:
            self.in_inbox[pid] = False
            self.actions.append(("quarantine", pid))
        else:
            self.in_inbox[pid] = True
            self.actions.append(("release", pid))

    async def release(self, provider_message_id: str) -> None:
        self.labels.setdefault(provider_message_id, set()).discard("Secureddy/Checking")
        self.in_inbox[provider_message_id] = True
        self.actions.append(("release", provider_message_id))

    async def quarantine(self, provider_message_id: str) -> None:
        self.labels.setdefault(provider_message_id, set()).add("Secureddy/Quarantine")
        self.in_inbox[provider_message_id] = False
        self.actions.append(("quarantine", provider_message_id))

    async def restore(self, provider_message_id: str) -> None:
        labels = self.labels.setdefault(provider_message_id, set())
        labels.discard("Secureddy/Quarantine")
        labels.add("Secureddy/Released by you")
        self.in_inbox[provider_message_id] = True
        self.actions.append(("restore", provider_message_id))

    async def mark_safe(self, provider_message_id: str) -> None:
        labels = self.labels.setdefault(provider_message_id, set())
        for name in ("Secureddy/Suspicious", "Secureddy/Quarantine", "Secureddy/Checking"):
            labels.discard(name)
        labels.add("Secureddy/Checked")
        self.in_inbox[provider_message_id] = True
        self.actions.append(("mark_safe", provider_message_id))

    async def release_all_pending(self) -> int:
        n = 0
        for pid, labels in self.labels.items():
            if "Secureddy/Checking" in labels:
                labels.discard("Secureddy/Checking")
                self.in_inbox[pid] = True
                n += 1
        self.actions.append(("release_all_pending", str(n)))
        return n

    async def teardown(self) -> None:
        self.hold_rule_installed = False
        self.actions.append(("teardown", ""))


class FakeIntel:
    """Threat-intel lookups with a scripted blocklist. Offline."""

    def __init__(self, bad_urls: set[str] | None = None, bad_hashes: set[str] | None = None) -> None:
        self.bad_urls = bad_urls or set()
        self.bad_hashes = bad_hashes or set()
        self.domain_ages: dict[str, int] = {}  # registrable domain -> age in days

    async def url_is_known_bad(self, url: str) -> bool:
        return url in self.bad_urls

    async def hash_is_known_bad(self, sha256: str) -> bool:
        return sha256 in self.bad_hashes

    async def domain_age_days(self, registrable_domain: str) -> int | None:
        return self.domain_ages.get(registrable_domain)
