"""The pipeline: lane routing, detonation orchestration, timeouts, determinism."""

from __future__ import annotations

import asyncio

from reddysec.analysis import analyze
from reddysec.analysis.bec import LlmAssessment
from reddysec.analysis.intel import OfflineIntel
from reddysec.analysis.parser import parse_raw
from reddysec.analysis.pipeline import AnalysisContext
from reddysec.models import (
    DetonationResult,
    DetonationStatus,
    DownloadRecord,
    PolicyConfig,
    SenderHistory,
    TriageLane,
    VerdictLevel,
)
from reddysec.testing.fakes import FakeDetonator, FakeIntel

from .support import RECEIVED_AT, build_raw, ok_result

ALIGNED = "mx.google.com; dkim=pass header.i=@{d}; spf=pass smtp.mailfrom={d}; dmarc=pass header.from={d}"


def parse(**kw):
    return parse_raw(build_raw(**kw), provider_message_id="pm", mailbox_id="mbx", received_at=RECEIVED_AT)


def ctx(detonator=None, intel=None, llm=None, artifact_store=None, history=None, policy=None, **kw):
    return AnalysisContext(
        policy=policy or PolicyConfig(),
        history=history,
        intel=intel or OfflineIntel(),
        detonator=detonator,
        llm=llm,
        artifact_store=artifact_store,
        **kw,
    )


class TestLaneRouting:
    async def test_release_fast_still_runs_bec(self):
        p = parse(from_header="CEO <ceo.office@gmail.com>", auth=ALIGNED.format(d="gmail.com"),
                  text="Are you available? I need you to buy Apple gift cards and send the codes. Keep it confidential.")
        v = await analyze(p, ctx())
        assert v.lane is TriageLane.RELEASE_FAST
        assert v.level in (VerdictLevel.SUSPICIOUS, VerdictLevel.MALICIOUS)
        assert any(s.code == "bec.gift_card" for s in v.signals)

    async def test_block_lane_no_detonation(self):
        det = FakeDetonator()
        p = parse(from_header="Spam <s@blocked.example>", text="hi")
        policy = PolicyConfig(blocked_senders=["blocked.example"])
        v = await analyze(p, ctx(detonator=det, policy=policy))
        assert v.lane is TriageLane.BLOCK
        assert det.jobs == []  # nothing detonated

    async def test_trusted_lane_no_detonation(self):
        det = FakeDetonator()
        p = parse(from_header="Maria <maria@friend.example>",
                  html='<a href="https://www.google.com/doc">doc</a>', text=None,
                  auth=ALIGNED.format(d="friend.example"))
        hist = SenderHistory(address="maria@friend.example", message_count=10, replied_to=True)
        v = await analyze(p, ctx(detonator=det, history=hist))
        assert v.lane is TriageLane.TRUSTED
        assert det.jobs == []


class TestDetonation:
    async def test_detonates_and_adds_dynamic_signals(self):
        det = FakeDetonator()
        det.script("https://docusign-secure.com/review/1",
                   ok_result(final_host="docusign-secure.com", final_url="https://docusign-secure.com/login",
                             has_password=True, brand_keywords=["docusign"]))
        p = parse(from_header="DocuSign <x@docusign-secure.com>",
                  html='<a href="https://docusign-secure.com/review/1">review</a>', text=None,
                  auth=ALIGNED.format(d="docusign-secure.com"))
        v = await analyze(p, ctx(detonator=det, intel=OfflineIntel(domain_ages={"docusign-secure.com": 3})))
        assert det.jobs and det.jobs[0].url == "https://docusign-secure.com/review/1"
        assert v.level is VerdictLevel.MALICIOUS
        assert any(s.code == "dynamic.credential_phish" for s in v.signals)
        assert v.urls[0].detonated and v.urls[0].final_url == "https://docusign-secure.com/login"

    async def test_no_detonator_skips_dynamic(self):
        p = parse(html='<a href="https://unknown.example/x">x</a>', text=None,
                  from_header="X <x@unknown-sender.example>")
        v = await analyze(p, ctx(detonator=None))
        assert v.urls and not v.urls[0].detonated

    async def test_concurrency_limited(self):
        active = {"now": 0, "max": 0}

        class SlowDetonator:
            async def detonate(self, job):
                active["now"] += 1
                active["max"] = max(active["max"], active["now"])
                await asyncio.sleep(0.02)
                active["now"] -= 1
                return ok_result(job_id=job.job_id, final_url=job.url, final_host="x.example")

        links = "".join(f'<a href="https://x{i}.example/p">l{i}</a>' for i in range(6))
        p = parse(html=links, text=None, from_header="X <x@unknown-sender.example>")
        await analyze(p, ctx(detonator=SlowDetonator(), max_concurrent_detonations=2))
        assert active["max"] <= 2

    async def test_detonator_exception_becomes_unknown_url(self):
        det = FakeDetonator()
        det.fail_with = RuntimeError("chamber crashed")
        p = parse(from_header="X <x@docusign-secure.com>",
                  html='<a href="https://docusign-secure.com/x">x</a>', text=None,
                  auth=ALIGNED.format(d="docusign-secure.com"))
        v = await analyze(p, ctx(detonator=det))
        # static risk is high (lookalike) so the un-openable URL flags for review
        assert v.needs_human_review
        assert any(u.level is VerdictLevel.UNKNOWN for u in v.urls) or v.level is VerdictLevel.MALICIOUS

    async def test_detonator_timeout(self):
        class Hanger:
            async def detonate(self, job):
                await asyncio.sleep(5)
                return ok_result()

        p = parse(html='<a href="https://unknown-site.example/x">x</a>', text=None,
                  from_header="X <x@unknown-sender.example>")
        v = await analyze(p, ctx(detonator=Hanger(), detonation_timeout_s=0.05))
        assert any(s.code == "dynamic.unavailable" for s in v.signals)

    async def test_file_detonation_with_artifact_store(self, tmp_path):
        from reddysec.core.artifacts import LocalArtifactStore

        store = LocalArtifactStore(tmp_path)
        det = FakeDetonator()

        def file_result(job):
            return DetonationResult(job_id=job.job_id, status=DetonationStatus.OK,
                                    downloads=[DownloadRecord(suggested_filename="payload.exe", sha256="a" * 64, size=1)])

        det.script("Invoice.docx", file_result)
        p = parse(text="see attached", from_header="X <x@unknown-sender.example>",
                  attachments=[("Invoice.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                                b"PK\x03\x04" + b"\x00" * 50, None)])
        v = await analyze(p, ctx(detonator=det, artifact_store=store))
        file_jobs = [j for j in det.jobs if j.kind.value == "file"]
        assert file_jobs and file_jobs[0].file_ref is not None
        assert any(s.code == "dynamic.dangerous_download" for s in v.signals)

    async def test_file_detonation_skipped_without_store(self):
        det = FakeDetonator()
        p = parse(text="see attached", from_header="X <x@unknown-sender.example>",
                  attachments=[("doc.pdf", "application/pdf", b"%PDF-1.4\n" + b"x" * 50, None)])
        await analyze(p, ctx(detonator=det, artifact_store=None))
        assert all(j.kind.value != "file" for j in det.jobs)


class TestIntelIntegration:
    async def test_known_bad_url_from_intel(self):
        intel = FakeIntel(bad_urls={"https://unknown-phish.example/x"})
        p = parse(html='<a href="https://unknown-phish.example/x">x</a>', text=None,
                  from_header="X <x@unknown-sender.example>")
        v = await analyze(p, ctx(detonator=FakeDetonator(), intel=intel))
        assert v.level is VerdictLevel.MALICIOUS
        assert any(s.code == "url.known_bad" for s in v.signals)

    async def test_known_bad_attachment_hash(self):
        import hashlib

        data = b"%PDF-1.4\n" + b"evil" * 20
        digest = hashlib.sha256(data).hexdigest()
        intel = FakeIntel(bad_hashes={digest})
        p = parse(text="x", from_header="X <x@unknown-sender.example>",
                  attachments=[("doc.pdf", "application/pdf", data, None)])
        v = await analyze(p, ctx(detonator=FakeDetonator(), intel=intel))
        assert any(s.code == "attachment.known_bad" for s in v.signals)
        assert v.level is VerdictLevel.MALICIOUS


class TestLlmIntegration:
    async def test_llm_signal_added(self):
        class YesLlm:
            async def assess(self, parsed, static_summary):
                return LlmAssessment(is_bec_likely=True, confidence=1.0, intent="wire fraud",
                                     plain_summary="This asks you to move money urgently.")

        # Pair the LLM opinion with a real payment-change trigger so the overall
        # verdict is suspicious and the LLM's plain summary surfaces to the client.
        p = parse(from_header="X <x@first-time-vendor.example>", auth=ALIGNED.format(d="first-time-vendor.example"),
                  text="Our bank has changed. Please use the updated wiring instructions below. Account number 44718833.")
        v = await analyze(p, ctx(llm=YesLlm()))
        assert any(s.code == "bec.llm_assessment" for s in v.signals)
        assert v.level in (VerdictLevel.SUSPICIOUS, VerdictLevel.MALICIOUS)
        assert "move money" in v.summary

    async def test_llm_failure_ignored(self):
        class BadLlm:
            async def assess(self, parsed, static_summary):
                raise RuntimeError("model down")

        p = parse(from_header="X <x@gmail.com>", auth=ALIGNED.format(d="gmail.com"), text="hello")
        v = await analyze(p, ctx(llm=BadLlm()))
        assert v.level in (VerdictLevel.SAFE, VerdictLevel.SUSPICIOUS, VerdictLevel.UNKNOWN)


class TestVerdictMetadata:
    async def test_engine_version_and_duration(self):
        from reddysec import ENGINE_VERSION

        p = parse(from_header="X <x@gmail.com>", text="hi", auth=ALIGNED.format(d="gmail.com"))
        v = await analyze(p, ctx())
        assert v.engine_version == ENGINE_VERSION
        assert v.duration_ms >= 0

    async def test_deterministic(self):
        det = FakeDetonator()
        det.script("https://docusign-secure.com/x",
                   ok_result(final_host="docusign-secure.com", has_password=True, brand_keywords=["docusign"]))
        p = parse(from_header="DocuSign <x@docusign-secure.com>",
                  html='<a href="https://docusign-secure.com/x">x</a>', text=None,
                  auth=ALIGNED.format(d="docusign-secure.com"))
        det2 = FakeDetonator()
        det2.script("https://docusign-secure.com/x",
                    ok_result(final_host="docusign-secure.com", has_password=True, brand_keywords=["docusign"]))
        v1 = await analyze(p, ctx(detonator=det))
        p2 = parse(from_header="DocuSign <x@docusign-secure.com>",
                   html='<a href="https://docusign-secure.com/x">x</a>', text=None,
                   auth=ALIGNED.format(d="docusign-secure.com"))
        v2 = await analyze(p2, ctx(detonator=det2))  # identically scripted -> identical inputs
        assert v1.score == v2.score and v1.level == v2.level

    async def test_job_id_deterministic(self):
        det = FakeDetonator()
        p = parse(html='<a href="https://x.example/a">a</a>', text=None, from_header="X <x@unknown-sender.example>")
        await analyze(p, ctx(detonator=det))
        first = det.jobs[0].job_id
        det2 = FakeDetonator()
        p2 = parse(html='<a href="https://x.example/a">a</a>', text=None, from_header="X <x@unknown-sender.example>")
        await analyze(p2, ctx(detonator=det2))
        assert first == det2.jobs[0].job_id


class TestRobustness:
    async def test_never_raises_on_broken_message(self):
        p = parse_raw(b"\xff\xfe broken", provider_message_id="x", mailbox_id="m", received_at=RECEIVED_AT)
        v = await analyze(p, ctx(detonator=FakeDetonator()))
        assert v.engine_version
        assert v.level in set(VerdictLevel)

    async def test_internal_failure_returns_unknown(self, monkeypatch):
        # Force an exception deep in analysis; the pipeline must still return a Verdict.
        import reddysec.analysis.pipeline as pipeline

        async def boom(*a, **k):
            raise RuntimeError("kaboom")

        monkeypatch.setattr(pipeline, "_analyze", boom)
        p = parse(text="hi")
        v = await analyze(p, ctx())
        assert v.level is VerdictLevel.UNKNOWN and v.needs_human_review
        assert "could not finish" in v.summary.lower()

    async def test_needs_human_review_on_suspicious(self):
        p = parse(from_header="CEO <ceo@gmail.com>", auth=ALIGNED.format(d="gmail.com"),
                  text="Are you available for a quick task? I'm in a meeting.")
        v = await analyze(p, ctx())
        if v.level is VerdictLevel.SUSPICIOUS:
            assert v.needs_human_review
