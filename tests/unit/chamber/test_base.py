"""Unit tests for DetonationChamber: policy, capacity, timeouts, finalization.

These use a fake backend; no browser runs here.
"""

from __future__ import annotations

import asyncio

import pytest

from reddysec.chamber.backends.base import DetonationChamber, make_chamber
from reddysec.models import (
    DetonationJob,
    DetonationKind,
    DetonationStatus,
    Detonator,
)

from .chamber_helpers import RecordingBackend, url_job


def chamber(store, backend=None, **kw):
    return DetonationChamber(backend or RecordingBackend(), store, **kw)


class TestProtocolShape:
    def test_is_a_detonator(self, store):
        assert isinstance(chamber(store), Detonator)

    def test_rejects_zero_concurrency(self, store):
        with pytest.raises(ValueError):
            DetonationChamber(RecordingBackend(), store, max_concurrency=0)


class TestUrlPolicy:
    async def test_blocks_private_by_default(self, store):
        backend = RecordingBackend()
        result = await chamber(store, backend).detonate(url_job("http://127.0.0.1/x"))
        assert result.status is DetonationStatus.BLOCKED
        assert not backend.calls  # never reached the sandbox

    async def test_blocks_non_http_scheme(self, store):
        result = await chamber(store).detonate(url_job("file:///etc/passwd"))
        assert result.status is DetonationStatus.BLOCKED and "bad_scheme" in result.error

    async def test_metadata_ip_blocked(self, store):
        result = await chamber(store).detonate(url_job("http://169.254.169.254/latest/"))
        assert result.status is DetonationStatus.BLOCKED

    async def test_allows_private_when_configured(self, store):
        backend = RecordingBackend()
        result = await chamber(store, backend, allow_private_targets=True).detonate(url_job("http://127.0.0.1:9/x"))
        assert result.status is DetonationStatus.OK and backend.calls

    async def test_dns_failure_is_error_not_blocked(self, store, monkeypatch):
        from reddysec.chamber import targets

        async def boom(host, timeout_s=5.0):
            raise OSError("nope")

        monkeypatch.setattr(targets, "resolve_host", boom)
        result = await chamber(store).detonate(url_job("https://does-not-resolve.invalid/"))
        assert result.status is DetonationStatus.ERROR and "dns_failure" in result.error


class TestFilePolicy:
    async def test_missing_ref_blocked(self, store):
        job = DetonationJob(job_id="d", kind=DetonationKind.FILE, file_ref=None)
        result = await chamber(store).detonate(job)
        assert result.status is DetonationStatus.BLOCKED and "no_file" in result.error

    async def test_file_scheme_ref_blocked(self, store):
        job = DetonationJob(job_id="d", kind=DetonationKind.FILE, file_ref="file:input/x")
        result = await chamber(store).detonate(job)
        assert result.status is DetonationStatus.BLOCKED and "bad_ref" in result.error

    async def test_absent_artifact_is_error(self, store):
        job = DetonationJob(job_id="d", kind=DetonationKind.FILE, file_ref="local:2026/does/not/exist.bin")
        result = await chamber(store).detonate(job)
        assert result.status is DetonationStatus.ERROR and "missing_file" in result.error

    async def test_present_artifact_reaches_backend(self, store):
        ref = store.put(b"%PDF data", ".pdf")
        backend = RecordingBackend()
        job = DetonationJob(job_id="d", kind=DetonationKind.FILE, file_ref=ref, file_name="x.pdf")
        result = await chamber(store, backend).detonate(job)
        assert result.status is DetonationStatus.OK and backend.calls


class TestTimeout:
    async def test_backend_timeout_yields_timeout_status(self, store):
        backend = RecordingBackend()
        backend.delay = 5.0
        job = url_job("https://example.com", timeout_s=1)
        result = await chamber(store, backend, allow_private_targets=True, grace_s=0).detonate(job)
        assert result.status is DetonationStatus.TIMEOUT
        assert result.sandbox_backend == "fake"

    async def test_backend_exception_becomes_error(self, store):
        backend = RecordingBackend()
        backend.raise_exc = RuntimeError("docker daemon gone")
        result = await chamber(store, backend, allow_private_targets=True).detonate(url_job())
        assert result.status is DetonationStatus.ERROR and "docker daemon gone" in result.error

    async def test_zero_timeout_uses_default(self, store):
        backend = RecordingBackend()
        await chamber(store, backend, default_timeout_s=30, allow_private_targets=True).detonate(url_job(timeout_s=0))
        assert backend.calls[0].timeout_s == 30


class TestConcurrency:
    async def test_semaphore_caps_parallelism(self, store):
        backend = RecordingBackend()
        backend.delay = 0.2
        chm = chamber(store, backend, max_concurrency=2, allow_private_targets=True)
        jobs = [url_job(f"https://example{i}.com", job_id=f"det_{i}") for i in range(6)]
        await asyncio.gather(*(chm.detonate(j) for j in jobs))
        assert backend.max_in_flight == 2
        assert len(backend.calls) == 6

    async def test_available_slots_restored(self, store):
        chm = chamber(store, max_concurrency=3, allow_private_targets=True)
        await chm.detonate(url_job())
        assert chm.available_slots == 3


class TestFinalization:
    async def test_sets_backend_and_job_id_and_duration(self, store):
        backend = RecordingBackend(name="docker")
        result = await chamber(store, backend, allow_private_targets=True).detonate(url_job(job_id="det_xyz"))
        assert result.sandbox_backend == "docker"
        assert result.job_id == "det_xyz"
        assert result.duration_ms >= 0

    async def test_rehomes_file_refs(self, store):
        from reddysec.chamber.protocol import SandboxOutput

        def produce(job):
            return SandboxOutput(
                job_id=job.job_id,
                status=DetonationStatus.OK,
                screenshot_ref="file:screenshot.jpg",
                files={"screenshot.jpg": b"\xff\xd8shot"},
            )

        backend = RecordingBackend(result=None)
        backend.result = produce
        result = await chamber(store, backend, allow_private_targets=True).detonate(url_job())
        assert result.screenshot_ref.startswith("local:")
        assert store.get(result.screenshot_ref) == b"\xff\xd8shot"

    async def test_rehome_failure_is_survivable(self, store, monkeypatch):
        from reddysec.chamber import protocol

        def produce(job):
            return protocol.SandboxOutput(job_id=job.job_id, status=DetonationStatus.OK, screenshot_ref="file:screenshot.jpg", files={"screenshot.jpg": b"x"})

        class BrokenStore:
            def put(self, *a, **k):
                raise OSError("disk full")

            def exists(self, ref):
                return True

            def get(self, ref):
                return b""

            def delete(self, ref):
                pass

        backend = RecordingBackend(result=produce)
        chm = DetonationChamber(backend, BrokenStore(), allow_private_targets=True)
        result = await chm.detonate(url_job())
        assert result.status is DetonationStatus.OK
        assert result.screenshot_ref is None
        assert any("artifact store failed" in e for e in result.console_errors)


class TestFactory:
    def test_make_chamber_local(self, store, monkeypatch):
        from reddysec.config import Settings

        settings = Settings(sandbox_backend="local", env="test")
        chm = make_chamber(settings, store)
        assert chm.backend.name == "local"
        assert chm.allow_private_targets is True  # test env

    def test_make_chamber_docker(self, store, monkeypatch):
        from reddysec.config import Settings

        monkeypatch.setenv("RS_CHAMBER_IMAGE", "custom:tag")
        settings = Settings(sandbox_backend="docker", env="prod")
        chm = make_chamber(settings, store)
        assert chm.backend.name == "docker"
        assert chm.backend.image == "custom:tag"
        assert chm.allow_private_targets is False  # prod

    def test_make_chamber_respects_concurrency(self, store):
        from reddysec.config import Settings

        settings = Settings(sandbox_backend="local", env="test", detonation_max_concurrency=5)
        chm = make_chamber(settings, store)
        assert chm.available_slots == 5
