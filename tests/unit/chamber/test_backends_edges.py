"""Edge-path tests for the backends and the factory that the happy-path tests
do not reach: the local subprocess timeout/kill, environment pinning, the
file-ref ValueError, download-ref clearing on a broken store, and the ACI
branch of the factory."""

from __future__ import annotations

import sys
from pathlib import Path

from reddysec.chamber.backends.base import DetonationChamber, make_chamber
from reddysec.chamber.backends.local import InProcessBackend, LocalProcessBackend, scrubbed_environment
from reddysec.models import DetonationJob, DetonationKind, DetonationStatus

from .chamber_helpers import url_job


class TestScrubbedEnvironment:
    def test_pins_browsers_path_when_absent(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        (home / ".cache" / "ms-playwright").mkdir(parents=True)
        env = scrubbed_environment(tmp_path / "work", {"PATH": "/usr/bin", "HOME": str(home)})
        assert env["PLAYWRIGHT_BROWSERS_PATH"] == str(home / ".cache" / "ms-playwright")

    def test_keeps_explicit_browsers_path(self, tmp_path):
        env = scrubbed_environment(tmp_path, {"PATH": "/usr/bin", "PLAYWRIGHT_BROWSERS_PATH": "/opt/pw"})
        assert env["PLAYWRIGHT_BROWSERS_PATH"] == "/opt/pw"

    def test_defaults_when_source_bare(self, tmp_path):
        env = scrubbed_environment(tmp_path, {})
        assert env["PATH"] and env["LANG"] and env["HOME"] == str(tmp_path)


class TestLocalProcessBackendEdges:
    async def test_subprocess_timeout_is_killed(self, store, monkeypatch):
        # A detonate module that just sleeps: the backend must kill it and
        # return TIMEOUT without a result file.
        backend = LocalProcessBackend(store, grace_s=1)

        def fake_argv(job_path, out_path, workdir):
            return [sys.executable, "-c", "import time; time.sleep(30)"]

        monkeypatch.setattr(backend, "build_argv", fake_argv)
        job = DetonationJob(job_id="det_slow", kind=DetonationKind.URL, url="https://example.com", timeout_s=1)
        result = await backend.run(job)
        assert result.status is DetonationStatus.TIMEOUT

    async def test_subprocess_exits_without_result(self, store, monkeypatch):
        backend = LocalProcessBackend(store)

        def fake_argv(job_path, out_path, workdir):
            return [sys.executable, "-c", "import sys; sys.stderr.write('kaboom'); sys.exit(3)"]

        monkeypatch.setattr(backend, "build_argv", fake_argv)
        job = DetonationJob(job_id="det_crash", kind=DetonationKind.URL, url="https://example.com", timeout_s=10)
        result = await backend.run(job)
        assert result.status is DetonationStatus.ERROR and "kaboom" in result.error

    def test_build_argv_shape(self, store):
        backend = LocalProcessBackend(store)
        argv = backend.build_argv(Path("/w/job.json"), Path("/w/out.json"), Path("/w"))
        assert argv[1:4] == ["-m", "reddysec.chamber.detonate", "--job"]
        assert "--out" in argv and "--workdir" in argv

    async def test_keep_workdir(self, store, evil_site=None):
        backend = LocalProcessBackend(store, keep_workdir=True, workdir_root=None)
        assert backend.keep_workdir is True


class TestChamberFinalizationEdges:
    async def test_file_ref_value_error_blocked(self, store):
        # A ref the store rejects (bad scheme) surfaces as BLOCKED bad_ref.
        job = DetonationJob(job_id="d", kind=DetonationKind.FILE, file_ref="s3:../bad", file_name="x")
        result = await DetonationChamber(InProcessBackend(store), store).detonate(job)
        assert result.status is DetonationStatus.BLOCKED and "bad_ref" in result.error

    async def test_broken_store_clears_download_refs(self, store, monkeypatch):
        from reddysec.chamber import protocol
        from reddysec.models import DownloadRecord

        def produce(job):
            return protocol.SandboxOutput(
                job_id=job.job_id,
                status=DetonationStatus.OK,
                downloads=[DownloadRecord(suggested_filename="a", sha256="0" * 64, size=1, stored_ref="file:dl_0.bin")],
                files={"dl_0.bin": b"MZ"},
            )

        from .chamber_helpers import RecordingBackend

        backend = RecordingBackend(result=produce)

        class BrokenStore:
            def put(self, *a, **k):
                raise OSError("disk full")

            def exists(self, ref):
                return True

            def get(self, ref):
                return b""

            def delete(self, ref):
                pass

        chm = DetonationChamber(backend, BrokenStore(), allow_private_targets=True)
        result = await chm.detonate(url_job())
        assert result.status is DetonationStatus.OK
        assert result.downloads[0].stored_ref is None


class TestFactoryAci:
    def test_make_chamber_aci(self, store, monkeypatch):
        from reddysec.config import Settings

        monkeypatch.setenv("RS_ACI_SUBSCRIPTION_ID", "sub-1")
        monkeypatch.setenv("RS_ACI_RESOURCE_GROUP", "rg-det")
        monkeypatch.setenv("RS_ACI_SUBNET_ID", "/subscriptions/sub-1/subnets/det")
        settings = Settings(sandbox_backend="aci", env="prod")
        chm = make_chamber(settings, store)
        assert chm.backend.name == "aci"
        assert chm.backend.subscription_id == "sub-1"

    def test_make_chamber_allow_private_override(self, store, monkeypatch):
        from reddysec.config import Settings

        monkeypatch.setenv("RS_CHAMBER_ALLOW_PRIVATE", "1")
        settings = Settings(sandbox_backend="local", env="prod")
        assert make_chamber(settings, store).allow_private_targets is True
