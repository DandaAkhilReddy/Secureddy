"""Unit tests for the Docker backend: argv construction, the stdio protocol,
timeout/kill handling. No daemon runs; a fake runner stands in."""

from __future__ import annotations

from reddysec.chamber.backends.docker import DEFAULT_IMAGE, DockerBackend, RunOutcome, subprocess_runner
from reddysec.chamber.protocol import SandboxOutput, decode_job_envelope, encode_result_envelope
from reddysec.models import DetonationJob, DetonationKind, DetonationResult, DetonationStatus, PageFeatures


def url_job(job_id="det_ABC123", **kw):
    return DetonationJob(job_id=job_id, kind=DetonationKind.URL, url="https://example.com", **kw)


class FakeRunner:
    """Records argv + stdin and replays scripted outcomes in order."""

    def __init__(self, *outcomes: RunOutcome) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[tuple[list[str], bytes, float]] = []

    async def __call__(self, argv, stdin, timeout_s):
        self.calls.append((argv, stdin, timeout_s))
        return self.outcomes.pop(0) if self.outcomes else RunOutcome(0, b"", b"")


class TestArgv:
    def test_hardening_flags_present(self, store):
        backend = DockerBackend(store, image="reddysec-chamber:latest", network="rs-detonation")
        argv = backend.build_argv(url_job())
        joined = " ".join(argv)
        assert argv[:3] == ["docker", "run", "--rm"]
        assert "-i" in argv
        assert "--read-only" in joined
        assert "--cap-drop ALL" in joined
        assert "no-new-privileges" in joined
        assert "seccomp=" in joined and "seccomp-chamber.json" in joined
        assert "--pids-limit 256" in joined
        assert "--memory 2g" in joined
        assert "--cpus 1.5" in joined
        assert "--tmpfs /tmp:rw,size=512m" in joined
        assert "--tmpfs /work:rw,size=1g" in joined
        assert "RS_CHAMBER=1" in joined
        assert "--init" in argv
        assert "--network rs-detonation" in joined

    def test_image_is_last_before_command(self, store):
        backend = DockerBackend(store, image="custom:v2")
        argv = backend.build_argv(url_job())
        idx = argv.index("custom:v2")
        assert argv[idx + 1 : idx + 5] == ["python", "-m", "reddysec.chamber.detonate", "--stdio"]

    def test_default_image(self, store):
        assert DockerBackend(store).image == DEFAULT_IMAGE

    def test_container_name_is_sanitized_and_bounded(self, store):
        backend = DockerBackend(store)
        name = backend.container_name(DetonationJob(job_id="det_AbC/../x" + "Z" * 80, kind=DetonationKind.URL, url="https://x.com"))
        assert name.startswith("rs-det-det_abc")
        assert "/" not in name and ".." not in name
        assert len(name) <= 63

    def test_kill_argv(self, store):
        backend = DockerBackend(store)
        job = url_job()
        assert backend.kill_argv(job) == ["docker", "rm", "-f", backend.container_name(job)]

    def test_max_file_bytes_passed_through(self, store):
        backend = DockerBackend(store, max_file_bytes=1000)
        assert "--max-file-bytes" in backend.build_argv(url_job())


class TestStdioProtocol:
    async def test_job_goes_in_on_stdin(self, store):
        runner = FakeRunner(RunOutcome(0, encode_result_envelope(SandboxOutput(job_id="det_ABC123", status="ok")).encode(), b""))
        backend = DockerBackend(store, runner=runner)
        await backend.run(url_job())
        argv, stdin, _timeout = runner.calls[0]
        job, files = decode_job_envelope(stdin)
        assert job.job_id == "det_ABC123" and files == {}

    async def test_file_job_bytes_in_envelope(self, store):
        ref = store.put(b"%PDF body", ".pdf")
        runner = FakeRunner(RunOutcome(0, encode_result_envelope(SandboxOutput(job_id="det_f", status="ok")).encode(), b""))
        backend = DockerBackend(store, runner=runner)
        job = DetonationJob(job_id="det_f", kind=DetonationKind.FILE, file_ref=ref, file_name="x.pdf")
        await backend.run(job)
        _argv, stdin, _t = runner.calls[0]
        shipped, files = decode_job_envelope(stdin)
        assert shipped.file_ref == "file:input/x.pdf"
        assert files == {"input/x.pdf": b"%PDF body"}

    async def test_result_parsed_and_rehomed(self, store):
        out = SandboxOutput(
            job_id="det_ABC123",
            status=DetonationStatus.OK,
            features=PageFeatures(title="hi", status_code=200),
            screenshot_ref="file:screenshot.jpg",
            files={"screenshot.jpg": b"\xff\xd8shot"},
        )
        runner = FakeRunner(RunOutcome(0, encode_result_envelope(out).encode(), b"chromium noise\n"))
        backend = DockerBackend(store, runner=runner)
        result = await backend.run(url_job())
        assert isinstance(result, DetonationResult)
        assert result.features.title == "hi"
        assert result.screenshot_ref.startswith("local:")
        assert store.get(result.screenshot_ref) == b"\xff\xd8shot"

    async def test_garbage_output_is_error(self, store):
        runner = FakeRunner(RunOutcome(1, b"segfault\n", b"traceback: boom"))
        backend = DockerBackend(store, runner=runner)
        result = await backend.run(url_job())
        assert result.status is DetonationStatus.ERROR
        assert "boom" in result.error


class TestTimeout:
    async def test_timeout_triggers_force_remove(self, store):
        runner = FakeRunner(RunOutcome(None, b"", b"", timed_out=True), RunOutcome(0, b"", b""))
        backend = DockerBackend(store, runner=runner)
        result = await backend.run(url_job(timeout_s=10))
        assert result.status is DetonationStatus.TIMEOUT
        # second call is the forced removal
        assert runner.calls[1][0] == ["docker", "rm", "-f", backend.container_name(url_job(timeout_s=10))]

    async def test_timeout_budget_includes_grace(self, store):
        runner = FakeRunner(RunOutcome(0, encode_result_envelope(SandboxOutput(job_id="det_ABC123", status="ok")).encode(), b""))
        backend = DockerBackend(store, runner=runner, grace_s=15)
        await backend.run(url_job(timeout_s=30))
        assert runner.calls[0][2] == 45.0  # timeout_s + grace_s

    async def test_kill_failure_still_returns_timeout(self, store):
        class ExplodingRunner(FakeRunner):
            async def __call__(self, argv, stdin, timeout_s):
                self.calls.append((argv, stdin, timeout_s))
                if "run" in argv:
                    return RunOutcome(None, b"", b"", timed_out=True)
                raise OSError("docker socket gone")

        backend = DockerBackend(store, runner=ExplodingRunner())
        result = await backend.run(url_job())
        assert result.status is DetonationStatus.TIMEOUT


class TestRealRunnerShape:
    async def test_subprocess_runner_runs_a_command(self):
        # Exercise the real runner against a harmless command (no docker needed).
        outcome = await subprocess_runner(["/bin/sh", "-c", "cat; printf done"], b"hello", 10.0)
        assert outcome.returncode == 0
        assert outcome.stdout == b"hellodone"

    async def test_subprocess_runner_times_out_and_kills(self):
        outcome = await subprocess_runner(["/bin/sh", "-c", "sleep 5"], b"", 0.3)
        assert outcome.timed_out is True
